import { createHash } from 'node:crypto';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  REPLAY_RECORD_COUNT,
  serializeCanonicalPageFileV1,
  type PageFileV1,
  type PageId,
  type PageIdentityV1,
  type ReplayRecord,
  type Sha256Digest,
  type UuidV4,
} from '@scene-glass/contracts';
import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import {
  ScgAnnotationStore,
  type ScgAnnotationStoreOptions,
} from '../../packages/server/src/storage/scg-annotation-store.js';

const temporaryRoots: string[] = [];
const canonicalIdentity = 'https://review.scene-glass.test/restart';
const pageId = pageIdFor(canonicalIdentity);
const project: AuthorizedProject = {
  projectId: 'storage-restart',
  effectiveLimits: BUILT_IN_LIMITS,
};

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe('strict .scg restart restore', () => {
  it.each([
    {
      name: 'corrupt UTF-8',
      bytes: Uint8Array.of(0xff, 0xfe, 0x00),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'byte order mark',
      bytes: Uint8Array.of(0xef, 0xbb, 0xbf, ...canonicalBytes(pageFile(1))),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'short JSON',
      bytes: canonicalBytes(pageFile(1)).subarray(0, 32),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'premature EOF before canonical newline',
      bytes: canonicalBytes(pageFile(1)).subarray(0, -1),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'noncanonical JSON',
      bytes: new TextEncoder().encode(JSON.stringify(pageFile(1))),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'trailing canonical JSON data',
      bytes: Uint8Array.of(...canonicalBytes(pageFile(1)), 0x20),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'non-NFC identity',
      bytes: uncheckedJsonBytes({
        schemaVersion: 1,
        page: {
          policyVersion: 1,
          canonicalIdentity: 'https://review.scene-glass.test/cafe\u0301',
          route: '/restart',
          pageId,
        },
        revision: 0,
        annotations: [],
        replayWindow: [],
      }),
      code: 'SCG_PAGE_CORRUPT',
    },
    {
      name: 'page ID digest mismatch',
      bytes: canonicalBytes({
        schemaVersion: 1,
        page: {
          policyVersion: 1,
          canonicalIdentity: 'https://review.scene-glass.test/a-different-page',
          route: '/restart',
          pageId,
        },
        revision: 0,
        annotations: [],
        replayWindow: [],
      }),
      code: 'SCG_PAGE_ID_COLLISION',
    },
  ] as const)('rejects persisted $name without silently resetting it', async ({ bytes, code }) => {
    const root = await createTemporaryRoot('scene-glass-invalid-storage-');
    const target = await writePersistedBytes(root, bytes);
    const store = storeFor(root);
    const validPage = pageFile(3);

    await expect(store.readPage(project, validPage.page, activeSignal())).rejects.toMatchObject({
      code,
    });
    expectBytes(await readFile(target), bytes);

    await expect(store.commitPage(project, validPage, activeSignal())).rejects.toMatchObject({
      code,
    });
    expectBytes(await readFile(target), bytes);
  });

  it('restores only the exact canonical page through a new store instance', async () => {
    const root = await createTemporaryRoot('scene-glass-restart-');
    const committed = pageFile(3);
    const target = join(root, '.scg', 'annotations', `${pageId}.json`);

    await storeFor(root).commitPage(project, committed, activeSignal());
    const persistedBytes = await readFile(target);
    expectBytes(persistedBytes, canonicalBytes(committed));

    const restartedStore = storeFor(root);
    await expect(restartedStore.readPage(project, committed.page, activeSignal())).resolves.toEqual(
      committed,
    );

    const restoredPages: PageFileV1[] = [];
    for await (const page of restartedStore.listPages(project, activeSignal())) {
      restoredPages.push(page);
    }
    expect(restoredPages).toEqual([committed]);
    expectBytes(await readFile(target), persistedBytes);
  });
  it('grandfathers oversized persisted replay results while enforcing a tightened candidate tail', async () => {
    const root = await createTemporaryRoot('scene-glass-replay-result-tightening-');
    const historical = pageFileWithOversizedReplayHistory(REPLAY_RECORD_COUNT);
    const target = join(root, '.scg', 'annotations', `${pageId}.json`);

    await storeFor(root).commitPage(project, historical, activeSignal());

    const compliantRecord = replayTail(REPLAY_RECORD_COUNT + 1).at(-1);
    if (compliantRecord === undefined) {
      throw new Error('expected a compliant replay tail');
    }
    const limits = {
      ...BUILT_IN_LIMITS,
      replayResultBytes: replayResultByteLength(compliantRecord),
    };
    expect(
      historical.replayWindow.every(
        (record) => replayResultByteLength(record) > limits.replayResultBytes,
      ),
    ).toBe(true);

    const restartedStore = storeFor(root, { limits });
    await expect(
      restartedStore.readPage(project, historical.page, activeSignal()),
    ).resolves.toEqual(historical);

    const listedHistory: PageFileV1[] = [];
    for await (const stored of restartedStore.listPages(project, activeSignal())) {
      listedHistory.push(stored);
    }
    expect(listedHistory).toEqual([historical]);

    const compliant = {
      ...historical,
      revision: REPLAY_RECORD_COUNT + 1,
      replayWindow: [...historical.replayWindow.slice(1), compliantRecord],
    };
    await expect(
      restartedStore.commitPage(project, compliant, activeSignal()),
    ).resolves.toBeUndefined();

    const committed = await storeFor(root, { limits }).readPage(
      project,
      historical.page,
      activeSignal(),
    );
    expect(committed).toEqual(compliant);
    if (committed === null) {
      throw new Error('expected the compliant page to persist');
    }
    expect(committed.replayWindow).toHaveLength(REPLAY_RECORD_COUNT);
    expect(committed.replayWindow.map((record) => record.appliedRevision)).toEqual(
      Array.from({ length: REPLAY_RECORD_COUNT }, (_, index) => index + 2),
    );
    expect(
      committed.replayWindow
        .slice(0, -1)
        .every((record) => replayResultByteLength(record) > limits.replayResultBytes),
    ).toBe(true);

    const oversizedRecord = oversizedReplayRecord(REPLAY_RECORD_COUNT + 2);
    expect(replayResultByteLength(oversizedRecord)).toBeGreaterThan(limits.replayResultBytes);
    const oversized = {
      ...committed,
      revision: REPLAY_RECORD_COUNT + 2,
      replayWindow: [...committed.replayWindow.slice(1), oversizedRecord],
    };
    const beforeOversizedCommit = await readFile(target);

    await expect(
      restartedStore.commitPage(project, oversized, activeSignal()),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    expectBytes(await readFile(target), beforeOversizedCommit);
    await expect(
      storeFor(root, { limits }).readPage(project, committed.page, activeSignal()),
    ).resolves.toEqual(committed);
  });
  it('rejects unpersisted oversized replay history before creating or rewriting a page', async () => {
    const root = await createTemporaryRoot('scene-glass-replay-provenance-');
    const annotationDirectory = join(root, '.scg', 'annotations');
    const target = join(annotationDirectory, `${pageId}.json`);
    await mkdir(annotationDirectory, { recursive: true });

    const historical = pageFileWithOversizedReplayHistory(REPLAY_RECORD_COUNT);
    const compliantTail = replayTail(REPLAY_RECORD_COUNT).at(-1);
    if (compliantTail === undefined) {
      throw new Error('expected a compliant replay tail');
    }
    const limits = {
      ...BUILT_IN_LIMITS,
      replayResultBytes: replayResultByteLength(compliantTail),
    };
    const absentCandidate = {
      ...historical,
      replayWindow: [...historical.replayWindow.slice(0, -1), compliantTail],
    };
    expect(
      absentCandidate.replayWindow
        .slice(0, -1)
        .every((record) => replayResultByteLength(record) > limits.replayResultBytes),
    ).toBe(true);

    const beforeAbsentNames = await readdir(annotationDirectory);
    await expect(
      storeFor(root, { limits }).commitPage(project, absentCandidate, activeSignal()),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    expect(await readdir(annotationDirectory)).toEqual(beforeAbsentNames);
    await expect(access(target)).rejects.toMatchObject({ code: 'ENOENT' });

    const existing = pageFile(REPLAY_RECORD_COUNT);
    await storeFor(root).commitPage(project, existing, activeSignal());
    const beforeRewrite = await readFile(target);
    const nextTail = replayTail(existing.revision + 1).at(-1);
    const persistedOverlap = existing.replayWindow.slice(1);
    if (nextTail === undefined || persistedOverlap[0] === undefined) {
      throw new Error('expected full persisted replay overlap');
    }
    const rewritten = {
      ...existing,
      revision: existing.revision + 1,
      replayWindow: [
        oversizedReplayRecord(persistedOverlap[0].appliedRevision),
        ...persistedOverlap.slice(1),
        nextTail,
      ],
    };

    await expect(
      storeFor(root, { limits }).commitPage(project, rewritten, activeSignal()),
    ).rejects.toMatchObject({
      code: 'SCG_PAGE_INVALID',
      message: 'annotation page replay history must preserve the persisted tail',
    });
    expectBytes(await readFile(target), beforeRewrite);
    expect(await readdir(annotationDirectory)).toEqual([`${pageId}.json`]);
  });
  it('accepts an exact page-byte limit and rejects N+1 growth before decoding', async () => {
    const root = await createTemporaryRoot('scene-glass-page-byte-limit-');
    const candidate = pageFile(4);
    const canonical = canonicalBytes(candidate);
    const target = await writePersistedBytes(root, canonical);
    const limits = { ...BUILT_IN_LIMITS, pageFileBytes: canonical.byteLength };

    await expect(
      storeFor(root, { limits }).readPage(project, candidate.page, activeSignal()),
    ).resolves.toEqual(candidate);

    await writeFile(target, Uint8Array.of(...canonical, 0xff));
    await expect(
      storeFor(root, { limits }).readPage(project, candidate.page, activeSignal()),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
  });
  it('preserves effective replay ledger and annotation limit errors for persisted pages', async () => {
    const ledgerRoot = await createTemporaryRoot('scene-glass-replay-ledger-limit-');
    const ledgerPage = pageFile(1);
    const ledgerTarget = await writePersistedBytes(ledgerRoot, canonicalBytes(ledgerPage));
    const replayLedgerBytes = replayLedgerByteLength(ledgerPage);

    await expect(
      storeFor(ledgerRoot, {
        limits: { ...BUILT_IN_LIMITS, replayLedgerBytes },
      }).readPage(project, ledgerPage.page, activeSignal()),
    ).resolves.toEqual(ledgerPage);
    const ledgerBytes = await readFile(ledgerTarget);
    await expect(
      storeFor(ledgerRoot, {
        limits: { ...BUILT_IN_LIMITS, replayLedgerBytes: replayLedgerBytes - 1 },
      }).readPage(project, ledgerPage.page, activeSignal()),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    expectBytes(await readFile(ledgerTarget), ledgerBytes);

    const annotationRoot = await createTemporaryRoot('scene-glass-annotation-limit-');
    const annotationRecord = oversizedReplayRecord(1);
    if (annotationRecord.result.kind !== 'create') {
      throw new Error('expected a create replay record');
    }
    const secondAnnotationRecord = oversizedReplayRecord(2);
    if (secondAnnotationRecord.result.kind !== 'create') {
      throw new Error('expected a second create replay record');
    }
    const annotationPage = {
      ...pageFile(0),
      annotations: [annotationRecord.result.annotation],
    };
    const annotationTarget = await writePersistedBytes(
      annotationRoot,
      canonicalBytes(annotationPage),
    );

    await expect(
      storeFor(annotationRoot, {
        limits: { ...BUILT_IN_LIMITS, annotationsPerPage: 1 },
      }).readPage(project, annotationPage.page, activeSignal()),
    ).resolves.toEqual(annotationPage);

    const overAnnotationLimitPage = {
      ...annotationPage,
      annotations: [annotationRecord.result.annotation, secondAnnotationRecord.result.annotation],
    };
    await writeFile(annotationTarget, canonicalBytes(overAnnotationLimitPage));
    const annotationBytes = await readFile(annotationTarget);
    await expect(
      storeFor(annotationRoot, {
        limits: { ...BUILT_IN_LIMITS, annotationsPerPage: 1 },
      }).readPage(project, annotationPage.page, activeSignal()),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    expectBytes(await readFile(annotationTarget), annotationBytes);
  });

  it('quarantines only the project with unknown commit durability', async () => {
    const root = await createTemporaryRoot('scene-glass-durability-quarantine-');
    const alphaPage = pageFile(1);
    const betaProject = { ...project, projectId: 'storage-restart-beta' };
    const betaPage = pageFile(1, 'https://review.scene-glass.test/restart-beta');
    let faulted = false;
    const store = storeFor(root, {
      faultPoints: {
        'dir-sync': () => {
          if (!faulted) {
            faulted = true;
            throw new Error('simulated directory sync failure');
          }
        },
      },
    });

    await expect(store.commitPage(project, alphaPage, activeSignal())).rejects.toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
    });
    await expect(store.readPage(project, alphaPage.page, activeSignal())).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });
    expect(() => store.listPages(project, activeSignal())).toThrow(
      'annotation project is quarantined',
    );
    await expect(store.commitPage(project, alphaPage, activeSignal())).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });

    await expect(store.commitPage(betaProject, betaPage, activeSignal())).resolves.toBeUndefined();
    await expect(store.readPage(betaProject, betaPage.page, activeSignal())).resolves.toEqual(
      betaPage,
    );
  });

  it('quarantines only the project with post-rename storage integrity loss', async () => {
    const root = await createTemporaryRoot('scene-glass-integrity-quarantine-');
    const alphaPage = pageFile(2);
    const betaProject = { ...project, projectId: 'storage-restart-beta-integrity' };
    const betaPage = pageFile(2, 'https://review.scene-glass.test/restart-beta-integrity');
    let faulted = false;
    const store = storeFor(root, {
      faultPoints: {
        'dir-sync': async ({ targetPath }) => {
          if (!faulted) {
            faulted = true;
            await writeFile(targetPath, Uint8Array.of(0xff));
            throw new Error('simulated replacement after rename');
          }
        },
      },
    });

    await expect(store.commitPage(project, alphaPage, activeSignal())).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
    });
    await expect(store.readPage(project, alphaPage.page, activeSignal())).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });

    await expect(store.commitPage(betaProject, betaPage, activeSignal())).resolves.toBeUndefined();
    await expect(store.readPage(betaProject, betaPage.page, activeSignal())).resolves.toEqual(
      betaPage,
    );
  });
  it('latches a root failure before a late abort and stops every project', async () => {
    const root = await createTemporaryRoot('scene-glass-root-abort-');
    const controller = new AbortController();
    const reason = new Error('request cancelled while resolving root');
    let releaseResolver!: () => void;
    let resolverEntered!: () => void;
    const resolverPaused = new Promise<void>((resolve) => {
      releaseResolver = resolve;
    });
    const resolverStarted = new Promise<void>((resolve) => {
      resolverEntered = resolve;
    });
    let firstResolution = true;
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: async () => {
        if (firstResolution) {
          firstResolution = false;
          resolverEntered();
          await resolverPaused;
          throw new Error('authorized root changed');
        }
        return root;
      },
    });

    const pending = store.readPage(project, pageFile(3).page, controller.signal);
    await resolverStarted;
    controller.abort(reason);
    releaseResolver();

    await expect(pending).rejects.toBe(reason);
    await expect(
      store.readPage(
        { ...project, projectId: 'storage-restart-root-abort-other-project' },
        pageFile(3, 'https://review.scene-glass.test/root-abort-other').page,
        activeSignal(),
      ),
    ).rejects.toMatchObject({
      code: 'SCG_ROOT_CHANGED',
      message: 'annotation storage is stopped after a root change',
    });
  });

  it('fails a suspended read after concurrent quarantine', async () => {
    const root = await createTemporaryRoot('scene-glass-read-quarantine-race-');
    let releaseResolver!: () => void;
    let resolverEntered!: () => void;
    const resolverPaused = new Promise<void>((resolve) => {
      releaseResolver = resolve;
    });
    const resolverStarted = new Promise<void>((resolve) => {
      resolverEntered = resolve;
    });
    let resolverCalls = 0;
    const store = new ScgAnnotationStore(
      {
        getAuthorizedRoot: async () => {
          resolverCalls += 1;
          if (resolverCalls === 1) {
            resolverEntered();
            await resolverPaused;
          }
          return root;
        },
      },
      {
        faultPoints: {
          'dir-sync': () => {
            throw new Error('simulated directory sync failure');
          },
        },
      },
    );
    const candidate = pageFile(3, 'https://review.scene-glass.test/read-quarantine-race');
    const pendingRead = store.readPage(project, candidate.page, activeSignal());

    await resolverStarted;
    await expect(store.commitPage(project, candidate, activeSignal())).rejects.toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
    });
    releaseResolver();

    await expect(pendingRead).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });
  });

  it('stops a queued commit before rename after concurrent quarantine', async () => {
    const root = await createTemporaryRoot('scene-glass-commit-quarantine-race-');
    const first = pageFile(3, 'https://review.scene-glass.test/commit-quarantine-first');
    const second = pageFile(3, 'https://review.scene-glass.test/commit-quarantine-second');
    let releaseRename!: () => void;
    let renameEntered!: () => void;
    const renamePaused = new Promise<void>((resolve) => {
      releaseRename = resolve;
    });
    const renameStarted = new Promise<void>((resolve) => {
      renameEntered = resolve;
    });
    let renameCalls = 0;
    const store = storeFor(root, {
      faultPoints: {
        rename: async () => {
          renameCalls += 1;
          if (renameCalls === 1) {
            renameEntered();
            await renamePaused;
          }
        },
        'dir-sync': () => {
          throw new Error('simulated directory sync failure');
        },
      },
    });
    const secondTarget = join(root, '.scg', 'annotations', `${second.page.pageId}.json`);
    const pendingFirstCommit = store.commitPage(project, first, activeSignal());

    await renameStarted;
    const pendingSecondCommit = store.commitPage(project, second, activeSignal());
    releaseRename();

    await expect(pendingFirstCommit).rejects.toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
    });
    await expect(pendingSecondCommit).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });
    await expect(access(secondTarget)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(store.readPage(project, second.page, activeSignal())).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
      message: 'annotation project is quarantined',
    });
  });

  it('rejects the pages-per-project sentinel for listing and commit', async () => {
    const root = await createTemporaryRoot('scene-glass-page-count-sentinel-');
    const limitedProject: AuthorizedProject = {
      ...project,
      effectiveLimits: { ...BUILT_IN_LIMITS, pagesPerProject: 1 },
    };
    const first = pageFile(0, 'https://review.scene-glass.test/page-count-first');
    const second = pageFile(0, 'https://review.scene-glass.test/page-count-second');
    await writePersistedPage(root, first);
    await writePersistedPage(root, second);
    const store = storeFor(root);
    const iterator = store.listPages(limitedProject, activeSignal())[Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    await expect(store.commitPage(limitedProject, first, activeSignal())).rejects.toMatchObject({
      code: 'SCG_LIMIT_FILE',
    });
  });
  it('atomically adopts one concurrent initial root and latches a different resolver root', async () => {
    const firstRoot = await createTemporaryRoot('scene-glass-concurrent-root-first-');
    const secondRoot = await createTemporaryRoot('scene-glass-concurrent-root-second-');
    let resolverCalls = 0;
    let releaseResolvers!: () => void;
    let secondResolverEntered!: () => void;
    const resolverPaused = new Promise<void>((resolve) => {
      releaseResolvers = resolve;
    });
    const secondResolverStarted = new Promise<void>((resolve) => {
      secondResolverEntered = resolve;
    });
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: async () => {
        const call = (resolverCalls += 1);
        if (call === 2) {
          secondResolverEntered();
        }
        await resolverPaused;
        return call === 1 ? firstRoot : secondRoot;
      },
    });
    const candidate = pageFile(0, 'https://review.scene-glass.test/concurrent-root');
    const firstRead = store.readPage(project, candidate.page, activeSignal());
    const secondRead = store.readPage(project, candidate.page, activeSignal());

    await secondResolverStarted;
    releaseResolvers();

    const results = await Promise.allSettled([firstRead, secondRead]);
    expect(resolverCalls).toBe(2);
    expect(
      results.some(
        (result) => result.status === 'rejected' && hasErrorCode(result.reason, 'SCG_ROOT_CHANGED'),
      ),
    ).toBe(true);
    expect(
      (await Promise.all([hasScgDirectory(firstRoot), hasScgDirectory(secondRoot)])).filter(
        Boolean,
      ),
    ).toHaveLength(1);
    await expect(
      store.readPage(
        { ...project, projectId: 'storage-restart-concurrent-root-other-project' },
        pageFile(0, 'https://review.scene-glass.test/concurrent-root-other').page,
        activeSignal(),
      ),
    ).rejects.toMatchObject({ code: 'SCG_ROOT_CHANGED' });
  });

  it('serializes concurrent distinct-page admission at a limit of one', async () => {
    const root = await createTemporaryRoot('scene-glass-concurrent-page-limit-');
    const limitedProject: AuthorizedProject = {
      ...project,
      effectiveLimits: { ...BUILT_IN_LIMITS, pagesPerProject: 1 },
    };
    const first = pageFile(0, 'https://review.scene-glass.test/concurrent-page-limit-first');
    const second = pageFile(0, 'https://review.scene-glass.test/concurrent-page-limit-second');
    let releaseRename!: () => void;
    let renameEntered!: () => void;
    const renamePaused = new Promise<void>((resolve) => {
      releaseRename = resolve;
    });
    const renameStarted = new Promise<void>((resolve) => {
      renameEntered = resolve;
    });
    let renameCalls = 0;
    const store = storeFor(root, {
      faultPoints: {
        rename: async () => {
          renameCalls += 1;
          if (renameCalls === 1) {
            renameEntered();
            await renamePaused;
          }
        },
      },
    });
    const pendingFirstCommit = store.commitPage(limitedProject, first, activeSignal());

    await renameStarted;
    const pendingSecondCommit = store.commitPage(limitedProject, second, activeSignal());
    releaseRename();

    await expect(pendingFirstCommit).resolves.toBeUndefined();
    await expect(pendingSecondCommit).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    const pages: PageFileV1[] = [];
    for await (const page of store.listPages(limitedProject, activeSignal())) {
      pages.push(page);
    }
    expect(pages).toEqual([first]);
  });

  it('bounds junk-dominated annotation directory enumeration', async () => {
    const root = await createTemporaryRoot('scene-glass-junk-enumeration-');
    const limitedProject: AuthorizedProject = {
      ...project,
      effectiveLimits: { ...BUILT_IN_LIMITS, pagesPerProject: 1 },
    };
    const annotationsDirectory = join(root, '.scg', 'annotations');
    await mkdir(annotationsDirectory, { recursive: true });
    await Promise.all([
      writeFile(join(annotationsDirectory, 'junk-first'), 'junk\n'),
      writeFile(
        join(annotationsDirectory, `.${pageId}.json.00000000-0000-4000-8000-000000000000.tmp`),
        'orphaned atomic temporary file\n',
      ),
      writeFile(join(annotationsDirectory, 'junk-second'), 'junk\n'),
    ]);
    const pages = storeFor(root).listPages(limitedProject, activeSignal());
    const iterator = pages[Symbol.asyncIterator]();

    await expect(iterator.next()).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
  });

  it('rethrows abort reasons without latching root or project faults', async () => {
    const root = await createTemporaryRoot('scene-glass-abort-');
    const candidate = pageFile(5);
    const controller = new AbortController();
    const reason = new Error('cancelled before rename');
    const store = storeFor(root, {
      faultPoints: {
        write: () => {
          controller.abort(reason);
        },
      },
    });

    await expect(store.commitPage(project, candidate, controller.signal)).rejects.toBe(reason);
    await expect(store.readPage(project, candidate.page, activeSignal())).resolves.toBeNull();

    let resolverCalls = 0;
    const entryStore = new ScgAnnotationStore({
      getAuthorizedRoot: () => {
        resolverCalls += 1;
        return root;
      },
    });
    const cancelled = new AbortController();
    const entryReason = new Error('cancelled at public entry');
    cancelled.abort(entryReason);

    expect(() => entryStore.listPages(project, cancelled.signal)).toThrow(entryReason);
    expect(resolverCalls).toBe(0);
    await expect(entryStore.readPage(project, candidate.page, activeSignal())).resolves.toBeNull();
  });

  it('does not accept a client root field or an escaping page ID', async () => {
    const root = await createTemporaryRoot('scene-glass-authorized-root-');
    const outside = await createTemporaryRoot('scene-glass-outside-root-');
    const sentinel = join(outside, 'outside-sentinel');
    const sentinelBytes = new TextEncoder().encode('must remain outside .scg');
    await writeFile(sentinel, sentinelBytes);

    let resolverCalls = 0;
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: async () => {
        resolverCalls += 1;
        return root;
      },
    });
    const clientSuppliedProject = Object.assign({}, project, {
      root: outside,
    });

    await expect(
      store.readPage(clientSuppliedProject, pageFile(0).page, activeSignal()),
    ).resolves.toBeNull();
    expect(resolverCalls).toBe(1);
    expectBytes(await readFile(sentinel), sentinelBytes);
    await expect(access(join(outside, '.scg'))).rejects.toMatchObject({ code: 'ENOENT' });

    resolverCalls = 0;
    const escapeAttempt = {
      ...pageFile(0).page,
      pageId: '../../outside-root' as PageId,
    } as PageIdentityV1;
    await expect(store.readPage(project, escapeAttempt, activeSignal())).rejects.toMatchObject({
      code: 'SCG_PAGE_INVALID',
    });
    expect(resolverCalls).toBe(0);
  });
});

async function createTemporaryRoot(prefix: string): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryRoots.push(root);
  return root;
}

function storeFor(root: string, options: ScgAnnotationStoreOptions = {}): ScgAnnotationStore {
  return new ScgAnnotationStore(
    {
      getAuthorizedRoot: () => root,
    },
    options,
  );
}

async function writePersistedBytes(root: string, bytes: Uint8Array): Promise<string> {
  const directory = join(root, '.scg', 'annotations');
  await mkdir(directory, { recursive: true });
  const target = join(directory, `${pageId}.json`);
  await writeFile(target, bytes);
  return target;
}
async function writePersistedPage(root: string, page: PageFileV1): Promise<void> {
  const directory = join(root, '.scg', 'annotations');
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, `${page.page.pageId}.json`), canonicalBytes(page));
}

function pageFile(revision: number, identity = canonicalIdentity): PageFileV1 {
  return {
    schemaVersion: 1,
    page: {
      policyVersion: 1,
      canonicalIdentity: identity,
      route: '/restart',
      pageId: pageIdFor(identity),
    },
    revision,
    annotations: [],
    replayWindow: replayTail(revision),
  };
}
function pageFileWithOversizedReplayHistory(revision: number): PageFileV1 {
  return {
    ...pageFile(revision),
    replayWindow: oversizedReplayTail(revision),
  };
}

function oversizedReplayTail(revision: number): readonly ReplayRecord[] {
  const count = Math.min(revision, REPLAY_RECORD_COUNT);
  return Array.from({ length: count }, (_, index) =>
    oversizedReplayRecord(revision - count + index + 1),
  );
}

function oversizedReplayRecord(appliedRevision: number): ReplayRecord {
  return {
    operationId:
      `00000000-0000-4000-8000-${appliedRevision.toString(16).padStart(12, '0')}` as UuidV4,
    kind: 'create',
    inputDigest: `sha256:${'0'.repeat(64)}` as Sha256Digest,
    appliedRevision,
    result: {
      kind: 'create',
      revision: appliedRevision,
      annotation: {
        id: `00000000-0000-4000-8000-${appliedRevision.toString(16).padStart(12, '0')}` as UuidV4,
        locator: { dataScgId: `historical-${appliedRevision}` },
        memo: `historical replay result ${'x'.repeat(512)}`,
        surroundingText: 'Historical replay result',
        domOrder: appliedRevision,
        resolution: { status: 'resolved', reason: null },
        createdAt: '2026-01-01T00:00:00Z',
        updatedAt: '2026-01-01T00:00:00Z',
      },
    },
  };
}

function replayResultByteLength(record: ReplayRecord): number {
  return new TextEncoder().encode(JSON.stringify(record.result)).byteLength;
}
function replayLedgerByteLength(page: PageFileV1): number {
  return new TextEncoder().encode(JSON.stringify(page.replayWindow)).byteLength;
}

function replayTail(revision: number): readonly ReplayRecord[] {
  const count = Math.min(revision, REPLAY_RECORD_COUNT);
  return Array.from({ length: count }, (_, index): ReplayRecord => {
    const appliedRevision = revision - count + index + 1;
    return {
      operationId:
        `00000000-0000-4000-8000-${appliedRevision.toString(16).padStart(12, '0')}` as UuidV4,
      kind: 'delete',
      inputDigest: `sha256:${'0'.repeat(64)}` as Sha256Digest,
      appliedRevision,
      result: {
        kind: 'delete',
        revision: appliedRevision,
        annotationId: '00000000-0000-4000-8000-000000000001' as UuidV4,
      },
    };
  });
}
function pageIdFor(identity: string): PageId {
  return `p_${createHash('sha256').update(identity, 'utf8').digest('hex')}` as PageId;
}

function canonicalBytes(page: unknown): Uint8Array {
  return new TextEncoder().encode(serializeCanonicalPageFileV1(page));
}
function uncheckedJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.byteLength).toBe(expected.byteLength);
  expect([...actual]).toEqual([...expected]);
}
function activeSignal(): AbortSignal {
  return new AbortController().signal;
}
async function hasScgDirectory(root: string): Promise<boolean> {
  try {
    await access(join(root, '.scg'));
    return true;
  } catch (error: unknown) {
    if (hasErrorCode(error, 'ENOENT')) {
      return false;
    }
    throw error;
  }
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
