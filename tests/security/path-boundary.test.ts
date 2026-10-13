import { Dir, type Dirent } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  effectiveLimits,
  type PageFileV1,
  type PageId,
} from '@scene-glass/contracts';
import { resolvePageIdentity } from '@scene-glass/core/page-identity';

import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import {
  ScgAnnotationStore,
  type AuthorizedProjectRootResolver,
} from '../../packages/server/src/storage/scg-annotation-store.js';
import {
  ScgStorageError,
  guardAnnotationPaths,
} from '../../packages/server/src/storage/path-guard.js';

const FIXED_PAGE_ID = `p_${'a'.repeat(64)}` as PageId;
const workspaces: string[] = [];

afterEach(async () => {
  await Promise.all(
    workspaces.splice(0).map((workspace) => rm(workspace, { force: true, recursive: true })),
  );
});

async function createProjectRoot(): Promise<{ readonly root: string; readonly workspace: string }> {
  const workspace = await mkdtemp(join(tmpdir(), 'scene-glass-path-boundary-'));
  workspaces.push(workspace);
  const root = join(workspace, 'project');
  await mkdir(root);
  return { root: await realpath(root), workspace };
}

async function expectStorageError(
  action: () => Promise<unknown>,
  code: ScgStorageError['code'],
): Promise<void> {
  let caught: unknown;
  try {
    await action();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(ScgStorageError);
  expect((caught as ScgStorageError).code).toBe(code);
}

function authorizedProject(limits = BUILT_IN_LIMITS): AuthorizedProject {
  return Object.freeze({
    projectId: 'project-alpha',
    effectiveLimits: limits,
  });
}

async function pageFile(pathname = '/storage-boundary'): Promise<PageFileV1> {
  const page = await resolvePageIdentity({ pathname });
  return {
    schemaVersion: 1,
    page,
    revision: 0,
    annotations: [],
    replayWindow: [],
  };
}
function activeSignal(): AbortSignal {
  return new AbortController().signal;
}

async function consumePages(pages: AsyncIterable<PageFileV1>): Promise<void> {
  for await (const page of pages) {
    void page;
  }
}
function regularDirectoryEntry(name: string): Dirent {
  return {
    name,
    isFile: () => true,
    isSymbolicLink: () => false,
  } as Dirent;
}

function replaceDirectoryRead(read: () => Dirent | null): () => void {
  const descriptor = Object.getOwnPropertyDescriptor(Dir.prototype, 'read');
  if (descriptor === undefined) {
    throw new Error('directory read is unavailable');
  }

  Object.defineProperty(Dir.prototype, 'read', {
    ...descriptor,
    value: async (): Promise<Dirent | null> => read(),
  });
  return () => {
    Object.defineProperty(Dir.prototype, 'read', descriptor);
  };
}

describe('annotation storage path boundaries', () => {
  it('derives one fixed annotation file path and rejects traversal or encoded separators', async () => {
    const { root } = await createProjectRoot();
    const guarded = await guardAnnotationPaths(root);

    const pageFilePath = await guarded.pageFile(FIXED_PAGE_ID);
    expect(pageFilePath.path).toBe(join(root, '.scg', 'annotations', `${FIXED_PAGE_ID}.json`));
    expect((await lstat(guarded.scgDirectory)).isDirectory()).toBe(true);
    expect((await lstat(guarded.annotationsDirectory)).isDirectory()).toBe(true);

    for (const pageId of [
      '../outside',
      `${FIXED_PAGE_ID}/../../outside`,
      `${FIXED_PAGE_ID}%2f..%2foutside`,
    ]) {
      await expectStorageError(() => guarded.pageFile(pageId as PageId), 'SCG_PAGE_INVALID');
    }
  });
  it('accepts the exact-case target at the entry budget and rejects it at N+1', async () => {
    const { root } = await createProjectRoot();
    const guarded = await guardAnnotationPaths(root);
    const target = await guarded.pageFile(FIXED_PAGE_ID);
    await writeFile(target.path, '{}');

    const scanLimit =
      BUILT_IN_LIMITS.pagesPerProject + BUILT_IN_LIMITS.concurrentRequestsPerProject;
    async function scanAt(targetRead: number): Promise<Readonly<Record<string, unknown>>> {
      let reads = 0;
      const restoreDirectoryRead = replaceDirectoryRead(() => {
        reads += 1;
        return regularDirectoryEntry(
          reads < targetRead ? `unrelated-${reads}` : `${FIXED_PAGE_ID}.json`,
        );
      });

      try {
        const found = await target.assertExistingFile();
        return Object.freeze({ found, reads });
      } catch (error: unknown) {
        return Object.freeze({
          code:
            typeof error === 'object' && error !== null && 'code' in error
              ? (error as { readonly code?: unknown }).code
              : undefined,
          reads,
        });
      } finally {
        restoreDirectoryRead();
      }
    }

    await expect(scanAt(scanLimit)).resolves.toEqual({ found: true, reads: scanLimit });
    await expect(scanAt(scanLimit + 1)).resolves.toEqual({
      code: 'SCG_LIMIT_FILE',
      reads: scanLimit + 1,
    });
  });
  it('fails a new page at the non-metadata entry cap without a write or commit leak', async () => {
    const { root } = await createProjectRoot();
    const project = authorizedProject(effectiveLimits(undefined, { pagesPerProject: 2 }));
    const existing = await pageFile('/storage-boundary-existing');
    const rejected = await pageFile('/storage-boundary-rejected');
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: () => root,
    });
    const annotationDirectory = join(root, '.scg', 'annotations');
    const unknownEntryName = 'unknown-entry-at-cap';

    await store.commitPage(project, existing, activeSignal());
    await writeFile(join(annotationDirectory, unknownEntryName), 'unrecognized entry');

    await expectStorageError(
      () => store.commitPage(project, rejected, activeSignal()),
      'SCG_LIMIT_FILE',
    );
    expect((await readdir(annotationDirectory)).sort()).toEqual(
      [`${existing.page.pageId}.json`, unknownEntryName].sort(),
    );
    await expect(store.readPage(project, existing.page, activeSignal())).resolves.toEqual(existing);

    await expect(store.commitPage(project, existing, activeSignal())).resolves.toBeUndefined();
    await expect(store.readPage(project, existing.page, activeSignal())).resolves.toEqual(existing);
  });
  it('admits one recognized metadata entry without consuming page capacity and rejects N+1', async () => {
    const { root } = await createProjectRoot();
    const project = authorizedProject(effectiveLimits(undefined, { pagesPerProject: 2 }));
    const first = await pageFile('/storage-boundary-metadata-first');
    const second = await pageFile('/storage-boundary-metadata-second');
    const rejected = await pageFile('/storage-boundary-metadata-rejected');
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: () => root,
    });
    const annotationDirectory = join(root, '.scg', 'annotations');
    const firstMetadata = `.${first.page.pageId}.json.00000000-0000-4000-8000-000000000000.tmp`;
    const secondMetadata = `.${second.page.pageId}.json.00000000-0000-4000-8000-000000000001.tmp`;

    await store.commitPage(project, first, activeSignal());
    await writeFile(join(annotationDirectory, firstMetadata), 'recognized atomic temporary file');
    await expect(store.commitPage(project, second, activeSignal())).resolves.toBeUndefined();
    expect((await readdir(annotationDirectory)).sort()).toEqual(
      [`${first.page.pageId}.json`, `${second.page.pageId}.json`, firstMetadata].sort(),
    );

    await writeFile(
      join(annotationDirectory, secondMetadata),
      'second recognized atomic temporary file',
    );
    const beforeRejectedCommit = (await readdir(annotationDirectory)).sort();
    await expectStorageError(
      () => store.commitPage(project, rejected, activeSignal()),
      'SCG_LIMIT_FILE',
    );
    expect((await readdir(annotationDirectory)).sort()).toEqual(beforeRejectedCommit);
  });
  it('rejects a case-variant page-file alias for guarded and store operations', async () => {
    expect.assertions(8);
    const { root } = await createProjectRoot();
    const project = authorizedProject();
    const candidate = await pageFile();
    const guarded = await guardAnnotationPaths(root);
    const target = await guarded.pageFile(candidate.page.pageId);
    await writeFile(target.path, JSON.stringify(candidate));
    const alias = `${candidate.page.pageId.replace(/^p_/, 'P_')}.json`;

    async function expectCaseAliasCollision(action: () => Promise<unknown>): Promise<void> {
      let reads = 0;
      const restoreDirectoryRead = replaceDirectoryRead(() => {
        reads += 1;
        return reads === 1 ? regularDirectoryEntry(alias) : null;
      });
      try {
        await expectStorageError(action, 'SCG_PAGE_ID_COLLISION');
      } finally {
        restoreDirectoryRead();
      }
    }

    await expectCaseAliasCollision(() => target.assertExistingFile());

    const store = new ScgAnnotationStore({
      getAuthorizedRoot: () => root,
    });
    await expectCaseAliasCollision(() => store.readPage(project, candidate.page, activeSignal()));
    await expectCaseAliasCollision(() => consumePages(store.listPages(project, activeSignal())));
    await expectCaseAliasCollision(() => store.commitPage(project, candidate, activeSignal()));
  });

  it('propagates the exact abort reason before another exact-case directory read', async () => {
    const { root } = await createProjectRoot();
    const guarded = await guardAnnotationPaths(root);
    const target = await guarded.pageFile(FIXED_PAGE_ID);
    await writeFile(target.path, '{}');

    const controller = new AbortController();
    const reason = new Error('exact-case directory scan cancelled');
    let reads = 0;
    const restoreDirectoryRead = replaceDirectoryRead(() => {
      reads += 1;
      controller.abort(reason);
      return regularDirectoryEntry('unrelated');
    });

    try {
      await expect(target.assertExistingFile(controller.signal)).rejects.toBe(reason);
      expect(reads).toBe(1);
    } finally {
      restoreDirectoryRead();
    }
  });

  it('rejects symlinked project roots, .scg directories, and annotations directories', async () => {
    expect.assertions(6);
    const { root, workspace } = await createProjectRoot();
    const outside = join(workspace, 'outside');
    await mkdir(outside);

    const linkedRoot = join(workspace, 'linked-root');
    await symlink(root, linkedRoot);
    await expectStorageError(() => guardAnnotationPaths(linkedRoot), 'SCG_ROOT_CHANGED');

    const scgRootPath = join(workspace, 'scg-root');
    await mkdir(scgRootPath);
    const scgRoot = await realpath(scgRootPath);
    await symlink(outside, join(scgRoot, '.scg'));
    await expectStorageError(() => guardAnnotationPaths(scgRoot), 'SCG_ROOT_CHANGED');

    const annotationsRootPath = join(workspace, 'annotations-root');
    await mkdir(join(annotationsRootPath, '.scg'), { recursive: true });
    const annotationsRoot = await realpath(annotationsRootPath);
    await symlink(outside, join(annotationsRoot, '.scg', 'annotations'));
    await expectStorageError(() => guardAnnotationPaths(annotationsRoot), 'SCG_ROOT_CHANGED');
  });

  it('detects a project-root dev/ino swap after a path was guarded', async () => {
    expect.assertions(2);
    const { root } = await createProjectRoot();
    const guarded = await guardAnnotationPaths(root);
    const replacedRoot = `${root}-replaced`;

    await rename(root, replacedRoot);
    await mkdir(root);

    await expectStorageError(() => guarded.assertUnchanged(), 'SCG_ROOT_CHANGED');
  });

  it('latches a root change detected between yielded list pages', async () => {
    const { root } = await createProjectRoot();
    const project = authorizedProject();
    const firstPage = await pageFile('/storage-boundary-first');
    const secondPage = await pageFile('/storage-boundary-second');
    const store = new ScgAnnotationStore({
      getAuthorizedRoot: () => root,
    });

    await store.commitPage(project, firstPage, activeSignal());
    await store.commitPage(project, secondPage, activeSignal());
    const iterator = store.listPages(project, activeSignal())[Symbol.asyncIterator]();
    await expect(iterator.next()).resolves.toMatchObject({ done: false });

    await rename(root, `${root}-replaced`);
    await mkdir(root);

    await expectStorageError(() => iterator.next(), 'SCG_ROOT_CHANGED');
    await expectStorageError(
      () => store.readPage(project, firstPage.page, activeSignal()),
      'SCG_ROOT_CHANGED',
    );
  });
  it.each(['readPage', 'listPages', 'commitPage'] as const)(
    'globally latches a root change discovered by %s',
    async (origin) => {
      const { root } = await createProjectRoot();
      const project = authorizedProject();
      const candidate = await pageFile();
      let rootResolverCalls = 0;
      const rootResolver: AuthorizedProjectRootResolver = {
        getAuthorizedRoot: () => {
          rootResolverCalls += 1;
          return root;
        },
      };
      const store = new ScgAnnotationStore(rootResolver);

      await expect(store.readPage(project, candidate.page, activeSignal())).resolves.toBeNull();
      await rename(root, `${root}-replaced`);
      await mkdir(root);

      if (origin === 'readPage') {
        await expectStorageError(
          () => store.readPage(project, candidate.page, activeSignal()),
          'SCG_ROOT_CHANGED',
        );
      } else if (origin === 'listPages') {
        await expectStorageError(
          () => consumePages(store.listPages(project, activeSignal())),
          'SCG_ROOT_CHANGED',
        );
      } else {
        await expectStorageError(
          () => store.commitPage(project, candidate, activeSignal()),
          'SCG_ROOT_CHANGED',
        );
      }

      await expectStorageError(
        () => store.readPage(project, candidate.page, activeSignal()),
        'SCG_ROOT_CHANGED',
      );
      await expectStorageError(
        () => consumePages(store.listPages(project, activeSignal())),
        'SCG_ROOT_CHANGED',
      );
      await expectStorageError(
        () => store.commitPage(project, candidate, activeSignal()),
        'SCG_ROOT_CHANGED',
      );
      expect(rootResolverCalls).toBe(2);
    },
  );
});
