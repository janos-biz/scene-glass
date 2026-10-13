import { createHash } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  parsePageFileV1,
  serializeCanonicalPageFileV1,
  type PageFileV1,
} from '@scene-glass/contracts';
import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import { probeProjectRoot } from '../../packages/server/src/platform/probe.js';
import { ScgAnnotationStore } from '../../packages/server/src/storage/scg-annotation-store.js';
import {
  acquireLifecycleLock,
  finalizeLifecycleQuarantine,
  quarantineLifecycleExactFile,
  readExactLifecycleWal,
  releaseLifecycleLock,
  removeExactStagedFile,
  replaceReservedLifecycleFileExact,
  reserveLifecycleStagedFile,
  restoreLifecycleQuarantine,
  writeLifecycleStagedFile,
  type NativeLifecycleQuarantine,
} from '../../packages/onboarding/src/native.js';
import type { FileIdentity } from '../../packages/onboarding/src/types.js';

const temporaryRoots: string[] = [];
const canonicalIdentity = 'https://review.scene-glass.test/macos-durability';
const pageId = `p_${createHash('sha256').update(canonicalIdentity, 'utf8').digest('hex')}`;
const POST_EXCHANGE_MUTATION_WORKER_DEADLINE_MS = 5_000;
const POST_EXCHANGE_MUTATION_BYTES = 12 * 1024 * 1024;
const POST_EXCHANGE_MUTATION_WORKER_SOURCE = `
const { closeSync, openSync, statSync, writeSync } = require('node:fs');
const { parentPort, workerData } = require('node:worker_threads');

function identity(path) {
  const information = statSync(path, { bigint: true });
  return { device: information.dev.toString(), inode: information.ino.toString() };
}

function matches(left, right) {
  return left.device === right.device && left.inode === right.inode;
}

try {
  parentPort.postMessage({ type: 'prepared' });
  const deadline = Date.now() + workerData.deadlineMilliseconds;
  let mutated = false;
  while (Date.now() < deadline) {
    try {
      if (
        matches(identity(workerData.targetPath), workerData.stagingIdentity) &&
        matches(identity(workerData.stagingPath), workerData.targetIdentity)
      ) {
        const descriptor = openSync(workerData.stagingPath, 'r+');
        try {
          if (
            writeSync(
              descriptor,
              Buffer.from([workerData.replacementByte]),
              0,
              1,
              workerData.offset,
            ) !== 1
          ) {
            throw new Error('post-exchange mutation write was incomplete');
          }
        } finally {
          closeSync(descriptor);
        }
        const observed = statSync(workerData.stagingPath, { bigint: true });
        if (
          observed.dev.toString() !== workerData.targetIdentity.device ||
          observed.ino.toString() !== workerData.targetIdentity.inode ||
          observed.size !== BigInt(workerData.expectedSize)
        ) {
          throw new Error('post-exchange mutation changed exact-file authority');
        }
        mutated = true;
        parentPort.postMessage({ type: 'mutated' });
        break;
      }
    } catch (error) {
      if (error && typeof error === 'object' && error.code === 'ENOENT') {
        continue;
      }
      throw error;
    }
  }
  if (!mutated) {
    throw new Error('post-exchange mutation worker did not observe the exchange');
  }
} catch {
  parentPort.postMessage({
    type: 'error',
    message: 'post-exchange mutation worker failed',
  });
}
`;

const project: AuthorizedProject = {
  projectId: 'macos-durability',
  effectiveLimits: BUILT_IN_LIMITS,
};

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe.skipIf(process.platform !== 'darwin')('macOS authoritative durability', () => {
  it('accepts a local Darwin root and replaces a complete same-directory .scg page', async () => {
    const root = await createTemporaryRoot();
    const result = await probeProjectRoot(root, {
      platform: 'darwin',
      macosVolumeInspector: async () => ({ network: false, removable: false }),
    });

    expect(result).toMatchObject({
      platform: 'darwin',
      supported: true,
      authority: 'macos-authoritative',
      code: null,
      failStopReason: null,
    });
    expect(result.facts?.realPath).toBe(root);

    const store = new ScgAnnotationStore({
      getAuthorizedRoot: () => root,
    });
    const oldPage = pageFile(0);
    const newPage = pageFile(1);
    const target = join(root, '.scg', 'annotations', `${pageId}.json`);
    const signal = new AbortController().signal;

    await store.commitPage(project, oldPage, signal);
    const oldBytes = await readFile(target);
    expectBytes(oldBytes, canonicalBytes(oldPage));

    await store.commitPage(project, newPage, signal);
    const newBytes = await readFile(target);
    expectBytes(newBytes, canonicalBytes(newPage));
    expect([...newBytes]).not.toEqual([...oldBytes]);
    expect(await readdir(join(root, '.scg', 'annotations'))).toEqual([`${pageId}.json`]);
  });
  it('retains exact staged-file authority when the quarantined inode is rewritten', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    const targetPath = join(root, 'same-inode.txt');
    const original = 'same-size';
    const replacement = 'forgery!!';
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    await writeFile(targetPath, original, { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);

    try {
      const identity = await lifecycleIdentity(targetPath);
      const removed = removeExactStagedFile({
        lock,
        target: {
          path: targetPath,
          identity,
          mode: 0o600,
          size: Buffer.byteLength(original),
          digest: `sha256:${createHash('sha256').update(original, 'utf8').digest('hex')}`,
        },
      });
      if (removed.state !== 'completed' || removed.quarantine === undefined) {
        throw new Error('Exact staged-file removal did not retain a quarantine capability.');
      }

      await writeFile(join(root, `.scg-remove-${identity.device}-${identity.inode}`), replacement, {
        mode: 0o600,
      });

      const finalized = finalizeLifecycleQuarantine({ lock, quarantine: removed.quarantine });
      expect(finalized.state).toBe('indeterminate');
      expect(finalized.quarantine).toBe(removed.quarantine);
    } finally {
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });
  it('rejects a same-inode, same-size staged mutation before exact WAL exchange', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    const targetPath = join(root, 'staged-mutation-target');
    const stagingPath = join(root, 'staged-mutation-stage');
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    await writeFile(targetPath, 'previous!', { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);

    try {
      const targetIdentity = await lifecycleIdentity(targetPath);
      const snapshot = readExactLifecycleWal({
        lock,
        target: { path: targetPath, identity: targetIdentity, mode: 0o600 },
      });
      if (snapshot.state !== 'completed') {
        throw new Error('Exact WAL snapshot was indeterminate before staged mutation.');
      }
      snapshot.bytes.fill(0);
      const staged = reserveLifecycleStagedFile({ lock, path: stagingPath, mode: 0o600 });
      if (staged.state !== 'completed') {
        throw new Error('Exact WAL stage reservation was indeterminate.');
      }
      expect(
        writeLifecycleStagedFile({
          lock,
          reservation: staged.reservation,
          expectedSize: 0,
          bytes: Buffer.from('staged-ok', 'utf8'),
        }).state,
      ).toBe('completed');
      await writeFile(stagingPath, 'forgery!!', { mode: 0o600 });

      expect(() =>
        replaceReservedLifecycleFileExact({
          lock,
          reservation: staged.reservation,
          targetPath,
          targetIdentity,
          targetMode: 0o600,
          targetSize: snapshot.size,
          targetDigest: snapshot.digest,
          targetStat: snapshot.stat,
        }),
      ).toThrow();
      expect(await readFile(targetPath, 'utf8')).toBe('previous!');
      expect(await lifecycleIdentity(stagingPath)).toEqual(staged.identity);
    } finally {
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });

  it('does not complete an exact replacement after a same-inode, same-size post-exchange mutation', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    const targetPath = join(root, 'exact-wal');
    const stagingPath = join(root, 'exact-wal-stage');
    const original = Buffer.alloc(POST_EXCHANGE_MUTATION_BYTES, 0x61);
    const replacement = Buffer.from('replacement', 'utf8');
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    await writeFile(targetPath, original, { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);
    let worker: Worker | undefined;

    try {
      const targetIdentity = await lifecycleIdentity(targetPath);
      const snapshot = readExactLifecycleWal({
        lock,
        target: { path: targetPath, identity: targetIdentity, mode: 0o600 },
      });
      if (snapshot.state !== 'completed') {
        throw new Error('Exact WAL snapshot was indeterminate before the post-exchange mutation.');
      }
      snapshot.bytes.fill(0);
      const staged = reserveLifecycleStagedFile({ lock, path: stagingPath, mode: 0o600 });
      if (staged.state !== 'completed') {
        throw new Error('Exact replacement staging reservation was indeterminate.');
      }
      expect(
        writeLifecycleStagedFile({
          lock,
          reservation: staged.reservation,
          expectedSize: 0,
          bytes: replacement,
        }).state,
      ).toBe('completed');

      worker = await startPostExchangeMutationWorker({
        targetPath,
        stagingPath,
        targetIdentity,
        stagingIdentity: staged.identity,
        expectedSize: original.byteLength,
        offset: Math.floor(original.byteLength / 2),
      });
      const replaced = replaceReservedLifecycleFileExact({
        lock,
        reservation: staged.reservation,
        targetPath,
        targetIdentity,
        targetMode: 0o600,
        targetSize: snapshot.size,
        targetDigest: snapshot.digest,
        targetStat: snapshot.stat,
      });
      await waitForPostExchangeMutation(worker, 'mutated');

      expect(replaced.state).toBe('indeterminate');
      if (replaced.quarantine === undefined) {
        throw new Error('Post-exchange failure did not retain its exact quarantine authority.');
      }
      expect(finalizeLifecycleQuarantine({ lock, quarantine: replaced.quarantine })).toMatchObject({
        state: 'indeterminate',
        quarantine: replaced.quarantine,
      });
      expect(await lifecycleIdentity(stagingPath)).toEqual(targetIdentity);
      const mutated = await readFile(stagingPath);
      expect(mutated.byteLength).toBe(original.byteLength);
      expect(mutated[Math.floor(mutated.byteLength / 2)]).toBe(0x62);
      expect(await readFile(targetPath)).toEqual(replacement);
    } finally {
      if (worker !== undefined) {
        await terminatePostExchangeMutationWorker(worker);
      }
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });
  it('retains quarantine authority when identity-conditional finalization is unavailable', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    const targetPath = join(root, 'cleanup.txt');
    const quarantinePath = join(root, '.cleanup');
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    await writeFile(targetPath, 'cleanup', { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);

    try {
      const quarantined = quarantineLifecycleExactFile({
        lock,
        path: targetPath,
        quarantinePath,
        identity: await lifecycleIdentity(targetPath),
        mode: 0o600,
      });
      if (quarantined.state !== 'completed' || quarantined.quarantine === undefined) {
        throw new Error('Exact-file quarantine did not return a cleanup capability.');
      }

      const firstFinalize = finalizeLifecycleQuarantine({
        lock,
        quarantine: quarantined.quarantine,
      });
      expect(firstFinalize).toMatchObject({
        state: 'indeterminate',
        quarantine: quarantined.quarantine,
      });
      expect(
        finalizeLifecycleQuarantine({ lock, quarantine: firstFinalize.quarantine! }),
      ).toMatchObject({
        state: 'indeterminate',
        quarantine: quarantined.quarantine,
      });
      expect(
        restoreLifecycleQuarantine({ lock, quarantine: firstFinalize.quarantine! }).state,
      ).toBe('completed');
      expect(await readFile(targetPath, 'utf8')).toBe('cleanup');
      expect(() =>
        finalizeLifecycleQuarantine({ lock, quarantine: {} as typeof quarantined.quarantine }),
      ).toThrow();
    } finally {
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });
  it('retains exact quarantine authority when a foreign name replaces the quarantine link', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    const targetPath = join(root, 'foreign-name.txt');
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    await writeFile(targetPath, 'original', { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);

    try {
      const identity = await lifecycleIdentity(targetPath);
      const removed = removeExactStagedFile({
        lock,
        target: {
          path: targetPath,
          identity,
          mode: 0o600,
          size: Buffer.byteLength('original'),
          digest: `sha256:${createHash('sha256').update('original', 'utf8').digest('hex')}`,
        },
      });
      if (removed.state !== 'completed' || removed.quarantine === undefined) {
        throw new Error('Exact staged-file removal did not retain a quarantine capability.');
      }

      const quarantinePath = join(root, `.scg-remove-${identity.device}-${identity.inode}`);
      const displacedPath = join(root, 'foreign-name-displaced');
      await rename(quarantinePath, displacedPath);
      await writeFile(quarantinePath, 'foreign!!', { mode: 0o600 });

      expect(finalizeLifecycleQuarantine({ lock, quarantine: removed.quarantine })).toMatchObject({
        state: 'indeterminate',
        quarantine: removed.quarantine,
      });
      expect(await readFile(quarantinePath, 'utf8')).toBe('foreign!!');
      expect(await readFile(displacedPath, 'utf8')).toBe('original');
    } finally {
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });
  it('recovers quarantine capacity after saturation by restoring exact retained handles', async () => {
    const root = await createTemporaryRoot();
    const lockPath = join(root, '.lifecycle.lock');
    await writeFile(lockPath, 'lock', { mode: 0o600 });
    const lock = acquireLifecycleLock(lockPath);
    const quarantines: NativeLifecycleQuarantine[] = [];

    try {
      let exhausted = false;
      for (let index = 0; index <= 64; index += 1) {
        const targetPath = join(root, `saturation-${index}`);
        const contents = `entry-${index}`;
        await writeFile(targetPath, contents, { mode: 0o600 });
        let removed: ReturnType<typeof removeExactStagedFile> | undefined;
        try {
          removed = removeExactStagedFile({
            lock,
            target: {
              path: targetPath,
              identity: await lifecycleIdentity(targetPath),
              mode: 0o600,
              size: Buffer.byteLength(contents),
              digest: `sha256:${createHash('sha256').update(contents, 'utf8').digest('hex')}`,
            },
          });
        } catch {
          exhausted = true;
          break;
        }
        if (
          removed === undefined ||
          removed.state !== 'completed' ||
          removed.quarantine === undefined
        ) {
          exhausted = true;
          break;
        }
        quarantines.push(removed.quarantine);
      }
      expect(exhausted).toBe(true);

      const released = quarantines.shift();
      if (released === undefined) {
        throw new Error('Quarantine saturation did not retain a recoverable authority.');
      }
      expect(restoreLifecycleQuarantine({ lock, quarantine: released }).state).toBe('completed');

      const retryPath = join(root, 'saturation-retry');
      await writeFile(retryPath, 'retry', { mode: 0o600 });
      const retry = removeExactStagedFile({
        lock,
        target: {
          path: retryPath,
          identity: await lifecycleIdentity(retryPath),
          mode: 0o600,
          size: Buffer.byteLength('retry'),
          digest: `sha256:${createHash('sha256').update('retry', 'utf8').digest('hex')}`,
        },
      });
      if (retry.state !== 'completed' || retry.quarantine === undefined) {
        throw new Error('Released quarantine capacity was not reusable.');
      }
      expect(restoreLifecycleQuarantine({ lock, quarantine: retry.quarantine }).state).toBe(
        'completed',
      );
      for (const quarantine of quarantines.splice(0)) {
        expect(restoreLifecycleQuarantine({ lock, quarantine }).state).toBe('completed');
      }
    } finally {
      expect(releaseLifecycleLock(lock).state).toBe('completed');
    }
  });
});

async function createTemporaryRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-macos-')));
  temporaryRoots.push(root);
  return root;
}

async function lifecycleIdentity(path: string): Promise<FileIdentity> {
  const information = await stat(path, { bigint: true });
  return Object.freeze({ device: information.dev.toString(), inode: information.ino.toString() });
}
interface PostExchangeMutationWorkerMessage {
  readonly type?: unknown;
  readonly message?: unknown;
}

async function startPostExchangeMutationWorker({
  targetPath,
  stagingPath,
  targetIdentity,
  stagingIdentity,
  expectedSize,
  offset,
}: {
  readonly targetPath: string;
  readonly stagingPath: string;
  readonly targetIdentity: FileIdentity;
  readonly stagingIdentity: FileIdentity;
  readonly expectedSize: number;
  readonly offset: number;
}): Promise<Worker> {
  const worker = new Worker(POST_EXCHANGE_MUTATION_WORKER_SOURCE, {
    eval: true,
    workerData: {
      targetPath,
      stagingPath,
      targetIdentity,
      stagingIdentity,
      expectedSize,
      offset,
      replacementByte: 0x62,
      deadlineMilliseconds: POST_EXCHANGE_MUTATION_WORKER_DEADLINE_MS,
    },
  });
  try {
    await waitForPostExchangeMutation(worker, 'prepared');
    return worker;
  } catch (error: unknown) {
    await terminatePostExchangeMutationWorker(worker);
    throw error;
  }
}

async function terminatePostExchangeMutationWorker(worker: Worker): Promise<void> {
  await waitForPostExchangeMutationDeadline(worker.terminate(), 'termination');
}

function waitForPostExchangeMutationDeadline<T>(operation: Promise<T>, phase: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Timed out during post-exchange mutation worker ${phase}.`));
    }, POST_EXCHANGE_MUTATION_WORKER_DEADLINE_MS);
    void operation.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function waitForPostExchangeMutation(
  worker: Worker,
  type: string,
): Promise<PostExchangeMutationWorkerMessage> {
  return new Promise<PostExchangeMutationWorkerMessage>((resolve, reject) => {
    const timeout = setTimeout(() => {
      fail(new Error(`Timed out waiting for post-exchange mutation worker ${type}.`));
    }, POST_EXCHANGE_MUTATION_WORKER_DEADLINE_MS);
    const onMessage = (value: unknown) => {
      const message = asPostExchangeMutationWorkerMessage(value);
      if (message?.type === 'error') {
        fail(new Error('Post-exchange mutation worker failed.'));
      } else if (message?.type === type) {
        succeed(message);
      }
    };
    const onError = (error: Error) => {
      fail(error);
    };
    const onExit = (code: number) => {
      fail(new Error(`Post-exchange mutation worker exited before ${type} with code ${code}.`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      worker.off('message', onMessage);
      worker.off('error', onError);
      worker.off('exit', onExit);
    };
    const succeed = (message: PostExchangeMutationWorkerMessage) => {
      cleanup();
      resolve(message);
    };
    const fail = (error: Error) => {
      cleanup();
      reject(error);
    };
    worker.on('message', onMessage);
    worker.once('error', onError);
    worker.once('exit', onExit);
  });
}

function asPostExchangeMutationWorkerMessage(
  value: unknown,
): PostExchangeMutationWorkerMessage | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as PostExchangeMutationWorkerMessage;
}
function pageFile(revision: number): PageFileV1 {
  return parsePageFileV1({
    schemaVersion: 1,
    page: {
      policyVersion: 1,
      canonicalIdentity,
      route: '/macos-durability',
      pageId,
    },
    revision,
    annotations: [],
    replayWindow:
      revision === 0
        ? []
        : [
            {
              operationId: '00000000-0000-4000-8000-000000000001',
              kind: 'delete',
              inputDigest:
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              appliedRevision: 1,
              result: {
                kind: 'delete',
                revision: 1,
                annotationId: '11111111-1111-4111-8111-111111111111',
              },
            },
          ],
  });
}

function canonicalBytes(page: PageFileV1): Uint8Array {
  return new TextEncoder().encode(serializeCanonicalPageFileV1(page));
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.byteLength).toBe(expected.byteLength);
  expect([...actual]).toEqual([...expected]);
}
