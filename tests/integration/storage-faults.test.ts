import { mkdtemp, lstat, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  commitAtomically,
  ScgStorageError,
  type AtomicCommitFaultContext,
  type AtomicCommitFaultPoint,
  type AtomicCommitFaultPoints,
} from '../../packages/server/src/storage/index.js';

const temporaryRoots: string[] = [];
const oldBytes = new TextEncoder().encode('complete old annotation payload\n');
const newBytes = new TextEncoder().encode('complete new annotation payload\n');
const preRenameFaults = ['open', 'write', 'fsync', 'close', 'rename'] as const;

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe('atomic storage fault handling', () => {
  it.each(preRenameFaults)(
    'preserves the complete old target and cleans contained temps when %s fails',
    async (point) => {
      const { directory, target } = await createTarget();
      let faultContext: AtomicCommitFaultContext | undefined;
      const faultPoints = faultAt(point, (context) => {
        faultContext = context;
        expect(dirname(context.temporaryPath)).toBe(directory);
        expect(context.targetPath).toBe(target);
        throw new Error(`${point} fault`);
      });

      await expect(
        commitAtomically(commitInput(directory, target, faultPoints)),
      ).rejects.toMatchObject({
        code: 'SCG_COMMIT_FAILED',
      });

      expect(faultContext?.point).toBe(point);
      expectBytes(await readFile(target), oldBytes);
      expect(await readdir(directory)).toEqual([basename(target)]);
    },
  );
  it.each(preRenameFaults)(
    'rethrows the typed cancellation reason and cleans contained temps when cancelled at %s',
    async (point) => {
      const { directory, target } = await createTarget();
      const controller = new AbortController();
      const reason = new Error(`${point} cancellation`);
      const faultPoints = faultAt(point, () => {
        controller.abort(reason);
      });

      await expect(
        commitAtomically(commitInput(directory, target, faultPoints, controller.signal)),
      ).rejects.toBe(reason);

      expectBytes(await readFile(target), oldBytes);
      expect(await readdir(directory)).toEqual([basename(target)]);
    },
  );

  it('finishes post-rename durability work when the request is cancelled', async () => {
    const { directory, target } = await createTarget();
    const controller = new AbortController();
    const reason = new Error('request cancelled after rename');
    let directorySyncStarted = false;
    const faultPoints = faultAt('dir-sync', () => {
      directorySyncStarted = true;
      controller.abort(reason);
    });

    await expect(
      commitAtomically(commitInput(directory, target, faultPoints, controller.signal)),
    ).resolves.toBeUndefined();

    expect(directorySyncStarted).toBe(true);
    expect(controller.signal.reason).toBe(reason);
    expectBytes(await readFile(target), newBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });

  it('classifies a directory sync failure after rename as visible-new', async () => {
    const { directory, target } = await createTarget();
    const faultPoints = faultAt('dir-sync', () => {
      throw new Error('directory sync fault');
    });

    await expect(
      commitAtomically(commitInput(directory, target, faultPoints)),
    ).rejects.toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
      outcome: 'visible-new',
    });

    expectBytes(await readFile(target), newBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });

  it('classifies a post-rename replacement of the target as visible-old', async () => {
    const { directory, target } = await createTarget();
    const faultPoints = faultAt('dir-sync', async (context) => {
      await writeFile(context.targetPath, oldBytes);
      throw new Error('directory sync fault after replacement');
    });

    await expect(
      commitAtomically(commitInput(directory, target, faultPoints)),
    ).rejects.toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
      outcome: 'visible-old',
    });

    expectBytes(await readFile(target), oldBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });

  it('does not turn an unclassified post-rename target into a success', async () => {
    const { directory, target } = await createTarget();
    const unexpectedBytes = new TextEncoder().encode('partial replacement\n');
    const faultPoints = faultAt('dir-sync', async (context) => {
      await writeFile(context.targetPath, unexpectedBytes);
      throw new Error('directory sync fault after unexpected replacement');
    });

    await expect(
      commitAtomically(commitInput(directory, target, faultPoints)),
    ).rejects.toMatchObject({
      code: 'SCG_STORAGE_INTEGRITY',
    });
    expectBytes(await readFile(target), unexpectedBytes);
  });
  it('preserves a root-change readback failure when a concurrent abort arrives', async () => {
    const { directory, target } = await createTarget();
    const controller = new AbortController();
    const rootChange = new ScgStorageError('SCG_ROOT_CHANGED', 'authorized root changed');
    const faultPoints = faultAt('dir-sync', () => {
      throw new Error('directory sync fault');
    });

    await expect(
      commitAtomically({
        ...commitInput(directory, target, faultPoints, controller.signal),
        strictReadBack: async (): Promise<Uint8Array | null> => {
          controller.abort(new Error('request cancelled during readback'));
          throw rootChange;
        },
      }),
    ).rejects.toBe(rootChange);

    expectBytes(await readFile(target), newBytes);
  });
});

async function createTarget(): Promise<{ directory: string; target: string }> {
  const directory = await mkdtemp(join(tmpdir(), 'scene-glass-storage-fault-'));
  temporaryRoots.push(directory);
  const target = join(directory, 'p_atomic.json');
  await writeFile(target, oldBytes);
  return { directory, target };
}

function commitInput(
  directory: string,
  target: string,
  faultPoints: AtomicCommitFaultPoints,
  signal: AbortSignal = new AbortController().signal,
) {
  return {
    directory,
    targetPath: target,
    bytes: newBytes,
    previousBytes: oldBytes,
    faultPoints,
    signal,
    assertPathUnchanged: async (): Promise<void> => {
      const directoryStats = await lstat(directory);
      if (!directoryStats.isDirectory() || dirname(target) !== directory) {
        throw new Error('atomic target directory changed');
      }
    },
    strictReadBack: async (): Promise<Uint8Array | null> => {
      try {
        return await readFile(target);
      } catch (error: unknown) {
        if (hasErrorCode(error, 'ENOENT')) {
          return null;
        }
        throw error;
      }
    },
  };
}

function faultAt(
  point: AtomicCommitFaultPoint,
  hook: (context: AtomicCommitFaultContext) => void | Promise<void>,
): AtomicCommitFaultPoints {
  return { [point]: hook };
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.byteLength).toBe(expected.byteLength);
  expect([...actual]).toEqual([...expected]);
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
