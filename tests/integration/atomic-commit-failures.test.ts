import { lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  commitAtomically,
  ScgStorageError,
  type AtomicCommitFaultContext,
  type AtomicCommitFaultPoint,
  type AtomicCommitFaultPoints,
  type AtomicCommitInput,
} from '../../packages/server/src/storage/index.js';

const filesystemFailures = vi.hoisted(() => ({
  open: [] as Error[],
  close: [] as Error[],
  faultedCloseHandles: [] as Array<{ close(): Promise<void> }>,
  unlink: [] as Error[],
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...original,
    async open(...args: Parameters<typeof original.open>) {
      const failure = filesystemFailures.open.shift();
      if (failure !== undefined) {
        throw failure;
      }
      const file = await original.open(...args);
      return new Proxy(file, {
        get(target, property) {
          if (property === 'close') {
            return async (): Promise<void> => {
              const failure = filesystemFailures.close.shift();
              if (failure !== undefined) {
                filesystemFailures.faultedCloseHandles.push(target);
                throw failure;
              }
              await target.close();
            };
          }
          const value = Reflect.get(target, property);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
    async unlink(...args: Parameters<typeof original.unlink>) {
      const failure = filesystemFailures.unlink.shift();
      if (failure !== undefined) {
        throw failure;
      }
      await original.unlink(...args);
    },
  };
});

const temporaryRoots: string[] = [];
const oldBytes = new TextEncoder().encode('complete old annotation payload\n');
const newBytes = new TextEncoder().encode('complete new annotation payload\n');

afterEach(async () => {
  await Promise.all(
    filesystemFailures.faultedCloseHandles.splice(0).map((handle) => handle.close()),
  );
  filesystemFailures.open.splice(0);
  filesystemFailures.close.splice(0);
  filesystemFailures.unlink.splice(0);
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe('atomic commit pre-rename failure handling', () => {
  it('prioritizes a directory identity swap over a write fault before rename', async () => {
    const { directory, target, workspace } = await createTarget();
    const swappedDirectory = join(workspace, 'swapped-annotations');
    const writeFailure = new Error('write fault before rename');
    const input = await commitInput(
      directory,
      target,
      faultAt('write', async () => {
        await rename(directory, swappedDirectory);
        await mkdir(directory);
        throw writeFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_ROOT_CHANGED' });
    expect(error.cause).toBe(writeFailure);
    expectBytes(await readFile(join(swappedDirectory, basename(target))), oldBytes);
  });

  it('retains a non-ENOENT close cleanup failure with the pre-rename failure', async () => {
    const { directory, target } = await createTarget();
    const writeFailure = new Error('write fault');
    const closeFailure = errorWithCode('EIO', 'temporary close failed');
    filesystemFailures.close.push(closeFailure);
    const input = await commitInput(
      directory,
      target,
      faultAt('write', () => {
        throw writeFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_COMMIT_FAILED' });
    expectAggregateCause(error, [writeFailure, closeFailure]);
    expect(filesystemFailures.faultedCloseHandles).toHaveLength(1);
    expectBytes(await readFile(target), oldBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });
  it('retains an ENOENT close cleanup failure with the pre-rename failure', async () => {
    const { directory, target } = await createTarget();
    const writeFailure = new Error('write fault');
    const closeFailure = errorWithCode('ENOENT', 'temporary close failed');
    filesystemFailures.close.push(closeFailure);
    const input = await commitInput(
      directory,
      target,
      faultAt('write', () => {
        throw writeFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_COMMIT_FAILED' });
    expectAggregateCause(error, [writeFailure, closeFailure]);
    expect(filesystemFailures.faultedCloseHandles).toHaveLength(1);
    expectBytes(await readFile(target), oldBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });

  it('quarantines when a non-ENOENT unlink failure leaves an owned temporary unaccounted for', async () => {
    const { directory, target } = await createTarget();
    const writeFailure = new Error('write fault');
    const unlinkFailure = errorWithCode('EIO', 'temporary unlink failed');
    filesystemFailures.unlink.push(unlinkFailure);
    const input = await commitInput(
      directory,
      target,
      faultAt('write', () => {
        throw writeFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_STORAGE_INTEGRITY' });
    expectAggregateCause(error, [writeFailure, unlinkFailure]);
    expectBytes(await readFile(target), oldBytes);
    expect((await readdir(directory)).some((name) => name.endsWith('.tmp'))).toBe(true);
  });
  it('treats an ENOENT temporary-path unlink as idempotent', async () => {
    const { directory, target } = await createTarget();
    const writeFailure = new Error('write fault');
    filesystemFailures.unlink.push(errorWithCode('ENOENT', 'temporary file already removed'));
    const input = await commitInput(
      directory,
      target,
      faultAt('write', () => {
        throw writeFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_COMMIT_FAILED' });
    expect(error.cause).toBe(writeFailure);
    expectBytes(await readFile(target), oldBytes);
  });
});
describe('atomic commit post-rename failure reconciliation', () => {
  it('retains the post-rename failure when the new bytes are visible', async () => {
    const { directory, target } = await createTarget();
    const postRenameFailure = new Error('directory sync failed');
    const input = await commitInput(
      directory,
      target,
      faultAt('dir-sync', () => {
        throw postRenameFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
      outcome: 'visible-new',
    });
    expect(error.cause).toBe(postRenameFailure);
    expectBytes(await readFile(target), newBytes);
  });

  it('retains the post-rename failure when the old bytes are visible', async () => {
    const { directory, target } = await createTarget();
    const postRenameFailure = new Error('directory sync failed');
    const input = await commitInput(
      directory,
      target,
      faultAt('dir-sync', async ({ targetPath }) => {
        await writeFile(targetPath, oldBytes);
        throw postRenameFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({
      code: 'SCG_COMMIT_DURABILITY_UNKNOWN',
      outcome: 'visible-old',
    });
    expect(error.cause).toBe(postRenameFailure);
    expectBytes(await readFile(target), oldBytes);
  });

  it('retains the post-rename failure when unexpected bytes are visible', async () => {
    const { directory, target } = await createTarget();
    const postRenameFailure = new Error('directory sync failed');
    const unexpectedBytes = new TextEncoder().encode('unexpected annotation payload\n');
    const input = await commitInput(
      directory,
      target,
      faultAt('dir-sync', async ({ targetPath }) => {
        await writeFile(targetPath, unexpectedBytes);
        throw postRenameFailure;
      }),
    );

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_STORAGE_INTEGRITY' });
    expect(error.cause).toBe(postRenameFailure);
    expect((error as Error & { readonly outcome?: unknown }).outcome).toBeUndefined();
    expectBytes(await readFile(target), unexpectedBytes);
  });

  it('aggregates the post-rename and readback failures', async () => {
    const { directory, target } = await createTarget();
    const postRenameFailure = new Error('directory sync failed');
    const readBackFailure = new Error('readback failed');
    const baseInput = await commitInput(
      directory,
      target,
      faultAt('dir-sync', () => {
        throw postRenameFailure;
      }),
    );
    const input: AtomicCommitInput = {
      ...baseInput,
      async strictReadBack(): Promise<Uint8Array | null> {
        throw readBackFailure;
      },
    };

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_STORAGE_INTEGRITY' });
    expectAggregateCause(error, [postRenameFailure, readBackFailure]);
    expect((error as Error & { readonly outcome?: unknown }).outcome).toBeUndefined();
    expectBytes(await readFile(target), newBytes);
  });
});

describe('atomic commit temporary-file allocation', () => {
  it('retries a colliding temporary name before committing', async () => {
    const { directory, target } = await createTarget();
    filesystemFailures.open.push(errorWithCode('EEXIST', 'temporary name already exists'));
    const input = await commitInput(directory, target, {});

    await expect(commitAtomically(input)).resolves.toBeUndefined();

    expect(filesystemFailures.open).toHaveLength(0);
    expectBytes(await readFile(target), newBytes);
    expect(await readdir(directory)).toEqual([basename(target)]);
  });

  it('stops after 16 colliding temporary names', async () => {
    const { directory, target } = await createTarget();
    filesystemFailures.open.push(
      ...Array.from({ length: 16 }, () => errorWithCode('EEXIST', 'temporary name already exists')),
    );
    const input = await commitInput(directory, target, {});

    const error = await captureFailure(() => commitAtomically(input));

    expect(error).toMatchObject({ code: 'SCG_COMMIT_FAILED' });
    expect(error.cause).toMatchObject({
      message: 'could not allocate a unique annotation temp file',
    });
    expect(filesystemFailures.open).toHaveLength(0);
    expectBytes(await readFile(target), oldBytes);
  });
});

async function createTarget(): Promise<{ directory: string; target: string; workspace: string }> {
  const workspace = await mkdtemp(join(tmpdir(), 'scene-glass-atomic-commit-failures-'));
  temporaryRoots.push(workspace);
  const directory = join(workspace, 'annotations');
  const target = join(directory, 'p_atomic.json');
  await mkdir(directory);
  await writeFile(target, oldBytes);
  return { directory, target, workspace };
}

async function commitInput(
  directory: string,
  target: string,
  faultPoints: AtomicCommitFaultPoints,
): Promise<AtomicCommitInput> {
  const expectedDirectory = await lstat(directory);
  return {
    directory,
    targetPath: target,
    bytes: newBytes,
    previousBytes: oldBytes,
    faultPoints,
    signal: new AbortController().signal,
    async assertPathUnchanged(): Promise<void> {
      let currentDirectory: Awaited<ReturnType<typeof lstat>>;
      try {
        currentDirectory = await lstat(directory);
      } catch {
        throw new ScgStorageError('SCG_ROOT_CHANGED', 'atomic target directory is unavailable');
      }
      if (
        !currentDirectory.isDirectory() ||
        currentDirectory.dev !== expectedDirectory.dev ||
        currentDirectory.ino !== expectedDirectory.ino ||
        dirname(target) !== directory
      ) {
        throw new ScgStorageError('SCG_ROOT_CHANGED', 'atomic target directory changed');
      }
    },
    async strictReadBack(): Promise<Uint8Array | null> {
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

async function captureFailure(action: () => Promise<void>): Promise<Error> {
  try {
    await action();
  } catch (error: unknown) {
    if (error instanceof Error) {
      return error;
    }
    throw new Error('atomic commit rejected with a non-Error value');
  }
  throw new Error('atomic commit unexpectedly succeeded');
}

function expectAggregateCause(error: Error, expected: readonly Error[]): void {
  expect(error.cause).toBeInstanceOf(AggregateError);
  expect((error.cause as AggregateError).errors).toEqual(expected);
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.byteLength).toBe(expected.byteLength);
  expect([...actual]).toEqual([...expected]);
}

function errorWithCode(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}
function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
