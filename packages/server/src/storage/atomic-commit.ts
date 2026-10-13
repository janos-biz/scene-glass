import { randomUUID } from 'node:crypto';
import { open, rename, unlink } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import type { FileHandle } from 'node:fs/promises';
import { type AtomicCommitFaultPoints, invokeAtomicCommitFaultPoint } from './fault-points.js';
import { ScgStorageError } from './path-guard.js';

export type AtomicCommitVisibility = 'visible-old' | 'visible-new';

export interface AtomicCommitInput {
  readonly directory: string;
  readonly targetPath: string;
  readonly bytes: Uint8Array;
  readonly previousBytes: Uint8Array | null;
  readonly strictReadBack: () => Promise<Uint8Array | null>;
  readonly assertPathUnchanged: () => Promise<void>;
  readonly signal: AbortSignal;
  readonly faultPoints?: AtomicCommitFaultPoints;
}

interface OpenedTemporaryFile {
  readonly file: FileHandle;
  readonly path: string;
}

export class AtomicCommitError extends ScgStorageError {
  public readonly outcome?: AtomicCommitVisibility;

  public constructor(
    code: 'SCG_COMMIT_FAILED' | 'SCG_COMMIT_DURABILITY_UNKNOWN' | 'SCG_STORAGE_INTEGRITY',
    message: string,
    outcome?: AtomicCommitVisibility,
    cause?: unknown,
  ) {
    super(code, message);
    this.name = 'AtomicCommitError';
    if (outcome !== undefined) {
      this.outcome = outcome;
    }
    if (cause !== undefined) {
      Object.defineProperty(this, 'cause', {
        configurable: true,
        enumerable: false,
        value: cause,
        writable: true,
      });
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Replaces a page file only after the complete temp file is synced. A returned
 * promise means the rename and containing-directory sync both completed.
 * Request cancellation is honored only before rename. Any post-rename
 * uncertainty is reported as an error with a visible-old/new outcome; it is
 * never returned as a successful commit.
 */
export async function commitAtomically(input: AtomicCommitInput): Promise<void> {
  assertSameDirectory(input.directory, input.targetPath);
  input.signal.throwIfAborted();
  await input.assertPathUnchanged();
  input.signal.throwIfAborted();

  let temporaryPath = temporaryPathFor(input.directory, input.targetPath);
  let file: FileHandle | undefined;
  let renamed = false;
  let ownsTemporary = false;

  try {
    const opened = await openTemporaryFile(input, temporaryPath);
    file = opened.file;
    temporaryPath = opened.path;
    ownsTemporary = true;

    await invokeAtomicCommitFaultPoint(input.faultPoints, 'write', temporaryPath, input.targetPath);
    input.signal.throwIfAborted();
    await file.writeFile(input.bytes);
    input.signal.throwIfAborted();

    await invokeAtomicCommitFaultPoint(input.faultPoints, 'fsync', temporaryPath, input.targetPath);
    input.signal.throwIfAborted();
    await file.sync();
    input.signal.throwIfAborted();

    await invokeAtomicCommitFaultPoint(input.faultPoints, 'close', temporaryPath, input.targetPath);
    input.signal.throwIfAborted();
    await file.close();
    file = undefined;
    input.signal.throwIfAborted();

    await input.assertPathUnchanged();
    input.signal.throwIfAborted();
    await invokeAtomicCommitFaultPoint(
      input.faultPoints,
      'rename',
      temporaryPath,
      input.targetPath,
    );
    await input.assertPathUnchanged();
    input.signal.throwIfAborted();
    await rename(temporaryPath, input.targetPath);
    renamed = true;

    await input.assertPathUnchanged();
    await syncContainingDirectory(input, temporaryPath);
    await input.assertPathUnchanged();
  } catch (error: unknown) {
    const firstPathFailure = await pathFailure(input);
    const rootChangeBeforeCleanup = rootChangeFrom(error, firstPathFailure);
    if (!renamed) {
      const cleanup = await cleanupPreRenameTemporary(
        input,
        file,
        temporaryPath,
        ownsTemporary,
        rootChangeBeforeCleanup === undefined,
      );
      const finalPathFailure =
        rootChangeBeforeCleanup === undefined ? await pathFailure(input) : undefined;
      const failures = [
        error,
        firstPathFailure,
        cleanup.pathFailure,
        ...cleanup.failures,
        finalPathFailure,
      ];
      const rootChange = rootChangeFrom(...failures);

      if (rootChange !== undefined) {
        throw withFailureCauses(rootChange, failures);
      }
      if (cleanup.temporaryUnaccountedFor) {
        throw new AtomicCommitError(
          'SCG_STORAGE_INTEGRITY',
          'annotation commit temporary file cannot be accounted for',
          undefined,
          failureCause(failures),
        );
      }
      if (
        isAbortReason(input.signal, error) &&
        cleanup.failures.length === 0 &&
        firstPathFailure === undefined &&
        finalPathFailure === undefined
      ) {
        throw error;
      }
      throw new AtomicCommitError(
        'SCG_COMMIT_FAILED',
        'annotation commit failed before rename',
        undefined,
        failureCause(failures),
      );
    }
    const rootChange = rootChangeFrom(error, firstPathFailure);
    if (rootChange !== undefined) {
      throw withFailureCauses(rootChange, [error, firstPathFailure]);
    }
    throw await postRenameError(input, error);
  }
}

async function openTemporaryFile(
  input: AtomicCommitInput,
  initialPath: string,
): Promise<OpenedTemporaryFile> {
  let temporaryPath = initialPath;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    await invokeAtomicCommitFaultPoint(input.faultPoints, 'open', temporaryPath, input.targetPath);
    input.signal.throwIfAborted();
    try {
      return Object.freeze({
        file: await open(temporaryPath, 'wx', 0o600),
        path: temporaryPath,
      });
    } catch (error: unknown) {
      if (!hasErrorCode(error, 'EEXIST')) {
        throw error;
      }
      temporaryPath = temporaryPathFor(input.directory, input.targetPath);
    }
  }
  throw new Error('could not allocate a unique annotation temp file');
}

async function syncContainingDirectory(
  input: AtomicCommitInput,
  temporaryPath: string,
): Promise<void> {
  let directory: FileHandle | undefined;
  let failure: unknown;
  try {
    directory = await open(input.directory, 'r');
    await invokeAtomicCommitFaultPoint(
      input.faultPoints,
      'dir-sync',
      temporaryPath,
      input.targetPath,
    );
    await directory.sync();
  } catch (error: unknown) {
    failure = error;
  }

  if (directory !== undefined) {
    try {
      await directory.close();
    } catch (error: unknown) {
      failure ??= error;
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function postRenameError(
  input: AtomicCommitInput,
  postRenameFailure: unknown,
): Promise<AtomicCommitError> {
  let visible: Uint8Array | null;
  try {
    visible = await input.strictReadBack();
  } catch (readBackFailure: unknown) {
    if (readBackFailure instanceof ScgStorageError && readBackFailure.code === 'SCG_ROOT_CHANGED') {
      throw withFailureCauses(readBackFailure, [postRenameFailure, readBackFailure]);
    }
    return new AtomicCommitError(
      'SCG_STORAGE_INTEGRITY',
      'annotation storage cannot be verified after rename',
      undefined,
      failureCause([postRenameFailure, readBackFailure]),
    );
  }

  if (sameBytes(visible, input.bytes)) {
    return new AtomicCommitError(
      'SCG_COMMIT_DURABILITY_UNKNOWN',
      'annotation commit durability is unknown after rename',
      'visible-new',
      postRenameFailure,
    );
  }
  if (sameBytes(visible, input.previousBytes)) {
    return new AtomicCommitError(
      'SCG_COMMIT_DURABILITY_UNKNOWN',
      'annotation commit durability is unknown after rename',
      'visible-old',
      postRenameFailure,
    );
  }
  return new AtomicCommitError(
    'SCG_STORAGE_INTEGRITY',
    'annotation storage contains an unexpected file after rename',
    undefined,
    postRenameFailure,
  );
}

function temporaryPathFor(directory: string, targetPath: string): string {
  return resolve(directory, `.${basename(targetPath)}.${randomUUID()}.tmp`);
}

function assertSameDirectory(directory: string, targetPath: string): void {
  if (dirname(targetPath) !== directory || resolve(directory) !== directory) {
    throw new AtomicCommitError('SCG_COMMIT_FAILED', 'annotation commit path is invalid');
  }
}

interface PreRenameCleanup {
  readonly failures: readonly unknown[];
  readonly pathFailure: unknown | undefined;
  readonly temporaryUnaccountedFor: boolean;
}

async function cleanupPreRenameTemporary(
  input: AtomicCommitInput,
  file: FileHandle | undefined,
  temporaryPath: string,
  ownsTemporary: boolean,
  mayUnlinkTemporary: boolean,
): Promise<PreRenameCleanup> {
  const failures: unknown[] = [];
  if (file !== undefined) {
    const failure = await closeTemporary(file);
    if (failure !== undefined) {
      failures.push(failure);
    }
  }

  let cleanupPathFailure: unknown | undefined;
  let temporaryUnaccountedFor = false;
  if (ownsTemporary && mayUnlinkTemporary) {
    cleanupPathFailure = await pathFailure(input);
    if (cleanupPathFailure !== undefined) {
      temporaryUnaccountedFor = true;
    } else {
      const failure = await unlinkTemporary(temporaryPath);
      if (failure !== undefined) {
        failures.push(failure);
        temporaryUnaccountedFor = true;
      }
    }
  }
  return { failures, pathFailure: cleanupPathFailure, temporaryUnaccountedFor };
}

async function closeTemporary(file: FileHandle): Promise<unknown | undefined> {
  try {
    await file.close();
  } catch (error: unknown) {
    return error;
  }
  return undefined;
}

async function unlinkTemporary(path: string): Promise<unknown | undefined> {
  try {
    await unlink(path);
  } catch (error: unknown) {
    if (!hasErrorCode(error, 'ENOENT')) {
      return error;
    }
  }
  return undefined;
}

async function pathFailure(input: AtomicCommitInput): Promise<unknown | undefined> {
  try {
    await input.assertPathUnchanged();
  } catch (error: unknown) {
    return error;
  }
  return undefined;
}

function rootChangeFrom(...failures: readonly unknown[]): ScgStorageError | undefined {
  for (const failure of failures) {
    if (failure instanceof ScgStorageError && failure.code === 'SCG_ROOT_CHANGED') {
      return failure;
    }
  }
  return undefined;
}

function withFailureCauses<T extends Error>(error: T, failures: readonly unknown[]): T {
  const failuresWithoutError = failures.filter((failure) => failure !== error);
  if (error.cause !== undefined && !failuresWithoutError.includes(error.cause)) {
    failuresWithoutError.unshift(error.cause);
  }
  const cause = failureCause(failuresWithoutError);
  if (cause !== undefined) {
    Object.defineProperty(error, 'cause', {
      configurable: true,
      enumerable: false,
      value: cause,
      writable: true,
    });
  }
  return error;
}

function failureCause(failures: readonly unknown[]): unknown | undefined {
  const causes = failures.filter((failure) => failure !== undefined);
  if (causes.length === 0) {
    return undefined;
  }
  if (causes.length === 1) {
    return causes[0];
  }
  return new AggregateError(causes, 'annotation commit failed with additional failures');
}

function sameBytes(left: Uint8Array | null, right: Uint8Array | null): boolean {
  if (left === null || right === null) {
    return left === right;
  }
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function isAbortReason(signal: AbortSignal, error: unknown): boolean {
  return signal.aborted && error === signal.reason;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
