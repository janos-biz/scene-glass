import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, readdir, rmdir, unlink, type FileHandle } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

import {
  MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES,
  parseCredentialAuthorityRegistryJsonV1,
  parseCredentialAuthorityRegistrySelectionV1,
  serializeCredentialAuthorityRegistryV1,
  type CredentialAuthorityRegistryEntry,
  type CredentialAuthorityRegistrySelectionV1,
} from '../credential-authority.js';
import { parseServerConfigV1, type ProjectConfigV1 } from '@scene-glass/contracts';
import { MAX_CONFIG_BYTES } from './config.js';
import { STATIC_LOADER_MARKER } from './host-plan.js';
const VITE_SPA_LOADER_TAG =
  '<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>';
import {
  acquireLifecycleLock,
  assertNativeLifecycleMutationCompleted,
  closeLifecycleStagedDirectoryReservation,
  closeLifecycleStagedFileReservation,
  discardLifecycleStagedDirectoryReservation,
  discardLifecycleStagedFileReservation,
  finalizeLifecycleQuarantine,
  prepareLifecycleCreationIntent,
  publishLifecycleStagedDirectoryNoReplace,
  publishLifecycleStagedFileNoReplace,
  publishReservedLifecycleStagedDirectoryNoReplace,
  publishReservedLifecycleStagedFileNoReplace,
  quarantineLifecycleExactDirectory,
  quarantineLifecycleExactFile,
  quarantineLifecycleExactCredential,
  readExactLifecycleWal,
  releaseLifecycleLockSession,
  revalidateLifecycleLock,
  removeExactStagedFile,
  removeExactWal,
  removeExactCredential,
  replaceLifecycleStagedFileExact,
  replaceReservedLifecycleFileExact,
  replaceReservedLifecycleOrdinaryFileExact,
  reserveCredentialFromIntent,
  recoverLifecycleCreationIntent,
  reserveLifecycleFileFromIntent,
  reserveDirectoryFromIntent,
  reserveLifecycleStagedFile,
  retainReservationForRecovery,
  restoreLifecycleQuarantine,
  validateExactCredential,
  validateExactDirectory,
  validateLifecycleStagedFileReservation,
  syncLifecycleStagedDirectoryReservation,
  syncLifecycleStagedFileReservation,
  writeLifecycleStagedFile,
  type NativeLifecycleLock,
  type NativeLifecycleQuarantine,
  type NativeLifecycleQuarantineResult,
  type NativeLifecycleMutationResult,
  type NativeLifecycleStagedDirectoryReservation,
  type NativeLifecycleStagedFileReservation,
  type NativeLifecycleWalExactFile,
} from '../native.js';

import type {
  LifecycleAdvisoryLock,
  LifecycleExactDirectory,
  LifecycleExactFile,
  LifecycleExactContentFile,
  LifecycleFileSnapshot,
  LifecyclePathObservation,
  LifecycleReservedStagedDirectory,
  LifecycleReservedStagedWrite,
  LifecycleStagedWrite,
  LifecycleTransactionPort,
  LifecycleUninstallMaterializationInput,
  LifecycleWalFileSnapshot,
  LifecycleWalSnapshotAuthority,
} from './transaction.js';
import type { RestoreOwnedFileInverseOperation, SemanticConfigImage } from './types.js';

const OPEN_NO_FOLLOW = constants.O_NOFOLLOW;
const MAX_MANAGED_VITE_RUNTIME_ENTRIES = 16 * 1024;
const MANAGED_VITE_RUNTIME_ENTRIES = new Set([
  'vite-cache',
  'vite-provenance',
  'vite-root',
  'vite-staging',
]);

if (OPEN_NO_FOLLOW === undefined || OPEN_NO_FOLLOW === 0) {
  throw new Error('O_NOFOLLOW support is required for lifecycle transactions');
}

interface ReservedStagedWriteState {
  readonly path: string;
  readonly nativeReservation: NativeLifecycleStagedFileReservation;
  readonly lock: NativeLifecycleLock;
  size: bigint;
  status: 'open' | 'published' | 'retained' | 'discarded' | 'closed' | 'indeterminate';
  targetPath: string | undefined;
  written: boolean;
}
interface ReservedStagedDirectoryState {
  readonly path: string;
  physicalPath: string;
  readonly targetPath: string | undefined;
  readonly nativeReservation: NativeLifecycleStagedDirectoryReservation;
  readonly lock: NativeLifecycleLock;
  closeRequested: boolean;
  status: 'open' | 'published' | 'retained' | 'discarded' | 'closed' | 'indeterminate';
}

interface WalSnapshotState {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly identity: LifecycleExactFile['identity'];
  readonly mode: number;
  readonly size: number;
  readonly digest: string;
  readonly stat: string;
}

/**
 * Node implementation of the lifecycle port. The lock path must already be a
 * regular file; this adapter deliberately never creates, takes over, or falls
 * back from a lifecycle lock path.
 */
export function createNodeLifecycleTransactionPort(): LifecycleTransactionPort {
  return new NodeLifecycleTransactionPort();
}

class NodeLifecycleTransactionPort implements LifecycleTransactionPort {
  #reserved = new WeakMap<LifecycleReservedStagedWrite, ReservedStagedWriteState>();
  #reservedDirectories = new WeakMap<
    LifecycleReservedStagedDirectory,
    ReservedStagedDirectoryState
  >();
  #reservedDirectoryTargets = new Map<string, ReservedStagedDirectoryState>();
  #stagedWrites = new WeakMap<LifecycleStagedWrite, ReservedStagedWriteState>();
  #publishedStagedWrites = new Map<string, ReservedStagedWriteState>();
  #durabilityReceipts = new Map<string, NativeLifecycleLock>();
  #nativeLocks = new WeakMap<LifecycleAdvisoryLock, NativeLifecycleLock>();
  #walSnapshots = new WeakMap<LifecycleWalSnapshotAuthority, WalSnapshotState>();
  #pendingLockReleases = new Set<LifecycleAdvisoryLock>();

  public async acquireAdvisoryLock(path: string): Promise<LifecycleAdvisoryLock> {
    await this.releasePendingLocks();
    const nativeLock = acquireLifecycleLock(path);
    let released = false;
    const lock: LifecycleAdvisoryLock = Object.freeze({
      revalidate: async (): Promise<void> => {
        assertNativeLifecycleMutationCompleted(
          revalidateLifecycleLock(nativeLock),
          'lifecycle lock revalidation',
        );
      },
      release: async (): Promise<void> => {
        if (released) {
          return;
        }
        try {
          this.closeRetainedReservations(nativeLock);
          const result = releaseLifecycleLockSession(nativeLock);
          assertNativeLifecycleMutationCompleted(result, 'lifecycle lock release');
        } catch (error) {
          this.#pendingLockReleases.add(lock);
          throw error;
        }
        released = true;
        this.#pendingLockReleases.delete(lock);
        this.#nativeLocks.delete(lock);
      },
    });
    this.#nativeLocks.set(lock, nativeLock);
    return lock;
  }

  public async lstatNoFollow(path: string): Promise<LifecyclePathObservation | undefined> {
    try {
      return observation(await lstat(path, { bigint: true }));
    } catch (error) {
      if (isNotFound(error)) {
        return undefined;
      }
      throw error;
    }
  }
  public async purgeManagedViteRuntime(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly directory: LifecycleExactDirectory;
  }): Promise<boolean> {
    this.nativeLock(input.lock);
    const ownerUid = lifecycleOwnerUid();
    let root: BigIntStats;
    try {
      root = await lstat(input.directory.path, { bigint: true });
    } catch (error) {
      if (isNotFound(error)) {
        return true;
      }
      throw error;
    }
    if (!isManagedViteRuntimeDirectory(root, input.directory, root.dev, ownerUid)) {
      return false;
    }
    const entries = await readdir(input.directory.path);
    if (entries.some((entry) => !MANAGED_VITE_RUNTIME_ENTRIES.has(entry))) {
      return false;
    }
    const budget = { remaining: MAX_MANAGED_VITE_RUNTIME_ENTRIES };
    for (const entry of entries) {
      if (
        !(await removeManagedViteRuntimeEntry(
          join(input.directory.path, entry),
          root.dev,
          ownerUid,
          budget,
        ))
      ) {
        return false;
      }
    }
    return true;
  }

  public async readFileNoFollow(path: string): Promise<LifecycleFileSnapshot | undefined> {
    return this.readFileNoFollowBounded(path, MAX_CONFIG_BYTES, 'lifecycle target');
  }
  public async readWalFileNoFollow(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<LifecycleWalFileSnapshot | undefined> {
    const nativeLock = this.nativeLock(input.lock);
    const observed = await this.lstatNoFollow(input.path);
    if (observed === undefined) {
      return undefined;
    }
    if (observed.kind !== 'file' || observed.mode !== 0o600) {
      throw new Error('lifecycle WAL is not an exact 0600 regular file');
    }
    const result = readExactLifecycleWal({
      lock: nativeLock,
      target: {
        path: input.path,
        identity: observed.identity,
        mode: observed.mode,
      },
    });
    if (result.state !== 'completed') {
      throw new Error('lifecycle WAL exact read is indeterminate');
    }
    const snapshot = Object.freeze({}) as LifecycleWalSnapshotAuthority;
    this.#walSnapshots.set(snapshot, {
      lock: nativeLock,
      path: input.path,
      identity: result.identity,
      mode: 0o600,
      size: result.size,
      digest: result.digest,
      stat: result.stat,
    });
    return Object.freeze({
      observation: Object.freeze({
        kind: 'file',
        identity: result.identity,
        mode: 0o600,
      }),
      bytes: result.bytes,
      snapshot,
    });
  }

  private async readFileNoFollowBounded(
    path: string,
    maximum: number,
    name: string,
  ): Promise<LifecycleFileSnapshot | undefined> {
    let handle: FileHandle;
    try {
      handle = await open(path, constants.O_RDONLY | OPEN_NO_FOLLOW);
    } catch (error) {
      if (isNotFound(error)) {
        return undefined;
      }
      throw error;
    }

    let buffer: Uint8Array | undefined;
    let result: LifecycleFileSnapshot | undefined;
    let primaryError: unknown;
    try {
      const before = await handle.stat({ bigint: true });
      const expectedSize = boundedFileSize(before, maximum, name);
      buffer = new Uint8Array(expectedSize + 1);
      let offset = 0;
      while (offset < buffer.byteLength) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.byteLength - offset, offset);
        if (bytesRead === 0) {
          break;
        }
        offset += bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      if (
        offset !== expectedSize ||
        offset === buffer.byteLength ||
        !sameReadFileStat(before, after)
      ) {
        throw new Error(`${name} exceeds its byte limit or changed during read`);
      }
      result = Object.freeze({
        observation: observation(before),
        bytes: buffer.slice(0, offset),
      });
    } catch (error) {
      primaryError = error;
    } finally {
      buffer?.fill(0);
    }

    let closeError: unknown;
    try {
      await handle.close();
    } catch (error) {
      closeError = error;
    }
    if (primaryError !== undefined || closeError !== undefined) {
      result?.bytes.fill(0);
      throw combinedError('lifecycle bounded read failed', primaryError, closeError);
    }
    return result;
  }

  public async stageWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly bytes: Uint8Array;
    readonly mode: number;
    readonly creationIntentMarkerPath?: string;
  }): Promise<LifecycleStagedWrite> {
    const lock = this.nativeLock(input.lock);
    const parent = this.liveParentDirectory(input.stagingPath, lock);
    if (parent !== undefined && input.creationIntentMarkerPath === undefined) {
      throw new Error('embedded lifecycle stage requires a durable creation intent marker');
    }
    const created =
      input.creationIntentMarkerPath === undefined
        ? reserveLifecycleStagedFile({
            lock,
            path: input.stagingPath,
            mode: input.mode,
          })
        : (() => {
            const intent = prepareLifecycleCreationIntent({
              lock,
              path: input.stagingPath,
              ...(input.creationIntentMarkerPath === undefined
                ? {}
                : { markerPath: input.creationIntentMarkerPath }),
              ...(parent === undefined
                ? {}
                : { parentDirectoryReservation: parent.nativeReservation }),
              kind: 'file',
            });
            return reserveLifecycleFileFromIntent({
              lock,
              intent: intent.intent,
              mode: input.mode,
            });
          })();
    let outcome: LifecycleStagedWrite['state'] =
      created.state === 'completed' ? 'completed' : 'indeterminate';
    const stage = Object.freeze({
      path: input.stagingPath,
      identity: created.identity,
      mode: input.mode,
      get state(): LifecycleStagedWrite['state'] {
        return outcome;
      },
    }) as LifecycleStagedWrite;
    const state: ReservedStagedWriteState = {
      path: input.stagingPath,
      nativeReservation: created.reservation,
      lock,
      size: 0n,
      targetPath: undefined,
      written: false,
      status: 'open',
    };
    this.#stagedWrites.set(stage, state);
    if (outcome !== 'completed') {
      return stage;
    }
    try {
      const written = writeLifecycleStagedFile({
        lock,
        reservation: state.nativeReservation,
        expectedSize: 0,
        bytes: input.bytes,
      });
      if (written.state !== 'completed') {
        state.status = 'indeterminate';
        outcome = 'indeterminate';
        return stage;
      }
      state.size = BigInt(input.bytes.byteLength);
      state.written = true;
      return stage;
    } catch {
      state.status = 'indeterminate';
      outcome = 'indeterminate';
      return stage;
    }
  }
  public async publishStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    readonly targetPath: string;
  }): Promise<void> {
    const state = this.openStagedWrite(input.stage, input.lock);
    if (!state.written || dirname(state.path) !== dirname(input.targetPath)) {
      throw new Error('reserved lifecycle stage must remain in its target directory');
    }
    assertNativeLifecycleMutationCompleted(
      publishReservedLifecycleStagedFileNoReplace({
        lock: state.lock,
        reservation: state.nativeReservation,
        targetPath: input.targetPath,
      }),
      'reserved lifecycle stage publication',
    );
    state.status = 'published';
    state.targetPath = input.targetPath;
    this.#publishedStagedWrites.set(input.targetPath, state);
  }
  public async replaceStagedWriteWithQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    readonly targetPath: string;
    readonly current: LifecycleExactContentFile;
  }): Promise<NativeLifecycleQuarantineResult> {
    const state = this.openStagedWrite(input.stage, input.lock);
    if (!state.written || dirname(state.path) !== dirname(input.targetPath)) {
      throw new Error('reserved lifecycle stage must remain in its target directory');
    }
    const result = replaceReservedLifecycleOrdinaryFileExact({
      lock: state.lock,
      reservation: state.nativeReservation,
      targetPath: input.targetPath,
      targetIdentity: input.current.identity,
      targetMode: input.current.mode,
      targetSize: input.current.size,
      targetDigest: input.current.digest,
    });
    if (result.state !== 'completed' && result.quarantine === undefined) {
      state.status = 'indeterminate';
      return result;
    }
    state.status = result.state === 'completed' ? 'closed' : 'indeterminate';
    this.recordDurabilityReceipt(input.targetPath, state.lock);
    return result;
  }
  public async discardStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.stagedWriteState(input.stage);
    this.assertReservationLock(state.lock, input.lock);
    if (state.status === 'discarded') {
      return Object.freeze({ state: 'completed' });
    }
    if (state.status !== 'open' && state.status !== 'indeterminate') {
      return Object.freeze({ state: 'indeterminate' });
    }
    const result = discardLifecycleStagedFileReservation({
      lock: state.lock,
      reservation: state.nativeReservation,
    });
    state.status = result.state === 'completed' ? 'discarded' : 'indeterminate';
    return result;
  }
  public async retainStagedWriteForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.stagedWriteState(input.stage);
    this.assertReservationLock(state.lock, input.lock);
    try {
      if (
        state.status === 'closed' ||
        state.status === 'discarded' ||
        state.status === 'retained'
      ) {
        return Object.freeze({ state: 'completed' });
      }
      if (state.status !== 'open' || !this.revalidateLinkedWal(input.snapshot, input.lock)) {
        state.status = 'indeterminate';
        return Object.freeze({ state: 'indeterminate' });
      }
      const result = retainReservationForRecovery({
        lock: state.lock,
        reservation: state.nativeReservation,
      });
      if (result.state === 'completed') {
        state.status = 'retained';
        this.#stagedWrites.delete(input.stage);
      } else {
        state.status = 'indeterminate';
      }
      return result;
    } finally {
      this.#walSnapshots.delete(input.snapshot);
    }
  }

  public async reserveStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
    readonly creationIntentMarkerPath?: string;
    readonly mode: number;
  }): Promise<LifecycleReservedStagedWrite> {
    if (input.mode !== 0o600) {
      throw new Error('reserved lifecycle stage mode must be 0600');
    }
    const lock = this.nativeLock(input.lock);
    const parent = this.liveParentDirectory(input.path, lock);
    if (parent !== undefined && input.creationIntentMarkerPath === undefined) {
      throw new Error('embedded lifecycle stage requires a durable creation intent marker');
    }
    const intent = prepareLifecycleCreationIntent({
      lock,
      path: input.path,
      ...(input.creationIntentMarkerPath === undefined
        ? {}
        : { markerPath: input.creationIntentMarkerPath }),
      ...(parent === undefined ? {} : { parentDirectoryReservation: parent.nativeReservation }),
      kind: 'credential',
    });
    const created = reserveCredentialFromIntent({ lock, intent: intent.intent, mode: 0o600 });
    const reservation = Object.freeze({
      path: input.path,
      identity: created.identity,
      state:
        intent.state === 'completed' && created.state === 'completed'
          ? 'completed'
          : 'indeterminate',
    });
    this.#reserved.set(reservation, {
      path: input.path,
      nativeReservation: created.reservation,
      lock,
      size: 0n,
      targetPath: undefined,
      written: false,
      status: 'open',
    });
    return reservation;
  }

  public async writeReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    readonly bytes: Uint8Array;
  }): Promise<void> {
    const state = this.openReservation(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    if (state.written) {
      throw new Error('reserved lifecycle stage was already written');
    }

    let primaryError: unknown;
    try {
      assertNativeLifecycleMutationCompleted(
        writeLifecycleStagedFile({
          lock: state.lock,
          reservation: state.nativeReservation,
          expectedSize: Number(state.size),
          bytes: input.bytes,
        }),
        'reserved lifecycle stage write',
      );
      state.size = BigInt(input.bytes.byteLength);
      state.written = true;
      return;
    } catch (error) {
      primaryError = error;
    }

    let cleanupError: unknown;
    try {
      await this.discardReservedState(state);
    } catch (error) {
      cleanupError = error;
    }
    throw combinedError('reserved lifecycle stage write failed', primaryError, cleanupError);
  }

  public async renameReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    readonly targetPath: string;
  }): Promise<void> {
    const state = this.openReservation(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    let primaryError: unknown;
    try {
      if (!state.written) {
        throw new Error('reserved lifecycle stage has not been written');
      }
      if (dirname(state.path) !== dirname(input.targetPath)) {
        throw new Error('reserved lifecycle stage must remain in its target directory');
      }
      assertNativeLifecycleMutationCompleted(
        publishReservedLifecycleStagedFileNoReplace({
          lock: state.lock,
          reservation: state.nativeReservation,
          targetPath: input.targetPath,
        }),
        'reserved lifecycle stage publication',
      );
      state.status = 'published';
      state.targetPath = input.targetPath;
      this.#publishedStagedWrites.set(input.targetPath, state);
      return;
    } catch (error) {
      primaryError = error;
    }

    let cleanupError: unknown;
    try {
      await this.discardReservedState(state);
    } catch (error) {
      cleanupError = error;
    }
    throw combinedError('reserved lifecycle stage rename failed', primaryError, cleanupError);
  }

  public async validatePublishedCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleReservedStagedWrite;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.reservationState(input.credential);
    this.assertReservationLock(state.lock, input.lock);
    const result = validateLifecycleStagedFileReservation({
      lock: state.lock,
      reservation: state.nativeReservation,
    });
    if (result.state !== 'completed') {
      state.status = 'indeterminate';
    }
    return result;
  }
  public async validateExactCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleExactFile;
  }): Promise<NativeLifecycleMutationResult> {
    return validateExactCredential({
      lock: this.nativeLock(input.lock),
      target: input.credential,
    });
  }
  public async removeExactCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleExactFile;
  }): Promise<NativeLifecycleQuarantineResult> {
    const result = removeExactCredential({
      lock: this.nativeLock(input.lock),
      target: input.credential,
    });
    if (result.state === 'completed') {
      this.recordDurabilityReceipt(input.credential.path, this.nativeLock(input.lock));
    }
    return result;
  }
  public async retainReservedStagedWriteForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.reservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    try {
      if (state.status !== 'open' || !this.revalidateLinkedWal(input.snapshot, input.lock)) {
        state.status = 'indeterminate';
        return Object.freeze({ state: 'indeterminate' });
      }
      const result = retainReservationForRecovery({
        lock: state.lock,
        reservation: state.nativeReservation,
      });
      if (result.state === 'completed') {
        state.status = 'retained';
        this.#reserved.delete(input.reservation);
      } else {
        state.status = 'indeterminate';
      }
      return result;
    } finally {
      this.#walSnapshots.delete(input.snapshot);
    }
  }
  public async retainReservedStagedDirectoryForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.directoryReservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    try {
      if (state.status !== 'open' || !this.revalidateLinkedWal(input.snapshot, input.lock)) {
        state.status = 'indeterminate';
        this.unregisterDirectoryReservation(state);
        return Object.freeze({ state: 'indeterminate' });
      }
      const result = retainReservationForRecovery({
        lock: state.lock,
        reservation: state.nativeReservation,
      });
      if (result.state === 'completed') {
        state.status = 'retained';
        this.#reservedDirectories.delete(input.reservation);
        this.unregisterDirectoryReservation(state);
      } else {
        state.status = 'indeterminate';
      }
      return result;
    } finally {
      this.#walSnapshots.delete(input.snapshot);
    }
  }
  public async recoverCreationIntent(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagePath: string;
    readonly markerPath: string;
    readonly kind: 'credential' | 'directory' | 'file';
    readonly mode: number;
  }): Promise<NativeLifecycleQuarantineResult> {
    return recoverLifecycleCreationIntent({
      lock: this.nativeLock(input.lock),
      stagePath: input.stagePath,
      markerPath: input.markerPath,
      kind: input.kind,
      mode: input.mode,
    });
  }
  public async validateExactDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly directory: LifecycleExactDirectory;
  }): Promise<NativeLifecycleMutationResult> {
    return validateExactDirectory({
      lock: this.nativeLock(input.lock),
      target: input.directory,
    });
  }
  public async closeReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
  }): Promise<void> {
    const state = this.reservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    if (state.status === 'closed' || state.status === 'discarded' || state.status === 'retained') {
      return;
    }
    if (state.status !== 'published') {
      throw new Error('unpublished reserved lifecycle stage must be discarded');
    }
    assertNativeLifecycleMutationCompleted(
      closeLifecycleStagedFileReservation({
        lock: state.lock,
        reservation: state.nativeReservation,
      }),
      'reserved lifecycle stage validation and close',
    );
    state.status = 'closed';
    this.unregisterPublishedStagedWrite(state);
  }

  public async discardReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
  }): Promise<NativeLifecycleMutationResult> {
    const state = this.reservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    if (state.status === 'discarded') {
      return Object.freeze({ state: 'completed' });
    }
    if (state.status !== 'open' && state.status !== 'indeterminate') {
      return Object.freeze({ state: 'indeterminate' });
    }
    const result = discardLifecycleStagedFileReservation({
      lock: state.lock,
      reservation: state.nativeReservation,
    });
    state.status = result.state === 'completed' ? 'discarded' : 'indeterminate';
    if (result.state === 'completed') {
      this.unregisterPublishedStagedWrite(state);
    }
    return result;
  }

  private reservationState(reservation: LifecycleReservedStagedWrite): ReservedStagedWriteState {
    const state = this.#reserved.get(reservation);
    if (state === undefined) {
      throw new Error('reserved lifecycle stage is not owned by this port');
    }
    return state;
  }
  private stagedWriteState(stage: LifecycleStagedWrite): ReservedStagedWriteState {
    const state = this.#stagedWrites.get(stage);
    if (state === undefined) {
      throw new Error('lifecycle staged write is not owned by this port');
    }
    return state;
  }
  private openStagedWrite(
    stage: LifecycleStagedWrite,
    lock: LifecycleAdvisoryLock,
  ): ReservedStagedWriteState {
    if (stage.state !== 'completed') {
      throw new Error('lifecycle staged write is indeterminate');
    }
    const state = this.stagedWriteState(stage);
    this.assertReservationLock(state.lock, lock);
    if (state.status !== 'open') {
      throw new Error('lifecycle staged write is not open');
    }
    return state;
  }

  private openReservation(reservation: LifecycleReservedStagedWrite): ReservedStagedWriteState {
    const state = this.reservationState(reservation);
    if (state.status !== 'open') {
      throw new Error('reserved lifecycle stage is not open');
    }
    return state;
  }

  private async discardReservedState(state: ReservedStagedWriteState): Promise<void> {
    const result = discardLifecycleStagedFileReservation({
      lock: state.lock,
      reservation: state.nativeReservation,
    });
    if (result.state !== 'completed') {
      state.status = 'indeterminate';
      assertNativeLifecycleMutationCompleted(result, 'reserved lifecycle stage exact cleanup');
    }
    state.status = 'discarded';
  }
  public async reserveStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
    readonly targetPath?: string;
    readonly creationIntentMarkerPath?: string;
    readonly mode: number;
  }): Promise<LifecycleReservedStagedDirectory> {
    const lock = this.nativeLock(input.lock);
    const parent = this.liveParentDirectory(input.targetPath ?? input.path, lock);
    if (parent !== undefined && input.creationIntentMarkerPath === undefined) {
      throw new Error('embedded lifecycle stage requires a durable creation intent marker');
    }
    const physicalPath = this.directoryReservationPath(input, lock);
    const intent = prepareLifecycleCreationIntent({
      lock,
      path: input.path,
      ...(input.creationIntentMarkerPath === undefined
        ? {}
        : { markerPath: input.creationIntentMarkerPath }),
      ...(parent === undefined ? {} : { parentDirectoryReservation: parent.nativeReservation }),
      kind: 'directory',
    });
    const created = reserveDirectoryFromIntent({ lock, intent: intent.intent, mode: input.mode });
    const reservation = Object.freeze({
      path: input.path,
      identity: created.identity,
      mode: input.mode,
      state:
        intent.state === 'completed' && created.state === 'completed'
          ? 'completed'
          : 'indeterminate',
    });
    const state: ReservedStagedDirectoryState = {
      path: input.path,
      physicalPath,
      targetPath: input.targetPath,
      nativeReservation: created.reservation,
      lock,
      closeRequested: false,
      status: 'open',
    };
    this.#reservedDirectories.set(reservation, state);
    if (input.targetPath !== undefined && state.status === 'open') {
      this.#reservedDirectoryTargets.set(input.targetPath, state);
    }
    return reservation;
  }

  public async publishReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
    readonly targetPath: string;
  }): Promise<void> {
    const state = this.openDirectoryReservation(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    await this.publishReservedDirectoryState(state, input.targetPath);
  }

  public async closeReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
  }): Promise<void> {
    const state = this.directoryReservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    if (state.status === 'closed' || state.status === 'discarded' || state.status === 'retained') {
      return;
    }
    if (state.status !== 'published') {
      throw new Error('unpublished reserved lifecycle directory must be discarded');
    }
    state.closeRequested = true;
  }

  public async discardReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
  }): Promise<NativeLifecycleQuarantineResult> {
    const state = this.directoryReservationState(input.reservation);
    this.assertReservationLock(state.lock, input.lock);
    if (state.status === 'discarded') {
      return Object.freeze({ state: 'completed' });
    }
    if (state.status !== 'open' && state.status !== 'indeterminate') {
      return Object.freeze({ state: 'indeterminate' });
    }
    const result = discardLifecycleStagedDirectoryReservation({
      lock: state.lock,
      reservation: state.nativeReservation,
    });
    if (result.state === 'completed') {
      state.status = 'discarded';
      this.#reservedDirectories.delete(input.reservation);
      this.unregisterDirectoryReservation(state);
    } else {
      state.status = 'indeterminate';
    }
    return result;
  }

  public async publishExactStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleExactDirectory['identity'];
    readonly mode: number;
  }): Promise<void> {
    if (dirname(input.stagingPath) !== dirname(input.targetPath)) {
      throw new Error('lifecycle staged directory crosses filesystems');
    }
    assertNativeLifecycleMutationCompleted(
      publishLifecycleStagedDirectoryNoReplace({
        lock: this.nativeLock(input.lock),
        stagingPath: input.stagingPath,
        targetPath: input.targetPath,
        identity: input.identity,
        mode: input.mode,
      }),
      'exact lifecycle directory publication',
    );
    this.recordDurabilityReceipt(input.targetPath, this.nativeLock(input.lock));
  }

  public async fsyncDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<void> {
    const state = this.#reservedDirectoryTargets.get(input.path);
    if (state !== undefined) {
      this.assertReservationLock(state.lock, input.lock);
      this.syncPublishedDirectory(state);
      return;
    }
    this.requireDurabilityReceipt(input.path, input.lock);
  }

  public async quarantineExactDirectory(
    input: LifecycleExactDirectory & {
      readonly lock: LifecycleAdvisoryLock;
      readonly quarantinePath: string;
    },
  ): Promise<NativeLifecycleQuarantineResult> {
    this.closePublishedDirectoryForMutation(input.path, input.lock);
    const result = quarantineLifecycleExactDirectory({
      lock: this.nativeLock(input.lock),
      path: input.path,
      quarantinePath: input.quarantinePath,
      identity: input.identity,
      mode: input.mode,
    });
    if (result.state === 'completed' || result.quarantine !== undefined) {
      this.recordDurabilityReceipt(input.path, this.nativeLock(input.lock));
    }
    return result;
  }

  private directoryReservationState(
    reservation: LifecycleReservedStagedDirectory,
  ): ReservedStagedDirectoryState {
    const state = this.#reservedDirectories.get(reservation);
    if (state === undefined) {
      throw new Error('reserved lifecycle directory is not owned by this port');
    }
    return state;
  }

  private openDirectoryReservation(
    reservation: LifecycleReservedStagedDirectory,
  ): ReservedStagedDirectoryState {
    const state = this.directoryReservationState(reservation);
    if (state.status !== 'open') {
      throw new Error('reserved lifecycle directory is not open');
    }
    return state;
  }

  private async publishReservedDirectoryState(
    state: ReservedStagedDirectoryState,
    targetPath: string,
  ): Promise<void> {
    if (
      dirname(state.path) !== dirname(targetPath) ||
      (state.targetPath !== undefined && state.targetPath !== targetPath)
    ) {
      throw new Error('reserved lifecycle directory must remain in its target directory');
    }
    assertNativeLifecycleMutationCompleted(
      publishReservedLifecycleStagedDirectoryNoReplace({
        lock: state.lock,
        reservation: state.nativeReservation,
        targetPath,
      }),
      'reserved lifecycle directory publication',
    );
    this.relocateDirectoryReservationPaths(state.physicalPath, targetPath);
    state.status = 'published';
    this.recordDurabilityReceipt(targetPath, state.lock);
  }

  public async replaceExactStagedFileWithQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleExactFile['identity'];
    readonly mode: number;
    readonly current: LifecycleExactFile & { readonly size?: number; readonly digest?: string };
  }): Promise<NativeLifecycleQuarantineResult> {
    if (dirname(input.stagingPath) !== dirname(input.targetPath)) {
      throw new Error('lifecycle staged write crosses filesystems');
    }
    const result = replaceLifecycleStagedFileExact({
      lock: this.nativeLock(input.lock),
      stagingPath: input.stagingPath,
      targetPath: input.targetPath,
      identity: input.identity,
      mode: input.mode,
      targetIdentity: input.current.identity,
      targetMode: input.current.mode,
      ...(input.current.size === undefined || input.current.digest === undefined
        ? {}
        : { targetSize: input.current.size, targetDigest: input.current.digest }),
    });
    if (result.state === 'completed' || result.quarantine !== undefined) {
      this.recordDurabilityReceipt(input.targetPath, this.nativeLock(input.lock));
    }
    return result;
  }

  public async replaceExactWal(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactFile;
    readonly replacement: LifecycleStagedWrite;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<NativeLifecycleQuarantineResult> {
    const state = this.openStagedWrite(input.replacement, input.lock);
    const target = this.exactWalSnapshot(input.snapshot, input.lock, input.current);
    if (!state.written || dirname(state.path) !== dirname(target.path)) {
      throw new Error('reserved lifecycle WAL stage must remain in its target directory');
    }
    const result = replaceReservedLifecycleFileExact({
      lock: state.lock,
      reservation: state.nativeReservation,
      targetPath: target.path,
      targetIdentity: target.identity,
      targetMode: target.mode,
      targetSize: target.size,
      targetDigest: target.digest,
      targetStat: target.stat,
      discardReplacedTarget: false,
    });
    if (result.state !== 'completed' && result.quarantine === undefined) {
      state.status = 'indeterminate';
      return result;
    }
    state.status = result.state === 'completed' ? 'closed' : 'indeterminate';
    this.recordDurabilityReceipt(target.path, state.lock);
    this.#stagedWrites.delete(input.replacement);
    this.#walSnapshots.delete(input.snapshot);
    return this.finalizeResolvedQuarantineResidue(result, this.nativeLock(input.lock));
  }
  public async removeExactWal(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactFile;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<NativeLifecycleQuarantineResult> {
    const target = this.exactWalSnapshot(input.snapshot, input.lock, input.current);
    const result = removeExactWal({
      lock: this.nativeLock(input.lock),
      target,
    });
    if (result.state === 'completed' || result.quarantine !== undefined) {
      this.recordDurabilityReceipt(target.path, this.nativeLock(input.lock));
      this.#walSnapshots.delete(input.snapshot);
    }
    return this.finalizeResolvedQuarantineResidue(result, this.nativeLock(input.lock));
  }

  /**
   * WAL publication and removal must leave no stage residue behind any caller
   * failure point. When the exact mutation completed and retained a
   * content-bound quarantine, finalize it immediately inside the same port
   * operation; only an incomplete residue cleanup keeps the retryable handle.
   */
  private finalizeResolvedQuarantineResidue(
    result: NativeLifecycleQuarantineResult,
    lock: NativeLifecycleLock,
  ): NativeLifecycleQuarantineResult {
    if (result.state !== 'completed' || result.quarantine === undefined) {
      return result;
    }
    const finalized = finalizeLifecycleQuarantine({ lock, quarantine: result.quarantine });
    if (finalized.state !== 'completed') {
      return result;
    }
    return Object.freeze({ state: 'completed' });
  }

  public async removeExactStagedFile(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactFile & { readonly size: number; readonly digest: string };
  }): Promise<NativeLifecycleQuarantineResult> {
    const result = removeExactStagedFile({
      lock: this.nativeLock(input.lock),
      target: input.current,
    });
    if (result.state === 'completed' || result.quarantine !== undefined) {
      this.recordDurabilityReceipt(input.current.path, this.nativeLock(input.lock));
    }
    return result;
  }

  public async publishExactStagedFile(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleExactFile['identity'];
    readonly mode: number;
  }): Promise<void> {
    if (dirname(input.stagingPath) !== dirname(input.targetPath)) {
      throw new Error('lifecycle staged write crosses filesystems');
    }
    assertNativeLifecycleMutationCompleted(
      publishLifecycleStagedFileNoReplace({
        lock: this.nativeLock(input.lock),
        stagingPath: input.stagingPath,
        targetPath: input.targetPath,
        identity: input.identity,
        mode: input.mode,
      }),
      'exact lifecycle staged file publication',
    );
    this.recordDurabilityReceipt(input.targetPath, this.nativeLock(input.lock));
  }

  public async fsyncFile(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<void> {
    const state = this.#publishedStagedWrites.get(input.path);
    if (state !== undefined) {
      this.assertReservationLock(state.lock, input.lock);
      this.syncPublishedStagedWrite(state);
      return;
    }
    this.requireDurabilityReceipt(input.path, input.lock);
  }
  public async fsyncParent(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<void> {
    const state = this.#publishedStagedWrites.get(input.path);
    if (state !== undefined) {
      this.assertReservationLock(state.lock, input.lock);
      this.syncPublishedStagedWrite(state);
    }
    const parent = this.liveParentDirectory(input.path, this.nativeLock(input.lock));
    if (state !== undefined) {
      this.closePublishedStagedWrite(state);
      return;
    }
    if (parent !== undefined) {
      return;
    }
    this.requireDurabilityReceipt(input.path, input.lock);
  }

  public async quarantineExactFile(
    input: LifecycleExactFile & {
      readonly lock: LifecycleAdvisoryLock;
      readonly quarantinePath: string;
      readonly credential?: boolean;
      readonly size?: number;
      readonly digest?: string;
    },
  ): Promise<NativeLifecycleQuarantineResult> {
    const nativeInput = {
      lock: this.nativeLock(input.lock),
      path: input.path,
      quarantinePath: input.quarantinePath,
      identity: input.identity,
      mode: input.mode,
    };
    const result =
      input.credential === true
        ? quarantineLifecycleExactCredential(nativeInput)
        : quarantineLifecycleExactFile({
            ...nativeInput,
            ...(input.size === undefined || input.digest === undefined
              ? {}
              : { expectedSize: input.size, expectedDigest: input.digest }),
          });
    if (result.state === 'completed' || result.quarantine !== undefined) {
      this.recordDurabilityReceipt(input.path, nativeInput.lock);
    }
    return result;
  }

  public async finalizeQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly quarantine: object;
  }): Promise<NativeLifecycleQuarantineResult> {
    return finalizeLifecycleQuarantine({
      lock: this.nativeLock(input.lock),
      quarantine: input.quarantine as NativeLifecycleQuarantine,
    });
  }

  public async restoreQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly quarantine: object;
  }): Promise<NativeLifecycleQuarantineResult> {
    return restoreLifecycleQuarantine({
      lock: this.nativeLock(input.lock),
      quarantine: input.quarantine as NativeLifecycleQuarantine,
    });
  }
  public async materializeUninstallInverse(
    input: LifecycleUninstallMaterializationInput,
  ): Promise<Uint8Array> {
    const { inverse, expected } = input;
    if (inverse.path !== expected.path) {
      throw new Error('uninstall inverse path does not match its exact preimage');
    }
    if (inverse.kind === 'restore-owned-file') {
      return restoreOwnedLoader(expected.bytes, inverse);
    }
    if (inverse.kind === 'restore-config' || inverse.kind === 'remove-config-hunks') {
      const parsed = parseConfig(expected.bytes);
      const transformed = transformConfig(
        parsed.projects,
        inverse.preimage,
        inverse.postimage,
        inverse.kind === 'remove-config-hunks' ? inverse.hunks.map((hunk) => hunk.subject) : [],
      );
      if (sameProjects(parsed.projects, transformed)) {
        return new Uint8Array(expected.bytes);
      }
      return new TextEncoder().encode(
        `${JSON.stringify(
          parseServerConfigV1({
            schemaVersion: 1,
            ...(parsed.globalLimits === undefined ? {} : { globalLimits: parsed.globalLimits }),
            projects: transformed,
          }),
          null,
          2,
        )}\n`,
      );
    }
    const current = parseCredentialAuthorityRegistry(expected.bytes);
    const transformed = transformCredentialAuthorityRegistry(
      current.projects,
      inverse.postimage,
      inverse.preimage,
    );
    if (sameRegistryEntries(current.projects, transformed)) {
      return new Uint8Array(expected.bytes);
    }
    return new TextEncoder().encode(
      serializeCredentialAuthorityRegistryV1({ schemaVersion: 1, projects: transformed }),
    );
  }

  private async releasePendingLocks(): Promise<void> {
    for (const lock of [...this.#pendingLockReleases]) {
      await lock.release();
    }
  }
  private assertReservationLock(expected: NativeLifecycleLock, lock: LifecycleAdvisoryLock): void {
    if (this.nativeLock(lock) !== expected) {
      throw new Error('lifecycle reservation is bound to a different lock capability');
    }
  }
  private directoryReservationPath(
    input: { readonly path: string; readonly targetPath?: string },
    lock: NativeLifecycleLock,
  ): string {
    if (input.targetPath === undefined) {
      return input.path;
    }
    if (dirname(input.path) !== dirname(input.targetPath)) {
      throw new Error('reserved lifecycle directory must be staged beside its target');
    }
    const parent = this.liveParentDirectory(input.targetPath, lock);
    return parent === undefined ? input.path : join(parent.physicalPath, basename(input.path));
  }
  private liveParentDirectory(
    path: string,
    lock: NativeLifecycleLock,
  ): ReservedStagedDirectoryState | undefined {
    let parent = this.#reservedDirectoryTargets.get(dirname(path));
    const directParent = parent;
    const ancestors: ReservedStagedDirectoryState[] = [];
    while (parent !== undefined) {
      if (parent.lock !== lock || parent.status !== 'published') {
        throw new Error('reserved lifecycle parent is not an exact live authority');
      }
      ancestors.push(parent);
      parent =
        parent.targetPath === undefined
          ? undefined
          : this.#reservedDirectoryTargets.get(dirname(parent.targetPath));
    }
    for (const ancestor of ancestors.reverse()) {
      this.syncPublishedDirectory(ancestor);
    }
    return directParent;
  }
  private relocateDirectoryReservationPaths(sourcePath: string, targetPath: string): void {
    for (const state of this.#reservedDirectoryTargets.values()) {
      if (state.physicalPath === sourcePath) {
        state.physicalPath = targetPath;
      } else if (state.physicalPath.startsWith(`${sourcePath}/`)) {
        state.physicalPath = `${targetPath}${state.physicalPath.slice(sourcePath.length)}`;
      }
    }
  }
  private unregisterDirectoryReservation(state: ReservedStagedDirectoryState): void {
    if (
      state.targetPath !== undefined &&
      this.#reservedDirectoryTargets.get(state.targetPath) === state
    ) {
      this.#reservedDirectoryTargets.delete(state.targetPath);
    }
  }
  private recordDurabilityReceipt(path: string, lock: NativeLifecycleLock): void {
    this.#durabilityReceipts.set(path, lock);
  }
  private requireDurabilityReceipt(path: string, lock: LifecycleAdvisoryLock): void {
    const nativeLock = this.revalidateNativeLock(lock);
    if (this.#durabilityReceipts.get(path) !== nativeLock) {
      throw new Error('lifecycle durability requires an exact native mutation authority');
    }
  }
  private syncPublishedStagedWrite(state: ReservedStagedWriteState): void {
    assertNativeLifecycleMutationCompleted(
      syncLifecycleStagedFileReservation({
        lock: state.lock,
        reservation: state.nativeReservation,
      }),
      'reserved lifecycle file durability',
    );
  }
  private syncPublishedDirectory(state: ReservedStagedDirectoryState): void {
    assertNativeLifecycleMutationCompleted(
      syncLifecycleStagedDirectoryReservation({
        lock: state.lock,
        reservation: state.nativeReservation,
      }),
      'reserved lifecycle directory durability',
    );
  }
  private closePublishedDirectoryForMutation(path: string, lock: LifecycleAdvisoryLock): void {
    const state = this.#reservedDirectoryTargets.get(path);
    if (state === undefined) {
      return;
    }
    this.assertReservationLock(state.lock, lock);
    if (state.status !== 'published') {
      throw new Error('lifecycle directory mutation requires an exact published reservation');
    }
    this.syncPublishedDirectory(state);
    assertNativeLifecycleMutationCompleted(
      closeLifecycleStagedDirectoryReservation({
        lock: state.lock,
        reservation: state.nativeReservation,
      }),
      'reserved lifecycle directory mutation close',
    );
    state.status = 'closed';
    this.unregisterDirectoryReservation(state);
  }
  private closePublishedStagedWrite(state: ReservedStagedWriteState): void {
    assertNativeLifecycleMutationCompleted(
      closeLifecycleStagedFileReservation({
        lock: state.lock,
        reservation: state.nativeReservation,
      }),
      'reserved lifecycle file durability close',
    );
    state.status = 'closed';
    if (state.targetPath !== undefined) {
      this.recordDurabilityReceipt(state.targetPath, state.lock);
    }
    this.unregisterPublishedStagedWrite(state);
  }
  private unregisterPublishedStagedWrite(state: ReservedStagedWriteState): void {
    if (
      state.targetPath !== undefined &&
      this.#publishedStagedWrites.get(state.targetPath) === state
    ) {
      this.#publishedStagedWrites.delete(state.targetPath);
    }
  }
  private closeRetainedReservations(lock: NativeLifecycleLock): void {
    for (const state of new Set(this.#publishedStagedWrites.values())) {
      if (state.lock === lock && state.status === 'published') {
        this.closePublishedStagedWrite(state);
      }
    }
    const directories = [...new Set(this.#reservedDirectoryTargets.values())]
      .filter((state) => state.lock === lock && state.status === 'published')
      .sort(
        (left, right) => right.physicalPath.split('/').length - left.physicalPath.split('/').length,
      );
    for (const state of directories) {
      assertNativeLifecycleMutationCompleted(
        closeLifecycleStagedDirectoryReservation({
          lock,
          reservation: state.nativeReservation,
        }),
        'retained lifecycle directory close',
      );
      state.status = 'closed';
      this.unregisterDirectoryReservation(state);
    }
  }
  private revalidateNativeLock(lock: LifecycleAdvisoryLock): NativeLifecycleLock {
    const nativeLock = this.nativeLock(lock);
    assertNativeLifecycleMutationCompleted(
      revalidateLifecycleLock(nativeLock),
      'lifecycle lock revalidation',
    );
    return nativeLock;
  }
  private revalidateLinkedWal(
    snapshot: LifecycleWalSnapshotAuthority,
    lock: LifecycleAdvisoryLock,
  ): boolean {
    try {
      const state = this.nativeWalSnapshot(snapshot, lock);
      const observed = readExactLifecycleWal({
        lock: state.lock,
        target: {
          path: state.path,
          identity: state.identity,
          mode: state.mode,
        },
      });
      if (observed.state !== 'completed') {
        return false;
      }
      try {
        return (
          observed.identity.device === state.identity.device &&
          observed.identity.inode === state.identity.inode &&
          observed.size === state.size &&
          observed.digest === state.digest &&
          observed.stat === state.stat
        );
      } finally {
        observed.bytes.fill(0);
      }
    } catch {
      return false;
    }
  }
  private nativeWalSnapshot(
    snapshot: LifecycleWalSnapshotAuthority,
    lock: LifecycleAdvisoryLock,
  ): WalSnapshotState {
    const state = this.#walSnapshots.get(snapshot);
    if (state === undefined || state.lock !== this.nativeLock(lock)) {
      throw new Error('lifecycle WAL snapshot is not bound to this lock session');
    }
    return state;
  }
  private exactWalSnapshot(
    snapshot: LifecycleWalSnapshotAuthority,
    lock: LifecycleAdvisoryLock,
    current: LifecycleExactFile,
  ): NativeLifecycleWalExactFile {
    const state = this.nativeWalSnapshot(snapshot, lock);
    if (
      state.path !== current.path ||
      state.mode !== current.mode ||
      state.identity.device !== current.identity.device ||
      state.identity.inode !== current.identity.inode
    ) {
      throw new Error('lifecycle WAL mutation does not match its native read snapshot');
    }
    return Object.freeze({
      path: state.path,
      identity: state.identity,
      mode: state.mode,
      size: state.size,
      digest: state.digest,
      stat: state.stat,
    });
  }

  private nativeLock(lock: LifecycleAdvisoryLock): NativeLifecycleLock {
    const nativeLock = this.#nativeLocks.get(lock);
    if (nativeLock === undefined) {
      throw new Error('lifecycle mutation requires this port’s live lock capability');
    }
    return nativeLock;
  }
  public async failurePoint(): Promise<void> {}
}
function lifecycleOwnerUid(): bigint {
  if (typeof process.geteuid !== 'function') {
    throw new Error('lifecycle runtime purge requires a POSIX owner identity');
  }
  const uid = process.geteuid();
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error('lifecycle runtime purge could not determine the invoking user');
  }
  return BigInt(uid);
}

function isManagedViteRuntimeDirectory(
  stat: BigIntStats,
  expected: LifecycleExactDirectory,
  device: bigint,
  ownerUid: bigint,
): boolean {
  return (
    stat.isDirectory() &&
    !stat.isSymbolicLink() &&
    stat.dev === device &&
    stat.ino.toString(10) === expected.identity.inode &&
    stat.dev.toString(10) === expected.identity.device &&
    stat.uid === ownerUid &&
    modeBits(stat.mode) === expected.mode &&
    stat.nlink >= 2n
  );
}

async function removeManagedViteRuntimeEntry(
  path: string,
  device: bigint,
  ownerUid: bigint,
  budget: { remaining: number },
): Promise<boolean> {
  if (budget.remaining-- <= 0) {
    return false;
  }
  let stat: BigIntStats;
  try {
    stat = await lstat(path, { bigint: true });
  } catch (error) {
    if (isNotFound(error)) {
      return true;
    }
    throw error;
  }
  if (stat.dev !== device || stat.uid !== ownerUid || stat.isSymbolicLink()) {
    return false;
  }
  if (stat.isFile()) {
    if (modeBits(stat.mode) !== 0o600 || stat.nlink !== 1n) {
      return false;
    }
    await unlink(path);
    return true;
  }
  if (!stat.isDirectory() || modeBits(stat.mode) !== 0o700 || stat.nlink < 2n) {
    return false;
  }
  for (const entry of await readdir(path)) {
    if (!(await removeManagedViteRuntimeEntry(join(path, entry), device, ownerUid, budget))) {
      return false;
    }
  }
  await rmdir(path);
  return true;
}
function combinedError(message: string, ...errors: readonly unknown[]): Error {
  const failures = errors.filter((error) => error !== undefined);
  if (failures.length === 1 && failures[0] instanceof Error) {
    return failures[0];
  }
  return new AggregateError(failures, message);
}

function boundedFileSize(stat: BigIntStats, maximum: number, name: string): number {
  if (!stat.isFile() || stat.size < 0n || stat.size > BigInt(maximum)) {
    throw new Error(`${name} is not a bounded regular file`);
  }
  return Number(stat.size);
}

function sameReadFileStat(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function modeBits(mode: number | bigint): number {
  return typeof mode === 'bigint' ? Number(mode & 0o7777n) : mode & 0o7777;
}
function parseCredentialAuthorityRegistry(
  bytes: Uint8Array,
): ReturnType<typeof parseCredentialAuthorityRegistryJsonV1> {
  if (bytes.byteLength > MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES) {
    throw new Error('credential authority registry is invalid');
  }
  let serialized: string;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('credential authority registry is not UTF-8');
  }
  try {
    return parseCredentialAuthorityRegistryJsonV1(serialized);
  } catch {
    throw new Error('credential authority registry is invalid');
  }
}

/**
 * `current` must be the exact authorized source registry. The deterministic
 * result is later compared as a complete snapshot during recovery.
 */
function transformCredentialAuthorityRegistry(
  current: readonly CredentialAuthorityRegistryEntry[],
  fromImage: CredentialAuthorityRegistrySelectionV1,
  toImage: CredentialAuthorityRegistrySelectionV1,
): readonly CredentialAuthorityRegistryEntry[] {
  let parsedFromImage: CredentialAuthorityRegistrySelectionV1;
  let parsedToImage: CredentialAuthorityRegistrySelectionV1;
  try {
    parsedFromImage = parseCredentialAuthorityRegistrySelectionV1(fromImage);
    parsedToImage = parseCredentialAuthorityRegistrySelectionV1(toImage);
  } catch {
    throw new Error('credential authority registry transition is invalid');
  }

  const fromImageEntry = parsedFromImage.projects[0];
  const toImageEntry = parsedToImage.projects[0];
  const selected = fromImageEntry ?? toImageEntry;
  if (
    parsedFromImage.projects.length > 1 ||
    parsedToImage.projects.length > 1 ||
    selected === undefined ||
    (fromImageEntry !== undefined &&
      toImageEntry !== undefined &&
      fromImageEntry.projectId !== toImageEntry.projectId)
  ) {
    throw new Error('credential authority registry transition is invalid');
  }

  const actual = current.find((entry) => entry.projectId === selected.projectId);
  const matchesFromImage =
    (fromImageEntry === undefined && actual === undefined) ||
    (fromImageEntry !== undefined &&
      actual !== undefined &&
      sameRegistryEntry(actual, fromImageEntry));
  if (!matchesFromImage) {
    throw new Error('credential authority registry selected entry changed');
  }

  const transformed = current.filter((entry) => entry.projectId !== selected.projectId);
  if (toImageEntry !== undefined) {
    transformed.push(toImageEntry);
  }
  transformed.sort((left, right) =>
    left.projectId < right.projectId ? -1 : left.projectId > right.projectId ? 1 : 0,
  );
  return Object.freeze(transformed);
}

function sameRegistryEntry(
  left: CredentialAuthorityRegistryEntry,
  right: CredentialAuthorityRegistryEntry,
): boolean {
  return (
    left.projectId === right.projectId &&
    left.tokenEnv === right.tokenEnv &&
    left.canonicalRoot === right.canonicalRoot &&
    left.credentialPath === right.credentialPath &&
    left.device === right.device &&
    left.inode === right.inode
  );
}

function sameRegistryEntries(
  left: readonly CredentialAuthorityRegistryEntry[],
  right: readonly CredentialAuthorityRegistryEntry[],
): boolean {
  return (
    left.length === right.length &&
    left.every((entry, index) => {
      const other = right[index];
      return other !== undefined && sameRegistryEntry(entry, other);
    })
  );
}

function restoreOwnedLoader(
  bytes: Uint8Array,
  inverse: RestoreOwnedFileInverseOperation,
): Uint8Array {
  const restored = reconstructOwnedStaticFilePreimage(inverse, bytes);
  if (restored === undefined) {
    throw new Error('owned file restoration preimage does not match');
  }
  return restored;
}

export function reconstructOwnedStaticFilePreimage(
  inverse: Pick<
    RestoreOwnedFileInverseOperation,
    'preimageFingerprint' | 'postimageFingerprint' | 'ownedInsertion' | 'hunks'
  >,
  bytes: Uint8Array,
): Uint8Array | undefined {
  const [hunk] = inverse.hunks;
  if (
    inverse.preimageFingerprint === inverse.postimageFingerprint ||
    inverse.hunks.length !== 1 ||
    hunk === undefined ||
    hunk.operation !== 'insert' ||
    (hunk.subject !== 'scg-html-loader' &&
      hunk.subject !== 'scg-vue3-loader' &&
      hunk.subject !== 'scg-react-loader') ||
    hunk.fingerprint !== inverse.postimageFingerprint
  ) {
    return undefined;
  }

  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }

  const candidates =
    hunk.subject === 'scg-html-loader'
      ? loaderLineCandidates(source, STATIC_LOADER_MARKER)
      : hunk.subject === 'scg-vue3-loader' || hunk.subject === 'scg-react-loader'
        ? loaderLineCandidates(source, VITE_SPA_LOADER_TAG)
        : Object.freeze([]);
  const candidate = candidates.find((item) => item.insertion === inverse.ownedInsertion);
  if (candidate === undefined) {
    return undefined;
  }

  /*
   * The no-edit path remains a byte-exact restoration proof. With unrelated
   * edits, prove instead that this candidate removes only the owned insertion.
   */
  if (fingerprintBytes(bytes) === inverse.postimageFingerprint) {
    const restored = new TextEncoder().encode(candidate.source);
    return fingerprintBytes(restored) === inverse.preimageFingerprint ? restored : undefined;
  }
  if (
    `${candidate.source.slice(0, candidate.offset)}${candidate.removed}${candidate.source.slice(
      candidate.offset,
    )}` !== source
  ) {
    return undefined;
  }
  return new TextEncoder().encode(candidate.source);
}

interface LoaderLineCandidate {
  readonly insertion: 'line' | 'preceding-newline-line';
  readonly offset: number;
  readonly removed: string;
  readonly source: string;
}

function loaderLineCandidates(source: string, marker: string): readonly LoaderLineCandidate[] {
  const markerIndex = source.indexOf(marker);
  if (
    markerIndex === -1 ||
    source.indexOf(marker, markerIndex + marker.length) !== -1 ||
    (markerIndex > 0 && source[markerIndex - 1] !== '\n')
  ) {
    return Object.freeze([]);
  }

  const afterMarker = markerIndex + marker.length;
  const followingNewline = newlineLengthAt(source, afterMarker);
  if (followingNewline === undefined) {
    return Object.freeze([]);
  }
  const headMatches = source.match(/<\/head>/gi);
  if (headMatches === null || headMatches.length !== 1) {
    return Object.freeze([]);
  }
  let headIndex = afterMarker + followingNewline;
  while (source[headIndex] === ' ' || source[headIndex] === '\t') {
    headIndex += 1;
  }
  if (source.slice(headIndex, headIndex + '</head>'.length).toLowerCase() !== '</head>') {
    return Object.freeze([]);
  }

  const afterInsertion = source.slice(afterMarker + followingNewline);
  const candidates: LoaderLineCandidate[] = [
    Object.freeze({
      insertion: 'line',
      offset: markerIndex,
      removed: source.slice(markerIndex, afterMarker + followingNewline),
      source: source.slice(0, markerIndex) + afterInsertion,
    }),
  ];
  const precedingNewline = precedingNewlineLength(source, markerIndex);
  if (precedingNewline !== undefined) {
    const offset = markerIndex - precedingNewline;
    candidates.push(
      Object.freeze({
        insertion: 'preceding-newline-line',
        offset,
        removed: source.slice(offset, afterMarker + followingNewline),
        source: source.slice(0, offset) + afterInsertion,
      }),
    );
  }
  return Object.freeze(candidates);
}

function newlineLengthAt(source: string, index: number): 1 | 2 | undefined {
  if (source[index] === '\n') return 1;
  if (source[index] === '\r' && source[index + 1] === '\n') return 2;
  return undefined;
}

function precedingNewlineLength(source: string, index: number): 1 | 2 | undefined {
  if (index === 0 || source[index - 1] !== '\n') return undefined;
  return index > 1 && source[index - 2] === '\r' ? 2 : 1;
}

function fingerprintBytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function transformConfig(
  current: readonly ProjectConfigV1[],
  preimage: SemanticConfigImage,
  postimage: SemanticConfigImage,
  ownedSubjects: readonly string[],
): readonly ProjectConfigV1[] {
  const postById = new Map(postimage.projects.map((project) => [project.projectId, project]));
  const preById = new Map(preimage.projects.map((project) => [project.projectId, project]));
  const ownedIds = new Set([...postById.keys(), ...preById.keys(), ...ownedSubjects]);
  for (const [projectId, expected] of postById) {
    const actual = current.find((project) => project.projectId === projectId);
    if (actual === undefined || !sameProject(actual, expected)) {
      throw new Error('owned config postimage changed');
    }
  }
  for (const projectId of ownedIds) {
    if (!postById.has(projectId) && current.some((project) => project.projectId === projectId)) {
      throw new Error('owned config postimage changed');
    }
  }

  const result: ProjectConfigV1[] = [];
  const emitted = new Set<string>();
  for (const project of current) {
    if (!ownedIds.has(project.projectId)) {
      result.push(project);
      continue;
    }
    const replacement = preById.get(project.projectId);
    if (replacement !== undefined) {
      result.push(replacement);
      emitted.add(project.projectId);
    }
  }
  for (const project of preimage.projects) {
    if (!emitted.has(project.projectId)) {
      result.push(project);
    }
  }
  return result;
}

function parseConfig(bytes: Uint8Array): ReturnType<typeof parseServerConfigV1> {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('owned config is not UTF-8');
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error('owned config is not JSON');
  }
  return parseServerConfigV1(json);
}

function observation(stat: {
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  dev: number | bigint;
  ino: number | bigint;
  mode: number | bigint;
}): LifecyclePathObservation {
  return Object.freeze({
    kind: stat.isFile()
      ? 'file'
      : stat.isDirectory()
        ? 'directory'
        : stat.isSymbolicLink()
          ? 'symlink'
          : 'other',
    identity: Object.freeze({
      device: decimalIdentity(stat.dev),
      inode: decimalIdentity(stat.ino),
    }),
    mode: modeBits(stat.mode),
  });
}

function decimalIdentity(value: number | bigint): string {
  if (typeof value === 'bigint') {
    return value.toString(10);
  }
  if (!Number.isSafeInteger(value)) {
    throw new Error('lifecycle file identity is not exactly representable');
  }
  return BigInt(value).toString(10);
}

function sameProjects(
  left: readonly ProjectConfigV1[],
  right: readonly ProjectConfigV1[],
): boolean {
  return (
    left.length === right.length &&
    left.every((project, index) => right[index] !== undefined && sameProject(project, right[index]))
  );
}

function sameProject(left: ProjectConfigV1, right: ProjectConfigV1): boolean {
  return (
    left.projectId === right.projectId &&
    left.root === right.root &&
    left.framework === right.framework &&
    left.tokenEnv === right.tokenEnv &&
    left.allowedOrigins.length === right.allowedOrigins.length &&
    left.allowedOrigins.every((origin, index) => origin === right.allowedOrigins[index]) &&
    sameNumberRecord(left.limits, right.limits)
  );
}

function sameNumberRecord(
  left: Readonly<Record<string, number>> | undefined,
  right: Readonly<Record<string, number>> | undefined,
): boolean {
  const leftKeys = Object.keys(left ?? {}).sort();
  const rightKeys = Object.keys(right ?? {}).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && left?.[key] === right?.[key])
  );
}

function isNotFound(error: unknown): boolean {
  return (
    error !== null && typeof error === 'object' && (error as { code?: unknown }).code === 'ENOENT'
  );
}
