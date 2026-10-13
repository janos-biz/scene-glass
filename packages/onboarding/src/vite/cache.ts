import { Buffer } from 'node:buffer';
import { lstat, mkdir, open, rmdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';

import type { FileIdentity } from '../types.js';

/** The only modes accepted for a setup-owned Vite cache. */
export const VITE_CACHE_DIRECTORY_MODE = 0o700;
export const VITE_CACHE_FILE_MODE = 0o600;
export const VITE_CACHE_PROCESS_UMASK = 0o077;
export const VITE_CACHE_MAX_FILES = 1_000;
export const VITE_CACHE_MAX_BYTES = 64 * 1024 * 1024;
export const VITE_CACHE_MAX_ENTRIES = 2_000;
export const VITE_CACHE_MAX_DEPTH = 8;
/** Maximum UTF-8 size of the internal inherited-FD provenance transport. */
export const VITE_CACHE_PROVENANCE_MAX_BYTES = 16 * 1024;
/** Canonical project-local managed-Vite cache runtime directory. */
export const VITE_CACHE_ROOT_DIRECTORY = '.scg/runtime/vite-cache';

export interface CacheOwner {
  readonly uid: number;
  readonly gid: number;
}

/** The native session brand is intentionally not exported to TypeScript callers. */
declare const cacheNativeSessionBrand: unique symbol;

/**
 * An opaque native capability for the opened cache root and its parent. Only
 * the native adapter may issue it after identity-checking both descriptors.
 */
export interface CacheNativeSession {
  readonly [cacheNativeSessionBrand]: true;
}

const viteCacheSessionBrand: unique symbol = Symbol('vite-cache-session');
const CACHE_IDENTIFIER_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const issuedViteCacheSessions = new WeakSet<object>();

/**
 * Couples persistable provenance to the live native root capability required
 * for any recursive cache operation. Sessions are module-issued; provenance
 * alone is never authority.
 */
export interface ViteCacheSession {
  readonly provenance: ViteCacheProvenance;
  readonly nativeSession: CacheNativeSession;
  readonly [viteCacheSessionBrand]: true;
}

/**
 * A native adapter-owned directory descriptor and capability. It is
 * deliberately never serialized.
 */
export interface CacheDirectoryReference {
  readonly identity: FileIdentity;
  readonly canonicalPath: string;
  readonly device: string;
  readonly owner: CacheOwner;
  readonly mode: number;
  readonly nativeSession: CacheNativeSession;
}

/**
 * Immutable facts observed from an opened cache directory. Root and parent
 * records use this shape; neither is a path-based authority.
 */
export interface CacheRootRecord {
  readonly identity: FileIdentity;
  readonly canonicalPath: string;
  readonly device: string;
  readonly owner: CacheOwner;
  readonly mode: number;
}

export interface CacheInverseMetadata {
  readonly kind: 'remove-created-vite-cache';
  readonly rootIdentity: FileIdentity;
  readonly parentIdentity: FileIdentity;
  readonly canonicalPath: string;
}

/**
 * Persistable authority record. It contains identities and immutable parent
 * facts rather than a claim that either path remains owned, so a replacement
 * at the same path is always a conflict.
 */
export interface ViteCacheProvenance {
  readonly version: 1;
  readonly installId: string;
  readonly canonicalParentPath: string;
  readonly root: CacheRootRecord;
  readonly parent: CacheRootRecord;
  readonly parentIdentity: FileIdentity;
  readonly inverse: CacheInverseMetadata;
}

export interface ViteCacheLimits {
  readonly maxEntries: number;
  readonly maxFiles: number;
  readonly maxBytes: number;
  readonly maxDepth: number;
}

export const VITE_CACHE_LIMITS: Readonly<ViteCacheLimits> = Object.freeze({
  maxEntries: VITE_CACHE_MAX_ENTRIES,
  maxFiles: VITE_CACHE_MAX_FILES,
  maxBytes: VITE_CACHE_MAX_BYTES,
  maxDepth: VITE_CACHE_MAX_DEPTH,
});
/** Rejects monitor limits outside the cache authority bounds before a writer starts. */
export function assertViteCacheLimits(limits: ViteCacheLimits): void {
  assertLimits(limits);
}

export type CacheEntryKind =
  | 'directory'
  | 'regular-file'
  | 'symlink'
  | 'socket'
  | 'fifo'
  | 'block-device'
  | 'character-device'
  | 'unknown';

/** A pathless result from an FD-bound, no-follow recursive scan. */
export interface CacheTreeEntry {
  readonly identity: FileIdentity;
  readonly parentIdentity: FileIdentity | null;
  readonly device: string;
  readonly owner: CacheOwner;
  readonly mode: number;
  readonly kind: CacheEntryKind;
  readonly depth: number;
  readonly sizeBytes: number;
  readonly linkCount: number;
  /** Set by the native traversal when a child is not contained by the opened root. */
  readonly escaped: boolean;
}

export interface CacheTreeScan {
  readonly rootIdentity: FileIdentity;
  readonly entries: readonly CacheTreeEntry[];
}

export interface CacheTreeWatcher {
  close(): Promise<void> | void;
}

export type CacheWatchEvent = 'created' | 'changed' | 'removed' | 'unknown';

export interface CacheStage {
  readonly originalRootIdentity: FileIdentity;
  readonly stagedIdentity: FileIdentity;
  readonly stagingParentIdentity: FileIdentity;
  readonly stagedCanonicalPath: string;
}

export interface CacheTerminalReceipt {
  readonly version: 1;
  readonly kind: 'vite-cache-terminal-removal';
  readonly installId: string;
  readonly canonicalPath: string;
  readonly rootIdentity: FileIdentity;
}

/**
 * Native runtime inspection boundary. Every operation resolves through the
 * root and parent FDs bound into `session`, uses O_NOFOLLOW for every child,
 * and revalidates supplied facts before and after observing state.
 */
export interface CacheTreeInspectionPort {
  scanCacheTree(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly limits: ViteCacheLimits;
  }): Promise<CacheTreeScan>;
  watchCacheTree(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly onEvent: (event: CacheWatchEvent) => void;
    readonly onFailure: () => void;
  }): Promise<CacheTreeWatcher>;
}

/**
 * A freshly opened, native-retained parent/root descriptor pair. It is valid
 * only after `reopenViteCacheSession` compares it to persisted provenance.
 */
export interface CacheOpenedSession {
  readonly nativeSession: CacheNativeSession;
  readonly root: CacheRootRecord;
  readonly parent: CacheRootRecord;
}

/**
 * Native runtime authority for an already committed cache root. The opaque
 * native session retains parent and root descriptors until explicit close.
 */
export interface CacheRuntimeFilesystemPort extends CacheTreeInspectionPort, CacheSessionClosePort {
  openCacheSession(input: {
    readonly provenance: ViteCacheProvenance;
  }): Promise<CacheOpenedSession>;
}

/** Releases a native directory/session capability retained by a filesystem port. */
export interface CacheSessionClosePort {
  closeCacheSession(input: { readonly session: CacheNativeSession }): Promise<void>;
}
/**
 * Native setup and mutation boundary. It is deliberately separate from the
 * runtime inspection port so a running Vite process cannot mint setup state.
 */
export interface CacheMutationFilesystemPort extends CacheSessionClosePort {
  openCacheParent(input: {
    readonly canonicalParentPath: string;
  }): Promise<CacheDirectoryReference>;
  /**
   * Must create a new leaf with the supplied opened parent reference, bind the
   * returned native session to both the root and that parent FD, and fail on
   * every pre-existing name, including a same-owner/same-path replacement.
   */
  createCacheRoot(input: {
    readonly parent: CacheDirectoryReference;
    readonly directoryName: string;
    readonly owner: CacheOwner;
    readonly mode: number;
  }): Promise<CacheDirectoryReference>;
  stageCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
  }): Promise<CacheStage>;
  restoreCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly stage: CacheStage;
  }): Promise<void>;
  removeStagedCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly stage: CacheStage;
    readonly receipt: CacheTerminalReceipt;
  }): Promise<void>;
  /** Rejects both an existing replacement and an identity mismatch. */
  assertCacheAbsent(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly receipt: CacheTerminalReceipt;
  }): Promise<void>;
}

export interface CacheCreatePredecision {
  readonly action: 'create-vite-cache';
  readonly installId: string;
  readonly canonicalPath: string;
  readonly parentIdentity: FileIdentity;
  readonly inverse: 'remove-created-vite-cache';
}

export interface CacheStagePredecision {
  readonly action: 'stage-vite-cache-removal';
  readonly provenance: ViteCacheProvenance;
  readonly inverse: 'restore-staged-vite-cache';
}

export interface CacheRestorePredecision {
  readonly action: 'restore-staged-vite-cache';
  readonly provenance: ViteCacheProvenance;
  readonly stage: CacheStage;
  readonly inverse: 'remove-staged-vite-cache';
}

export interface CacheTerminalRemovalPredecision {
  readonly action: 'terminal-remove-vite-cache';
  readonly provenance: ViteCacheProvenance;
  readonly receipt: CacheTerminalReceipt;
  readonly inverse: 'none';
}

export type CachePredecision =
  | CacheCreatePredecision
  | CacheStagePredecision
  | CacheRestorePredecision
  | CacheTerminalRemovalPredecision;

/**
 * The transaction implementation writes/approves its WAL predecision before
 * invoking execute, then durably records commit(result). This ordering is what
 * prevents a cache root from being created outside setup authority.
 */
export interface CacheTransactionalOperation<T, R> {
  readonly predecision: CachePredecision;
  execute(): Promise<T>;
  commit(value: T): R;
}

export interface CacheTransactionPort {
  execute<T, R>(operation: CacheTransactionalOperation<T, R>): Promise<R>;
}

export interface ViteCacheCreateInput {
  readonly installId: string;
  readonly canonicalParentPath: string;
  readonly directoryName: string;
  readonly owner: CacheOwner;
}
/**
 * Creates the setup-owned cache leaf and its persisted provenance in one
 * creation path. The caller must immediately reopen the resulting provenance
 * through the native runtime port before granting Vite any cache authority.
 */
export async function createViteCacheRootAndProvenanceArtifact(input: {
  readonly installId: string;
  readonly canonicalParentPath: string;
  readonly owner: CacheOwner;
  readonly expectedDevice: string;
}): Promise<ViteCacheProvenance> {
  assertInstallId(input.installId);
  assertDirectoryName(input.installId);
  assertOwner(input.owner);
  if (
    !isCanonicalAbsolutePath(input.canonicalParentPath) ||
    !/^(?:0|[1-9][0-9]*)$/.test(input.expectedDevice)
  ) {
    throw invalid('cache parent path is invalid');
  }

  const parent = await cacheRootRecord(
    input.canonicalParentPath,
    input.canonicalParentPath,
    input.owner,
    input.expectedDevice,
    VITE_CACHE_DIRECTORY_MODE,
  );
  const canonicalPath = canonicalChildPath(input.canonicalParentPath, input.installId);
  const provenancePath = join(input.canonicalParentPath, `${input.installId}.provenance.v1.json`);
  await mkdir(canonicalPath, { mode: VITE_CACHE_DIRECTORY_MODE });
  let artifactCreated = false;
  let committed = false;
  try {
    const root = await cacheRootRecord(
      canonicalPath,
      canonicalPath,
      input.owner,
      parent.device,
      VITE_CACHE_DIRECTORY_MODE,
    );
    const provenance = Object.freeze<ViteCacheProvenance>({
      version: 1,
      installId: input.installId,
      canonicalParentPath: input.canonicalParentPath,
      root,
      parent,
      parentIdentity: parent.identity,
      inverse: Object.freeze({
        kind: 'remove-created-vite-cache',
        rootIdentity: root.identity,
        parentIdentity: parent.identity,
        canonicalPath,
      }),
    });
    const serialized = serializeViteCacheProvenanceJson(provenance);
    const artifact = await open(provenancePath, 'wx', VITE_CACHE_FILE_MODE);
    artifactCreated = true;
    try {
      await artifact.writeFile(serialized, 'utf8');
      await artifact.sync();
    } finally {
      await artifact.close();
    }
    const artifactMetadata = await lstat(provenancePath);
    if (
      !artifactMetadata.isFile() ||
      artifactMetadata.isSymbolicLink() ||
      artifactMetadata.nlink !== 1 ||
      artifactMetadata.uid !== input.owner.uid ||
      artifactMetadata.gid !== input.owner.gid ||
      (artifactMetadata.mode & 0o7777) !== VITE_CACHE_FILE_MODE ||
      String(artifactMetadata.dev) !== parent.device
    ) {
      throw invalid('created cache provenance is invalid');
    }
    committed = true;
    return provenance;
  } finally {
    if (!committed) {
      if (artifactCreated) {
        await unlink(provenancePath);
      }
      await rmdir(canonicalPath);
    }
  }
}

async function cacheRootRecord(
  path: string,
  canonicalPath: string,
  owner: CacheOwner,
  expectedDevice: string,
  mode: number,
): Promise<CacheRootRecord> {
  const metadata = await lstat(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== owner.uid ||
    metadata.gid !== owner.gid ||
    (metadata.mode & 0o7777) !== mode ||
    String(metadata.dev) !== expectedDevice
  ) {
    throw invalid('created cache directory is invalid');
  }
  return Object.freeze({
    identity: Object.freeze({ device: String(metadata.dev), inode: String(metadata.ino) }),
    canonicalPath,
    device: String(metadata.dev),
    owner: Object.freeze({ ...owner }),
    mode,
  });
}

export interface ViteCacheTerminalRemovalInput {
  readonly session: ViteCacheSession;
  readonly receipt: CacheTerminalReceipt;
  /** Omit only for a repeated cleanup after a terminal removal has completed. */
  readonly stage?: CacheStage;
}

export interface UmaskPort {
  umask(mask?: number): number;
}

export type ViteCacheAuthorityErrorCode =
  'SCG_VITE_CACHE_CONFLICT' | 'SCG_VITE_CACHE_INVALID' | 'SCG_VITE_CACHE_LIMIT';

export type ViteCacheAuthorityCleanupOperation = 'close-native-session';

export class ViteCacheAuthorityError extends Error {
  public readonly code: ViteCacheAuthorityErrorCode;
  /** Generic cleanup operation names only; never paths or native errors. */
  public readonly cleanupFailures: readonly ViteCacheAuthorityCleanupOperation[];
  /** A later reopen retries a failed native cleanup before opening a fresh session. */
  public readonly retryable: boolean;

  public constructor(
    code: ViteCacheAuthorityErrorCode,
    message: string,
    cleanupFailures: readonly ViteCacheAuthorityCleanupOperation[] = [],
    retryable = false,
  ) {
    super(message);
    this.name = 'ViteCacheAuthorityError';
    this.code = code;
    this.cleanupFailures = Object.freeze([...cleanupFailures]);
    this.retryable = retryable;
  }
}
interface PendingViteCacheReopenCleanup {
  readonly session: CacheNativeSession;
  readonly error: ViteCacheAuthorityError;
}

interface PendingViteCacheReopenCleanupQueue {
  readonly cleanups: PendingViteCacheReopenCleanup[];
  draining: Promise<void> | undefined;
}

/**
 * Failed close handles stay private and are retried before a later operation
 * can observe fresh authority. The queue retains every failed handle without
 * replacing prior capabilities.
 */
const pendingViteCacheReopenCleanups = new WeakMap<
  CacheSessionClosePort,
  PendingViteCacheReopenCleanupQueue
>();
const viteCacheReopenTurns = new WeakMap<CacheRuntimeFilesystemPort, Promise<void>>();

/**
 * This belongs in the dedicated managed-Vite child bootstrap, before its first
 * dynamic import of Vite or any cache writer. It must not be reset while that
 * child can still write cache material.
 */
export function establishDedicatedViteCacheProcessUmask(processPort: UmaskPort): void {
  processPort.umask(VITE_CACHE_PROCESS_UMASK);
}

export function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}
/**
 * Returns an immutable, validated snapshot before a caller can hand cache
 * authority to a side-effecting native port.
 */
export function snapshotViteCacheSession(session: ViteCacheSession): ViteCacheSession {
  if (!issuedViteCacheSessions.has(session)) {
    throw invalid('cache session was not issued by this module');
  }
  return issueViteCacheSession(session.provenance, session.nativeSession);
}
/**
 * Atomically reopens persisted setup provenance through the native FD-bound
 * port. A session is issued only after every observed root and parent fact is
 * an exact match; failed post-open validation always releases the handle.
 * A failed release is retained privately and retried before a later reopen.
 */
export async function reopenViteCacheSession(input: {
  readonly filesystem: CacheRuntimeFilesystemPort;
  readonly provenance: ViteCacheProvenance;
}): Promise<ViteCacheSession> {
  const filesystem = input.filesystem;
  const suppliedProvenance = input.provenance;
  assertProvenance(suppliedProvenance);
  const provenance = freezeProvenance(suppliedProvenance);
  const release = await acquireViteCacheReopenTurn(filesystem);
  try {
    await retryPendingViteCacheReopenCleanup(filesystem);
    const opened = await filesystem.openCacheSession({ provenance });
    try {
      assertOpenedSession(provenance, opened);
      return issueViteCacheSession(provenance, opened.nativeSession);
    } catch (error: unknown) {
      try {
        await filesystem.closeCacheSession({ session: opened.nativeSession });
      } catch {
        const cleanupError = withReopenCleanupFailure(error);
        enqueuePendingViteCacheReopenCleanup(filesystem, {
          session: opened.nativeSession,
          error: cleanupError,
        });
        throw cleanupError;
      }
      throw error;
    }
  } finally {
    release();
  }
}
/**
 * Serializes only the exact persisted-provenance shape accepted by the
 * inherited-FD transport. It never opens or observes the filesystem.
 */
export function serializeViteCacheProvenanceJson(provenance: ViteCacheProvenance): string {
  assertCanonicalProvenanceShape(provenance);
  const serialized = `${JSON.stringify(
    {
      version: provenance.version,
      installId: provenance.installId,
      canonicalParentPath: provenance.canonicalParentPath,
      root: serializeCacheRootRecord(provenance.root),
      parent: serializeCacheRootRecord(provenance.parent),
      parentIdentity: serializeIdentity(provenance.parentIdentity),
      inverse: {
        kind: provenance.inverse.kind,
        rootIdentity: serializeIdentity(provenance.inverse.rootIdentity),
        parentIdentity: serializeIdentity(provenance.inverse.parentIdentity),
        canonicalPath: provenance.inverse.canonicalPath,
      },
    },
    null,
    2,
  )}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > VITE_CACHE_PROVENANCE_MAX_BYTES) {
    throw invalid('cache provenance transport is too large');
  }
  return serialized;
}

/**
 * Parses only canonical, bounded JSON emitted by
 * `serializeViteCacheProvenanceJson`. It is a pure codec: current filesystem
 * facts cannot authorize, repair, or replace persisted provenance.
 */
export function parseViteCacheProvenanceJson(serialized: string): ViteCacheProvenance {
  if (
    typeof serialized !== 'string' ||
    Buffer.byteLength(serialized, 'utf8') > VITE_CACHE_PROVENANCE_MAX_BYTES
  ) {
    throw invalid('cache provenance transport is invalid');
  }

  let candidate: unknown;
  try {
    candidate = JSON.parse(serialized);
  } catch {
    throw invalid('cache provenance transport is invalid');
  }
  assertCanonicalProvenanceShape(candidate);
  const provenance = freezeProvenance(candidate);
  if (serializeViteCacheProvenanceJson(provenance) !== serialized) {
    throw invalid('cache provenance transport is not canonical');
  }
  return provenance;
}

function issueViteCacheSession(
  provenance: ViteCacheProvenance,
  nativeSession: CacheNativeSession,
): ViteCacheSession {
  assertProvenance(provenance);
  assertNativeSession(nativeSession);
  const session = Object.freeze({
    provenance: freezeProvenance(provenance),
    nativeSession,
    [viteCacheSessionBrand]: true,
  }) as ViteCacheSession;
  issuedViteCacheSessions.add(session);
  return session;
}

export class ViteCacheAuthority {
  readonly #filesystem: CacheMutationFilesystemPort;
  readonly #transactions: CacheTransactionPort;

  public constructor(input: {
    readonly filesystem: CacheMutationFilesystemPort;
    readonly transactions: CacheTransactionPort;
  }) {
    this.#filesystem = input.filesystem;
    this.#transactions = input.transactions;
  }

  /**
   * Creates a root only inside the transaction callback. A transaction port
   * must persist the predecision before it is allowed to invoke that callback.
   */
  public async create(input: ViteCacheCreateInput): Promise<ViteCacheSession> {
    assertInstallId(input.installId);
    assertDirectoryName(input.directoryName);
    assertOwner(input.owner);
    if (!isCanonicalAbsolutePath(input.canonicalParentPath)) {
      throw invalid('cache parent path is invalid');
    }
    const installId = input.installId;
    const directoryName = input.directoryName;
    const canonicalParentPath = input.canonicalParentPath;
    const owner = Object.freeze({ ...input.owner });

    await retryPendingViteCacheReopenCleanup(this.#filesystem);
    const openedParent = await this.#filesystem.openCacheParent({
      canonicalParentPath,
    });
    let parentSession: CacheNativeSession | undefined;
    try {
      parentSession = openedParent.nativeSession;
      assertNativeSession(parentSession);
      assertOpenedParent(openedParent, canonicalParentPath, owner);
      const parent = freezeDirectoryReference(openedParent);
      const canonicalPath = canonicalChildPath(canonicalParentPath, directoryName);

      return await this.#transactions.execute({
        predecision: {
          action: 'create-vite-cache',
          installId,
          canonicalPath,
          parentIdentity: parent.identity,
          inverse: 'remove-created-vite-cache',
        },
        execute: async () => {
          const root = await this.#filesystem.createCacheRoot({
            parent,
            directoryName,
            owner,
            mode: VITE_CACHE_DIRECTORY_MODE,
          });
          assertCreatedRoot(root, parent, canonicalPath, owner);
          return root;
        },
        commit: (root) =>
          issueViteCacheSession(
            {
              version: 1,
              installId,
              canonicalParentPath,
              root: {
                identity: root.identity,
                canonicalPath: root.canonicalPath,
                device: root.device,
                owner: root.owner,
                mode: VITE_CACHE_DIRECTORY_MODE,
              },
              parent: {
                identity: parent.identity,
                canonicalPath: parent.canonicalPath,
                device: parent.device,
                owner: parent.owner,
                mode: parent.mode,
              },
              parentIdentity: parent.identity,
              inverse: {
                kind: 'remove-created-vite-cache',
                rootIdentity: root.identity,
                parentIdentity: parent.identity,
                canonicalPath: root.canonicalPath,
              },
            },
            root.nativeSession,
          ),
      });
    } catch (error: unknown) {
      if (parentSession === undefined) {
        throw error;
      }
      try {
        await this.#filesystem.closeCacheSession({ session: parentSession });
      } catch {
        const cleanupError = withReopenCleanupFailure(error);
        enqueuePendingViteCacheReopenCleanup(this.#filesystem, {
          session: parentSession,
          error: cleanupError,
        });
        throw cleanupError;
      }
      throw error;
    }
  }

  /** A predecision-safe, reversible stage; it never deletes a live root. */
  public async stageForRemoval(session: ViteCacheSession): Promise<CacheStage> {
    const active = snapshotViteCacheSession(session);
    const record = active.provenance;
    return this.#transactions.execute({
      predecision: {
        action: 'stage-vite-cache-removal',
        provenance: record,
        inverse: 'restore-staged-vite-cache',
      },
      execute: async () => {
        const stage = await this.#filesystem.stageCacheRoot({
          session: active.nativeSession,
          provenance: record,
        });
        assertStage(record, stage);
        return stage;
      },
      commit: (stage) => freezeStage(stage),
    });
  }

  /** Restores only the exact staged root through the native FD-bound port. */
  public async restoreStaged(session: ViteCacheSession, stage: CacheStage): Promise<void> {
    const active = snapshotViteCacheSession(session);
    const record = active.provenance;
    const staged = freezeStage(stage);
    assertStage(record, staged);
    await this.#transactions.execute({
      predecision: {
        action: 'restore-staged-vite-cache',
        provenance: record,
        stage: staged,
        inverse: 'remove-staged-vite-cache',
      },
      execute: () =>
        this.#filesystem.restoreCacheRoot({
          session: active.nativeSession,
          provenance: record,
          stage: staged,
        }),
      commit: () => undefined,
    });
  }

  /**
   * Forward terminal removal. The first call removes the already staged tree;
   * later calls are successful only when the original location remains absent.
   * In both cases the supplied terminal receipt is committed by the WAL port.
   */
  public async finalizeTerminalRemoval(
    input: ViteCacheTerminalRemovalInput,
  ): Promise<CacheTerminalReceipt> {
    const active = snapshotViteCacheSession(input.session);
    const provenance = active.provenance;
    const receipt = freezeReceipt(input.receipt);
    const stage = input.stage === undefined ? undefined : freezeStage(input.stage);
    assertTerminalReceipt(provenance, receipt);
    if (stage !== undefined) {
      assertStage(provenance, stage);
    }

    return this.#transactions.execute({
      predecision: {
        action: 'terminal-remove-vite-cache',
        provenance,
        receipt,
        inverse: 'none',
      },
      execute: async () => {
        if (stage === undefined) {
          await this.#filesystem.assertCacheAbsent({
            session: active.nativeSession,
            provenance,
            receipt,
          });
          return;
        }
        await this.#filesystem.removeStagedCacheRoot({
          session: active.nativeSession,
          provenance,
          stage,
          receipt,
        });
      },
      commit: () => freezeReceipt(receipt),
    });
  }

  public createTerminalReceipt(session: ViteCacheSession): CacheTerminalReceipt {
    const record = snapshotViteCacheSession(session).provenance;
    return freezeReceipt({
      version: 1,
      kind: 'vite-cache-terminal-removal',
      installId: record.installId,
      canonicalPath: record.root.canonicalPath,
      rootIdentity: record.root.identity,
    });
  }
}

/** Validates reports produced by the native FD-bound scanner. */
export function assertSafeViteCacheTree(
  provenance: ViteCacheProvenance,
  scan: CacheTreeScan,
  limits: ViteCacheLimits = VITE_CACHE_LIMITS,
): void {
  assertProvenance(provenance);
  assertLimits(limits);
  const observed = snapshotViteCacheTreeScan(scan, limits);
  if (!sameFileIdentity(observed.rootIdentity, provenance.root.identity)) {
    throw conflict('cache root identity changed');
  }

  let entryCount = 0;
  let fileCount = 0;
  let aggregateBytes = 0;
  let rootCount = 0;
  const identities = new Set<string>();
  const directories = new Map<string, CacheTreeEntry>();
  for (const entry of observed.entries) {
    entryCount += 1;
    if (entryCount > limits.maxEntries) {
      throw limit('cache entry limit exceeded');
    }
    if (
      entry.escaped ||
      !Number.isSafeInteger(entry.depth) ||
      entry.depth < 0 ||
      entry.depth > limits.maxDepth
    ) {
      throw conflict('cache traversal escaped its authority');
    }
    if (
      !isFileIdentity(entry.identity) ||
      (entry.parentIdentity !== null && !isFileIdentity(entry.parentIdentity)) ||
      entry.identity.device !== entry.device
    ) {
      throw invalid('cache entry identity is invalid');
    }
    if (entry.device !== provenance.root.device) {
      throw conflict('cache entry crossed devices');
    }
    if (!sameOwner(entry.owner, provenance.root.owner)) {
      throw conflict('cache entry owner changed');
    }
    const key = fileIdentityKey(entry.identity);
    if (identities.has(key)) {
      throw conflict('cache traversal contains duplicate identities');
    }
    identities.add(key);
    if (entry.depth === 0) {
      rootCount += 1;
      if (
        entry.kind !== 'directory' ||
        !sameFileIdentity(entry.identity, provenance.root.identity) ||
        entry.parentIdentity === null ||
        !sameFileIdentity(entry.parentIdentity, provenance.parentIdentity)
      ) {
        throw conflict('cache root was replaced');
      }
    }

    if (entry.kind === 'directory') {
      if (entry.mode !== VITE_CACHE_DIRECTORY_MODE) {
        throw invalid('cache directory mode is not 0700');
      }
      directories.set(key, entry);
      continue;
    }
    if (entry.kind !== 'regular-file') {
      throw invalid('cache contains a forbidden entry type');
    }
    if (entry.mode !== VITE_CACHE_FILE_MODE || entry.linkCount !== 1) {
      throw invalid('cache file mode or link count is unsafe');
    }
    if (!Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes < 0) {
      throw invalid('cache file size is invalid');
    }
    fileCount += 1;
    aggregateBytes += entry.sizeBytes;
    if (!Number.isSafeInteger(aggregateBytes) || aggregateBytes > limits.maxBytes) {
      throw limit('cache aggregate byte limit exceeded');
    }
    if (fileCount > limits.maxFiles) {
      throw limit('cache file limit exceeded');
    }
  }
  if (rootCount !== 1) {
    throw conflict('cache root is absent or ambiguous');
  }
  for (const entry of observed.entries) {
    if (entry.depth === 0) {
      continue;
    }
    if (entry.parentIdentity === null) {
      throw conflict('cache entry parent identity is absent');
    }
    const parent = directories.get(fileIdentityKey(entry.parentIdentity));
    if (parent === undefined || parent.depth !== entry.depth - 1) {
      throw conflict('cache entry parent identity changed');
    }
  }
}

function snapshotViteCacheTreeScan(scan: unknown, limits: ViteCacheLimits): CacheTreeScan {
  const [rootIdentity, entries] = readExactCacheDataRecord(
    scan,
    ['rootIdentity', 'entries'],
    'cache tree scan is invalid',
  );
  return Object.freeze({
    rootIdentity: snapshotCacheIdentity(rootIdentity),
    entries: snapshotCacheTreeEntries(entries, limits.maxEntries),
  });
}

function snapshotCacheTreeEntries(value: unknown, maxEntries: number): readonly CacheTreeEntry[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      throw invalid('cache tree scan is invalid');
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (
      lengthDescriptor === undefined ||
      !('value' in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0
    ) {
      throw invalid('cache tree scan is invalid');
    }
    if (lengthDescriptor.value > maxEntries) {
      throw limit('cache entry limit exceeded');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length !== lengthDescriptor.value + 1 || keys[keys.length - 1] !== 'length') {
      throw invalid('cache tree scan is invalid');
    }

    const entries: CacheTreeEntry[] = [];
    for (let index = 0; index < lengthDescriptor.value; index += 1) {
      if (keys[index] !== String(index)) {
        throw invalid('cache tree scan is invalid');
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
        throw invalid('cache tree scan is invalid');
      }
      entries.push(snapshotCacheTreeEntry(descriptor.value));
    }
    return Object.freeze(entries);
  } catch (error: unknown) {
    if (error instanceof ViteCacheAuthorityError) {
      throw error;
    }
    throw invalid('cache tree scan is invalid');
  }
}

function snapshotCacheTreeEntry(value: unknown): CacheTreeEntry {
  const [
    identity,
    parentIdentity,
    device,
    owner,
    mode,
    kind,
    depth,
    sizeBytes,
    linkCount,
    escaped,
  ] = readExactCacheDataRecord(
    value,
    [
      'identity',
      'parentIdentity',
      'device',
      'owner',
      'mode',
      'kind',
      'depth',
      'sizeBytes',
      'linkCount',
      'escaped',
    ],
    'cache tree entry is invalid',
  );
  if (
    typeof device !== 'string' ||
    typeof mode !== 'number' ||
    typeof kind !== 'string' ||
    typeof depth !== 'number' ||
    typeof sizeBytes !== 'number' ||
    typeof linkCount !== 'number' ||
    typeof escaped !== 'boolean'
  ) {
    throw invalid('cache tree entry is invalid');
  }
  return Object.freeze({
    identity: snapshotCacheIdentity(identity),
    parentIdentity: parentIdentity === null ? null : snapshotCacheIdentity(parentIdentity),
    device,
    owner: snapshotCacheOwner(owner),
    mode,
    kind: kind as CacheEntryKind,
    depth,
    sizeBytes,
    linkCount,
    escaped,
  });
}

function snapshotCacheIdentity(value: unknown): FileIdentity {
  const [device, inode] = readExactCacheDataRecord(
    value,
    ['device', 'inode'],
    'cache entry identity is invalid',
  );
  const identity = { device, inode };
  if (!isFileIdentity(identity)) {
    throw invalid('cache entry identity is invalid');
  }
  return freezeIdentity(identity);
}

function snapshotCacheOwner(value: unknown): CacheOwner {
  const [uid, gid] = readExactCacheDataRecord(
    value,
    ['uid', 'gid'],
    'cache entry owner is invalid',
  );
  const owner = { uid, gid };
  if (!isCacheOwner(owner)) {
    throw invalid('cache entry owner is invalid');
  }
  return Object.freeze(owner);
}

function readExactCacheDataRecord(
  value: unknown,
  keys: readonly string[],
  message: string,
): readonly unknown[] {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    ) {
      throw invalid(message);
    }
    const actual = Reflect.ownKeys(value);
    if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
      throw invalid(message);
    }
    return keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
        throw invalid(message);
      }
      return descriptor.value;
    });
  } catch (error: unknown) {
    if (error instanceof ViteCacheAuthorityError) {
      throw error;
    }
    throw invalid(message);
  }
}
function assertCanonicalProvenanceShape(value: unknown): asserts value is ViteCacheProvenance {
  if (
    !isExactRecord(value, [
      'version',
      'installId',
      'canonicalParentPath',
      'root',
      'parent',
      'parentIdentity',
      'inverse',
    ])
  ) {
    throw invalid('cache provenance transport is invalid');
  }
  const provenance = value as unknown as ViteCacheProvenance;
  if (
    !isExactCacheRootRecord(provenance.root) ||
    !isExactCacheRootRecord(provenance.parent) ||
    !isExactIdentity(provenance.parentIdentity) ||
    !isExactInverseMetadata(provenance.inverse)
  ) {
    throw invalid('cache provenance transport is invalid');
  }
  assertProvenance(provenance);
}

function isExactCacheRootRecord(value: unknown): value is CacheRootRecord {
  return (
    isExactRecord(value, ['identity', 'canonicalPath', 'device', 'owner', 'mode']) &&
    isExactIdentity(value.identity) &&
    isExactOwner(value.owner)
  );
}

function isExactInverseMetadata(value: unknown): value is CacheInverseMetadata {
  return (
    isExactRecord(value, ['kind', 'rootIdentity', 'parentIdentity', 'canonicalPath']) &&
    isExactIdentity(value.rootIdentity) &&
    isExactIdentity(value.parentIdentity)
  );
}

function isExactOwner(value: unknown): value is CacheOwner {
  return isExactRecord(value, ['uid', 'gid']) && isCacheOwner(value);
}

function isExactIdentity(value: unknown): value is FileIdentity {
  return isExactRecord(value, ['device', 'inode']) && isFileIdentity(value);
}

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    return false;
  }
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function serializeCacheRootRecord(record: CacheRootRecord): CacheRootRecord {
  return {
    identity: serializeIdentity(record.identity),
    canonicalPath: record.canonicalPath,
    device: record.device,
    owner: { uid: record.owner.uid, gid: record.owner.gid },
    mode: record.mode,
  };
}

function serializeIdentity(identity: FileIdentity): FileIdentity {
  return { device: identity.device, inode: identity.inode };
}
function assertOpenedSession(provenance: ViteCacheProvenance, opened: CacheOpenedSession): void {
  if (
    typeof opened !== 'object' ||
    opened === null ||
    !isCacheRootRecord(opened.root) ||
    !isCacheRootRecord(opened.parent)
  ) {
    throw invalid('opened cache session is invalid');
  }
  assertNativeSession(opened.nativeSession);
  if (
    !sameCacheRootRecord(opened.root, provenance.root) ||
    !sameCacheRootRecord(opened.parent, provenance.parent)
  ) {
    throw conflict('opened cache session does not match persisted provenance');
  }
}

function sameCacheRootRecord(left: CacheRootRecord, right: CacheRootRecord): boolean {
  return (
    sameFileIdentity(left.identity, right.identity) &&
    left.canonicalPath === right.canonicalPath &&
    left.device === right.device &&
    sameOwner(left.owner, right.owner) &&
    left.mode === right.mode
  );
}
function assertOpenedParent(
  parent: CacheDirectoryReference,
  expectedPath: string,
  expectedOwner: CacheOwner,
): void {
  if (
    !isFileIdentity(parent.identity) ||
    parent.device !== parent.identity.device ||
    parent.canonicalPath !== expectedPath ||
    !isCanonicalAbsolutePath(parent.canonicalPath)
  ) {
    throw conflict('cache parent path or device changed during creation');
  }
  assertOwner(parent.owner);
  assertNativeSession(parent.nativeSession);
  if (!sameOwner(parent.owner, expectedOwner) || parent.mode !== VITE_CACHE_DIRECTORY_MODE) {
    throw invalid('cache parent owner or mode is unsafe');
  }
}

function assertCreatedRoot(
  root: CacheDirectoryReference,
  parent: CacheDirectoryReference,
  expectedPath: string,
  expectedOwner: CacheOwner,
): void {
  if (
    !isFileIdentity(root.identity) ||
    !isFileIdentity(parent.identity) ||
    root.device !== root.identity.device ||
    parent.device !== parent.identity.device ||
    root.canonicalPath !== expectedPath ||
    root.device !== parent.device
  ) {
    throw conflict('cache root path or device changed during creation');
  }
  assertNativeSession(root.nativeSession);
  assertOwner(root.owner);
  if (!sameOwner(root.owner, expectedOwner) || root.mode !== VITE_CACHE_DIRECTORY_MODE) {
    throw invalid('cache root owner or mode is unsafe');
  }
  if (sameFileIdentity(root.identity, parent.identity)) {
    throw conflict('cache root cannot be its parent');
  }
}

function assertProvenance(provenance: ViteCacheProvenance): void {
  if (
    typeof provenance !== 'object' ||
    provenance === null ||
    typeof provenance.installId !== 'string' ||
    typeof provenance.canonicalParentPath !== 'string' ||
    !isCacheRootRecord(provenance.root) ||
    !isCacheRootRecord(provenance.parent) ||
    !isFileIdentity(provenance.parentIdentity) ||
    !isCacheInverseMetadata(provenance.inverse)
  ) {
    throw invalid('cache provenance is invalid');
  }
  assertInstallId(provenance.installId);
  assertOwner(provenance.root.owner);
  assertOwner(provenance.parent.owner);
  if (
    provenance.version !== 1 ||
    !isCanonicalAbsolutePath(provenance.canonicalParentPath) ||
    !isCanonicalAbsolutePath(provenance.root.canonicalPath) ||
    !isCanonicalChildPath(provenance.canonicalParentPath, provenance.root.canonicalPath) ||
    provenance.parent.canonicalPath !== provenance.canonicalParentPath ||
    sameFileIdentity(provenance.root.identity, provenance.parentIdentity) ||
    !sameFileIdentity(provenance.parent.identity, provenance.parentIdentity) ||
    provenance.root.device !== provenance.root.identity.device ||
    provenance.parent.device !== provenance.parent.identity.device ||
    provenance.parent.device !== provenance.root.device ||
    !sameOwner(provenance.parent.owner, provenance.root.owner) ||
    provenance.root.mode !== VITE_CACHE_DIRECTORY_MODE ||
    provenance.parent.mode !== VITE_CACHE_DIRECTORY_MODE ||
    provenance.inverse.kind !== 'remove-created-vite-cache' ||
    provenance.inverse.canonicalPath !== provenance.root.canonicalPath ||
    !sameFileIdentity(provenance.inverse.rootIdentity, provenance.root.identity) ||
    !sameFileIdentity(provenance.inverse.parentIdentity, provenance.parentIdentity)
  ) {
    throw invalid('cache provenance is invalid');
  }
}

function assertStage(provenance: ViteCacheProvenance, stage: CacheStage): void {
  if (
    !sameFileIdentity(stage.originalRootIdentity, provenance.root.identity) ||
    !sameFileIdentity(stage.stagedIdentity, provenance.root.identity) ||
    stage.stagedIdentity.device !== provenance.root.device ||
    !sameFileIdentity(stage.stagingParentIdentity, provenance.parentIdentity) ||
    !isCanonicalAbsolutePath(stage.stagedCanonicalPath) ||
    !isCanonicalChildPath(provenance.canonicalParentPath, stage.stagedCanonicalPath) ||
    stage.stagedCanonicalPath === provenance.root.canonicalPath
  ) {
    throw conflict('cache stage identity changed');
  }
}

function assertTerminalReceipt(
  provenance: ViteCacheProvenance,
  receipt: CacheTerminalReceipt,
): void {
  if (
    receipt.version !== 1 ||
    receipt.kind !== 'vite-cache-terminal-removal' ||
    receipt.installId !== provenance.installId ||
    receipt.canonicalPath !== provenance.root.canonicalPath ||
    !sameFileIdentity(receipt.rootIdentity, provenance.root.identity)
  ) {
    throw invalid('cache terminal receipt does not match provenance');
  }
}

function assertLimits(limits: ViteCacheLimits): void {
  if (
    !Number.isSafeInteger(limits.maxEntries) ||
    !Number.isSafeInteger(limits.maxFiles) ||
    !Number.isSafeInteger(limits.maxBytes) ||
    !Number.isSafeInteger(limits.maxDepth) ||
    limits.maxEntries < 1 ||
    limits.maxEntries > VITE_CACHE_MAX_ENTRIES ||
    limits.maxFiles < 1 ||
    limits.maxFiles > VITE_CACHE_MAX_FILES ||
    limits.maxBytes < 1 ||
    limits.maxBytes > VITE_CACHE_MAX_BYTES ||
    limits.maxDepth < 0 ||
    limits.maxDepth > VITE_CACHE_MAX_DEPTH
  ) {
    throw invalid('cache limits are outside the authority bounds');
  }
}

function assertInstallId(installId: string): void {
  if (typeof installId !== 'string' || !CACHE_IDENTIFIER_PATTERN.test(installId)) {
    throw invalid('cache install identifier is invalid');
  }
}

function assertDirectoryName(directoryName: string): void {
  if (typeof directoryName !== 'string' || !CACHE_IDENTIFIER_PATTERN.test(directoryName)) {
    throw invalid('cache directory name is invalid');
  }
}

function assertOwner(owner: unknown): asserts owner is CacheOwner {
  if (!isCacheOwner(owner)) {
    throw invalid('cache owner is invalid');
  }
}

function isCacheOwner(owner: unknown): owner is CacheOwner {
  if (typeof owner !== 'object' || owner === null) {
    return false;
  }
  const candidate = owner as Record<string, unknown>;
  return (
    typeof candidate.uid === 'number' &&
    Number.isSafeInteger(candidate.uid) &&
    candidate.uid >= 0 &&
    typeof candidate.gid === 'number' &&
    Number.isSafeInteger(candidate.gid) &&
    candidate.gid >= 0
  );
}

function canonicalChildPath(parent: string, child: string): string {
  if (!isCanonicalAbsolutePath(parent)) {
    throw invalid('cache parent path is invalid');
  }
  return `${parent === '/' ? '' : parent}/${child}`;
}
function isCanonicalChildPath(parent: string, child: string): boolean {
  if (!isCanonicalAbsolutePath(parent) || !isCanonicalAbsolutePath(child)) {
    return false;
  }
  const prefix = parent === '/' ? '/' : `${parent}/`;
  const suffix = child.slice(prefix.length);
  return child.startsWith(prefix) && suffix.length > 0 && !suffix.includes('/');
}

function assertNativeSession(session: unknown): asserts session is CacheNativeSession {
  if ((typeof session !== 'object' || session === null) && typeof session !== 'function') {
    throw invalid('cache native session is invalid');
  }
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !value.startsWith('/') ||
    value.includes('\u0000')
  ) {
    return false;
  }
  return (
    value === '/' ||
    value
      .split('/')
      .slice(1)
      .every((component) => component.length > 0 && component !== '.' && component !== '..')
  );
}
function sameOwner(left: CacheOwner, right: CacheOwner): boolean {
  return left.uid === right.uid && left.gid === right.gid;
}
function fileIdentityKey(identity: FileIdentity): string {
  return `${identity.device}:${identity.inode}`;
}
function isFileIdentity(identity: unknown): identity is FileIdentity {
  if (typeof identity !== 'object' || identity === null) {
    return false;
  }
  const candidate = identity as Partial<FileIdentity>;
  return (
    typeof candidate.device === 'string' &&
    typeof candidate.inode === 'string' &&
    /^(?:0|[1-9][0-9]*)$/.test(candidate.device) &&
    /^(?:0|[1-9][0-9]*)$/.test(candidate.inode)
  );
}

function isCacheRootRecord(record: unknown): record is CacheRootRecord {
  if (typeof record !== 'object' || record === null) {
    return false;
  }
  const candidate = record as Partial<CacheRootRecord>;
  return (
    isFileIdentity(candidate.identity) &&
    typeof candidate.canonicalPath === 'string' &&
    typeof candidate.device === 'string' &&
    isCacheOwner(candidate.owner) &&
    typeof candidate.mode === 'number'
  );
}

function isCacheInverseMetadata(metadata: unknown): metadata is CacheInverseMetadata {
  if (typeof metadata !== 'object' || metadata === null) {
    return false;
  }
  const candidate = metadata as Partial<CacheInverseMetadata>;
  return (
    candidate.kind === 'remove-created-vite-cache' &&
    isFileIdentity(candidate.rootIdentity) &&
    isFileIdentity(candidate.parentIdentity) &&
    typeof candidate.canonicalPath === 'string'
  );
}

function freezeProvenance(provenance: ViteCacheProvenance): ViteCacheProvenance {
  return Object.freeze({
    ...provenance,
    parentIdentity: freezeIdentity(provenance.parentIdentity),
    root: freezeCacheRootRecord(provenance.root),
    parent: freezeCacheRootRecord(provenance.parent),
    inverse: Object.freeze({
      ...provenance.inverse,
      rootIdentity: freezeIdentity(provenance.inverse.rootIdentity),
      parentIdentity: freezeIdentity(provenance.inverse.parentIdentity),
    }),
  });
}

function freezeCacheRootRecord(record: CacheRootRecord): CacheRootRecord {
  return Object.freeze({
    ...record,
    identity: freezeIdentity(record.identity),
    owner: Object.freeze({ ...record.owner }),
  });
}

function freezeDirectoryReference(reference: CacheDirectoryReference): CacheDirectoryReference {
  return Object.freeze({
    ...reference,
    identity: freezeIdentity(reference.identity),
    owner: Object.freeze({ ...reference.owner }),
  });
}

function freezeStage(stage: CacheStage): CacheStage {
  return Object.freeze({
    ...stage,
    originalRootIdentity: freezeIdentity(stage.originalRootIdentity),
    stagedIdentity: freezeIdentity(stage.stagedIdentity),
    stagingParentIdentity: freezeIdentity(stage.stagingParentIdentity),
  });
}

function freezeReceipt(receipt: CacheTerminalReceipt): CacheTerminalReceipt {
  return Object.freeze({ ...receipt, rootIdentity: freezeIdentity(receipt.rootIdentity) });
}

function freezeIdentity(identity: FileIdentity): FileIdentity {
  return Object.freeze({ device: identity.device, inode: identity.inode });
}

function enqueuePendingViteCacheReopenCleanup(
  filesystem: CacheSessionClosePort,
  cleanup: PendingViteCacheReopenCleanup,
): void {
  let queue = pendingViteCacheReopenCleanups.get(filesystem);
  if (queue === undefined) {
    queue = { cleanups: [], draining: undefined };
    pendingViteCacheReopenCleanups.set(filesystem, queue);
  }
  queue.cleanups.push(cleanup);
}
async function acquireViteCacheReopenTurn(
  filesystem: CacheRuntimeFilesystemPort,
): Promise<() => void> {
  const previous = viteCacheReopenTurns.get(filesystem);
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  viteCacheReopenTurns.set(filesystem, current);
  if (previous !== undefined) {
    await previous;
  }
  return () => {
    release();
    if (viteCacheReopenTurns.get(filesystem) === current) {
      viteCacheReopenTurns.delete(filesystem);
    }
  };
}

async function retryPendingViteCacheReopenCleanup(
  filesystem: CacheSessionClosePort,
): Promise<void> {
  const queue = pendingViteCacheReopenCleanups.get(filesystem);
  if (queue === undefined) {
    return;
  }

  const active = queue.draining;
  if (active !== undefined) {
    return active;
  }

  const draining = (async (): Promise<void> => {
    for (;;) {
      const pending = queue.cleanups[0];
      if (pending === undefined) {
        if (pendingViteCacheReopenCleanups.get(filesystem) === queue) {
          pendingViteCacheReopenCleanups.delete(filesystem);
        }
        return;
      }
      try {
        await filesystem.closeCacheSession({ session: pending.session });
      } catch {
        throw new ViteCacheAuthorityError(
          pending.error.code,
          pending.error.message,
          ['close-native-session'],
          true,
        );
      }
      queue.cleanups.shift();
    }
  })();
  queue.draining = draining;
  void draining
    .finally(() => {
      if (queue.draining === draining) {
        queue.draining = undefined;
      }
    })
    .catch(() => undefined);
  return draining;
}
function withReopenCleanupFailure(error: unknown): ViteCacheAuthorityError {
  if (error instanceof ViteCacheAuthorityError) {
    return new ViteCacheAuthorityError(error.code, error.message, ['close-native-session'], true);
  }
  return new ViteCacheAuthorityError(
    'SCG_VITE_CACHE_INVALID',
    'opened cache session is invalid',
    ['close-native-session'],
    true,
  );
}
function conflict(message: string): ViteCacheAuthorityError {
  return new ViteCacheAuthorityError('SCG_VITE_CACHE_CONFLICT', message);
}

function invalid(message: string): ViteCacheAuthorityError {
  return new ViteCacheAuthorityError('SCG_VITE_CACHE_INVALID', message);
}

function limit(message: string): ViteCacheAuthorityError {
  return new ViteCacheAuthorityError('SCG_VITE_CACHE_LIMIT', message);
}
