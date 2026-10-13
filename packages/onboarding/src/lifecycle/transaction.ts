import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';

import {
  finalizeSetupManifestV1,
  parseLifecycleReceiptJsonV1,
  parseSetupManifestJsonV1,
  parseSetupManifestV1,
  parseWalRecordJson,
  serializeLifecycleReceiptV1,
  serializeSetupManifestV1,
  serializeWalRecordV2,
  validateFinalizedSetupProvenance,
  type UninstallPreflight,
} from './provenance.js';
import type {
  LifecycleId,
  RemoveConfigHunksInverseOperation,
  RestoreConfigInverseOperation,
  RestoreCredentialAuthorityRegistryEntryInverseOperation,
  RestoreOwnedFileInverseOperation,
  SemanticCredentialAuthorityRegistryImage,
  SetupManifestV1,
  WalCreationIntentV2,
  WalCredentialMutationV2,
  WalFileIdentityV2,
  WalMutationV2,
  WalOrdinaryMutationV2,
  WalPreimageV2,
  WalRecordV2,
} from './types.js';
import {
  parseCredentialAuthorityRegistryJsonV1,
  serializeCredentialAuthorityRegistryV1,
} from '../credential-authority.js';

export interface LifecycleFileIdentity {
  readonly device: string;
  readonly inode: string;
}

export type LifecyclePathKind = 'file' | 'directory' | 'symlink' | 'other';

/** A no-follow observation. Identities are opaque and must only be compared. */
export interface LifecyclePathObservation {
  readonly kind: LifecyclePathKind;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}
type LifecycleRegularFileObservation = LifecyclePathObservation & { readonly kind: 'file' };
type LifecycleDirectoryObservation = LifecyclePathObservation & { readonly kind: 'directory' };
type OrdinaryWalPreimageV2 = Exclude<WalPreimageV2, { readonly kind: 'credential' | 'directory' }>;
declare const lifecycleWalSnapshotAuthorityBrand: unique symbol;

export interface LifecycleWalSnapshotAuthority {
  readonly [lifecycleWalSnapshotAuthorityBrand]: never;
}

export interface LifecycleFileSnapshot {
  readonly observation: LifecyclePathObservation;
  readonly bytes: Uint8Array;
}

/**
 * Exact native read authority for the current WAL inode. It is single-session
 * opaque capability, not a serializable WAL field.
 */
export interface LifecycleWalFileSnapshot extends LifecycleFileSnapshot {
  readonly snapshot: LifecycleWalSnapshotAuthority;
}

/** A noncredential file image retained by the planning authority. */
export interface LifecycleAbsentPreimage {
  readonly path: string;
  readonly state: 'absent';
}

export interface LifecyclePresentPreimage {
  readonly path: string;
  readonly state: 'file';
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
  readonly bytes: Uint8Array;
}
export interface LifecycleDirectoryPreimage {
  readonly path: string;
  readonly state: 'directory';
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}

/** Credential authority is deliberately metadata-only. */
export interface LifecycleCredentialPreimage {
  readonly path: string;
  readonly state: 'credential';
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}

export type LifecyclePreimage =
  | LifecycleAbsentPreimage
  | LifecyclePresentPreimage
  | LifecycleDirectoryPreimage
  | LifecycleCredentialPreimage;

export interface LifecycleStagedWrite {
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
  /** Native retained-stage outcome, registered before any caller branch. */
  readonly state: 'completed' | 'indeterminate';
}

/** Opaque same-FD authority for a credential stage file. */
export interface LifecycleReservedStagedWrite {
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  /** Native create outcome, registered with its retained capability before branching. */
  readonly state: 'completed' | 'indeterminate';
}
/** Opaque same-FD authority for an empty setup-owned directory stage. */
export interface LifecycleReservedStagedDirectory {
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
  /** Native create outcome, registered with its retained capability before branching. */
  readonly state: 'completed' | 'indeterminate';
}

export interface LifecycleExactDirectory {
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}
export interface LifecycleExactFile {
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}
export interface LifecycleExactContentFile extends LifecycleExactFile {
  readonly size: number;
  readonly digest: string;
}

export interface LifecycleExactMutationResult {
  readonly state: 'completed' | 'indeterminate';
  readonly quarantine?: object;
  readonly targetIdentity?: LifecycleFileIdentity;
  readonly quarantineIdentity?: LifecycleFileIdentity;
}

export interface LifecycleAdvisoryLock {
  /** Revalidates the exact lock FD/identity after acquisition. */
  revalidate(): Promise<void>;
  release(): Promise<void>;
}

export type LifecycleMaterializableUninstallInverse =
  | RestoreOwnedFileInverseOperation
  | RestoreConfigInverseOperation
  | RemoveConfigHunksInverseOperation
  | RestoreCredentialAuthorityRegistryEntryInverseOperation;

export interface LifecycleUninstallMaterializationInput {
  readonly inverse: LifecycleMaterializableUninstallInverse;
  readonly expected: LifecyclePresentPreimage;
}

export interface LifecycleCredentialAuthorityRegistryMutationOperation {
  readonly kind: 'apply-credential-authority-registry';
  readonly path: string;
  readonly preimage: SemanticCredentialAuthorityRegistryImage;
  readonly postimage: SemanticCredentialAuthorityRegistryImage;
  readonly fingerprint?: string;
  readonly mode: number;
}

/** The sole host capability used by lifecycle mutation. */
export interface LifecycleTransactionPort {
  acquireAdvisoryLock(path: string): Promise<LifecycleAdvisoryLock>;
  lstatNoFollow(path: string): Promise<LifecyclePathObservation | undefined>;
  readFileNoFollow(path: string): Promise<LifecycleFileSnapshot | undefined>;
  readWalFileNoFollow(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<LifecycleWalFileSnapshot | undefined>;
  stageWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    /** Deterministic same-parent stage path recorded before publication. */
    readonly stagingPath: string;
    readonly bytes: Uint8Array;
    readonly mode: number;
    /**
     * A durable WAL creation intent must authorize ordinary stage creation.
     * Omitted only for the WAL's own replacement stage.
     */
    readonly creationIntentMarkerPath?: string;
  }): Promise<LifecycleStagedWrite>;
  publishStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    readonly targetPath: string;
  }): Promise<void>;
  replaceStagedWriteWithQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    readonly targetPath: string;
    readonly current: LifecycleExactContentFile;
  }): Promise<LifecycleExactMutationResult>;
  discardStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
  }): Promise<LifecycleExactMutationResult>;
  /**
   * Retains a generic WAL/manifest/ordinary stage and detaches its process FD
   * only after the caller has proved its matching durable WAL record.
   */
  retainStagedWriteForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stage: LifecycleStagedWrite;
    /** Single-use same-session proof revalidated at the native detach boundary. */
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<LifecycleExactMutationResult>;
  reserveStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
    readonly creationIntentMarkerPath?: string;
    readonly mode: number;
  }): Promise<LifecycleReservedStagedWrite>;
  writeReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    readonly bytes: Uint8Array;
  }): Promise<void>;
  renameReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    readonly targetPath: string;
  }): Promise<void>;
  validatePublishedCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleReservedStagedWrite;
  }): Promise<LifecycleExactMutationResult>;
  validateExactCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleExactFile;
  }): Promise<LifecycleExactMutationResult>;
  removeExactCredential(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly credential: LifecycleExactFile;
  }): Promise<LifecycleExactMutationResult>;
  /**
   * Retains journal-owned stage recovery authority and detaches the process FD.
   * The caller must prove the matching WAL snapshot before this transition.
   */
  retainReservedStagedWriteForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
    /** Single-use same-session proof revalidated at the native detach boundary. */
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<LifecycleExactMutationResult>;
  retainReservedStagedDirectoryForRecovery(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
    /** Single-use same-session proof revalidated at the native detach boundary. */
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<LifecycleExactMutationResult>;
  validateExactDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly directory: LifecycleExactDirectory;
  }): Promise<LifecycleExactMutationResult>;
  closeReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
  }): Promise<void>;
  discardReservedStagedWrite(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedWrite;
  }): Promise<LifecycleExactMutationResult>;
  reserveStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
    readonly targetPath?: string;
    readonly creationIntentMarkerPath?: string;
    readonly mode: number;
  }): Promise<LifecycleReservedStagedDirectory>;
  publishReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
    readonly targetPath: string;
  }): Promise<void>;
  closeReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
  }): Promise<void>;
  discardReservedStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly reservation: LifecycleReservedStagedDirectory;
  }): Promise<LifecycleExactMutationResult>;
  recoverCreationIntent(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagePath: string;
    readonly markerPath: string;
    readonly kind: 'credential' | 'directory' | 'file';
    readonly mode: number;
  }): Promise<LifecycleExactMutationResult>;
  publishExactStagedDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleFileIdentity;
    readonly mode: number;
  }): Promise<void>;
  fsyncDirectory(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<void>;
  replaceExactStagedFileWithQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleFileIdentity;
    readonly mode: number;
    readonly current: LifecycleExactFile & { readonly size?: number; readonly digest?: string };
  }): Promise<LifecycleExactMutationResult>;
  replaceExactWal(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactFile;
    readonly replacement: LifecycleStagedWrite;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<LifecycleExactMutationResult>;
  publishExactStagedFile(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: LifecycleFileIdentity;
    readonly mode: number;
  }): Promise<void>;
  fsyncFile(input: { readonly lock: LifecycleAdvisoryLock; readonly path: string }): Promise<void>;
  fsyncParent(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly path: string;
  }): Promise<void>;
  removeExactWal(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactFile;
    readonly snapshot: LifecycleWalSnapshotAuthority;
  }): Promise<LifecycleExactMutationResult>;
  removeExactStagedFile(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly current: LifecycleExactContentFile;
  }): Promise<LifecycleExactMutationResult>;
  quarantineExactFile(
    input: LifecycleExactFile & {
      readonly lock: LifecycleAdvisoryLock;
      readonly quarantinePath: string;
      readonly credential?: boolean;
      readonly size?: number;
      readonly digest?: string;
    },
  ): Promise<LifecycleExactMutationResult>;
  quarantineExactDirectory(
    input: LifecycleExactDirectory & {
      readonly lock: LifecycleAdvisoryLock;
      readonly quarantinePath: string;
    },
  ): Promise<LifecycleExactMutationResult>;
  purgeManagedViteRuntime(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly directory: LifecycleExactDirectory;
  }): Promise<boolean>;
  finalizeQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly quarantine: object;
  }): Promise<LifecycleExactMutationResult>;
  restoreQuarantine(input: {
    readonly lock: LifecycleAdvisoryLock;
    readonly quarantine: object;
  }): Promise<LifecycleExactMutationResult>;
  /** Pure renderer: it must not observe, stage, rename, or mutate any target. */
  materializeUninstallInverse(input: LifecycleUninstallMaterializationInput): Promise<Uint8Array>;
  failurePoint(name: LifecycleFailurePoint): Promise<void>;
}

export type LifecycleFailurePoint =
  | 'lock-acquire'
  | 'lock-release'
  | 'wal-write'
  | 'wal-fsync'
  | 'stage-write'
  | 'target-rename'
  | 'target-fsync'
  | 'parent-fsync'
  | 'manifest-write'
  | 'manifest-fsync'
  | 'diagnostics'
  | 'credential-reserve'
  | 'credential-identity-wal'
  | 'credential-write'
  | 'credential-rename'
  | 'directory-reserve'
  | 'directory-identity-wal'
  | 'directory-publish'
  | 'directory-fsync'
  | 'directory-remove'
  | 'finalization'
  | 'uninstall-commit-decided'
  | 'credential-delete'
  | 'receipt-write'
  | 'receipt-fsync'
  | 'cleanup';

export type LifecycleMutationOperation =
  | { readonly kind: 'create-directory'; readonly path: string; readonly mode: number }
  | {
      readonly kind: 'write-file' | 'write-config' | 'write-credential';
      readonly path: string;
      readonly bytes: Uint8Array;
      readonly mode: number;
    }
  | {
      /** A move is persisted as an exact destination write plus source removal. */
      readonly kind: 'move-config';
      readonly sourcePath: string;
      readonly path: string;
      readonly bytes: Uint8Array;
      readonly mode: number;
    }
  | LifecycleCredentialAuthorityRegistryMutationOperation;

export interface LifecycleTransactionFailure {
  /** Bounded operation label; never host error text, a path, or secret material. */
  readonly stage: string;
}

export interface LifecycleTransactionResult {
  readonly state: 'active' | 'uninstalled' | 'never-installed' | 'recovery-required';
  readonly failures: readonly LifecycleTransactionFailure[];
}

export class LifecycleTransactionError extends Error {
  public readonly failures: readonly LifecycleTransactionFailure[];

  public constructor(
    operation: 'setup' | 'uninstall' | 'recovery',
    failures: readonly LifecycleTransactionFailure[],
  ) {
    super(`lifecycle ${operation} transaction failed`);
    this.name = 'LifecycleTransactionError';
    this.failures = Object.freeze([...failures]);
  }
}
const lifecycleTransactionConvergences = new WeakMap<
  LifecycleTransactionError,
  'never-installed'
>();

export function lifecycleTransactionConvergence(error: unknown): 'never-installed' | undefined {
  return error instanceof LifecycleTransactionError
    ? lifecycleTransactionConvergences.get(error)
    : undefined;
}

export interface SetupCredentialCandidate {
  readonly projectId: LifecycleId;
  readonly path: string;
  readonly stagingPath: string;
  readonly mode: number;
  /** Temporary credential-file bytes; zeroized after the retained-FD write boundary. */
  readonly contentBytes: Uint8Array;
}
export interface SetupDirectoryCandidate {
  readonly path: string;
  readonly stagingPath: string;
  readonly mode: number;
}

export interface SetupCreatedCredentialAuthority {
  readonly projectId: LifecycleId;
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
  readonly linkCount: 1;
}
/**
 * Lock-held reservation metadata. It is not publication authority and must not
 * be stored, observed, or used as a credential authority before exact native
 * validation of publication.
 */
export interface SetupReservedCredentialAuthority {
  readonly projectId: LifecycleId;
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
  /** Native reservation and exact credential validation both require one link. */
  readonly linkCount: 1;
}

export interface SetupFinalization {
  readonly manifest: unknown;
  /** Only remaining ordinary, noncredential writes belong here. */
  readonly operations: readonly LifecycleMutationOperation[];
  /**
   * Preimages for only remaining ordinary/registry writes. Created credential
   * authority remains the lock-held opening authority, never a stale absent
   * callback preimage.
   */
  readonly preimages: readonly LifecyclePreimage[];
}

export interface OpenSetupTransactionAuthorityInput {
  readonly port: LifecycleTransactionPort;
  readonly lockPath: string;
  readonly walPath: string;
  readonly manifestPath: string;
  readonly preimages: readonly LifecyclePreimage[];
  /** Stable setup identity used to bind the opening WAL before reservation. */
  readonly operationId: LifecycleId;
  /** Stable setup identity used to bind the opening WAL before reservation. */
  readonly installId: LifecycleId;
  /**
   * Missing setup-owned directories, ordered so every candidate parent comes
   * before its child. Omission preserves the existing file-only authority.
   */
  readonly directories?: readonly SetupDirectoryCandidate[];
  /** The target must be absent through lock-held revalidation. */
  readonly credential?: Omit<SetupCredentialCandidate, 'contentBytes'>;
}

/**
 * Single-use opaque setup authority. It owns the exact advisory lock from open
 * until publish or compensate. It cannot be fabricated by callers.
 */
export interface SetupTransactionAuthority {
  /** Runtime-branded and issued only by openSetupTransactionAuthority. */
  readonly __setupTransactionAuthority: never;
  readonly reservedCreatedCredential?: SetupReservedCredentialAuthority;
}

export interface ApplySetupTransactionInput {
  readonly authority: SetupTransactionAuthority;
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  /** Must exactly match the directory authority supplied at open. */
  readonly directories?: readonly SetupDirectoryCandidate[];
  readonly credential?: SetupCredentialCandidate;
  /**
   * Immutable plan precomputed from the lock-held opening authority. Opening may
   * bind setup-created identities, but this must finish before credential bytes
   * or any ordinary/manifest write is published.
   */
  readonly finalization: SetupFinalization;
  readonly diagnostics?: () => Promise<void>;
}

export interface SetupTransactionReceipt {
  readonly manifest: SetupManifestV1;
  /** Runtime-branded and issued only by applySetupTransaction. */
  readonly __setupTransactionReceipt: never;
}

export interface ApplyUninstallTransactionInput {
  readonly manifest: unknown;
  readonly operationId: LifecycleId;
  /** The completed, successful read-only eligibility proof. */
  readonly preflight: UninstallPreflight;
  readonly walPath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly lockPath: string;
  readonly port: LifecycleTransactionPort;
}

export interface RecoverLifecycleInput {
  /** Fixed, configured state path; recovery never derives or enumerates it. */
  readonly walPath: string;
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly receiptPath?: string;
  /** Optional caller authorization, revalidated from the lock-held WAL bytes. */
  readonly expectedRecoveryId?: string;
  readonly port: LifecycleTransactionPort;
}

type SetupAuthorityState =
  | 'open'
  | 'applying'
  | 'receipt-pending'
  | 'publishing'
  | 'compensating'
  | 'release-pending'
  | 'closed';

interface InternalSetupAuthority {
  readonly port: LifecycleTransactionPort;
  readonly lockPath: string;
  readonly walPath: string;
  readonly manifestPath: string;
  readonly initialPreimages: readonly LifecyclePreimage[];
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly directories: readonly SetupDirectoryCandidate[];
  readonly credential: Omit<SetupCredentialCandidate, 'contentBytes'> | undefined;
  readonly lock: LifecycleAdvisoryLock;
  credentialReservation: LifecycleReservedStagedWrite | undefined;
  readonly directoryReservations: LifecycleReservedStagedDirectory[];
  reservedCreatedCredential: SetupReservedCredentialAuthority | undefined;
  readonly stagedWrites: Map<string, LifecycleStagedWrite>;
  state: SetupAuthorityState;
  released: boolean;
  pendingCloseResult: LifecycleTransactionResult | undefined;
  record: WalRecordV2 | undefined;
}

interface PreparedOrdinaryMutation {
  readonly mutation: WalOrdinaryMutationV2;
  readonly action: 'write' | 'remove';
  /** Present only in the live transaction that owns the native stage capability. */
  readonly stage?: LifecycleStagedWrite;
}
interface LifecycleCreationIntentAuthority {
  readonly markerPath: string;
  readonly intent: WalCreationIntentV2;
}
type OrdinaryMutationIntent =
  | {
      readonly action: 'write';
      readonly path: string;
      readonly bytes: Uint8Array;
      readonly mode: number;
    }
  | {
      readonly action: 'remove';
      readonly path: string;
      readonly mode: number;
    };

interface InternalSetupReceipt {
  readonly authority: InternalSetupAuthority;
  readonly manifest: SetupManifestV1;
  readonly record: WalRecordV2;
}

const SETUP_AUTHORITY = Symbol('setup-transaction-authority');
const SETUP_RECEIPT = Symbol('setup-transaction-receipt');
const ZERO_FINGERPRINT = `sha256:${'0'.repeat(64)}`;
const REFLECT_APPLY = Reflect.apply;
const TYPED_ARRAY_FILL = Uint8Array.prototype.fill;
const TYPED_ARRAY_SLICE = Uint8Array.prototype.slice;
const MAX_SETUP_CREDENTIAL_BYTES = 8 * 1024;
const MAX_WAL_OPERATIONS = 64;
const MAX_WAL_MUTATIONS = 64;
const MAX_WAL_PREIMAGES = 128;
const MAX_WAL_STAGED_WRITES = 64;
const MAX_WAL_STRUCTURAL_BYTES = 1024 * 1024;
const MAX_SERIALIZED_WAL_BYTES = 32 * 1024 * 1024;

/**
 * Opens a lock-held setup authority. Setup-created directories are published
 * and a credential stage is reserved only after their deterministic creation
 * intents are durable in the rollback WAL. The credential's exact reservation
 * is returned so finalization can bind its authority before secret bytes exist.
 */
export async function openSetupTransactionAuthority(
  input: OpenSetupTransactionAuthorityInput,
): Promise<SetupTransactionAuthority> {
  let openingPreimages: readonly LifecyclePreimage[];
  let directories: readonly SetupDirectoryCandidate[] = Object.freeze([]);
  try {
    directories = freezeDirectoryCandidates(input.directories ?? []);
    validateStatePaths(input.lockPath, input.walPath, input.manifestPath);
    if (!validId(input.operationId) || !validId(input.installId)) {
      throw bounded('setup-authority');
    }
    validateSetupDirectoryAuthority(
      directories,
      input.preimages,
      input.lockPath,
      input.walPath,
      input.manifestPath,
      input.credential,
    );
    if (directories.length + (input.credential === undefined ? 0 : 1) + 1 > MAX_WAL_MUTATIONS) {
      throw bounded('setup-authority');
    }
    if (
      input.preimages.length + directories.length + (input.credential === undefined ? 0 : 1) >
      MAX_WAL_PREIMAGES
    ) {
      throw bounded('setup-authority');
    }
    if (input.credential !== undefined) {
      validateCredentialCandidateShape(input.credential);
      const credentialPreimage = requirePreimage(input.preimages, input.credential.path);
      if (credentialPreimage.state !== 'absent') {
        throw bounded('setup-authority');
      }
    }
    openingPreimages = Object.freeze([
      ...input.preimages,
      ...directories.map((candidate) =>
        Object.freeze({ path: candidate.stagingPath, state: 'absent' as const }),
      ),
      ...(input.credential === undefined
        ? []
        : [Object.freeze({ path: input.credential.stagingPath, state: 'absent' as const })]),
    ]);
    validatePreimages(openingPreimages, [
      input.lockPath,
      input.walPath,
      walStagingPath(input.walPath),
      input.manifestPath,
    ]);
  } catch (error) {
    throw transactionError('setup', error, 'setup-authority');
  }

  let lock: LifecycleAdvisoryLock | undefined;
  let authority: InternalSetupAuthority | undefined;
  try {
    lock = await boundary(input.port, 'lock-acquire', () =>
      input.port.acquireAdvisoryLock(input.lockPath),
    );
    await boundary(input.port, 'lock-acquire', () => lock!.revalidate());
    await assertPreimages(input.port, openingPreimages);
    await assertAbsent(input.port, input.walPath);
    const openedAuthority: InternalSetupAuthority = {
      port: input.port,
      lockPath: input.lockPath,
      walPath: input.walPath,
      manifestPath: input.manifestPath,
      initialPreimages: freezePreimages(openingPreimages),
      operationId: input.operationId,
      installId: input.installId,
      directories,
      credential: input.credential,
      lock,
      credentialReservation: undefined,
      directoryReservations: [],
      reservedCreatedCredential: undefined,
      stagedWrites: new Map(),
      state: 'open',
      released: false,
      pendingCloseResult: undefined,
      record: undefined,
    };
    authority = openedAuthority;
    const directorySources = directoryMutationSources(directories, input.operationId);
    if (
      validateWalPreimageStructuralBudget(openingPreimages) +
        directorySources.reduce((total, source) => total + Buffer.byteLength(source, 'utf8'), 0) >
      MAX_WAL_STRUCTURAL_BYTES
    ) {
      throw bounded('wal-authority');
    }
    assertDirectorySourcesDoNotCollide(openedAuthority, directorySources);
    await assertAbsentAll(input.port, directorySources);
    const baseRecord = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: input.operationId,
      installId: input.installId,
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: input.lockPath,
      manifestPath: input.manifestPath,
      cursor: 0,
      preimages: toWalPreimages(openedAuthority.initialPreimages),
      mutations: [],
    });
    const firstDirectory = directories[0];
    const initialIntent =
      firstDirectory !== undefined
        ? creationIntentFor(
            baseRecord,
            input.operationId,
            firstDirectory.path,
            firstDirectory.stagingPath,
            'directory',
            firstDirectory.mode,
          )
        : input.credential === undefined
          ? undefined
          : creationIntentFor(
              baseRecord,
              input.operationId,
              input.credential.path,
              input.credential.stagingPath,
              'credential',
              input.credential.mode,
            );
    const record =
      initialIntent === undefined
        ? baseRecord
        : (() => {
            const { authorityFingerprint: ignoredAuthorityFingerprint, ...unboundRecord } =
              baseRecord;
            void ignoredAuthorityFingerprint;
            return bindWal({
              ...unboundRecord,
              creationIntents: Object.freeze([initialIntent.intent]),
            });
          })();
    await writeWal(input.port, lock, input.walPath, record, undefined, () => {
      openedAuthority.record = record;
    });
    await prepareOpenedSetupCreatedResources(openedAuthority, directorySources);
    return Object.freeze({
      [SETUP_AUTHORITY]: openedAuthority,
      ...(openedAuthority.reservedCreatedCredential === undefined
        ? {}
        : { reservedCreatedCredential: openedAuthority.reservedCreatedCredential }),
    } as unknown as SetupTransactionAuthority);
  } catch (error) {
    const failures = [
      failure(failureStage(error, 'setup-authority')),
      ...cleanupFailuresFrom(error),
    ];
    if (authority !== undefined) {
      failures.push(
        ...(authority.record === undefined
          ? await discardUnpublishedSetupReservations(authority)
          : await retainOpenedSetupReservations(authority)),
      );
    }
    if (lock !== undefined) {
      const release = await releaseLock(input.port, lock);
      if (release !== undefined) {
        failures.push(release);
      }
    }
    throw new LifecycleTransactionError('setup', failures);
  }
}

async function prepareOpenedSetupCreatedResources(
  authority: InternalSetupAuthority,
  directorySources: readonly string[],
): Promise<void> {
  const openingRecord = authority.record;
  if (
    openingRecord === undefined ||
    openingRecord.operation !== 'setup' ||
    openingRecord.direction !== 'rollback' ||
    openingRecord.phase !== 'prepared' ||
    openingRecord.operationId !== authority.operationId ||
    openingRecord.installId !== authority.installId
  ) {
    throw bounded('setup-authority');
  }
  let record: WalRecordV2 = openingRecord;

  for (let index = 0; index < authority.directories.length; index += 1) {
    const candidate = authority.directories[index];
    const sourcePath = directorySources[index];
    if (candidate === undefined || sourcePath === undefined) {
      throw bounded('setup-authority');
    }
    const resolvedIntent = resolveCreationIntent(
      record,
      authority.operationId,
      candidate.path,
      candidate.stagingPath,
      'directory',
      candidate.mode,
    );
    const intent = resolvedIntent.intent;
    if (!resolvedIntent.durable) {
      const { authorityFingerprint: ignoredAuthorityFingerprint, ...unboundRecord } = record;
      void ignoredAuthorityFingerprint;
      const intentRecord = bindWal({
        ...unboundRecord,
        creationIntents: Object.freeze([intent.intent]),
      });
      await writeWal(
        authority.port,
        authority.lock,
        authority.walPath,
        intentRecord,
        authority.record,
        () => {
          authority.record = intentRecord;
        },
      );
      record = intentRecord;
    }

    const reservedDirectory = await boundary(authority.port, 'directory-reserve', () =>
      authority.port.reserveStagedDirectory({
        lock: authority.lock,
        path: candidate.stagingPath,
        targetPath: candidate.path,
        creationIntentMarkerPath: intent.markerPath,
        mode: candidate.mode,
      }),
    );
    authority.directoryReservations.push(reservedDirectory);
    assertDirectoryReservationMatchesCandidate(reservedDirectory, candidate);

    const identityPreimages = record.preimages.filter(
      (preimage) => preimage.path !== reservedDirectory.path,
    );
    const directoryMutation: WalOrdinaryMutationV2 = Object.freeze({
      step: intent.intent.step,
      kind: 'ordinary',
      targetPath: candidate.path,
      sourcePath,
      stagingPath: reservedDirectory.path,
      preimage: preimageIndex(identityPreimages, candidate.path),
      result: Object.freeze({
        kind: 'directory',
        identity: reservedDirectory.identity,
        mode: candidate.mode,
      }),
    });
    const { creationIntents: ignoredCreationIntents, ...completedRecord } = record;
    void ignoredCreationIntents;
    const identityRecord = bindWal({
      ...completedRecord,
      preimages: identityPreimages,
      mutations: Object.freeze([...record.mutations, directoryMutation]),
    });
    await boundary(authority.port, 'directory-identity-wal', () =>
      writeWal(authority.port, authority.lock, authority.walPath, identityRecord, record, () => {
        authority.record = identityRecord;
      }),
    );
    record = identityRecord;

    await boundary(authority.port, 'directory-publish', () =>
      authority.port.publishReservedStagedDirectory({
        lock: authority.lock,
        reservation: reservedDirectory,
        targetPath: candidate.path,
      }),
    );
    if (
      !sameDirectoryObservation(
        await authority.port.lstatNoFollow(candidate.path),
        reservedDirectory.identity,
        candidate.mode,
      )
    ) {
      throw bounded('directory-publish');
    }
    await boundary(authority.port, 'directory-fsync', () =>
      authority.port.fsyncDirectory({ lock: authority.lock, path: candidate.path }),
    );
    await boundary(authority.port, 'parent-fsync', () =>
      authority.port.fsyncParent({ lock: authority.lock, path: candidate.path }),
    );
    const advancedRecord = bindWal({ ...record, cursor: directoryMutation.step + 1 });
    await writeWal(
      authority.port,
      authority.lock,
      authority.walPath,
      advancedRecord,
      record,
      () => {
        authority.record = advancedRecord;
      },
    );
    record = advancedRecord;
    await authority.port.closeReservedStagedDirectory({
      lock: authority.lock,
      reservation: reservedDirectory,
    });
    const reservationIndex = authority.directoryReservations.indexOf(reservedDirectory);
    if (reservationIndex < 0) {
      throw bounded('setup-authority');
    }
    authority.directoryReservations.splice(reservationIndex, 1);
  }

  const credential = authority.credential;
  if (credential === undefined) {
    return;
  }
  const resolvedIntent = resolveCreationIntent(
    record,
    authority.operationId,
    credential.path,
    credential.stagingPath,
    'credential',
    credential.mode,
  );
  const intent = resolvedIntent.intent;
  if (!resolvedIntent.durable) {
    const { authorityFingerprint: ignoredAuthorityFingerprint, ...unboundRecord } = record;
    void ignoredAuthorityFingerprint;
    const intentRecord = bindWal({
      ...unboundRecord,
      creationIntents: Object.freeze([intent.intent]),
    });
    await writeWal(
      authority.port,
      authority.lock,
      authority.walPath,
      intentRecord,
      authority.record,
      () => {
        authority.record = intentRecord;
      },
    );
    record = intentRecord;
  }

  const reservedCredential = await boundary(authority.port, 'credential-reserve', () =>
    authority.port.reserveStagedWrite({
      lock: authority.lock,
      path: credential.stagingPath,
      creationIntentMarkerPath: intent.markerPath,
      mode: credential.mode,
    }),
  );
  authority.credentialReservation = reservedCredential;
  assertReservationMatchesCandidate(reservedCredential, credential);
  const reservedCreatedCredential = Object.freeze({
    projectId: credential.projectId,
    path: credential.path,
    identity: reservedCredential.identity,
    mode: credential.mode,
    linkCount: 1,
  });
  authority.reservedCreatedCredential = reservedCreatedCredential;

  const { creationIntents: ignoredCreationIntents, ...completedRecord } = record;
  void ignoredCreationIntents;
  const identityRecord = bindWal({
    ...completedRecord,
    preimages: record.preimages.filter((preimage) => preimage.path !== reservedCredential.path),
    mutations: Object.freeze([
      ...record.mutations,
      Object.freeze({
        step: intent.intent.step,
        kind: 'credential' as const,
        projectId: credential.projectId,
        path: credential.path,
        mode: credential.mode,
        stagingPath: reservedCredential.path,
        stagingIdentity: reservedCredential.identity,
        targetIdentity: reservedCredential.identity,
      }),
    ]),
  });
  await boundary(authority.port, 'credential-identity-wal', () =>
    writeWal(authority.port, authority.lock, authority.walPath, identityRecord, record, () => {
      authority.record = identityRecord;
    }),
  );
}

/**
 * Consumes the opening authority. All setup-created stage identities are
 * already bound in the rollback WAL; credential bytes are written only after
 * finalization confirms that exact reserved identity.
 */
export async function applySetupTransaction(
  input: ApplySetupTransactionInput,
): Promise<SetupTransactionReceipt | LifecycleTransactionResult> {
  let credential: SetupCredentialCandidate | undefined;
  let primaryError: unknown;
  let outcome: SetupTransactionReceipt | LifecycleTransactionResult | undefined;
  try {
    credential =
      input.credential === undefined ? undefined : ownCredentialCandidate(input.credential);
    outcome = await applyClaimedSetupTransaction(input, credential);
  } catch (error) {
    primaryError = error;
  }

  const zeroizationError = zeroizeCredentialBuffers(
    credential?.contentBytes,
    input.credential?.contentBytes,
  );
  if (primaryError !== undefined) {
    if (zeroizationError !== undefined) {
      throw new CleanupFailure(primaryError, [failure('credential-zeroization')], zeroizationError);
    }
    throw primaryError;
  }
  if (outcome === undefined) {
    throw new LifecycleTransactionError('setup', [failure('setup-apply')]);
  }
  if (zeroizationError === undefined) {
    return outcome;
  }
  if ('manifest' in outcome) {
    return closeSetupResult(
      unwrapReceipt(outcome).authority,
      recoveryRequired([failure('credential-zeroization')]),
    );
  }
  return recoveryRequired([...outcome.failures, failure('credential-zeroization')]);
}

async function applyClaimedSetupTransaction(
  input: ApplySetupTransactionInput,
  credential: SetupCredentialCandidate | undefined,
): Promise<SetupTransactionReceipt | LifecycleTransactionResult> {
  const authority = unwrapSetupAuthority(input.authority);
  claimSetupAuthority(authority, 'open', 'applying');

  let reservation: LifecycleReservedStagedWrite | undefined;
  let manifestStage: LifecycleStagedWrite | undefined;
  let preparedOrdinary: readonly PreparedOrdinaryMutation[] = Object.freeze([]);
  try {
    if (
      !sameDirectoryCandidates(input.directories ?? [], authority.directories) ||
      (credential === undefined) !== (authority.credential === undefined) ||
      input.operationId !== authority.operationId ||
      input.installId !== authority.installId
    ) {
      throw bounded('setup-authority');
    }
    await boundary(authority.port, 'lock-acquire', () => authority.lock.revalidate());
    if (credential !== undefined) {
      validateCredentialCandidate(credential, authority.credential);
    }
    let record: WalRecordV2 = await assertOpenedSetupRecord(authority);
    const finalized = input.finalization;
    const directoryBindings = finalizedDirectoryBindings(authority, record);
    const manifest = finalizeSetupManifestV1({
      manifest: finalized.manifest,
      operations: finalized.operations,
      credential:
        authority.reservedCreatedCredential === undefined
          ? undefined
          : finalizedCredentialBinding(authority.reservedCreatedCredential),
      directories: directoryBindings,
    });
    const persistedDirectoryBindings = directoryBindings.filter((directory) =>
      manifest.artifacts.some(
        (artifact) => artifact.kind === 'directory' && artifact.path === directory.path,
      ),
    );
    if (manifest.installId !== authority.installId) {
      throw bounded('finalization');
    }
    const manifestJson = serializeSetupManifestV1(manifest);
    const manifestBytes = validateWalManifestBudget(manifest, manifestJson);
    void manifestBytes;
    const reservedAuthority = authority.reservedCreatedCredential;
    if (credential === undefined) {
      if (authority.credentialReservation !== undefined || reservedAuthority !== undefined) {
        throw bounded('setup-authority');
      }
      assertFinalizedCredentialAuthority(manifest, undefined);
    } else {
      const reservedCredential = authority.credentialReservation;
      if (
        reservedCredential === undefined ||
        reservedAuthority === undefined ||
        reservedAuthority.projectId !== credential.projectId ||
        reservedAuthority.path !== credential.path ||
        reservedAuthority.mode !== credential.mode ||
        !sameIdentity(reservedAuthority.identity, reservedCredential.identity)
      ) {
        throw bounded('setup-authority');
      }
      assertReservationMatchesCandidate(reservedCredential, credential);
      assertFinalizedCredentialAuthority(manifest, reservedAuthority);
      reservation = reservedCredential;
    }
    const finalizationPreimages = freezePreimages(finalized.preimages);
    assertFinalizationOmitsCreatedAuthority(authority, finalizationPreimages, credential);
    validateFinalizedSetupProvenance({
      manifest,
      operations: finalized.operations,
      preimages: finalizationPreimages,
      credential:
        reservedAuthority === undefined ? undefined : finalizedCredentialBinding(reservedAuthority),
      directories: persistedDirectoryBindings,
    });
    const ordinaryIntents = intentsFromMutationOperations(
      finalized.operations,
      finalizationPreimages,
    );
    const ordinaryStageCount =
      ordinaryIntents.filter((intent) => intent.action === 'write').length + 1;
    if (
      finalized.preimages.length +
        authority.directories.length +
        (credential === undefined ? 0 : 1) +
        ordinaryStageCount +
        1 >
      MAX_WAL_PREIMAGES
    ) {
      throw bounded('wal-authority');
    }
    const createdPreimages = createdSetupPreimages(authority);
    const preimages = freezePreimages([...finalizationPreimages, ...createdPreimages]);
    validateFinalSetupAuthority(authority, preimages, credential);
    validateSetupPlanGeometry(
      authority,
      ordinaryIntents,
      authority.operationId,
      record.mutations.length,
    );

    let createdCredential: SetupCreatedCredentialAuthority | undefined;
    if (credential !== undefined) {
      const reservedCredential = reservation;
      const credentialMutation = record.mutations.find(
        (mutation): mutation is WalCredentialMutationV2 => mutation.kind === 'credential',
      );
      if (
        reservedCredential === undefined ||
        credentialMutation === undefined ||
        credentialMutation.projectId !== credential.projectId ||
        credentialMutation.path !== credential.path ||
        credentialMutation.mode !== credential.mode ||
        credentialMutation.stagingPath !== reservedCredential.path ||
        !sameIdentity(credentialMutation.stagingIdentity, reservedCredential.identity) ||
        !sameIdentity(credentialMutation.targetIdentity, reservedCredential.identity)
      ) {
        throw bounded('setup-authority');
      }
      await boundary(authority.port, 'credential-write', () =>
        authority.port.writeReservedStagedWrite({
          lock: authority.lock,
          reservation: reservedCredential,
          bytes: credential.contentBytes,
        }),
      );
      const zeroizationError = zeroizeCredentialBuffers(credential.contentBytes);
      if (zeroizationError !== undefined) {
        throw new CleanupFailure(
          bounded('credential-zeroization'),
          [failure('credential-zeroization')],
          zeroizationError,
        );
      }
      await boundary(authority.port, 'credential-rename', () =>
        authority.port.renameReservedStagedWrite({
          lock: authority.lock,
          reservation: reservedCredential,
          targetPath: credential.path,
        }),
      );
      const credentialValidation = await authority.port.validatePublishedCredential({
        lock: authority.lock,
        credential: reservedCredential,
      });
      if (credentialValidation.state !== 'completed') {
        throw bounded('indeterminate');
      }
      const observed = await authority.port.lstatNoFollow(credential.path);
      if (!sameObservation(observed, reservedCredential.identity, credential.mode)) {
        throw bounded('credential-rename');
      }
      if (
        (
          await authority.port.validateExactCredential({
            lock: authority.lock,
            credential: {
              path: credential.path,
              identity: reservedCredential.identity,
              mode: credential.mode,
            },
          })
        ).state !== 'completed'
      ) {
        throw bounded('credential-rename');
      }
      await authority.port.closeReservedStagedWrite({
        lock: authority.lock,
        reservation: reservedCredential,
      });
      reservation = undefined;
      authority.credentialReservation = undefined;
      createdCredential = Object.freeze({
        projectId: credential.projectId,
        path: credential.path,
        identity: observed.identity,
        mode: credential.mode,
        linkCount: 1,
      });
      if (
        reservedAuthority === undefined ||
        reservedAuthority.projectId !== createdCredential.projectId ||
        reservedAuthority.path !== createdCredential.path ||
        reservedAuthority.mode !== createdCredential.mode ||
        reservedAuthority.linkCount !== 1 ||
        createdCredential.linkCount !== 1 ||
        !sameIdentity(reservedAuthority.identity, createdCredential.identity)
      ) {
        throw bounded('credential-rename');
      }
      const advancedRecord = bindWal({ ...record, cursor: credentialMutation.step + 1 });
      await writeWal(
        authority.port,
        authority.lock,
        authority.walPath,
        advancedRecord,
        record,
        () => {
          authority.record = advancedRecord;
        },
      );
      record = advancedRecord;
    }

    assertFinalizedCredentialAuthority(manifest, createdCredential);
    assertOrdinaryIntentsDoNotTargetCreatedCredential(ordinaryIntents, createdCredential);
    const carriedMutations = rebindOrdinaryPreimages(record.mutations, preimages);
    const manifestAuthorityPath = setupManifestAuthorityPath(
      authority.manifestPath,
      authority.operationId,
    );
    const manifestStep = carriedMutations.length + ordinaryIntents.length;
    const manifestSourcePath = auxiliaryPath(
      manifestAuthorityPath,
      authority.operationId,
      manifestStep,
      'rollback',
    );
    const manifestStagingPath = auxiliaryPath(
      manifestAuthorityPath,
      authority.operationId,
      manifestStep,
      'stage',
    );
    const manifestStructuralBytes =
      Buffer.byteLength(manifestAuthorityPath, 'utf8') +
      Buffer.byteLength(manifestSourcePath, 'utf8') +
      Buffer.byteLength(manifestStagingPath, 'utf8');
    if (
      !validPath(manifestAuthorityPath) ||
      !validPath(manifestSourcePath) ||
      !validPath(manifestStagingPath) ||
      manifestStructuralBytes > MAX_WAL_STRUCTURAL_BYTES
    ) {
      throw bounded('wal-authority');
    }
    const manifestIntent: OrdinaryMutationIntent = Object.freeze({
      action: 'write',
      path: manifestAuthorityPath,
      bytes: encode(manifestJson),
      mode: 0o600,
    });
    const plannedIntents = Object.freeze([...ordinaryIntents, manifestIntent]);
    const stagePreimages = plannedIntents.flatMap((intent, index) =>
      intent.action === 'write'
        ? [
            Object.freeze({
              path: auxiliaryPath(
                intent.path,
                authority.operationId,
                carriedMutations.length + index,
                'stage',
              ),
              state: 'absent' as const,
            }),
          ]
        : [],
    );
    const finalPreimages = freezePreimages([
      ...preimages,
      Object.freeze({ path: manifestAuthorityPath, state: 'absent' as const }),
      ...stagePreimages,
    ]);
    validateOrdinaryIntents(
      plannedIntents,
      validateWalPreimageBudget(finalPreimages),
      validateWalPreimageStructuralBudget(finalPreimages),
      authority.operationId,
      carriedMutations.length,
    );
    await assertPreimages(
      authority.port,
      finalPreimages,
      createdPreimages.map((preimage) => preimage.path),
    );
    const precreationRecord = bindWal({
      ...record,
      cursor: carriedMutations.length,
      preimages: toWalPreimages(finalPreimages),
      mutations: carriedMutations,
    });
    await writeWal(
      authority.port,
      authority.lock,
      authority.walPath,
      precreationRecord,
      record,
      () => {
        authority.record = precreationRecord;
      },
    );
    record = precreationRecord;
    const prepared: PreparedOrdinaryMutation[] = [];
    for (const item of plannedIntents) {
      const persisted = await persistOrdinaryMutationWithIntent({
        port: authority.port,
        lock: authority.lock,
        walPath: authority.walPath,
        record,
        item,
        onPublished: (next) => {
          authority.record = next;
        },
      });
      record = persisted.record;
      prepared.push(persisted.prepared);
      preparedOrdinary = Object.freeze([...prepared]);
      if (persisted.prepared.stage !== undefined) {
        authority.stagedWrites.set(persisted.prepared.stage.path, persisted.prepared.stage);
      }
    }
    const manifestPrepared = prepared.at(-1);
    if (
      manifestPrepared === undefined ||
      manifestPrepared.action !== 'write' ||
      manifestPrepared.stage === undefined
    ) {
      throw bounded('manifest-write');
    }
    manifestStage = manifestPrepared.stage;
    preparedOrdinary = Object.freeze(prepared.slice(0, -1));
    const ordinary = preparedOrdinary;
    if (
      record.operation !== 'setup' ||
      record.direction !== 'rollback' ||
      record.phase !== 'prepared'
    ) {
      throw bounded('setup-authority');
    }
    const { creationIntents: ignoredCreationIntents, ...finalizedRecord } = record;
    void ignoredCreationIntents;
    record = bindWal({
      ...finalizedRecord,
      phase: 'finalized',
      cursor: record.mutations.length,
    });
    await writeWal(
      authority.port,
      authority.lock,
      authority.walPath,
      record,
      authority.record,
      () => {
        authority.record = record;
      },
    );

    for (const item of ordinary) {
      const applied = await forwardOrdinaryMutation(
        authority.port,
        authority.lock,
        record,
        item.mutation,
        item.stage,
      );
      if (!applied) {
        throw bounded('target-rename');
      }
    }
    if (input.diagnostics !== undefined) {
      await boundary(authority.port, 'diagnostics', input.diagnostics);
    }
    manifestStage = undefined;
    authority.state = 'receipt-pending';
    const receipt: InternalSetupReceipt = {
      authority,
      manifest,
      record,
    };
    return Object.freeze({
      manifest,
      [SETUP_RECEIPT]: receipt,
    } as unknown as SetupTransactionReceipt);
  } catch (error) {
    const cleanupFailures: LifecycleTransactionFailure[] = [...cleanupFailuresFrom(error)];
    if (authority.record === undefined) {
      cleanupFailures.push(...(await discardUnpublishedSetupReservations(authority)));
      reservation = undefined;
    }
    if (authority.record?.phase !== 'finalized') {
      if (manifestStage !== undefined) {
        const cleanup = await discardStage(authority.port, authority.lock, manifestStage);
        if (cleanup !== undefined) {
          cleanupFailures.push(cleanup);
        }
      }
      cleanupFailures.push(
        ...(await discardPreparedStages(authority.port, authority.lock, preparedOrdinary)),
      );
    }
    if (reservation !== undefined && isRetainedOrIndeterminate(error)) {
      const cleanup = isBoundCredentialReservation(authority, reservation)
        ? await retainReservationForRecovery(
            authority.port,
            authority.lock,
            authority.walPath,
            authority.record,
            reservation,
          )
        : await discardReservation(authority.port, authority.lock, reservation);
      if (cleanup !== undefined) {
        cleanupFailures.push(cleanup);
      }
    }
    const original = failure(failureStage(error, 'setup-apply'));
    if (isRetainedOrIndeterminate(error) || cleanupFailures.length !== 0) {
      return closeSetupResult(authority, recoveryRequired([original, ...cleanupFailures]));
    }
    authority.state = 'compensating';
    const result = await compensateClaimedSetupTransaction(authority);
    if (result.state === 'never-installed') {
      throw convergedTransactionError('setup', error, 'setup-apply', 'never-installed');
    }
    return withFailure(result, original);
  }
}

/** Commit is durable before manifest publication and WAL cleanup. */
export async function publishSetupTransaction(
  receipt: SetupTransactionReceipt,
): Promise<LifecycleTransactionResult> {
  const internal = unwrapReceipt(receipt);
  const authority = internal.authority;
  if (authority.state === 'release-pending') {
    return closeSetupResult(
      authority,
      authority.pendingCloseResult ?? recoveryRequired([failure('lock-release')]),
    );
  }
  claimSetupAuthority(authority, 'receipt-pending', 'publishing');
  try {
    await boundary(authority.port, 'lock-acquire', () => authority.lock.revalidate());
    const record = internal.record;
    if (record.operation !== 'setup' || record.direction !== 'rollback') {
      return await closeSetupResult(authority, recoveryRequired([failure('setup-authority')]));
    }
    const committed = bindWal({ ...record, direction: 'commit', phase: 'commit-decided' });
    if (committed.operation !== 'setup' || committed.direction !== 'commit') {
      return await closeSetupResult(authority, recoveryRequired([failure('setup-authority')]));
    }
    await writeWal(authority.port, authority.lock, authority.walPath, committed, record, () => {
      authority.record = committed;
    });
    if (
      !(await finishForwardSetup(authority.port, authority.lock, committed, authority.stagedWrites))
    ) {
      return await closeSetupResult(authority, recoveryRequired([failure('third-state')]));
    }
    if (!(await removeExactWal(authority.port, authority.lock, authority.walPath, committed))) {
      return await closeSetupResult(authority, recoveryRequired([failure('cleanup')]));
    }
    return await closeSetupResult(authority, completed('active'));
  } catch (error) {
    return await closeSetupResult(
      authority,
      recoveryRequired(failuresFromError(error, 'setup-publish')),
    );
  }
}

/**
 * Reverses only rollback-directed setup. Original/result checks are exact;
 * replacement third states keep the WAL for an explicit later recovery.
 */
export async function compensateSetupTransaction(
  handle: SetupTransactionAuthority,
): Promise<LifecycleTransactionResult> {
  const authority = unwrapSetupAuthority(handle);
  if (authority.state === 'release-pending') {
    return closeSetupResult(
      authority,
      authority.pendingCloseResult ?? recoveryRequired([failure('lock-release')]),
    );
  }
  claimSetupAuthority(authority, ['open', 'receipt-pending'], 'compensating');
  return compensateClaimedSetupTransaction(authority);
}

async function compensateClaimedSetupTransaction(
  authority: InternalSetupAuthority,
): Promise<LifecycleTransactionResult> {
  const record = authority.record;
  if (record === undefined) {
    const cleanupFailures = await discardUnpublishedSetupReservations(authority);
    return closeSetupResult(
      authority,
      cleanupFailures.length === 0
        ? completed('never-installed')
        : recoveryRequired(cleanupFailures),
    );
  }
  if (record.operation !== 'setup' || record.direction !== 'rollback') {
    return closeSetupResult(authority, recoveryRequired([failure('setup-commit-decided')]));
  }
  try {
    await boundary(authority.port, 'lock-acquire', () => authority.lock.revalidate());
    if (authority.credentialReservation !== undefined) {
      if (!isBoundCredentialReservation(authority, authority.credentialReservation)) {
        return closeSetupResult(authority, recoveryRequired([failure('setup-authority')]));
      }
      const discarded = await discardReservation(
        authority.port,
        authority.lock,
        authority.credentialReservation,
      );
      if (discarded !== undefined) {
        return closeSetupResult(authority, recoveryRequired([discarded]));
      }
      authority.credentialReservation = undefined;
    }
    if (!(await rollbackSetupRecord(authority.port, authority.lock, record))) {
      return closeSetupResult(authority, recoveryRequired([failure('third-state')]));
    }
    if (!(await removeExactWal(authority.port, authority.lock, authority.walPath, record))) {
      return closeSetupResult(authority, recoveryRequired([failure('cleanup')]));
    }
    return closeSetupResult(authority, completed('never-installed'));
  } catch (error) {
    return closeSetupResult(
      authority,
      recoveryRequired(failuresFromError(error, 'setup-rollback')),
    );
  }
}

/**
 * Uninstall persists every reversible ordinary mutation and its preimage in a
 * rollback/prepared WAL. The fsynced commit decision precedes the only
 * nonreversible operation: deletion of an exact setup-created credential.
 */
export async function applyUninstallTransaction(
  input: ApplyUninstallTransactionInput,
): Promise<LifecycleTransactionResult> {
  let manifest: SetupManifestV1;
  let lock: LifecycleAdvisoryLock | undefined;
  let ordinary: readonly PreparedOrdinaryMutation[] = Object.freeze([]);
  let publishedRecord: Extract<WalRecordV2, { readonly operation: 'uninstall' }> | undefined;
  let result: LifecycleTransactionResult | undefined;
  let primaryError: unknown;
  let hasPrimaryError = false;
  let lockReleaseFailure: LifecycleTransactionFailure | undefined;
  try {
    manifest = parseSetupManifestV1(input.manifest);
    validateStatePaths(input.lockPath, input.walPath, input.manifestPath, input.receiptPath);
    if (!validId(input.operationId) || manifest.installId === '') {
      throw bounded('uninstall-authority');
    }
    const manifestJson = serializeSetupManifestV1(manifest);
    const manifestBytes = validateWalManifestBudget(manifest, manifestJson);
    lock = await boundary(input.port, 'lock-acquire', () =>
      input.port.acquireAdvisoryLock(input.lockPath),
    );
    await boundary(input.port, 'lock-acquire', () => lock!.revalidate());
    validateUninstallAuthority(manifest, input);
    await assertExactFile(input.port, input.manifestPath, encode(manifestJson));
    await assertAbsent(input.port, input.walPath);
    const capturedPreimages = await captureUninstallPreimages(input.port, manifest, input);
    const uninstallIntents = await materializeUninstallIntents(
      input.port,
      manifest,
      capturedPreimages,
      input.manifestPath,
      input.receiptPath,
      input.operationId,
    );
    const stagePreimages = uninstallIntents.flatMap((intent, step) =>
      intent.action === 'write'
        ? [
            Object.freeze({
              path: auxiliaryPath(intent.path, input.operationId, step, 'stage'),
              state: 'absent' as const,
            }),
          ]
        : [],
    );
    const preimages = freezePreimages([...capturedPreimages, ...stagePreimages]);
    validateOrdinaryIntents(
      uninstallIntents,
      validateWalPreimageBudget(preimages) + manifestBytes,
      validateWalPreimageStructuralBudget(preimages),
      input.operationId,
      0,
    );
    let record = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: input.operationId,
      installId: manifest.installId,
      operation: 'uninstall',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: input.lockPath,
      manifestPath: input.manifestPath,
      receiptPath: input.receiptPath,
      manifest,
      cursor: 0,
      preimages: toWalPreimages(preimages),
      mutations: [],
    });
    if (record.operation !== 'uninstall') {
      throw bounded('uninstall-authority');
    }
    let preparedRecord: Extract<WalRecordV2, { readonly operation: 'uninstall' }> = record;
    await writeWal(input.port, lock, input.walPath, record, undefined, () => {
      publishedRecord = preparedRecord;
    });

    for (const item of uninstallIntents) {
      const persisted = await persistOrdinaryMutationWithIntent({
        port: input.port,
        lock,
        walPath: input.walPath,
        record,
        item,
        onPublished: (next) => {
          if (next.operation !== 'uninstall') {
            throw bounded('uninstall-authority');
          }
          preparedRecord = next;
          publishedRecord = next;
        },
      });
      if (persisted.record.operation !== 'uninstall') {
        throw bounded('uninstall-authority');
      }
      record = persisted.record;
      ordinary = Object.freeze([...ordinary, persisted.prepared]);
      if (
        !(await forwardOrdinaryMutation(
          input.port,
          lock,
          record,
          persisted.prepared.mutation,
          persisted.prepared.stage,
        ))
      ) {
        throw bounded('target-rename');
      }
    }
    if (record.operation !== 'uninstall' || record.direction !== 'rollback') {
      throw bounded('uninstall-authority');
    }
    if (!(await validateSetupCreatedCredentialsForUninstall(input.port, lock, record))) {
      throw bounded('uninstall-commit-decided');
    }

    const committed = bindWal({ ...record, direction: 'commit', phase: 'commit-decided' });
    if (committed.operation !== 'uninstall' || committed.direction !== 'commit') {
      throw bounded('uninstall-commit-decided');
    }
    await boundary(input.port, 'uninstall-commit-decided', () =>
      writeWal(input.port, lock!, input.walPath, committed, record, () => {
        publishedRecord = committed;
      }),
    );
    result = await finishUninstallCommit(input.port, lock, input.walPath, committed);
  } catch (error) {
    if (lock === undefined) {
      primaryError = transactionError(
        'uninstall',
        error,
        failureStage(error, 'uninstall-authority'),
      );
      hasPrimaryError = true;
    } else {
      const cleanupFailures: LifecycleTransactionFailure[] = [
        ...cleanupFailuresFrom(error),
        ...(publishedRecord === undefined
          ? await discardPreparedStages(input.port, lock, ordinary)
          : await retainPreparedStagesForRecovery(
              input.port,
              lock,
              input.walPath,
              publishedRecord,
              ordinary,
            )),
      ];
      let recovered: LifecycleTransactionResult | undefined;
      if (
        !isRetainedOrIndeterminate(error) &&
        publishedRecord !== undefined &&
        cleanupFailures.length === 0
      ) {
        try {
          recovered = await rollbackUninstallFromDisk(
            input.port,
            lock,
            input.walPath,
            publishedRecord,
          );
        } catch (rollbackError) {
          recovered = recoveryRequired(failuresFromError(rollbackError, 'wal-authority'));
        }
      }
      const originalFailure = failure(failureStage(error, 'uninstall-apply'));
      result =
        cleanupFailures.length !== 0
          ? recoveryRequired([originalFailure, ...cleanupFailures])
          : recovered === undefined
            ? recoveryRequired([originalFailure])
            : withFailures(recovered, [originalFailure]);
    }
  } finally {
    if (lock !== undefined) {
      lockReleaseFailure = await releaseLock(input.port, lock);
      lock = undefined;
    }
  }

  if (hasPrimaryError) {
    const failures =
      primaryError instanceof LifecycleTransactionError
        ? primaryError.failures
        : failuresFromError(primaryError, 'uninstall-apply');
    if (lockReleaseFailure !== undefined) {
      throw new LifecycleTransactionError('uninstall', [...failures, lockReleaseFailure]);
    }
    throw primaryError;
  }
  if (result === undefined) {
    throw new LifecycleTransactionError(
      'uninstall',
      lockReleaseFailure === undefined
        ? [failure('uninstall-apply')]
        : [failure('uninstall-apply'), lockReleaseFailure],
    );
  }
  return lockReleaseFailure === undefined ? result : releasePending(result, lockReleaseFailure);
}

/**
 * Fresh recovery reloads the WAL from its fixed configured path. It accepts no
 * operations, preimages, manifest, or target paths out of band.
 */
export async function recoverLifecycle(
  input: RecoverLifecycleInput,
): Promise<LifecycleTransactionResult> {
  let lock: LifecycleAdvisoryLock | undefined;
  let result: LifecycleTransactionResult | undefined;
  let primaryFailures: readonly LifecycleTransactionFailure[] | undefined;
  let lockReleaseFailure: LifecycleTransactionFailure | undefined;
  try {
    validateStatePaths(input.lockPath, input.walPath, input.manifestPath, input.receiptPath);
    lock = await boundary(input.port, 'lock-acquire', () =>
      input.port.acquireAdvisoryLock(input.lockPath),
    );
    await boundary(input.port, 'lock-acquire', () => lock!.revalidate());
    const stagePath = walStagingPath(input.walPath);
    let currentAuthority = await readWalAuthority(input.port, lock!, input.walPath);
    let current = currentAuthority?.serialized;
    if (current === undefined) {
      const adopted = await adoptAuthoritativeUnpublishedWalStage(
        input.port,
        lock!,
        input.walPath,
        stagePath,
        input,
      );
      if (adopted === 'foreign') {
        result = recoveryRequired([failure('wal-authority')]);
      } else if (adopted === 'absent') {
        await boundary(input.port, 'lock-acquire', () => lock!.revalidate());
        if (
          (await readWal(input.port, lock!, input.walPath)) !== undefined ||
          (await input.port.lstatNoFollow(stagePath)) !== undefined
        ) {
          result = recoveryRequired([failure('wal-authority')]);
        } else {
          result = await classifyAbsentWalTerminal(input.port, lock!, input);
        }
      } else {
        await boundary(input.port, 'lock-acquire', () => lock!.revalidate());
        currentAuthority = await readWalAuthority(input.port, lock!, input.walPath);
        current = currentAuthority?.serialized;
        if (current === undefined) {
          result = recoveryRequired([failure('wal-authority')]);
        }
      }
    }
    if (result === undefined) {
      if (
        current === undefined ||
        (input.expectedRecoveryId !== undefined && recoveryId(current) !== input.expectedRecoveryId)
      ) {
        result = recoveryRequired([failure('wal-authority')]);
      } else {
        const parsed = parseWalRecordJson(current);
        if (parsed.classification === 'legacy-v1-recovery-required') {
          result = recoveryRequired([failure('legacy-v1-recovery-required')]);
        } else {
          const record = parsed.record;
          if (
            !matchesConfiguredRecovery(record, input) ||
            !hasValidAuthorityFingerprint(record) ||
            (record.creationIntents ?? []).some(
              (intent) => creationIntentAuthority(record, intent) === undefined,
            ) ||
            currentAuthority === undefined ||
            !(await discardReplacedWalStage(
              input.port,
              lock!,
              stagePath,
              currentAuthority,
              record,
              input,
            )) ||
            (await hasLegacyWalStageResidue(input.port, input.walPath, record.operationId))
          ) {
            result = recoveryRequired([failure('wal-authority')]);
          } else {
            result =
              record.operation === 'setup'
                ? await recoverSetupRecord(input.port, lock, input.walPath, record)
                : await recoverUninstallRecord(input.port, lock, input.walPath, record);
          }
        }
      }
    }
  } catch (error) {
    primaryFailures =
      error instanceof LifecycleTransactionError
        ? error.failures
        : failuresFromError(error, 'recovery');
  } finally {
    if (lock !== undefined) {
      lockReleaseFailure = await releaseLock(input.port, lock);
      lock = undefined;
    }
  }

  if (primaryFailures !== undefined) {
    return recoveryRequired(
      lockReleaseFailure === undefined ? primaryFailures : [...primaryFailures, lockReleaseFailure],
    );
  }
  if (result === undefined) {
    return recoveryRequired(
      lockReleaseFailure === undefined
        ? [failure('recovery')]
        : [failure('recovery'), lockReleaseFailure],
    );
  }
  return lockReleaseFailure === undefined ? result : releasePending(result, lockReleaseFailure);
}

async function adoptAuthoritativeUnpublishedWalStage(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  stagePath: string,
  input: RecoverLifecycleInput,
): Promise<'absent' | 'adopted' | 'foreign'> {
  let staged: WalObservation | undefined;
  try {
    staged = await observeWal(port, lock, stagePath);
    if (staged === undefined) {
      return 'absent';
    }
    const stagedAuthority = staged;
    if (stagedAuthority.mode !== 0o600) {
      return 'foreign';
    }
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(stagedAuthority.bytes);
    const parsed = parseWalRecordJson(serialized);
    if (
      parsed.classification !== 'v2-recovery-authority' ||
      parsed.record.replacedWalStage !== undefined ||
      (input.expectedRecoveryId !== undefined &&
        recoveryId(serialized) !== input.expectedRecoveryId) ||
      !matchesConfiguredRecovery(parsed.record, input) ||
      !hasValidAuthorityFingerprint(parsed.record) ||
      (parsed.record.creationIntents ?? []).some(
        (intent) => creationIntentAuthority(parsed.record, intent) === undefined,
      ) ||
      !sameBytes(stagedAuthority.bytes, encode(serializeWalRecordV2(parsed.record)))
    ) {
      return 'foreign';
    }
    await boundary(port, 'target-rename', () =>
      port.publishExactStagedFile({
        lock,
        stagingPath: stagePath,
        targetPath: walPath,
        identity: stagedAuthority.identity,
        mode: stagedAuthority.mode,
      }),
    );
    await boundary(port, 'wal-fsync', () => port.fsyncFile({ lock, path: walPath }));
    await boundary(port, 'parent-fsync', () => port.fsyncParent({ lock, path: walPath }));
    return 'adopted';
  } catch {
    return 'foreign';
  } finally {
    staged?.bytes.fill(0);
  }
}

async function discardReplacedWalStage(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  stagePath: string,
  currentObservation: ReadWalAuthority,
  current: WalRecordV2,
  input: RecoverLifecycleInput,
): Promise<boolean> {
  let staged: WalObservation | undefined;
  try {
    staged = await observeWal(port, lock, stagePath);
    if (staged === undefined) {
      return true;
    }
    const parsed = parseWalRecordJson(
      new TextDecoder('utf-8', { fatal: true }).decode(staged.bytes),
    );
    if (
      parsed.classification !== 'v2-recovery-authority' ||
      !isReplacedWalStageAuthority(parsed.record, staged, currentObservation, current, input)
    ) {
      return false;
    }
    return removeObservedWalStage(port, lock, stagePath, staged);
  } catch {
    return false;
  } finally {
    staged?.bytes.fill(0);
  }
}

function isReplacedWalStageAuthority(
  staged: WalRecordV2,
  stagedObservation: WalObservation,
  currentObservation: ReadWalAuthority,
  current: WalRecordV2,
  input: RecoverLifecycleInput,
): boolean {
  const lineage = replacedWalStageLineage(staged);
  return (
    lineage !== undefined &&
    lineage.mode === currentObservation.mode &&
    sameIdentity(lineage.identity, currentObservation.identity) &&
    lineage.authorityFingerprint === current.authorityFingerprint &&
    staged.operation === current.operation &&
    staged.operationId === current.operationId &&
    staged.installId === current.installId &&
    staged.lockPath === current.lockPath &&
    staged.manifestPath === current.manifestPath &&
    matchesConfiguredRecovery(staged, input) &&
    hasValidAuthorityFingerprint(staged) &&
    !(staged.creationIntents ?? []).some(
      (intent) => creationIntentAuthority(staged, intent) === undefined,
    ) &&
    stagedObservation.mode === 0o600 &&
    serializeWalRecordV2(staged) !== serializeWalRecordV2(current)
  );
}

async function removeObservedWalStage(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  stagePath: string,
  staged: WalObservation,
): Promise<boolean> {
  const removed = await exactMutationBoundary(port, 'cleanup', () =>
    port.removeExactWal({
      lock,
      current: { path: stagePath, identity: staged.identity, mode: staged.mode },
      snapshot: staged.snapshot,
    }),
  );
  if (removed.state !== 'completed') {
    return false;
  }
  await finalizeExactMutation(port, lock, 'cleanup', removed);
  return true;
}
async function classifyAbsentWalTerminal(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  input: RecoverLifecycleInput,
): Promise<LifecycleTransactionResult> {
  const manifest = await observeExactTerminalFile(port, input.manifestPath);
  const receipt =
    input.receiptPath === undefined
      ? undefined
      : await observeExactTerminalFile(port, input.receiptPath);
  try {
    const activeManifest =
      manifest === undefined || manifest === null
        ? undefined
        : parseExactActiveManifest(manifest.bytes);
    const uninstalledReceipt =
      receipt === undefined || receipt === null
        ? undefined
        : parseExactUninstalledReceipt(receipt.bytes);

    let terminal: LifecycleTransactionResult;
    if (
      activeManifest !== undefined &&
      (receipt === undefined ||
        (uninstalledReceipt !== undefined &&
          uninstalledReceipt.installId !== activeManifest.installId))
    ) {
      terminal = completed('active');
    } else if (manifest === undefined && uninstalledReceipt !== undefined) {
      terminal = completed('uninstalled');
    } else if (manifest === undefined && receipt === undefined) {
      terminal = completed('never-installed');
    } else {
      terminal = recoveryRequired([failure('terminal-authority')]);
    }
    await lock.revalidate();
    return terminal;
  } finally {
    manifest?.bytes.fill(0);
    receipt?.bytes.fill(0);
  }
}

async function observeExactTerminalFile(
  port: LifecycleTransactionPort,
  path: string,
): Promise<OrdinaryObservation | undefined | null> {
  const expected = await port.lstatNoFollow(path);
  if (expected === undefined) {
    return undefined;
  }
  if (!sameObservation(expected, expected.identity, 0o600)) {
    return null;
  }
  const observed = await observeOrdinary(port, path);
  const observedBytes = observed?.bytes;
  if (observed === undefined || !sameObservation(observed, expected.identity, expected.mode)) {
    observedBytes?.fill(0);
    return null;
  }
  return observed;
}

function parseExactActiveManifest(bytes: Uint8Array): SetupManifestV1 | undefined {
  try {
    return parseSetupManifestJsonV1(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

function parseExactUninstalledReceipt(
  bytes: Uint8Array,
): ReturnType<typeof parseLifecycleReceiptJsonV1> | undefined {
  try {
    const receipt = parseLifecycleReceiptJsonV1(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    );
    return receipt.terminalState === 'uninstalled' ? receipt : undefined;
  } catch {
    return undefined;
  }
}
async function recoverSetupRecord(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
): Promise<LifecycleTransactionResult> {
  if (record.direction === 'rollback') {
    if (!(await rollbackSetupRecord(port, lock, record))) {
      return recoveryRequired([failure('third-state')]);
    }
    return (await removeExactWal(port, lock, walPath, record))
      ? completed('never-installed')
      : recoveryRequired([failure('cleanup')]);
  }
  const manifest = manifestFromSetupRecord(record);
  if (manifest === undefined) {
    return recoveryRequired([failure('manifest-authority')]);
  }
  if (!(await finishForwardSetup(port, lock, record))) {
    return recoveryRequired([failure('third-state')]);
  }
  return (await removeExactWal(port, lock, walPath, record))
    ? completed('active')
    : recoveryRequired([failure('cleanup')]);
}

async function recoverUninstallRecord(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<LifecycleTransactionResult> {
  if (record.direction === 'rollback') {
    if (
      !(await rollbackCreationIntents(port, lock, record)) ||
      !(await rollbackOrdinaryMutations(port, lock, record)) ||
      !(await untouchedUnboundPreimages(port, record))
    ) {
      return recoveryRequired([failure('third-state')]);
    }
    return (await removeExactWal(port, lock, walPath, record))
      ? completed('active')
      : recoveryRequired([failure('cleanup')]);
  }
  return finishUninstallCommit(port, lock, walPath, record);
}

async function rollbackUninstallFromDisk(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  expected: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<LifecycleTransactionResult | undefined> {
  const json = await readWal(port, lock, walPath);
  if (
    json === undefined ||
    (json !== serializeWalRecordV2(expected) &&
      !sameWalRecordIgnoringReplacedStage(encode(json), expected))
  ) {
    return undefined;
  }
  const parsed = parseWalRecordJson(json);
  if (parsed.classification !== 'v2-recovery-authority') {
    return undefined;
  }
  const record = parsed.record;
  if (
    record.operation !== 'uninstall' ||
    record.direction !== 'rollback' ||
    !hasValidAuthorityFingerprint(record) ||
    (serializeWalRecordV2(record) !== serializeWalRecordV2(expected) &&
      !sameWalRecordIgnoringReplacedStage(encode(serializeWalRecordV2(record)), expected))
  ) {
    return undefined;
  }
  if (
    !(await rollbackCreationIntents(port, lock, record)) ||
    !(await rollbackOrdinaryMutations(port, lock, record)) ||
    !(await untouchedUnboundPreimages(port, record))
  ) {
    return recoveryRequired([failure('third-state')]);
  }
  return (await removeExactWal(port, lock, walPath, record))
    ? completed('active')
    : recoveryRequired([failure('cleanup')]);
}

async function finishForwardSetup(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
  stages: ReadonlyMap<string, LifecycleStagedWrite> | undefined = undefined,
): Promise<boolean> {
  for (const mutation of setupStateMutations(record)) {
    if (mutation.kind === 'credential') {
      if (!(await validateCredentialMutation(port, lock, mutation))) {
        return false;
      }
      continue;
    }
    if (
      !(await forwardOrdinaryMutation(
        port,
        lock,
        record,
        mutation,
        stages?.get(mutation.stagingPath),
      ))
    ) {
      return false;
    }
  }
  if (!(await publishSetupManifest(port, lock, record, stages))) {
    return false;
  }
  return cleanupForwardOrdinary(port, lock, record);
}

async function finishUninstallCommit(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<LifecycleTransactionResult> {
  try {
    if (!hasUninstallTerminalMutationAuthority(record)) {
      return recoveryRequired([failure('third-state')]);
    }
    for (const mutation of ordinaryMutations(record)) {
      if (!(await forwardOrdinaryMutation(port, lock, record, mutation))) {
        return recoveryRequired([failure('third-state')]);
      }
    }
    if (!(await cleanupForwardOrdinary(port, lock, record))) {
      return recoveryRequired([failure('third-state')]);
    }
    if (!(await deleteSetupCreatedCredentials(port, lock, record))) {
      return recoveryRequired([failure('third-state')]);
    }
    if (!(await purgeManagedViteRuntime(port, lock, record))) {
      return recoveryRequired([failure('third-state')]);
    }
    if (!(await deleteSetupCreatedDirectories(port, lock, record))) {
      return recoveryRequired([failure('third-state')]);
    }
    if (!(await removeExactWal(port, lock, walPath, record))) {
      return recoveryRequired([failure('cleanup')]);
    }
    return completed('uninstalled');
  } catch (error) {
    return recoveryRequired(failuresFromError(error, 'uninstall-forward'));
  }
}
function hasUninstallTerminalMutationAuthority(
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): boolean {
  const receipt = serializeLifecycleReceiptV1({
    schemaVersion: 1,
    kind: 'scene-glass-lifecycle-receipt',
    operationId: record.operationId,
    installId: record.installId,
    terminalState: 'uninstalled',
    manifestFingerprint: fingerprint(serializeSetupManifestV1(record.manifest)),
  });
  const receiptMutations = ordinaryMutations(record).filter(
    (mutation) => mutation.targetPath === record.receiptPath,
  );
  const manifestMutations = ordinaryMutations(record).filter(
    (mutation) => mutation.targetPath === record.manifestPath,
  );
  const receiptMutation = receiptMutations[0];
  const manifestMutation = manifestMutations[0];
  if (
    receiptMutations.length !== 1 ||
    manifestMutations.length !== 1 ||
    receiptMutation === undefined ||
    manifestMutation === undefined ||
    receiptMutation.result.kind !== 'file' ||
    receiptMutation.result.mode !== 0o600 ||
    !sameBytes(Buffer.from(receiptMutation.result.bytes, 'base64'), encode(receipt)) ||
    manifestMutation.result.kind !== 'absent'
  ) {
    return false;
  }
  const receiptPreimage = preimageFor(record, receiptMutation);
  const manifestPreimage = preimageFor(record, manifestMutation);
  return (
    (receiptPreimage.kind === 'absent' || receiptPreimage.kind === 'file') &&
    manifestPreimage.kind === 'file' &&
    sameBytes(
      Buffer.from(manifestPreimage.bytes, 'base64'),
      encode(serializeSetupManifestV1(record.manifest)),
    )
  );
}

async function rollbackSetupRecord(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
): Promise<boolean> {
  if (!(await rollbackCreationIntents(port, lock, record))) {
    return false;
  }
  for (const mutation of [...record.mutations].reverse()) {
    if (mutation.kind === 'credential') {
      if (!(await rollbackCredentialMutation(port, lock, record, mutation))) {
        return false;
      }
      continue;
    }
    if (!(await rollbackOrdinaryMutation(port, lock, record, mutation))) {
      return false;
    }
  }
  return untouchedUnboundPreimages(port, record);
}
async function rollbackCreationIntents(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
): Promise<boolean> {
  for (const intent of [...(record.creationIntents ?? [])].reverse()) {
    const authority = creationIntentAuthority(record, intent);
    if (authority === undefined || !(await rollbackCreationIntent(port, lock, authority))) {
      return false;
    }
  }
  return true;
}
async function rollbackCreationIntent(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  intent: LifecycleCreationIntentAuthority,
): Promise<boolean> {
  const cleanup = await exactMutationBoundary(port, 'cleanup', () =>
    port.recoverCreationIntent({
      lock,
      stagePath: intent.intent.stagingPath,
      markerPath: intent.markerPath,
      kind: intent.intent.kind,
      mode: intent.intent.mode,
    }),
  );
  await finalizeExactMutation(port, lock, 'cleanup', cleanup);
  return true;
}

async function rollbackOrdinaryMutations(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
): Promise<boolean> {
  for (const mutation of [...stateOrdinaryMutations(record)].reverse()) {
    if (!(await rollbackOrdinaryMutation(port, lock, record, mutation))) {
      return false;
    }
  }
  return true;
}

async function forwardOrdinaryMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
  mutation: WalOrdinaryMutationV2,
  stage: LifecycleStagedWrite | undefined = undefined,
): Promise<boolean> {
  if (mutation.result.kind === 'directory') {
    return forwardDirectoryMutation(port, lock, record, mutation);
  }
  const original = preimageFor(record, mutation);
  const target = await observeOrdinary(port, mutation.targetPath);
  const source = await observeOrdinary(port, mutation.sourcePath);
  const staged = await observeOrdinary(port, mutation.stagingPath);
  const state = classifyOrdinaryMutationState(original, mutation.result, target, source, staged);

  if (mutation.result.kind === 'absent') {
    if (original.kind === 'absent') {
      return state === 'stable-absent';
    }
    if (state === 'initial') {
      if (target === undefined) {
        return false;
      }
      const quarantine = await exactMutationBoundary(port, 'target-rename', () =>
        port.quarantineExactFile({
          lock,
          path: mutation.targetPath,
          identity: target.identity,
          mode: target.mode,
          quarantinePath: mutation.sourcePath,
        }),
      );
      requireQuarantineRetained(quarantine);
      return true;
    }
    if (state === 'source-preserved') {
      return true;
    }
    if (state === 'preimage-retained' && staged !== undefined) {
      return removeExactObservedFile(
        port,
        lock,
        mutation.stagingPath,
        staged,
        mutation.sourcePath,
        {
          size: staged.bytes.byteLength,
          digest: fingerprintBytes(staged.bytes),
        },
      );
    }
    return state === 'forward-cleaned';
  }

  if (state === 'preimage-retained') {
    return convergePreimageRetainedOrdinary(
      port,
      lock,
      original,
      mutation,
      target,
      source,
      staged,
      'commit',
    );
  }
  if (state === 'forward-complete' || state === 'forward-cleaned') {
    return true;
  }
  if (state === 'initial') {
    if (staged === undefined) {
      return false;
    }
    if (original.kind === 'file') {
      if (target === undefined) {
        return false;
      }
      const quarantine = await exactMutationBoundary(port, 'target-rename', () =>
        port.quarantineExactFile({
          lock,
          path: mutation.targetPath,
          identity: target.identity,
          mode: target.mode,
          quarantinePath: mutation.sourcePath,
        }),
      );
      requireQuarantineRetained(quarantine);
      return renameExact(
        port,
        lock,
        mutation.stagingPath,
        staged,
        mutation.targetPath,
        'target-rename',
        stage,
      );
    }
    return renameExact(
      port,
      lock,
      mutation.stagingPath,
      staged,
      mutation.targetPath,
      'target-rename',
      stage,
    );
  }
  if (state === 'source-preserved') {
    return staged !== undefined
      ? renameExact(
          port,
          lock,
          mutation.stagingPath,
          staged,
          mutation.targetPath,
          'target-rename',
          stage,
        )
      : false;
  }
  return false;
}

async function rollbackOrdinaryMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
  mutation: WalOrdinaryMutationV2,
): Promise<boolean> {
  if (mutation.result.kind === 'directory') {
    return rollbackDirectoryMutation(port, lock, record, mutation);
  }
  const original = preimageFor(record, mutation);
  const target = await observeOrdinary(port, mutation.targetPath);
  const source = await observeOrdinary(port, mutation.sourcePath);
  const staged = await observeOrdinary(port, mutation.stagingPath);
  const state = classifyOrdinaryMutationState(original, mutation.result, target, source, staged);

  if (mutation.result.kind === 'absent') {
    if (original.kind === 'absent') {
      return state === 'stable-absent';
    }
    if (state === 'initial' || state === 'rollback-complete') {
      return true;
    }
    if (state === 'source-preserved' && source !== undefined) {
      return renameExact(
        port,
        lock,
        mutation.sourcePath,
        source,
        mutation.targetPath,
        'target-rename',
      );
    }
    if (state === 'preimage-retained' && staged !== undefined) {
      return renameExact(
        port,
        lock,
        mutation.stagingPath,
        staged,
        mutation.targetPath,
        'target-rename',
      );
    }
    return false;
  }

  if (state === 'rollback-complete') {
    return true;
  }
  if (state === 'preimage-retained') {
    return convergePreimageRetainedOrdinary(
      port,
      lock,
      original,
      mutation,
      target,
      source,
      staged,
      'rollback',
    );
  }
  if (state === 'initial') {
    return discardExactResultStage(port, lock, mutation, staged, mutation.sourcePath);
  }
  if (state === 'forward-cleaned' && original.kind === 'absent' && target !== undefined) {
    return removeExactObservedFile(port, lock, mutation.targetPath, target, mutation.sourcePath, {
      size: target.bytes.byteLength,
      digest: fingerprintBytes(target.bytes),
    });
  }
  if (state === 'source-preserved') {
    if (
      original.kind !== 'file' ||
      source === undefined ||
      !matchesPresentPreimage(source, original)
    ) {
      return false;
    }
    if (
      !(await renameExact(
        port,
        lock,
        mutation.sourcePath,
        source,
        mutation.targetPath,
        'target-rename',
      ))
    ) {
      return false;
    }
    return discardExactResultStage(port, lock, mutation, staged, mutation.sourcePath);
  }
  if (state === 'forward-complete') {
    if (
      original.kind !== 'file' ||
      source === undefined ||
      !matchesPresentPreimage(source, original) ||
      target === undefined
    ) {
      return false;
    }
    const quarantine = await exactMutationBoundary(port, 'target-rename', () =>
      port.quarantineExactFile({
        lock,
        path: mutation.targetPath,
        identity: target.identity,
        mode: target.mode,
        quarantinePath: mutation.stagingPath,
        size: target.bytes.byteLength,
        digest: fingerprintBytes(target.bytes),
      }),
    );
    requireQuarantineRetained(quarantine);
    if (
      !(await renameExact(
        port,
        lock,
        mutation.sourcePath,
        source,
        mutation.targetPath,
        'target-rename',
      ))
    ) {
      return false;
    }
    await finalizeExactMutation(port, lock, 'target-rename', quarantine);
    return true;
  }
  return false;
}
async function convergePreimageRetainedOrdinary(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  original: OrdinaryWalPreimageV2,
  mutation: WalOrdinaryMutationV2,
  target: OrdinaryObservation | undefined,
  source: OrdinaryObservation | undefined,
  staged: OrdinaryObservation | undefined,
  direction: 'commit' | 'rollback',
): Promise<boolean> {
  const sourceIsResult = matchesOrdinaryResult(source, mutation.result);
  const targetIsResult = matchesOrdinaryResult(target, mutation.result);
  const targetIsPreimage = matchesPreimage(target, original);
  const stagedIsPreimage = original.kind === 'file' && matchesPresentPreimage(staged, original);

  if (sourceIsResult && staged === undefined && targetIsPreimage) {
    if (direction === 'rollback') {
      return removeExactObservedFile(
        port,
        lock,
        mutation.sourcePath,
        source!,
        mutation.stagingPath,
        {
          size: source!.bytes.byteLength,
          digest: fingerprintBytes(source!.bytes),
        },
      );
    }
    if (target === undefined || original.kind !== 'file') {
      return renameExact(
        port,
        lock,
        mutation.sourcePath,
        source!,
        mutation.targetPath,
        'target-rename',
      );
    }
    const replacement = await exactMutationBoundary(port, 'target-rename', () =>
      port.replaceExactStagedFileWithQuarantine({
        lock,
        stagingPath: mutation.sourcePath,
        targetPath: mutation.targetPath,
        identity: source!.identity,
        mode: source!.mode,
        current: {
          path: mutation.targetPath,
          identity: target.identity,
          mode: target.mode,
          size: target.bytes.byteLength,
          digest: fingerprintBytes(target.bytes),
        },
      }),
    );
    await finalizeExactMutation(port, lock, 'target-rename', replacement);
    return true;
  }

  if (targetIsResult && source === undefined && stagedIsPreimage) {
    if (direction === 'commit') {
      return removeExactObservedFile(
        port,
        lock,
        mutation.stagingPath,
        staged!,
        mutation.sourcePath,
        {
          size: staged!.bytes.byteLength,
          digest: fingerprintBytes(staged!.bytes),
        },
      );
    }
    if (target === undefined) {
      return false;
    }
    const replacement = await exactMutationBoundary(port, 'target-rename', () =>
      port.replaceExactStagedFileWithQuarantine({
        lock,
        stagingPath: mutation.stagingPath,
        targetPath: mutation.targetPath,
        identity: staged!.identity,
        mode: staged!.mode,
        current: {
          path: mutation.targetPath,
          identity: target.identity,
          mode: target.mode,
          size: target.bytes.byteLength,
          digest: fingerprintBytes(target.bytes),
        },
      }),
    );
    await finalizeExactMutation(port, lock, 'target-rename', replacement);
    return true;
  }

  return false;
}

async function forwardDirectoryMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
  mutation: WalOrdinaryMutationV2,
): Promise<boolean> {
  const original = preimageFor(record, mutation);
  const result = mutation.result;
  if (original.kind !== 'absent' || result.kind !== 'directory') {
    return false;
  }
  const target = await port.lstatNoFollow(mutation.targetPath);
  const source = await port.lstatNoFollow(mutation.sourcePath);
  const stage = await port.lstatNoFollow(mutation.stagingPath);
  if (
    source === undefined &&
    sameDirectoryObservation(target, result.identity, result.mode) &&
    stage === undefined
  ) {
    return (
      (
        await port.validateExactDirectory({
          lock,
          directory: {
            path: mutation.targetPath,
            identity: result.identity,
            mode: result.mode,
          },
        })
      ).state === 'completed'
    );
  }
  if (
    source === undefined &&
    target === undefined &&
    sameDirectoryObservation(stage, result.identity, result.mode) &&
    record.cursor > mutation.step
  ) {
    throw bounded('preimage-retained');
  }
  if (
    source !== undefined ||
    target !== undefined ||
    !sameDirectoryObservation(stage, result.identity, result.mode)
  ) {
    return false;
  }
  try {
    await boundary(port, 'directory-publish', () =>
      port.publishExactStagedDirectory({
        lock,
        stagingPath: mutation.stagingPath,
        targetPath: mutation.targetPath,
        identity: result.identity,
        mode: result.mode,
      }),
    );
    if (
      !sameDirectoryObservation(
        await port.lstatNoFollow(mutation.targetPath),
        result.identity,
        result.mode,
      ) ||
      (await port.lstatNoFollow(mutation.stagingPath)) !== undefined
    ) {
      return false;
    }
    if (
      (
        await port.validateExactDirectory({
          lock,
          directory: {
            path: mutation.targetPath,
            identity: result.identity,
            mode: result.mode,
          },
        })
      ).state !== 'completed'
    ) {
      return false;
    }
    await boundary(port, 'directory-fsync', () =>
      port.fsyncDirectory({ lock, path: mutation.targetPath }),
    );
    await boundary(port, 'parent-fsync', () =>
      port.fsyncParent({ lock, path: mutation.targetPath }),
    );
    return true;
  } catch {
    return false;
  }
}

async function rollbackDirectoryMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
  mutation: WalOrdinaryMutationV2,
): Promise<boolean> {
  const original = preimageFor(record, mutation);
  const result = mutation.result;
  if (original.kind !== 'absent' || result.kind !== 'directory') {
    return false;
  }
  const target = await port.lstatNoFollow(mutation.targetPath);
  const source = await port.lstatNoFollow(mutation.sourcePath);
  const stage = await port.lstatNoFollow(mutation.stagingPath);
  if (source !== undefined) {
    return false;
  }
  const targetMatches = sameDirectoryObservation(target, result.identity, result.mode);
  const stageMatches = sameDirectoryObservation(stage, result.identity, result.mode);
  if (target === undefined && stage === undefined) {
    return true;
  }
  if (targetMatches && stage === undefined) {
    return removeExactDirectory(
      port,
      lock,
      {
        path: mutation.targetPath,
        identity: result.identity,
        mode: result.mode,
      },
      mutation.stagingPath,
    );
  }
  if (stageMatches && target === undefined) {
    try {
      await boundary(port, 'directory-publish', () =>
        port.publishExactStagedDirectory({
          lock,
          stagingPath: mutation.stagingPath,
          targetPath: mutation.targetPath,
          identity: result.identity,
          mode: result.mode,
        }),
      );
    } catch {
      return false;
    }
    return removeExactDirectory(
      port,
      lock,
      {
        path: mutation.targetPath,
        identity: result.identity,
        mode: result.mode,
      },
      mutation.stagingPath,
    );
  }
  return false;
}

async function discardExactResultStage(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  mutation: WalOrdinaryMutationV2,
  staged: OrdinaryObservation | undefined,
  quarantinePath: string,
): Promise<boolean> {
  if (staged === undefined) {
    return true;
  }
  if (!matchesOrdinaryResult(staged, mutation.result)) {
    return false;
  }
  return removeExactObservedFile(port, lock, mutation.stagingPath, staged, quarantinePath, {
    size: staged.bytes.byteLength,
    digest: fingerprintBytes(staged.bytes),
  });
}
function exactResultStage(mutation: WalOrdinaryMutationV2): LifecycleExactContentFile {
  const result = mutation.result;
  if (result.kind !== 'file') {
    throw bounded('wal-authority');
  }
  const bytes = Buffer.from(result.bytes, 'base64');
  return Object.freeze({
    path: mutation.stagingPath,
    identity: result.identity,
    mode: result.mode,
    size: bytes.byteLength,
    digest: fingerprintBytes(bytes),
  });
}

async function cleanupForwardOrdinary(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: WalRecordV2,
): Promise<boolean> {
  for (const mutation of stateOrdinaryMutations(record)) {
    const original = preimageFor(record, mutation);
    const source = await observeOrdinary(port, mutation.sourcePath);
    if (source === undefined) {
      continue;
    }
    if (original.kind !== 'file' || !matchesPreimage(source, original)) {
      return false;
    }
    if (
      !(await removeExactObservedFile(
        port,
        lock,
        mutation.sourcePath,
        source,
        mutation.stagingPath,
        {
          size: source.bytes.byteLength,
          digest: fingerprintBytes(source.bytes),
        },
      ))
    ) {
      return false;
    }
  }
  return true;
}

async function rollbackCredentialMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
  mutation: WalCredentialMutationV2,
): Promise<boolean> {
  const target = await port.lstatNoFollow(mutation.path);
  const stage = await port.lstatNoFollow(mutation.stagingPath);
  if (target !== undefined) {
    if (!sameObservation(target, mutation.targetIdentity, mutation.mode) || stage !== undefined) {
      return false;
    }
    return removeExactObservedFile(
      port,
      lock,
      mutation.path,
      target,
      mutation.stagingPath,
      'credential',
    );
  }
  if (stage !== undefined) {
    if (!sameObservation(stage, mutation.stagingIdentity, mutation.mode)) {
      return false;
    }
    if (record.cursor > mutation.step) {
      throw bounded('preimage-retained');
    }
    return removeExactObservedFile(
      port,
      lock,
      mutation.stagingPath,
      stage,
      mutation.path,
      'credential',
    );
  }
  return true;
}
async function validateCredentialMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  mutation: WalCredentialMutationV2,
): Promise<boolean> {
  if (
    !sameObservation(
      await port.lstatNoFollow(mutation.path),
      mutation.targetIdentity,
      mutation.mode,
    ) ||
    (await port.lstatNoFollow(mutation.stagingPath)) !== undefined
  ) {
    return false;
  }
  return (
    (
      await port.validateExactCredential({
        lock,
        credential: {
          path: mutation.path,
          identity: mutation.targetIdentity,
          mode: mutation.mode,
        },
      })
    ).state === 'completed'
  );
}

async function removeExactDirectory(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  directory: LifecycleExactDirectory,
  quarantinePath: string,
): Promise<boolean> {
  if (
    !sameDirectoryObservation(
      await port.lstatNoFollow(directory.path),
      directory.identity,
      directory.mode,
    )
  ) {
    return false;
  }
  const quarantine = await exactMutationBoundary(port, 'directory-remove', () =>
    port.quarantineExactDirectory({ lock, ...directory, quarantinePath }),
  );
  await finalizeExactMutation(port, lock, 'directory-remove', quarantine);
  return true;
}

async function deleteSetupCreatedCredentials(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<boolean> {
  for (const artifact of record.manifest.artifacts) {
    if (artifact.kind !== 'credential' || artifact.ownership !== 'setup-created') {
      continue;
    }
    const preimage = record.preimages.find((item) => item.path === artifact.path);
    if (
      preimage === undefined ||
      preimage.kind !== 'credential' ||
      !matchesCreatedCredentialArtifact(artifact, preimage.identity, preimage.mode)
    ) {
      return false;
    }
    const firstQuarantinePath = credentialQuarantinePath(record, artifact.path);
    const secondQuarantinePath = credentialRemovalQuarantinePath(artifact.path, preimage.identity);
    const locations = await Promise.all(
      [artifact.path, firstQuarantinePath, secondQuarantinePath].map(async (path) =>
        Object.freeze({ path, observation: await port.lstatNoFollow(path) }),
      ),
    );
    const remaining = locations.filter((location) => location.observation !== undefined);
    if (remaining.length === 0) {
      continue;
    }
    if (remaining.length !== 1) {
      return false;
    }
    const location = remaining[0];
    if (
      location === undefined ||
      location.observation === undefined ||
      !sameObservation(location.observation, preimage.identity, preimage.mode) ||
      (
        await port.validateExactCredential({
          lock,
          credential: {
            path: location.path,
            identity: preimage.identity,
            mode: preimage.mode,
          },
        })
      ).state !== 'completed'
    ) {
      return false;
    }

    if (location.path === artifact.path) {
      const quarantine = await exactMutationBoundary(port, 'credential-delete', () =>
        port.quarantineExactFile({
          lock,
          path: artifact.path,
          identity: preimage.identity,
          mode: preimage.mode,
          credential: true,
          quarantinePath: firstQuarantinePath,
        }),
      );
      await finalizeExactMutation(port, lock, 'credential-delete', quarantine);
      await boundary(port, 'parent-fsync', () => port.fsyncParent({ lock, path: artifact.path }));
    } else {
      const removed = await exactMutationBoundary(port, 'credential-delete', () =>
        port.removeExactCredential({
          lock,
          credential: {
            path: location.path,
            identity: preimage.identity,
            mode: preimage.mode,
          },
        }),
      );
      if (removed.state !== 'completed') {
        return false;
      }
      await finalizeExactMutation(port, lock, 'credential-delete', removed);
    }

    if (
      (
        await Promise.all(
          [artifact.path, firstQuarantinePath, secondQuarantinePath].map((path) =>
            port.lstatNoFollow(path),
          ),
        )
      ).some((observed) => observed !== undefined)
    ) {
      return false;
    }
  }
  return true;
}
async function purgeManagedViteRuntime(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<boolean> {
  const candidates = record.manifest.artifacts.filter(
    (item): item is Extract<SetupManifestV1['artifacts'][number], { readonly kind: 'directory' }> =>
      item.kind === 'directory' &&
      basename(item.path) === 'runtime' &&
      basename(dirname(item.path)) === '.scg',
  );
  const artifact = candidates[0];
  if (candidates.length === 0) {
    return true;
  }
  if (candidates.length !== 1 || artifact === undefined) {
    return false;
  }
  const path = artifact.path;
  const preimage = record.preimages.find((item) => item.path === path);
  if (
    artifact === undefined ||
    preimage === undefined ||
    preimage.kind !== 'directory' ||
    artifact.mode !== preimage.mode ||
    !sameIdentity(artifact.identity, preimage.identity)
  ) {
    return false;
  }
  const observed = await port.lstatNoFollow(path);
  if (observed === undefined) {
    return true;
  }
  if (!sameDirectoryObservation(observed, artifact.identity, artifact.mode)) {
    return false;
  }
  return port.purgeManagedViteRuntime({
    lock,
    directory: { path, identity: artifact.identity, mode: artifact.mode },
  });
}
async function deleteSetupCreatedDirectories(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<boolean> {
  for (const artifact of record.manifest.artifacts) {
    if (artifact.kind !== 'directory') {
      continue;
    }
    if (
      basename(artifact.path) === '.scg' &&
      record.manifest.artifacts.some(
        (candidate) =>
          candidate.kind === 'directory' && candidate.path === join(artifact.path, 'runtime'),
      ) &&
      (await port.lstatNoFollow(join(artifact.path, 'annotations'))) !== undefined
    ) {
      continue;
    }
    const preimage = record.preimages.find((item) => item.path === artifact.path);
    if (
      preimage === undefined ||
      preimage.kind !== 'directory' ||
      preimage.mode !== artifact.mode ||
      !sameIdentity(preimage.identity, artifact.identity)
    ) {
      return false;
    }
    const quarantinePath = directoryRemovalQuarantinePath(record, artifact);
    const observed = await port.lstatNoFollow(artifact.path);
    if (observed === undefined) {
      const quarantined = await port.lstatNoFollow(quarantinePath);
      if (quarantined === undefined) {
        continue;
      }
      const reconciliationPath = directoryRemovalReconciliationPath(quarantinePath);
      if (
        !sameDirectoryObservation(quarantined, artifact.identity, artifact.mode) ||
        (await port.lstatNoFollow(reconciliationPath)) !== undefined ||
        !(await removeExactDirectory(
          port,
          lock,
          { path: quarantinePath, identity: artifact.identity, mode: artifact.mode },
          reconciliationPath,
        ))
      ) {
        return false;
      }
      continue;
    }
    if (
      !sameDirectoryObservation(observed, artifact.identity, artifact.mode) ||
      !(await removeExactDirectory(port, lock, artifact, quarantinePath))
    ) {
      return false;
    }
  }
  return true;
}
async function validateSetupCreatedCredentialsForUninstall(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
): Promise<boolean> {
  for (const artifact of record.manifest.artifacts) {
    if (artifact.kind !== 'credential' || artifact.ownership !== 'setup-created') {
      continue;
    }
    const preimage = record.preimages.find((item) => item.path === artifact.path);
    if (
      preimage === undefined ||
      preimage.kind !== 'credential' ||
      !matchesCreatedCredentialArtifact(artifact, preimage.identity, preimage.mode)
    ) {
      return false;
    }
    const observed = await port.lstatNoFollow(artifact.path);
    if (
      !sameObservation(observed, preimage.identity, preimage.mode) ||
      (
        await port.validateExactCredential({
          lock,
          credential: {
            path: artifact.path,
            identity: preimage.identity,
            mode: preimage.mode,
          },
        })
      ).state !== 'completed'
    ) {
      return false;
    }
  }
  return true;
}
function matchesCreatedCredentialArtifact(
  artifact: Extract<
    SetupManifestV1['artifacts'][number],
    { readonly kind: 'credential'; readonly ownership: 'setup-created' }
  >,
  identity: LifecycleFileIdentity,
  mode: number,
): boolean {
  return (
    artifact.projectId !== undefined &&
    artifact.identity !== undefined &&
    artifact.mode === 0o600 &&
    artifact.linkCount === 1 &&
    mode === artifact.mode &&
    sameIdentity(artifact.identity, identity) &&
    artifact.inverse.kind === 'delete-created-credential' &&
    artifact.inverse.projectId === artifact.projectId &&
    artifact.inverse.identity !== undefined &&
    sameIdentity(artifact.inverse.identity, identity) &&
    artifact.inverse.mode === mode &&
    artifact.inverse.linkCount === 1
  );
}

async function persistOrdinaryMutationWithIntent(input: {
  readonly port: LifecycleTransactionPort;
  readonly lock: LifecycleAdvisoryLock;
  readonly walPath: string;
  readonly record: WalRecordV2;
  readonly item: OrdinaryMutationIntent;
  readonly onPublished: (record: WalRecordV2) => void;
}): Promise<{ readonly record: WalRecordV2; readonly prepared: PreparedOrdinaryMutation }> {
  const { port, lock, walPath, item, onPublished } = input;
  const step = input.record.mutations.length;
  const sourcePath = auxiliaryPath(item.path, input.record.operationId, step, 'rollback');
  const stagingPath = auxiliaryPath(item.path, input.record.operationId, step, 'stage');
  await assertAbsent(port, sourcePath);

  if (item.action === 'remove') {
    const mutation: WalOrdinaryMutationV2 = Object.freeze({
      step,
      kind: 'ordinary',
      targetPath: item.path,
      sourcePath,
      stagingPath,
      preimage: preimageIndex(input.record.preimages, item.path),
      result: Object.freeze({ kind: 'absent' }),
    });
    const record = bindWal({
      ...input.record,
      cursor: step + 1,
      mutations: Object.freeze([...input.record.mutations, mutation]),
    });
    await writeWal(port, lock, walPath, record, input.record, () => onPublished(record));
    return Object.freeze({
      record,
      prepared: Object.freeze({ mutation, action: 'remove' }),
    });
  }

  const resolvedIntent = resolveCreationIntent(
    input.record,
    input.record.operationId,
    item.path,
    stagingPath,
    'file',
    item.mode,
  );
  let intentRecord = input.record;
  if (!resolvedIntent.durable) {
    const { authorityFingerprint: ignoredAuthorityFingerprint, ...unboundRecord } = input.record;
    void ignoredAuthorityFingerprint;
    intentRecord = bindWal({
      ...unboundRecord,
      creationIntents: Object.freeze([resolvedIntent.intent.intent]),
    });
    await writeWal(port, lock, walPath, intentRecord, input.record, () =>
      onPublished(intentRecord),
    );
  }

  let stage: LifecycleStagedWrite | undefined;
  try {
    stage = await boundary(port, 'stage-write', () =>
      port.stageWrite({
        lock,
        stagingPath,
        bytes: item.bytes,
        mode: item.mode,
        creationIntentMarkerPath: resolvedIntent.intent.markerPath,
      }),
    );
    const observation = await port.lstatNoFollow(stage.path);
    if (
      stage.path !== stagingPath ||
      stage.state !== 'completed' ||
      stage.mode !== item.mode ||
      !sameObservation(observation, stage.identity, stage.mode)
    ) {
      throw bounded('stage-write');
    }
    const mutation: WalOrdinaryMutationV2 = Object.freeze({
      step,
      kind: 'ordinary',
      targetPath: item.path,
      sourcePath,
      stagingPath,
      preimage: preimageIndex(intentRecord.preimages, item.path),
      result: Object.freeze({
        kind: 'file',
        identity: stage.identity,
        mode: stage.mode,
        bytes: Buffer.from(item.bytes).toString('base64'),
      }),
    });
    const { creationIntents: ignoredCreationIntents, ...completedRecord } = intentRecord;
    void ignoredCreationIntents;
    const record = bindWal({
      ...completedRecord,
      cursor: step + 1,
      preimages: intentRecord.preimages.filter((preimage) => preimage.path !== stagingPath),
      mutations: Object.freeze([...intentRecord.mutations, mutation]),
    });
    await writeWal(port, lock, walPath, record, intentRecord, () => onPublished(record));
    return Object.freeze({
      record,
      prepared: Object.freeze({ mutation, action: 'write', stage }),
    });
  } catch (error) {
    if (stage !== undefined) {
      const retained = await retainStagedWriteForRecovery(port, lock, walPath, intentRecord, stage);
      if (retained !== undefined) {
        throw new CleanupFailure(error, [retained]);
      }
    }
    throw error;
  }
}

const MAX_WAL_IMAGE_BYTES = 1024 * 1024;
const MAX_WAL_IMAGE_TOTAL_BYTES = 16 * 1024 * 1024;
function validateWalManifestBudget(manifest: SetupManifestV1, manifestJson: string): number {
  const bytes = Buffer.byteLength(manifestJson, 'utf8');
  if (
    manifest.artifacts.length > MAX_WAL_MUTATIONS ||
    bytes > MAX_WAL_IMAGE_BYTES ||
    bytes > MAX_WAL_STRUCTURAL_BYTES
  ) {
    throw bounded('wal-authority');
  }
  return bytes;
}
function validateWalPreimageStructuralBudget(preimages: readonly LifecyclePreimage[]): number {
  if (preimages.length > MAX_WAL_PREIMAGES) {
    throw bounded('wal-authority');
  }
  let bytes = 0;
  for (const preimage of preimages) {
    bytes += Buffer.byteLength(preimage.path, 'utf8');
    if (preimage.state !== 'absent') {
      bytes +=
        Buffer.byteLength(preimage.identity.device, 'utf8') +
        Buffer.byteLength(preimage.identity.inode, 'utf8');
    }
    if (bytes > MAX_WAL_STRUCTURAL_BYTES) {
      throw bounded('wal-authority');
    }
  }
  return bytes;
}

function validateWalPreimageBudget(preimages: readonly LifecyclePreimage[]): number {
  let bytes = 0;
  for (const preimage of preimages) {
    if (preimage.state !== 'file') {
      continue;
    }
    if (preimage.bytes.byteLength > MAX_WAL_IMAGE_BYTES) {
      throw bounded('wal-authority');
    }
    bytes += preimage.bytes.byteLength;
    if (bytes > MAX_WAL_IMAGE_TOTAL_BYTES) {
      throw bounded('wal-authority');
    }
  }
  return bytes;
}

function validateOrdinaryIntents(
  intents: readonly OrdinaryMutationIntent[],
  initialImageBytes: number,
  initialStructuralBytes: number,
  operationId: LifecycleId,
  startStep: number,
): void {
  if (intents.length > MAX_WAL_OPERATIONS || intents.length > MAX_WAL_STAGED_WRITES) {
    throw bounded('wal-authority');
  }
  const targets = new Set<string>();
  let imageBytes = initialImageBytes;
  let structuralBytes = initialStructuralBytes;
  for (const [index, intent] of intents.entries()) {
    if (!validPath(intent.path) || !validMode(intent.mode) || targets.has(intent.path)) {
      throw bounded('setup-authority');
    }
    targets.add(intent.path);
    structuralBytes += Buffer.byteLength(intent.path, 'utf8');
    const step = startStep + index;
    const sourcePath = auxiliaryPath(intent.path, operationId, step, 'rollback');
    const stagingPath = auxiliaryPath(intent.path, operationId, step, 'stage');
    if (!validPath(sourcePath) || !validPath(stagingPath)) {
      throw bounded('wal-authority');
    }
    structuralBytes +=
      Buffer.byteLength(sourcePath, 'utf8') + Buffer.byteLength(stagingPath, 'utf8');
    if (structuralBytes > MAX_WAL_STRUCTURAL_BYTES) {
      throw bounded('wal-authority');
    }
    if (intent.action !== 'write') {
      continue;
    }
    if (intent.bytes.byteLength > MAX_WAL_IMAGE_BYTES) {
      throw bounded('wal-authority');
    }
    imageBytes += intent.bytes.byteLength;
    if (imageBytes > MAX_WAL_IMAGE_TOTAL_BYTES) {
      throw bounded('wal-authority');
    }
  }
}
function assertOrdinaryIntentsDoNotTargetCreatedCredential(
  intents: readonly OrdinaryMutationIntent[],
  createdCredential: SetupCreatedCredentialAuthority | undefined,
): void {
  if (
    createdCredential !== undefined &&
    intents.some((intent) => intent.path === createdCredential.path)
  ) {
    throw bounded('setup-authority');
  }
}
function intentsFromMutationOperations(
  operations: readonly LifecycleMutationOperation[],
  preimages: readonly LifecyclePreimage[],
): readonly OrdinaryMutationIntent[] {
  if (operations.length > MAX_WAL_OPERATIONS) {
    throw bounded('setup-authority');
  }
  const intents: OrdinaryMutationIntent[] = [];
  for (const operation of operations) {
    if (operation.kind === 'write-file' || operation.kind === 'write-config') {
      intents.push(
        Object.freeze({
          action: 'write',
          path: operation.path,
          bytes: copyOrdinaryPlanBytes(operation.bytes),
          mode: operation.mode,
        }),
      );
      continue;
    }
    if (operation.kind === 'move-config') {
      intents.push(
        Object.freeze({
          action: 'write',
          path: operation.path,
          bytes: copyOrdinaryPlanBytes(operation.bytes),
          mode: operation.mode,
        }),
        Object.freeze({ action: 'remove', path: operation.sourcePath, mode: operation.mode }),
      );
      continue;
    }
    if (operation.kind === 'apply-credential-authority-registry') {
      intents.push(
        Object.freeze({
          action: 'write',
          path: operation.path,
          bytes: mergedCredentialAuthorityRegistryBytes(
            requirePreimage(preimages, operation.path),
            operation.preimage,
            operation.postimage,
          ),
          mode: operation.mode,
        }),
      );
      continue;
    }
    /* Credential and directory operations need explicit v2 authority, not an implicit write. */
    throw bounded('setup-authority');
  }
  return Object.freeze(intents);
}
function mergedCredentialAuthorityRegistryBytes(
  preimage: LifecyclePreimage,
  selectedPreimage: SemanticCredentialAuthorityRegistryImage,
  selectedPostimage: SemanticCredentialAuthorityRegistryImage,
): Uint8Array {
  const selected = selectedPreimage.projects[0] ?? selectedPostimage.projects[0];
  if (
    selected === undefined ||
    selectedPreimage.projects.length > 1 ||
    selectedPostimage.projects.length > 1 ||
    (selectedPreimage.projects[0] !== undefined &&
      selectedPostimage.projects[0] !== undefined &&
      selectedPreimage.projects[0].projectId !== selectedPostimage.projects[0].projectId)
  ) {
    throw bounded('setup-authority');
  }
  let current: ReturnType<typeof parseCredentialAuthorityRegistryJsonV1>;
  if (preimage.state === 'absent') {
    current = parseCredentialAuthorityRegistryJsonV1(
      serializeCredentialAuthorityRegistryV1({ schemaVersion: 1, projects: [] }),
    );
  } else if (preimage.state === 'file') {
    try {
      current = parseCredentialAuthorityRegistryJsonV1(
        new TextDecoder('utf-8', { fatal: true }).decode(preimage.bytes),
      );
    } catch {
      throw bounded('setup-authority');
    }
  } else {
    throw bounded('setup-authority');
  }
  const currentSelected = current.projects.find((entry) => entry.projectId === selected.projectId);
  const expectedSelected = selectedPreimage.projects[0];
  if (
    (expectedSelected === undefined && currentSelected !== undefined) ||
    (expectedSelected !== undefined &&
      (currentSelected === undefined ||
        !sameCredentialAuthorityRegistryEntry(currentSelected, expectedSelected)))
  ) {
    throw bounded('setup-authority');
  }
  const postimageEntry = selectedPostimage.projects[0];
  const projects = [
    ...current.projects.filter((entry) => entry.projectId !== selected.projectId),
    ...(postimageEntry === undefined ? [] : [postimageEntry]),
  ].sort((left, right) => left.projectId.localeCompare(right.projectId));
  return encode(serializeCredentialAuthorityRegistryV1({ schemaVersion: 1, projects }));
}
function sameCredentialAuthorityRegistryEntry(
  left: SemanticCredentialAuthorityRegistryImage['projects'][number],
  right: SemanticCredentialAuthorityRegistryImage['projects'][number],
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
function copyOrdinaryPlanBytes(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw bounded('setup-authority');
  }
  return REFLECT_APPLY(TYPED_ARRAY_SLICE, bytes, []) as Uint8Array;
}

async function materializeUninstallIntents(
  port: LifecycleTransactionPort,
  manifest: SetupManifestV1,
  preimages: readonly LifecyclePreimage[],
  manifestPath: string,
  receiptPath: string,
  operationId: LifecycleId,
): Promise<readonly OrdinaryMutationIntent[]> {
  const intents: OrdinaryMutationIntent[] = [];
  for (const artifact of manifest.artifacts) {
    const inverse = artifact.inverse;
    if (
      inverse.kind === 'none' ||
      inverse.kind === 'delete-created-credential' ||
      inverse.kind === 'delete-created-directory'
    ) {
      continue;
    }
    const expected = requirePresentPreimage(preimages, inverse.path);
    if (inverse.kind === 'delete-created-file') {
      if (
        artifact.kind !== 'file' ||
        fingerprintBytes(expected.bytes) !== inverse.expectedFingerprint
      ) {
        throw bounded('uninstall-authority');
      }
      intents.push(Object.freeze({ action: 'remove', path: inverse.path, mode: expected.mode }));
      continue;
    }
    if (
      (inverse.kind === 'restore-owned-file' && artifact.kind !== 'file') ||
      ((inverse.kind === 'restore-config' || inverse.kind === 'remove-config-hunks') &&
        artifact.kind !== 'config') ||
      (inverse.kind === 'restore-credential-authority-registry-entry' &&
        artifact.kind !== 'credential-authority-registry')
    ) {
      throw bounded('uninstall-authority');
    }
    const bytes = await port.materializeUninstallInverse({ inverse, expected });
    if (
      inverse.kind === 'restore-owned-file' &&
      fingerprintBytes(expected.bytes) === inverse.postimageFingerprint &&
      fingerprintBytes(bytes) !== inverse.preimageFingerprint
    ) {
      throw bounded('uninstall-authority');
    }
    intents.push(
      Object.freeze({ action: 'write', path: inverse.path, bytes, mode: expected.mode }),
    );
  }
  const receiptPreimage = requirePreimage(preimages, receiptPath);
  const manifestPreimage = requirePresentPreimage(preimages, manifestPath);
  const receipt = serializeLifecycleReceiptV1({
    schemaVersion: 1,
    kind: 'scene-glass-lifecycle-receipt',
    operationId,
    installId: manifest.installId,
    terminalState: 'uninstalled',
    manifestFingerprint: fingerprint(serializeSetupManifestV1(manifest)),
  });
  intents.push(
    Object.freeze({
      action: 'write',
      path: receiptPath,
      bytes: encode(receipt),
      mode: 0o600,
    }),
    Object.freeze({
      action: 'remove',
      path: manifestPath,
      mode: manifestPreimage.mode,
    }),
  );
  if (
    (receiptPreimage.state !== 'absent' && receiptPreimage.state !== 'file') ||
    !sameBytes(manifestPreimage.bytes, encode(serializeSetupManifestV1(manifest)))
  ) {
    throw bounded('uninstall-authority');
  }
  return Object.freeze(intents);
}

async function assertOpenedSetupRecord(
  authority: InternalSetupAuthority,
): Promise<Extract<WalRecordV2, { readonly operation: 'setup' }>> {
  const record = authority.record;
  if (record === undefined || record.operation !== 'setup') {
    throw bounded('setup-authority');
  }
  if (
    record.direction !== 'rollback' ||
    record.phase !== 'prepared' ||
    record.operationId !== authority.operationId ||
    record.installId !== authority.installId ||
    record.lockPath !== authority.lockPath ||
    record.manifestPath !== authority.manifestPath ||
    record.creationIntents !== undefined ||
    record.cursor !== authority.directories.length ||
    record.mutations.length !==
      authority.directories.length + (authority.credential === undefined ? 0 : 1)
  ) {
    throw bounded('setup-authority');
  }

  const directorySources = directoryMutationSources(authority.directories, authority.operationId);
  for (let index = 0; index < authority.directories.length; index += 1) {
    const candidate = authority.directories[index];
    const sourcePath = directorySources[index];
    const mutation = record.mutations[index];
    if (
      candidate === undefined ||
      sourcePath === undefined ||
      mutation === undefined ||
      mutation.kind !== 'ordinary' ||
      mutation.step !== index ||
      mutation.targetPath !== candidate.path ||
      mutation.sourcePath !== sourcePath ||
      mutation.stagingPath !== candidate.stagingPath ||
      mutation.result.kind !== 'directory' ||
      mutation.result.mode !== candidate.mode ||
      record.preimages[mutation.preimage]?.kind !== 'absent' ||
      record.preimages[mutation.preimage]?.path !== candidate.path ||
      record.preimages.some((preimage) => preimage.path === candidate.stagingPath) ||
      (await authority.port.lstatNoFollow(sourcePath)) !== undefined ||
      !sameDirectoryObservation(
        await authority.port.lstatNoFollow(candidate.path),
        mutation.result.identity,
        candidate.mode,
      )
    ) {
      throw bounded('setup-authority');
    }
  }

  const credential = authority.credential;
  if (credential === undefined) {
    if (
      authority.credentialReservation !== undefined ||
      authority.reservedCreatedCredential !== undefined
    ) {
      throw bounded('setup-authority');
    }
    return record;
  }

  const reservation = authority.credentialReservation;
  const reserved = authority.reservedCreatedCredential;
  const mutation = record.mutations[authority.directories.length];
  if (
    reservation === undefined ||
    reserved === undefined ||
    mutation === undefined ||
    mutation.kind !== 'credential' ||
    mutation.step !== authority.directories.length ||
    mutation.projectId !== credential.projectId ||
    mutation.path !== credential.path ||
    mutation.mode !== credential.mode ||
    mutation.stagingPath !== credential.stagingPath ||
    !sameIdentity(mutation.stagingIdentity, reservation.identity) ||
    !sameIdentity(mutation.targetIdentity, reservation.identity) ||
    reserved.projectId !== credential.projectId ||
    reserved.path !== credential.path ||
    reserved.mode !== credential.mode ||
    !sameIdentity(reserved.identity, reservation.identity) ||
    record.preimages.some((preimage) => preimage.path === credential.stagingPath) ||
    record.preimages.find((preimage) => preimage.path === credential.path)?.kind !== 'absent'
  ) {
    throw bounded('setup-authority');
  }
  assertReservationMatchesCandidate(reservation, credential);
  return record;
}
function finalizedCredentialBinding(authority: SetupReservedCredentialAuthority): Readonly<{
  readonly projectId: LifecycleId;
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: 0o600;
}> {
  if (authority.mode !== 0o600 || authority.linkCount !== 1) {
    throw bounded('finalization');
  }
  return Object.freeze({
    projectId: authority.projectId,
    path: authority.path,
    identity: authority.identity,
    mode: 0o600,
  });
}
function finalizedDirectoryBindings(
  authority: InternalSetupAuthority,
  record: WalRecordV2,
): readonly Readonly<{
  readonly path: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}>[] {
  const directories = authority.directories.map((candidate, index) => {
    const mutation = record.mutations[index];
    if (
      mutation?.kind !== 'ordinary' ||
      mutation.targetPath !== candidate.path ||
      mutation.result.kind !== 'directory' ||
      mutation.result.mode !== candidate.mode
    ) {
      throw bounded('finalization');
    }
    return Object.freeze({
      path: candidate.path,
      identity: mutation.result.identity,
      mode: candidate.mode,
    });
  });
  return Object.freeze(directories);
}
function validateFinalSetupAuthority(
  authority: InternalSetupAuthority,
  preimages: readonly LifecyclePreimage[],
  credential: SetupCredentialCandidate | undefined,
): void {
  validatePreimages(preimages, [
    authority.lockPath,
    authority.walPath,
    walStagingPath(authority.walPath),
    authority.manifestPath,
  ]);
  for (const candidate of authority.directories) {
    const expected = requirePreimage(preimages, candidate.path);
    if (expected.state !== 'absent') {
      throw bounded('setup-authority');
    }
  }
  if (credential !== undefined) {
    const expected = requirePreimage(preimages, credential.path);
    if (expected.state !== 'absent') {
      throw bounded('setup-authority');
    }
  }
}
function assertFinalizedCredentialAuthority(
  manifest: SetupManifestV1,
  createdCredential: SetupCreatedCredentialAuthority | undefined,
): void {
  const createdArtifacts = manifest.artifacts.filter(
    (
      artifact,
    ): artifact is Extract<
      SetupManifestV1['artifacts'][number],
      { readonly kind: 'credential'; readonly ownership: 'setup-created' }
    > => artifact.kind === 'credential' && artifact.ownership === 'setup-created',
  );
  if (createdCredential === undefined) {
    if (createdArtifacts.length !== 0) {
      throw bounded('finalization');
    }
    return;
  }

  const [createdArtifact] = createdArtifacts;
  if (
    createdArtifacts.length !== 1 ||
    createdArtifact === undefined ||
    createdArtifact.path !== createdCredential.path ||
    createdArtifact.projectId !== createdCredential.projectId ||
    createdArtifact.identity === undefined ||
    !sameIdentity(createdArtifact.identity, createdCredential.identity) ||
    createdArtifact.mode !== 0o600 ||
    createdArtifact.linkCount !== 1 ||
    createdArtifact.inverse.kind !== 'delete-created-credential' ||
    createdArtifact.inverse.projectId !== createdCredential.projectId ||
    createdArtifact.inverse.identity === undefined ||
    !sameIdentity(createdArtifact.inverse.identity, createdCredential.identity) ||
    createdArtifact.inverse.mode !== 0o600 ||
    createdArtifact.inverse.linkCount !== 1
  ) {
    throw bounded('finalization');
  }

  const witnesses = manifest.artifacts
    .filter((artifact) => artifact.kind === 'credential-authority-registry')
    .flatMap((artifact) => artifact.postimage.projects)
    .filter(
      (entry) =>
        entry.projectId === createdCredential.projectId &&
        entry.credentialPath === createdCredential.path &&
        entry.device === createdCredential.identity.device &&
        entry.inode === createdCredential.identity.inode,
    );
  if (
    witnesses.length !== 1 ||
    createdCredential.mode !== 0o600 ||
    createdCredential.linkCount !== 1
  ) {
    throw bounded('finalization');
  }
}

function assertFinalizationOmitsCreatedAuthority(
  authority: InternalSetupAuthority,
  preimages: readonly LifecyclePreimage[],
  credential: SetupCredentialCandidate | undefined,
): void {
  const createdPaths = new Set<string>(
    authority.directories.flatMap((candidate) => [candidate.path, candidate.stagingPath]),
  );
  if (credential !== undefined) {
    createdPaths.add(credential.path);
    createdPaths.add(credential.stagingPath);
  }
  if (preimages.some((preimage) => createdPaths.has(preimage.path))) {
    throw bounded('finalization');
  }
}

function createdSetupPreimages(authority: InternalSetupAuthority): readonly LifecyclePreimage[] {
  const createdPaths = new Set<string>(authority.directories.map((candidate) => candidate.path));
  if (authority.credential !== undefined) {
    createdPaths.add(authority.credential.path);
  }
  const created = authority.initialPreimages.filter((preimage) => createdPaths.has(preimage.path));
  if (
    created.length !== createdPaths.size ||
    created.some((preimage) => preimage.state !== 'absent')
  ) {
    throw bounded('setup-authority');
  }
  return freezePreimages(created);
}

function rebindOrdinaryPreimages(
  mutations: readonly WalMutationV2[],
  preimages: readonly LifecyclePreimage[],
): readonly WalMutationV2[] {
  const rebound: WalMutationV2[] = [];
  for (const mutation of mutations) {
    if (mutation.kind === 'credential') {
      rebound.push(mutation);
      continue;
    }
    rebound.push(
      Object.freeze({
        ...mutation,
        preimage: preimageIndex(preimages, mutation.targetPath),
      }),
    );
  }
  return Object.freeze(rebound);
}

async function captureUninstallPreimages(
  port: LifecycleTransactionPort,
  manifest: SetupManifestV1,
  input: ApplyUninstallTransactionInput,
): Promise<readonly LifecyclePreimage[]> {
  const captured: LifecyclePreimage[] = [];
  const manifestBytes = encode(serializeSetupManifestV1(manifest));
  const observedManifest = await observeOrdinary(port, input.manifestPath);
  if (observedManifest === undefined || !sameBytes(observedManifest.bytes, manifestBytes)) {
    throw bounded('uninstall-authority');
  }
  captured.push(
    Object.freeze({
      path: input.manifestPath,
      state: 'file' as const,
      identity: observedManifest.identity,
      mode: observedManifest.mode,
      bytes: observedManifest.bytes,
    }),
  );
  for (const artifact of manifest.artifacts) {
    if (artifact.kind === 'credential') {
      const observed = await port.lstatNoFollow(artifact.path);
      if (observed === undefined || observed.kind !== 'file') {
        throw bounded('uninstall-authority');
      }
      if (artifact.ownership === 'setup-created') {
        const witness = setupCreatedCredentialWitness(manifest, artifact.path);
        if (
          artifact.projectId === undefined ||
          artifact.identity === undefined ||
          artifact.mode !== 0o600 ||
          artifact.linkCount !== 1 ||
          observed.mode !== artifact.mode ||
          !sameIdentity(observed.identity, artifact.identity) ||
          witness.device !== artifact.identity.device ||
          witness.inode !== artifact.identity.inode
        ) {
          throw bounded('uninstall-authority');
        }
      }
      captured.push(
        Object.freeze({
          path: artifact.path,
          state: 'credential' as const,
          identity: observed.identity,
          mode: observed.mode,
        }),
      );
      continue;
    }
    if (artifact.kind === 'directory') {
      const observed = await port.lstatNoFollow(artifact.path);
      if (
        observed === undefined ||
        !sameDirectoryObservation(observed, artifact.identity, artifact.mode)
      ) {
        throw bounded('uninstall-authority');
      }
      captured.push(
        Object.freeze({
          path: artifact.path,
          state: 'directory' as const,
          identity: observed.identity,
          mode: observed.mode,
        }),
      );
      continue;
    }
    const observed = await observeOrdinary(port, artifact.path);
    if (observed === undefined) {
      throw bounded('uninstall-authority');
    }
    captured.push(
      Object.freeze({
        path: artifact.path,
        state: 'file' as const,
        identity: observed.identity,
        mode: observed.mode,
        bytes: observed.bytes,
      }),
    );
  }
  const priorReceipt = await observeOrdinary(port, input.receiptPath);
  if (priorReceipt === undefined) {
    captured.push(Object.freeze({ path: input.receiptPath, state: 'absent' as const }));
  } else {
    const receipt = parseLifecycleReceiptJsonV1(
      new TextDecoder('utf-8', { fatal: true }).decode(priorReceipt.bytes),
    );
    if (
      priorReceipt.mode !== 0o600 ||
      receipt.terminalState !== 'uninstalled' ||
      receipt.installId === manifest.installId
    ) {
      throw bounded('uninstall-authority');
    }
    captured.push(
      Object.freeze({
        path: input.receiptPath,
        state: 'file' as const,
        identity: priorReceipt.identity,
        mode: priorReceipt.mode,
        bytes: priorReceipt.bytes,
      }),
    );
  }
  const preimages = freezePreimages(captured);
  validatePreimages(preimages, [input.lockPath, input.walPath, walStagingPath(input.walPath)]);
  const expectedArtifactPreimages = manifest.artifacts.length;
  if (preimages.length !== expectedArtifactPreimages + 2) {
    throw bounded('uninstall-authority');
  }
  return preimages;
}

function validateUninstallAuthority(
  manifest: SetupManifestV1,
  input: ApplyUninstallTransactionInput,
): void {
  const preflight = input.preflight;
  if (manifest.artifacts.length > MAX_WAL_MUTATIONS) {
    throw bounded('uninstall-authority');
  }
  if (
    preflight.canUninstall !== true ||
    !Array.isArray(preflight.issues) ||
    preflight.issues.length !== 0 ||
    !Array.isArray(preflight.writes) ||
    preflight.writes.length !== 0 ||
    !Array.isArray(preflight.inverse) ||
    preflight.inverse.length !== manifest.artifacts.length
  ) {
    throw bounded('uninstall-authority');
  }
  for (let index = 0; index < manifest.artifacts.length; index += 1) {
    const artifact = manifest.artifacts[index];
    const inverse = preflight.inverse[index];
    if (
      artifact === undefined ||
      inverse === undefined ||
      JSON.stringify(inverse) !== JSON.stringify(artifact.inverse)
    ) {
      throw bounded('uninstall-authority');
    }
  }
}

function setupCreatedCredentialWitness(
  manifest: SetupManifestV1,
  credentialPath: string,
): LifecycleFileIdentity {
  const witnesses = manifest.artifacts
    .filter((artifact) => artifact.kind === 'credential-authority-registry')
    .flatMap((artifact) =>
      artifact.postimage.projects.filter((entry) => entry.credentialPath === credentialPath),
    );
  const witness = witnesses[0];
  if (witness === undefined || witnesses.length !== 1) {
    throw bounded('uninstall-authority');
  }
  return Object.freeze({ device: witness.device, inode: witness.inode });
}

function validatePreimages(
  preimages: readonly LifecyclePreimage[],
  reservedPaths: readonly string[],
): void {
  validateWalPreimageStructuralBudget(preimages);
  validateWalPreimageBudget(preimages);
  const paths = new Set<string>(reservedPaths);
  for (const preimage of preimages) {
    if (!validPath(preimage.path) || paths.has(preimage.path)) {
      throw bounded('setup-authority');
    }
    paths.add(preimage.path);
    if (
      preimage.state === 'file' &&
      (!validMode(preimage.mode) || !validIdentity(preimage.identity))
    ) {
      throw bounded('setup-authority');
    }
    if (
      preimage.state === 'credential' &&
      (preimage.mode !== 0o600 || !validIdentity(preimage.identity))
    ) {
      throw bounded('setup-authority');
    }
  }
}

function validateStatePaths(
  lockPath: string,
  walPath: string,
  manifestPath: string,
  receiptPath: string | undefined = undefined,
): void {
  const seen = new Set<string>();
  const paths =
    receiptPath === undefined
      ? [lockPath, walPath, walStagingPath(walPath), manifestPath]
      : [lockPath, walPath, walStagingPath(walPath), manifestPath, receiptPath];
  for (const path of paths) {
    if (!validPath(path) || seen.has(path)) {
      throw bounded('setup-authority');
    }
    seen.add(path);
  }
}
function freezeDirectoryCandidates(
  candidates: readonly SetupDirectoryCandidate[],
): readonly SetupDirectoryCandidate[] {
  if (candidates.length > MAX_WAL_MUTATIONS) {
    throw bounded('setup-authority');
  }
  const frozen: SetupDirectoryCandidate[] = [];
  for (const candidate of candidates) {
    frozen.push(
      Object.freeze({
        path: candidate.path,
        stagingPath: candidate.stagingPath,
        mode: candidate.mode,
      }),
    );
  }
  return Object.freeze(frozen);
}

function sameDirectoryCandidates(
  left: readonly SetupDirectoryCandidate[],
  right: readonly SetupDirectoryCandidate[],
): boolean {
  return (
    left.length === right.length &&
    left.every((candidate, index) => {
      const expected = right[index];
      return (
        expected !== undefined &&
        candidate.path === expected.path &&
        candidate.stagingPath === expected.stagingPath &&
        candidate.mode === expected.mode
      );
    })
  );
}

function validateSetupDirectoryAuthority(
  candidates: readonly SetupDirectoryCandidate[],
  suppliedPreimages: readonly LifecyclePreimage[],
  lockPath: string,
  walPath: string,
  manifestPath: string,
  credential: Omit<SetupCredentialCandidate, 'contentBytes'> | undefined,
): void {
  if (suppliedPreimages.length > MAX_WAL_PREIMAGES) {
    throw bounded('setup-authority');
  }
  const preimages = indexPreimages(suppliedPreimages);
  const protectedPaths = [lockPath, walPath, walStagingPath(walPath), manifestPath];
  if (credential !== undefined) {
    validateCredentialCandidateShape(credential);
  }
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    if (candidate === undefined || !validDirectoryCandidate(candidate)) {
      throw bounded('setup-authority');
    }
    const preimage = preimages.get(candidate.path);
    if (preimage?.state !== 'absent' || preimages.has(candidate.stagingPath)) {
      throw bounded('setup-authority');
    }
    for (const protectedPath of protectedPaths) {
      if (
        pathsOverlap(candidate.path, protectedPath) ||
        pathsOverlap(candidate.stagingPath, protectedPath)
      ) {
        throw bounded('setup-authority');
      }
    }
    if (credential !== undefined) {
      if (
        candidate.path === credential.path ||
        candidate.path === credential.stagingPath ||
        candidate.stagingPath === credential.path ||
        candidate.stagingPath === credential.stagingPath ||
        isSameOrAncestor(credential.path, candidate.path) ||
        isSameOrAncestor(credential.stagingPath, candidate.path)
      ) {
        throw bounded('setup-authority');
      }
    }
    for (let previousIndex = 0; previousIndex < index; previousIndex += 1) {
      const previous = candidates[previousIndex];
      if (previous === undefined) {
        throw bounded('setup-authority');
      }
      if (
        candidate.path === previous.path ||
        candidate.stagingPath === previous.stagingPath ||
        candidate.path === previous.stagingPath ||
        candidate.stagingPath === previous.path ||
        isSameOrAncestor(candidate.path, previous.path) ||
        isSameOrAncestor(candidate.stagingPath, previous.stagingPath) ||
        isSameOrAncestor(previous.stagingPath, candidate.stagingPath) ||
        isSameOrAncestor(candidate.stagingPath, previous.path) ||
        isSameOrAncestor(candidate.path, previous.stagingPath) ||
        isSameOrAncestor(previous.stagingPath, candidate.path)
      ) {
        throw bounded('setup-authority');
      }
    }
  }
}

function validDirectoryCandidate(candidate: SetupDirectoryCandidate): boolean {
  return (
    validPath(candidate.path) &&
    validPath(candidate.stagingPath) &&
    candidate.path !== candidate.stagingPath &&
    dirname(candidate.path) === dirname(candidate.stagingPath) &&
    validMode(candidate.mode)
  );
}

function directoryMutationSources(
  candidates: readonly SetupDirectoryCandidate[],
  operationId: LifecycleId,
): readonly string[] {
  const sources = candidates.map((candidate, index) =>
    auxiliaryPath(candidate.path, operationId, index, 'rollback'),
  );
  const paths = new Set<string>();
  for (const source of sources) {
    if (!validPath(source) || paths.has(source)) {
      throw bounded('setup-authority');
    }
    paths.add(source);
  }
  return Object.freeze(sources);
}
function validateSetupPlanGeometry(
  authority: InternalSetupAuthority,
  intents: readonly OrdinaryMutationIntent[],
  operationId: LifecycleId,
  startStep: number,
): void {
  if (
    !Number.isSafeInteger(startStep) ||
    startStep < 0 ||
    startStep + intents.length + 1 > MAX_WAL_MUTATIONS
  ) {
    throw bounded('wal-authority');
  }
  const protectedPaths = [
    authority.lockPath,
    authority.walPath,
    authority.manifestPath,
    setupManifestAuthorityPath(authority.manifestPath, operationId),
    walStagingPath(authority.walPath),
  ];
  const stagedPaths = new Set<string>();
  for (let index = 0; index < intents.length; index += 1) {
    const intent = intents[index];
    if (intent === undefined) {
      throw bounded('setup-authority');
    }
    const step = startStep + index;
    const sourcePath = auxiliaryPath(intent.path, operationId, step, 'rollback');
    const stagingPath = auxiliaryPath(intent.path, operationId, step, 'stage');
    if (
      !validPath(sourcePath) ||
      !validPath(stagingPath) ||
      dirname(intent.path) !== dirname(sourcePath) ||
      dirname(intent.path) !== dirname(stagingPath) ||
      stagedPaths.has(sourcePath) ||
      stagedPaths.has(stagingPath) ||
      sourcePath === stagingPath ||
      protectedPaths.some(
        (protectedPath) =>
          pathsOverlap(intent.path, protectedPath) ||
          pathsOverlap(sourcePath, protectedPath) ||
          pathsOverlap(stagingPath, protectedPath),
      )
    ) {
      throw bounded('setup-authority');
    }
    stagedPaths.add(sourcePath);
    stagedPaths.add(stagingPath);
  }
}
function assertDirectorySourcesDoNotCollide(
  authority: InternalSetupAuthority,
  sources: readonly string[],
): void {
  const reserved = new Set<string>([
    authority.lockPath,
    authority.walPath,
    authority.manifestPath,
    walStagingPath(authority.walPath),
    ...authority.initialPreimages.map((preimage) => preimage.path),
  ]);
  if (sources.some((source) => reserved.has(source))) {
    throw bounded('setup-authority');
  }
}

function pathsOverlap(left: string, right: string): boolean {
  return isSameOrAncestor(left, right) || isSameOrAncestor(right, left);
}

function isSameOrAncestor(ancestor: string, path: string): boolean {
  return ancestor === path || path.startsWith(`${ancestor}/`);
}

function validateCredentialCandidateShape(
  candidate: Omit<SetupCredentialCandidate, 'contentBytes'>,
): void {
  if (
    !validPath(candidate.path) ||
    !validPath(candidate.stagingPath) ||
    candidate.path === candidate.stagingPath ||
    dirname(candidate.path) !== dirname(candidate.stagingPath) ||
    candidate.mode !== 0o600 ||
    !validId(candidate.projectId)
  ) {
    throw bounded('setup-authority');
  }
}

function validateCredentialCandidate(
  candidate: SetupCredentialCandidate,
  expected: Omit<SetupCredentialCandidate, 'contentBytes'> | undefined,
): void {
  validateCredentialCandidateShape(candidate);
  if (
    !(candidate.contentBytes instanceof Uint8Array) ||
    candidate.contentBytes.byteLength === 0 ||
    candidate.contentBytes.byteLength > MAX_SETUP_CREDENTIAL_BYTES
  ) {
    throw bounded('setup-authority');
  }
  if (
    expected === undefined ||
    candidate.projectId !== expected.projectId ||
    candidate.path !== expected.path ||
    candidate.stagingPath !== expected.stagingPath ||
    candidate.mode !== expected.mode
  ) {
    throw bounded('setup-authority');
  }
}
function ownCredentialCandidate(candidate: SetupCredentialCandidate): SetupCredentialCandidate {
  validateCredentialCandidateShape(candidate);
  const bytes = candidate.contentBytes;
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength === 0 ||
    bytes.byteLength > MAX_SETUP_CREDENTIAL_BYTES
  ) {
    throw bounded('setup-authority');
  }
  const owned = REFLECT_APPLY(TYPED_ARRAY_SLICE, bytes, []) as Uint8Array;
  if (!(owned instanceof Uint8Array) || owned === bytes || owned.byteLength !== bytes.byteLength) {
    zeroizeCredentialBuffers(owned);
    throw bounded('setup-authority');
  }
  return Object.freeze({
    projectId: candidate.projectId,
    path: candidate.path,
    stagingPath: candidate.stagingPath,
    mode: candidate.mode,
    contentBytes: owned,
  });
}

function zeroizeCredentialBuffers(...values: readonly (Uint8Array | undefined)[]): unknown {
  const errors: unknown[] = [];
  for (const value of values) {
    if (value === undefined) {
      continue;
    }
    try {
      REFLECT_APPLY(TYPED_ARRAY_FILL, value, [0]);
    } catch (error) {
      errors.push(error);
    }
  }
  return errors.length === 0
    ? undefined
    : new AggregateError(errors, 'credential byte zeroization failed');
}

function assertReservationMatchesCandidate(
  reservation: LifecycleReservedStagedWrite,
  candidate: Omit<SetupCredentialCandidate, 'contentBytes'>,
): void {
  if (
    reservation.state !== 'completed' ||
    reservation.path !== candidate.stagingPath ||
    !validIdentity(reservation.identity)
  ) {
    throw bounded('credential-reserve');
  }
}
function assertDirectoryReservationMatchesCandidate(
  reservation: LifecycleReservedStagedDirectory,
  candidate: SetupDirectoryCandidate,
): void {
  if (
    reservation.state !== 'completed' ||
    reservation.path !== candidate.stagingPath ||
    reservation.mode !== candidate.mode ||
    !validIdentity(reservation.identity)
  ) {
    throw bounded('directory-reserve');
  }
}

function toWalPreimages(preimages: readonly LifecyclePreimage[]): readonly WalPreimageV2[] {
  return Object.freeze(
    preimages.map((preimage) => {
      if (preimage.state === 'absent') {
        return Object.freeze({ path: preimage.path, kind: 'absent' as const });
      }
      if (preimage.state === 'directory') {
        return Object.freeze({
          path: preimage.path,
          kind: 'directory' as const,
          identity: preimage.identity,
          mode: preimage.mode,
        });
      }
      if (preimage.state === 'credential') {
        return Object.freeze({
          path: preimage.path,
          kind: 'credential' as const,
          identity: preimage.identity,
          mode: preimage.mode,
        });
      }
      return Object.freeze({
        path: preimage.path,
        kind: 'file' as const,
        identity: preimage.identity,
        mode: preimage.mode,
        bytes: Buffer.from(preimage.bytes).toString('base64'),
      });
    }),
  );
}

function bindWal(value: object): WalRecordV2 {
  const unbound = withWalFingerprint(value, ZERO_FINGERPRINT);
  const serializedUnbound = serializeWalRecordV2(unbound);
  validateSerializedWalBudget(unbound, serializedUnbound);
  const authorityFingerprint = fingerprint(serializedUnbound);
  const bound = parseBoundWal(withWalFingerprint(value, authorityFingerprint));
  validateSerializedWalBudget(bound, serializeWalRecordV2(bound));
  return bound;
}

function validateSerializedWalBudget(record: WalRecordV2, serialized: string): void {
  if (
    record.preimages.length > MAX_WAL_PREIMAGES ||
    record.mutations.length > MAX_WAL_MUTATIONS ||
    (record.creationIntents?.length ?? 0) > 1 ||
    Buffer.byteLength(serialized, 'utf8') > MAX_SERIALIZED_WAL_BYTES
  ) {
    throw bounded('wal-authority');
  }
}

function withWalFingerprint(value: object, authorityFingerprint: string): WalRecordV2 {
  const candidate = value as Record<string, unknown>;
  const {
    replacedWalStage,
    authorityFingerprint: _ignoredAuthorityFingerprint,
    ...withoutTransportAuthority
  } = candidate;
  void _ignoredAuthorityFingerprint;
  if (candidate.operation === 'uninstall') {
    const { receiptPath, manifest, ...common } = withoutTransportAuthority;
    return {
      ...common,
      authorityFingerprint,
      receiptPath,
      manifest,
      ...(replacedWalStage === undefined ? {} : { replacedWalStage }),
    } as WalRecordV2;
  }
  return {
    ...withoutTransportAuthority,
    authorityFingerprint,
    ...(replacedWalStage === undefined ? {} : { replacedWalStage }),
  } as WalRecordV2;
}

function parseBoundWal(value: unknown): WalRecordV2 {
  const parsed = parseWalRecordJson(serializeWalRecordV2(value));
  if (parsed.classification !== 'v2-recovery-authority') {
    throw bounded('wal-authority');
  }
  return parsed.record;
}

function hasValidAuthorityFingerprint(record: WalRecordV2): boolean {
  const unbound = { ...record, authorityFingerprint: ZERO_FINGERPRINT } as WalRecordV2;
  return record.authorityFingerprint === fingerprint(serializeWalRecordV2(unbound));
}
function sameWalRecordIgnoringReplacedStage(bytes: Uint8Array, expected: WalRecordV2): boolean {
  try {
    const parsed = parseWalRecordJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      parsed.classification !== 'v2-recovery-authority' ||
      !hasValidAuthorityFingerprint(parsed.record)
    ) {
      return false;
    }
    const {
      replacedWalStage: _currentReplacedStage,
      authorityFingerprint: _currentFingerprint,
      ...currentLogicalRecord
    } = parsed.record as WalRecordV2 & { readonly replacedWalStage?: unknown };
    const {
      replacedWalStage: _expectedReplacedStage,
      authorityFingerprint: _expectedFingerprint,
      ...expectedLogicalRecord
    } = expected as WalRecordV2 & { readonly replacedWalStage?: unknown };
    void _currentReplacedStage;
    void _currentFingerprint;
    void _expectedReplacedStage;
    void _expectedFingerprint;
    return (
      serializeWalRecordV2(bindWal(currentLogicalRecord)) ===
      serializeWalRecordV2(bindWal(expectedLogicalRecord))
    );
  } catch {
    return false;
  }
}
function replacedWalStageLineage(record: WalRecordV2):
  | Readonly<{
      readonly identity: LifecycleFileIdentity;
      readonly mode: 0o600;
      readonly authorityFingerprint: string;
    }>
  | undefined {
  const lineage = (
    record as WalRecordV2 & {
      readonly replacedWalStage?: {
        readonly identity?: LifecycleFileIdentity;
        readonly mode?: number;
        readonly authorityFingerprint?: string;
      };
    }
  ).replacedWalStage;
  return lineage?.mode === 0o600 &&
    lineage.identity !== undefined &&
    typeof lineage.authorityFingerprint === 'string'
    ? Object.freeze({
        identity: lineage.identity,
        mode: lineage.mode,
        authorityFingerprint: lineage.authorityFingerprint,
      })
    : undefined;
}

function manifestFromSetupRecord(
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
): SetupManifestV1 | undefined {
  const mutation = setupManifestMutation(record);
  if (mutation === undefined) {
    return undefined;
  }
  const result = mutation.result;
  if (result.kind !== 'file') {
    return undefined;
  }
  const bytes = Buffer.from(result.bytes, 'base64');
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const manifest = parseSetupManifestV1(parsed);
    return manifest.installId === record.installId ? manifest : undefined;
  } catch {
    return undefined;
  } finally {
    bytes.fill(0);
  }
}

function setupManifestAuthorityPath(manifestPath: string, operationId: LifecycleId): string {
  return `${manifestPath}.scene-glass-${operationId}.manifest-authority`;
}

function setupManifestMutation(
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
): WalOrdinaryMutationV2 | undefined {
  return ordinaryMutations(record).find(
    (mutation) =>
      mutation.targetPath === setupManifestAuthorityPath(record.manifestPath, record.operationId),
  );
}

function stateOrdinaryMutations(record: WalRecordV2): readonly WalOrdinaryMutationV2[] {
  return ordinaryMutations(record).filter(
    (mutation) =>
      record.operation !== 'setup' ||
      mutation.targetPath !== setupManifestAuthorityPath(record.manifestPath, record.operationId),
  );
}
function setupStateMutations(
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
): readonly WalMutationV2[] {
  const manifestAuthorityPath = setupManifestAuthorityPath(record.manifestPath, record.operationId);
  return Object.freeze(
    record.mutations.filter(
      (mutation) => mutation.kind === 'credential' || mutation.targetPath !== manifestAuthorityPath,
    ),
  );
}

function ordinaryMutations(record: WalRecordV2): readonly WalOrdinaryMutationV2[] {
  return record.mutations.filter(
    (mutation): mutation is WalOrdinaryMutationV2 => mutation.kind === 'ordinary',
  );
}
function matchesConfiguredRecovery(record: WalRecordV2, input: RecoverLifecycleInput): boolean {
  return (
    record.lockPath === input.lockPath &&
    record.manifestPath === input.manifestPath &&
    (record.operation !== 'uninstall' || record.receiptPath === input.receiptPath)
  );
}

function preimageFor(record: WalRecordV2, mutation: WalOrdinaryMutationV2): OrdinaryWalPreimageV2 {
  const preimage = record.preimages[mutation.preimage];
  if (preimage === undefined || preimage.kind === 'credential' || preimage.kind === 'directory') {
    throw bounded('wal-authority');
  }
  return preimage;
}
async function untouchedUnboundPreimages(
  port: LifecycleTransactionPort,
  record: WalRecordV2,
): Promise<boolean> {
  const boundPaths = new Set(
    record.mutations.map((mutation) =>
      mutation.kind === 'credential' ? mutation.path : mutation.targetPath,
    ),
  );
  for (const preimage of record.preimages) {
    if (boundPaths.has(preimage.path)) {
      continue;
    }
    if (preimage.kind === 'absent') {
      if ((await port.lstatNoFollow(preimage.path)) !== undefined) {
        return false;
      }
      continue;
    }
    if (preimage.kind === 'directory') {
      if (
        !sameDirectoryObservation(
          await port.lstatNoFollow(preimage.path),
          preimage.identity,
          preimage.mode,
        )
      ) {
        return false;
      }
      continue;
    }
    if (preimage.kind === 'credential') {
      if (
        !sameObservation(await port.lstatNoFollow(preimage.path), preimage.identity, preimage.mode)
      ) {
        return false;
      }
      continue;
    }
    if (!matchesPresentPreimage(await observeOrdinary(port, preimage.path), preimage)) {
      return false;
    }
  }
  return true;
}

async function writeWal(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
  record: WalRecordV2,
  previous: WalRecordV2 | undefined = undefined,
  onPublished: (() => void) | undefined = undefined,
): Promise<void> {
  const current = await observeWal(port, lock, path);
  if (
    (current === undefined && previous !== undefined) ||
    (current !== undefined &&
      (previous === undefined || !sameWalRecordIgnoringReplacedStage(current.bytes, previous)))
  ) {
    throw bounded('wal-authority');
  }
  let persisted = record;
  if (current !== undefined) {
    const parsed = parseWalRecordJson(
      new TextDecoder('utf-8', { fatal: true }).decode(current.bytes),
    );
    if (
      parsed.classification !== 'v2-recovery-authority' ||
      !hasValidAuthorityFingerprint(parsed.record)
    ) {
      throw bounded('wal-authority');
    }
    persisted = bindWal({
      ...record,
      replacedWalStage: Object.freeze({
        identity: current.identity,
        mode: current.mode,
        authorityFingerprint: parsed.record.authorityFingerprint,
      }),
    });
  }
  const serialized = serializeWalRecordV2(persisted);
  validateSerializedWalBudget(persisted, serialized);
  const bytes = encode(serialized);
  if (bytes.byteLength > MAX_SERIALIZED_WAL_BYTES) {
    throw bounded('wal-authority');
  }
  await writeReplacingFile(
    port,
    lock,
    path,
    bytes,
    0o600,
    'wal',
    walStagingPath(path),
    current?.bytes,
    onPublished,
    current,
  );
}

async function writeReplacingFile(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
  bytes: Uint8Array,
  mode: number,
  boundaryName: 'wal' | 'manifest' | 'receipt',
  stagingPath: string,
  expectedPreviousBytes: Uint8Array | undefined = undefined,
  onPublished: (() => void) | undefined = undefined,
  currentWal: WalObservation | undefined = undefined,
): Promise<void> {
  let staged: LifecycleStagedWrite | undefined;
  let published = false;
  try {
    const current =
      boundaryName === 'wal' && currentWal !== undefined
        ? currentWal
        : boundaryName === 'wal'
          ? await observeWal(port, lock, path)
          : await observeOrdinary(port, path);
    if (
      (expectedPreviousBytes === undefined && current !== undefined) ||
      (expectedPreviousBytes !== undefined &&
        (current === undefined ||
          current.mode !== mode ||
          !sameBytes(current.bytes, expectedPreviousBytes)))
    ) {
      throw bounded(boundaryName === 'wal' ? 'wal-authority' : `${boundaryName}-write`);
    }
    const stage = await boundary(
      port,
      boundaryName === 'wal' ? 'wal-write' : (`${boundaryName}-write` as LifecycleFailurePoint),
      () => port.stageWrite({ lock, stagingPath, bytes, mode }),
    );
    staged = stage;
    if (stage.path !== stagingPath || stage.state !== 'completed') {
      throw bounded('stage-write');
    }
    if (boundaryName === 'wal' && current !== undefined) {
      if (!isWalObservation(current)) {
        throw bounded('wal-authority');
      }
      const replacement = await exactMutationBoundary(port, 'target-rename', () =>
        port.replaceExactWal({
          lock,
          current: { path, identity: current.identity, mode: current.mode },
          replacement: stage,
          snapshot: current.snapshot,
        }),
      );
      if (replacement.state === 'completed') {
        published = true;
        onPublished?.();
        staged = undefined;
      }
      await finalizeExactMutation(port, lock, 'target-rename', replacement);
    } else if (current === undefined) {
      await boundary(port, 'target-rename', () =>
        port.publishStagedWrite({
          lock,
          stage,
          targetPath: path,
        }),
      );
    } else {
      const replacement = await exactMutationBoundary(port, 'target-rename', () =>
        port.replaceStagedWriteWithQuarantine({
          lock,
          stage,
          targetPath: path,
          current: {
            path,
            identity: current.identity,
            mode: current.mode,
            size: current.bytes.byteLength,
            digest: fingerprintBytes(current.bytes),
          },
        }),
      );
      if (replacement.state === 'completed') {
        staged = undefined;
      }
      await finalizeExactMutation(port, lock, 'target-rename', replacement);
    }
    staged = undefined;
    if (!published) {
      published = true;
      onPublished?.();
    }
    await boundary(
      port,
      boundaryName === 'wal' ? 'wal-fsync' : (`${boundaryName}-fsync` as LifecycleFailurePoint),
      () => port.fsyncFile({ lock, path }),
    );
    await boundary(port, 'parent-fsync', () => port.fsyncParent({ lock, path }));
  } catch (error) {
    if (staged !== undefined) {
      const cleanup = await discardStage(port, lock, staged);
      if (cleanup !== undefined) {
        throw new CleanupFailure(error, [cleanup]);
      }
    }
    if (boundaryName === 'wal' && published) {
      throw new WalPublicationFailure(error);
    }
    throw error;
  }
}
async function publishSetupManifest(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  record: Extract<WalRecordV2, { readonly operation: 'setup' }>,
  stages: ReadonlyMap<string, LifecycleStagedWrite> | undefined = undefined,
): Promise<boolean> {
  const mutation = setupManifestMutation(record);
  if (mutation === undefined) {
    return false;
  }
  const result = mutation.result;
  if (result.kind !== 'file') {
    return false;
  }
  const current = await observeOrdinary(port, record.manifestPath);
  if (matchesOrdinaryResult(current, result)) {
    return true;
  }
  if (current !== undefined) {
    return false;
  }
  const staged = await observeOrdinary(port, mutation.stagingPath);
  if (!matchesOrdinaryResult(staged, result) || staged === undefined) {
    return false;
  }
  return renameExact(
    port,
    lock,
    mutation.stagingPath,
    staged,
    record.manifestPath,
    'manifest-write',
    stages?.get(mutation.stagingPath),
  );
}

async function removeExactWal(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
  record: WalRecordV2,
): Promise<boolean> {
  const current = await observeWal(port, lock, path);
  if (current === undefined) {
    return true;
  }
  if (
    current.mode !== 0o600 ||
    (!sameBytes(current.bytes, encode(serializeWalRecordV2(record))) &&
      !sameWalRecordIgnoringReplacedStage(current.bytes, record))
  ) {
    return false;
  }
  const removed = await exactMutationBoundary(port, 'cleanup', () =>
    port.removeExactWal({
      lock,
      current: { path, identity: current.identity, mode: current.mode },
      snapshot: current.snapshot,
    }),
  );
  if (removed.state !== 'completed') {
    throw bounded(removed.state);
  }
  await finalizeExactMutation(port, lock, 'cleanup', removed);
  return true;
}

async function removeExactObservedFile(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
  observed: LifecycleRegularFileObservation,
  quarantinePath: string,
  content: { readonly size: number; readonly digest: string } | 'credential',
): Promise<boolean> {
  if (observed.kind !== 'file') {
    return false;
  }
  const current = await port.lstatNoFollow(path);
  if (!sameObservation(current, observed.identity, observed.mode)) {
    return false;
  }
  const quarantine = await exactMutationBoundary(port, 'cleanup', () =>
    port.quarantineExactFile({
      lock,
      path,
      identity: observed.identity,
      mode: observed.mode,
      quarantinePath,
      ...(content === 'credential'
        ? { credential: true }
        : { size: content.size, digest: content.digest }),
    }),
  );
  await finalizeExactMutation(port, lock, 'cleanup', quarantine);
  await boundary(port, 'parent-fsync', () => port.fsyncParent({ lock, path }));
  return true;
}

async function renameExact(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  sourcePath: string,
  source: OrdinaryObservation,
  targetPath: string,
  point: LifecycleFailurePoint,
  stage: LifecycleStagedWrite | undefined = undefined,
): Promise<boolean> {
  try {
    if (
      stage !== undefined &&
      (stage.state !== 'completed' ||
        stage.path !== sourcePath ||
        stage.mode !== source.mode ||
        !sameIdentity(stage.identity, source.identity))
    ) {
      return false;
    }
    await boundary(port, point, () =>
      stage === undefined
        ? port.publishExactStagedFile({
            lock,
            stagingPath: sourcePath,
            targetPath,
            identity: source.identity,
            mode: source.mode,
          })
        : port.publishStagedWrite({ lock, stage, targetPath }),
    );
    await boundary(port, 'target-fsync', () => port.fsyncFile({ lock, path: targetPath }));
    await boundary(port, 'parent-fsync', () => port.fsyncParent({ lock, path: targetPath }));
    return true;
  } catch (error) {
    if (error instanceof BoundedFailure) {
      return false;
    }
    throw bounded('indeterminate');
  }
}

interface OrdinaryObservation extends LifecycleRegularFileObservation {
  readonly bytes: Uint8Array;
}

interface WalObservation extends OrdinaryObservation {
  readonly snapshot: LifecycleWalSnapshotAuthority;
}
type OrdinaryMutationState =
  | 'initial'
  | 'source-preserved'
  | 'preimage-retained'
  | 'forward-complete'
  | 'forward-cleaned'
  | 'rollback-complete'
  | 'stable-absent'
  | 'invalid';

function classifyOrdinaryMutationState(
  original: OrdinaryWalPreimageV2,
  result: WalOrdinaryMutationV2['result'],
  target: OrdinaryObservation | undefined,
  source: OrdinaryObservation | undefined,
  staged: OrdinaryObservation | undefined,
): OrdinaryMutationState {
  if (result.kind === 'directory') {
    return 'invalid';
  }
  if (result.kind === 'absent') {
    if (original.kind === 'absent') {
      return target === undefined && source === undefined && staged === undefined
        ? 'stable-absent'
        : 'invalid';
    }
    if (matchesPresentPreimage(target, original) && source === undefined && staged === undefined) {
      return 'initial';
    }
    if (target === undefined && matchesPresentPreimage(source, original) && staged === undefined) {
      return 'source-preserved';
    }
    if (target === undefined && source === undefined && matchesPresentPreimage(staged, original)) {
      return 'preimage-retained';
    }
    return target === undefined && source === undefined && staged === undefined
      ? 'forward-cleaned'
      : 'invalid';
  }

  const stageMatches = matchesOrdinaryResult(staged, result);
  if (matchesPreimage(target, original) && source === undefined && stageMatches) {
    return 'initial';
  }
  if (
    matchesPreimage(target, original) &&
    matchesOrdinaryResult(source, result) &&
    staged === undefined
  ) {
    return 'preimage-retained';
  }
  if (matchesPreimage(target, original) && source === undefined && staged === undefined) {
    return 'rollback-complete';
  }
  if (
    target === undefined &&
    original.kind === 'file' &&
    matchesPresentPreimage(source, original) &&
    stageMatches
  ) {
    return 'source-preserved';
  }
  if (
    original.kind === 'absent' &&
    target === undefined &&
    matchesOrdinaryResult(source, result) &&
    staged === undefined
  ) {
    return 'preimage-retained';
  }
  if (
    matchesOrdinaryResult(target, result) &&
    original.kind === 'file' &&
    matchesPresentPreimage(staged, original) &&
    source === undefined
  ) {
    return 'preimage-retained';
  }
  if (
    matchesOrdinaryResult(target, result) &&
    original.kind === 'file' &&
    matchesPresentPreimage(source, original) &&
    staged === undefined
  ) {
    return 'forward-complete';
  }
  if (matchesOrdinaryResult(target, result) && source === undefined && staged === undefined) {
    return 'forward-cleaned';
  }
  return 'invalid';
}

async function observeOrdinary(
  port: LifecycleTransactionPort,
  path: string,
): Promise<OrdinaryObservation | undefined> {
  const snapshot = await port.readFileNoFollow(path);
  if (snapshot === undefined || snapshot.observation.kind !== 'file') {
    snapshot?.bytes.fill(0);
    return undefined;
  }
  return {
    kind: 'file',
    identity: snapshot.observation.identity,
    mode: snapshot.observation.mode,
    bytes: snapshot.bytes,
  };
}
async function observeWal(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
): Promise<WalObservation | undefined> {
  const snapshot = await port.readWalFileNoFollow({ lock, path });
  if (snapshot === undefined || snapshot.observation.kind !== 'file') {
    snapshot?.bytes.fill(0);
    return undefined;
  }
  return {
    kind: 'file',
    identity: snapshot.observation.identity,
    mode: snapshot.observation.mode,
    bytes: snapshot.bytes,
    snapshot: snapshot.snapshot,
  };
}

async function assertPreimages(
  port: LifecycleTransactionPort,
  preimages: readonly LifecyclePreimage[],
  skipPaths: readonly string[] = [],
): Promise<void> {
  const skipped = new Set(skipPaths);
  for (const preimage of preimages) {
    if (skipped.has(preimage.path)) {
      continue;
    }
    if (preimage.state === 'absent') {
      await assertAbsent(port, preimage.path);
      continue;
    }
    if (preimage.state === 'directory') {
      const observed = await port.lstatNoFollow(preimage.path);
      if (!sameDirectoryObservation(observed, preimage.identity, preimage.mode)) {
        throw bounded('setup-authority');
      }
      continue;
    }
    if (preimage.state === 'credential') {
      const observed = await port.lstatNoFollow(preimage.path);
      if (!sameObservation(observed, preimage.identity, preimage.mode)) {
        throw bounded('setup-authority');
      }
      continue;
    }
    const observed = await observeOrdinary(port, preimage.path);
    if (!matchesPresentPreimage(observed, preimage)) {
      throw bounded('setup-authority');
    }
  }
}

async function assertExactFile(
  port: LifecycleTransactionPort,
  path: string,
  bytes: Uint8Array,
): Promise<void> {
  const observed = await observeOrdinary(port, path);
  if (observed === undefined || !sameBytes(observed.bytes, bytes)) {
    throw bounded('uninstall-authority');
  }
}

async function assertAbsent(port: LifecycleTransactionPort, path: string): Promise<void> {
  if ((await port.lstatNoFollow(path)) !== undefined) {
    throw bounded('setup-authority');
  }
}
async function assertAbsentAll(
  port: LifecycleTransactionPort,
  paths: readonly string[],
): Promise<void> {
  for (const path of paths) {
    await assertAbsent(port, path);
  }
}

interface ReadWalAuthority {
  readonly serialized: string;
  readonly identity: LifecycleFileIdentity;
  readonly mode: number;
}

async function readWalAuthority(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
): Promise<ReadWalAuthority | undefined> {
  const snapshot = await port.readWalFileNoFollow({ lock, path });
  if (snapshot === undefined) {
    return undefined;
  }
  try {
    if (
      snapshot.observation.kind !== 'file' ||
      snapshot.bytes.byteLength > MAX_SERIALIZED_WAL_BYTES
    ) {
      throw bounded('wal-authority');
    }
    return Object.freeze({
      serialized: new TextDecoder('utf-8', { fatal: true }).decode(snapshot.bytes),
      identity: snapshot.observation.identity,
      mode: snapshot.observation.mode,
    });
  } finally {
    snapshot.bytes.fill(0);
  }
}
async function readWal(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  path: string,
): Promise<string | undefined> {
  const snapshot = await port.readWalFileNoFollow({ lock, path });
  if (snapshot === undefined) {
    return undefined;
  }
  try {
    if (snapshot.observation.kind !== 'file') {
      throw bounded('wal-authority');
    }
    if (snapshot.bytes.byteLength > MAX_SERIALIZED_WAL_BYTES) {
      throw bounded('wal-authority');
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(snapshot.bytes);
  } finally {
    snapshot.bytes.fill(0);
  }
}

function isWalObservation(
  observation: OrdinaryObservation | WalObservation,
): observation is WalObservation {
  return 'snapshot' in observation;
}

function matchesPreimage(
  observed: OrdinaryObservation | undefined,
  expected: OrdinaryWalPreimageV2,
): boolean {
  if (expected.kind === 'absent') {
    return observed === undefined;
  }
  return matchesPresentPreimage(observed, expected);
}

function matchesPresentPreimage(
  observed: OrdinaryObservation | undefined,
  expected: {
    readonly identity: WalFileIdentityV2;
    readonly mode: number;
    readonly bytes: string | Uint8Array;
  },
): boolean {
  if (
    observed === undefined ||
    !sameIdentity(observed.identity, expected.identity) ||
    observed.mode !== expected.mode
  ) {
    return false;
  }
  const expectedBytes =
    typeof expected.bytes === 'string' ? Buffer.from(expected.bytes, 'base64') : expected.bytes;
  try {
    return sameBytes(observed.bytes, expectedBytes);
  } finally {
    if (typeof expected.bytes === 'string') {
      expectedBytes.fill(0);
    }
  }
}

function matchesOrdinaryResult(
  observed: OrdinaryObservation | undefined,
  result: WalOrdinaryMutationV2['result'],
): boolean {
  if (result.kind === 'absent') {
    return observed === undefined;
  }
  if (result.kind !== 'file') {
    return false;
  }
  return matchesPresentPreimage(observed, result);
}

function sameObservation(
  observed: LifecyclePathObservation | undefined,
  identity: LifecycleFileIdentity | undefined,
  mode: number,
): observed is LifecycleRegularFileObservation {
  return (
    observed !== undefined &&
    identity !== undefined &&
    observed.kind === 'file' &&
    observed.mode === mode &&
    sameIdentity(observed.identity, identity)
  );
}
function sameDirectoryObservation(
  observed: LifecyclePathObservation | undefined,
  identity: LifecycleFileIdentity | undefined,
  mode: number,
): observed is LifecycleDirectoryObservation {
  return (
    observed !== undefined &&
    identity !== undefined &&
    observed.kind === 'directory' &&
    observed.mode === mode &&
    sameIdentity(observed.identity, identity)
  );
}

function sameIdentity(left: LifecycleFileIdentity, right: LifecycleFileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let different = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    different |= left[index]! ^ right[index]!;
  }
  return different === 0;
}

function preimageIndex(preimages: readonly { readonly path: string }[], path: string): number {
  const index = preimages.findIndex((preimage) => preimage.path === path);
  if (index < 0) {
    throw bounded('setup-authority');
  }
  return index;
}

function requirePreimage(preimages: readonly LifecyclePreimage[], path: string): LifecyclePreimage {
  const value = preimages.find((preimage) => preimage.path === path);
  if (value === undefined) {
    throw bounded('setup-authority');
  }
  return value;
}
function requirePresentPreimage(
  preimages: readonly LifecyclePreimage[],
  path: string,
): LifecyclePresentPreimage {
  const preimage = requirePreimage(preimages, path);
  if (preimage.state !== 'file') {
    throw bounded('uninstall-authority');
  }
  return preimage;
}

function indexPreimages(
  preimages: readonly LifecyclePreimage[],
): ReadonlyMap<string, LifecyclePreimage> {
  return new Map(preimages.map((preimage) => [preimage.path, preimage]));
}

function freezePreimages(preimages: readonly LifecyclePreimage[]): readonly LifecyclePreimage[] {
  return Object.freeze(
    preimages.map((preimage) => {
      if (preimage.state === 'absent') {
        return Object.freeze({ path: preimage.path, state: 'absent' as const });
      }
      const identity = Object.freeze({
        device: preimage.identity.device,
        inode: preimage.identity.inode,
      });
      if (preimage.state === 'credential') {
        return Object.freeze({
          path: preimage.path,
          state: 'credential' as const,
          identity,
          mode: preimage.mode,
        });
      }
      if (preimage.state === 'directory') {
        return Object.freeze({
          path: preimage.path,
          state: 'directory' as const,
          identity,
          mode: preimage.mode,
        });
      }
      if (!(preimage.bytes instanceof Uint8Array)) {
        throw bounded('setup-authority');
      }
      return Object.freeze({
        path: preimage.path,
        state: 'file' as const,
        identity,
        mode: preimage.mode,
        bytes: REFLECT_APPLY(TYPED_ARRAY_SLICE, preimage.bytes, []) as Uint8Array,
      });
    }),
  );
}

function auxiliaryPath(
  path: string,
  operationId: LifecycleId,
  step: number,
  role: 'rollback' | 'stage',
): string {
  return `${path}.scene-glass-${operationId}-${step}.${role}`;
}
function walStagingPath(path: string): string {
  return `${path}.scene-glass-wal.stage`;
}
async function hasLegacyWalStageResidue(
  port: LifecycleTransactionPort,
  walPath: string,
  operationId: LifecycleId,
): Promise<boolean> {
  for (let step = 0; step <= MAX_WAL_MUTATIONS; step += 1) {
    if (
      (await port.lstatNoFollow(auxiliaryPath(walPath, operationId, step, 'stage'))) !== undefined
    ) {
      return true;
    }
  }
  return false;
}
function lifecycleCreationIntentStageToken(stagePath: string): string {
  return createHash('sha256').update(stagePath, 'utf8').digest('hex').slice(0, 16);
}
function lifecycleCreationIntentMarkerPath(
  stagePath: string,
  kind: WalCreationIntentV2['kind'],
  mode: number,
  token: string,
): string {
  const stageToken = lifecycleCreationIntentStageToken(stagePath);
  return join(
    dirname(stagePath),
    `.scg-intent-${stageToken}-${kind}-${mode.toString(8).padStart(3, '0')}-${token}.marker`,
  );
}
function creationIntentAuthority(
  record: WalRecordV2,
  intent: WalCreationIntentV2,
): LifecycleCreationIntentAuthority | undefined {
  if (
    intent.step !== record.mutations.length ||
    (record.operation === 'uninstall' && intent.kind !== 'file') ||
    !/^[a-f0-9]{32}$/.test(intent.validationToken) ||
    intent.validationToken !== lifecycleCreationIntentValidationToken(record, intent)
  ) {
    return undefined;
  }
  const markerPath = lifecycleCreationIntentMarkerPath(
    intent.stagingPath,
    intent.kind,
    intent.mode,
    intent.validationToken,
  );
  if (
    !validPath(markerPath) ||
    markerPath === intent.targetPath ||
    markerPath === intent.stagingPath ||
    dirname(markerPath) !== dirname(intent.stagingPath)
  ) {
    return undefined;
  }
  return Object.freeze({ markerPath, intent });
}
function resolveCreationIntent(
  record: WalRecordV2,
  operationId: LifecycleId,
  targetPath: string,
  stagePath: string,
  kind: WalCreationIntentV2['kind'],
  mode: number,
): {
  readonly intent: LifecycleCreationIntentAuthority;
  readonly durable: boolean;
} {
  const existing = record.creationIntents;
  if (existing === undefined) {
    return Object.freeze({
      intent: creationIntentFor(record, operationId, targetPath, stagePath, kind, mode),
      durable: false,
    });
  }
  const candidate = existing.length === 1 ? existing[0] : undefined;
  if (candidate === undefined) {
    throw bounded('wal-authority');
  }
  const authority = creationIntentAuthority(record, candidate);
  if (
    authority === undefined ||
    record.operationId !== operationId ||
    candidate.targetPath !== targetPath ||
    candidate.stagingPath !== stagePath ||
    candidate.kind !== kind ||
    candidate.mode !== mode
  ) {
    throw bounded('wal-authority');
  }
  return Object.freeze({ intent: authority, durable: true });
}
function creationIntentFor(
  record: WalRecordV2,
  operationId: LifecycleId,
  targetPath: string,
  stagePath: string,
  kind: WalCreationIntentV2['kind'],
  mode: number,
): LifecycleCreationIntentAuthority {
  if (
    record.operationId !== operationId ||
    record.creationIntents !== undefined ||
    !validMode(mode) ||
    (kind === 'credential' && (record.operation !== 'setup' || mode !== 0o600)) ||
    (kind === 'directory' && record.operation !== 'setup')
  ) {
    throw bounded('wal-authority');
  }
  const step = record.mutations.length;
  const targetPreimage = preimageIndex(record.preimages, targetPath);
  const stagingPreimage = preimageIndex(record.preimages, stagePath);
  if (
    targetPreimage === stagingPreimage ||
    record.preimages[stagingPreimage]?.kind !== 'absent' ||
    record.preimages[targetPreimage] === undefined ||
    (kind !== 'file' && record.preimages[targetPreimage]?.kind !== 'absent') ||
    (kind === 'file' && record.preimages[targetPreimage]?.kind === 'credential')
  ) {
    throw bounded('wal-authority');
  }
  const validationToken = lifecycleCreationIntentValidationToken(record, {
    step,
    kind,
    targetPath,
    stagingPath: stagePath,
    mode,
    targetPreimage,
    stagingPreimage,
  });
  const markerPath = lifecycleCreationIntentMarkerPath(stagePath, kind, mode, validationToken);
  if (
    !validPath(markerPath) ||
    markerPath === targetPath ||
    markerPath === stagePath ||
    dirname(markerPath) !== dirname(stagePath) ||
    record.preimages.some((preimage) => preimage.path === markerPath)
  ) {
    throw bounded('setup-authority');
  }
  return Object.freeze({
    markerPath,
    intent: Object.freeze({
      step,
      kind,
      targetPath,
      stagingPath: stagePath,
      mode,
      validationToken,
      targetPreimage,
      stagingPreimage,
    }),
  });
}

function lifecycleCreationIntentValidationToken(
  record: WalRecordV2,
  intent: Omit<WalCreationIntentV2, 'validationToken'>,
): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        record.operationId,
        record.installId,
        intent.step,
        intent.kind,
        intent.targetPath,
        intent.stagingPath,
        intent.mode,
        intent.targetPreimage,
        intent.stagingPreimage,
      ]),
      'utf8',
    )
    .digest('hex')
    .slice(0, 32);
}
function credentialQuarantinePath(
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
  credentialPath: string,
): string {
  return `${credentialPath}.scene-glass-${record.operationId}.credential-quarantine`;
}
function credentialRemovalQuarantinePath(
  credentialPath: string,
  identity: LifecycleFileIdentity,
): string {
  return join(dirname(credentialPath), `.scg-remove-${identity.device}-${identity.inode}`);
}
function directoryRemovalQuarantinePath(
  record: Extract<WalRecordV2, { readonly operation: 'uninstall' }>,
  artifact: Extract<SetupManifestV1['artifacts'][number], { readonly kind: 'directory' }>,
): string {
  return `${artifact.path}.scene-glass-${record.operationId}.directory-quarantine`;
}
function directoryRemovalReconciliationPath(quarantinePath: string): string {
  return `${quarantinePath}.reconcile`;
}

function unwrapSetupAuthority(handle: SetupTransactionAuthority): InternalSetupAuthority {
  const value = (handle as unknown as { readonly [SETUP_AUTHORITY]?: InternalSetupAuthority })[
    SETUP_AUTHORITY
  ];
  if (value === undefined) {
    throw new LifecycleTransactionError('setup', [failure('setup-authority')]);
  }
  return value;
}

function unwrapReceipt(receipt: SetupTransactionReceipt): InternalSetupReceipt {
  const value = (receipt as unknown as { readonly [SETUP_RECEIPT]?: InternalSetupReceipt })[
    SETUP_RECEIPT
  ];
  if (value === undefined) {
    throw new LifecycleTransactionError('setup', [failure('setup-authority')]);
  }
  return value;
}
function claimSetupAuthority(
  authority: InternalSetupAuthority,
  expected: SetupAuthorityState | readonly SetupAuthorityState[],
  next: Exclude<SetupAuthorityState, 'open' | 'closed' | 'receipt-pending' | 'release-pending'>,
): void {
  const states = typeof expected === 'string' ? [expected] : expected;
  if (authority.released || !states.includes(authority.state)) {
    throw new LifecycleTransactionError('setup', [failure('setup-authority')]);
  }
  authority.state = next;
}

async function closeSetupResult(
  authority: InternalSetupAuthority,
  result: LifecycleTransactionResult,
): Promise<LifecycleTransactionResult> {
  if (authority.state === 'closed') {
    return result;
  }

  let closedResult = authority.pendingCloseResult ?? result;
  if (
    authority.state !== 'release-pending' &&
    closedResult.state === 'recovery-required' &&
    authority.record?.operation === 'setup' &&
    authority.record.phase === 'finalized'
  ) {
    const retainedFailures: LifecycleTransactionFailure[] = [];
    for (const stage of authority.stagedWrites.values()) {
      const retained = await retainStagedWriteForRecovery(
        authority.port,
        authority.lock,
        authority.walPath,
        authority.record,
        stage,
      );
      if (retained !== undefined) {
        retainedFailures.push(retained);
      }
    }
    if (retainedFailures.length !== 0) {
      closedResult = withFailures(closedResult, retainedFailures);
    }
  }

  authority.pendingCloseResult = closedResult;
  const release = await releaseLock(authority.port, authority.lock);
  if (release !== undefined) {
    authority.state = 'release-pending';
    return releasePending(closedResult, release);
  }
  authority.released = true;
  authority.pendingCloseResult = undefined;
  authority.stagedWrites.clear();
  authority.state = 'closed';
  return closedResult;
}

async function releaseLock(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
): Promise<LifecycleTransactionFailure | undefined> {
  try {
    await boundary(port, 'lock-release', () => lock.release());
    return undefined;
  } catch {
    return failure('lock-release');
  }
}

async function discardReservation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  reservation: LifecycleReservedStagedWrite,
): Promise<LifecycleTransactionFailure | undefined> {
  try {
    return (await port.discardReservedStagedWrite({ lock, reservation })).state === 'completed'
      ? undefined
      : failure('cleanup');
  } catch {
    return failure('cleanup');
  }
}
async function retainReservationForRecovery(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: WalRecordV2 | undefined,
  reservation: LifecycleReservedStagedWrite | LifecycleReservedStagedDirectory,
): Promise<LifecycleTransactionFailure | undefined> {
  if (record === undefined) {
    return failure('cleanup');
  }

  let current: WalObservation | undefined;
  try {
    current = await observeWal(port, lock, walPath);
    if (
      current === undefined ||
      current.mode !== 0o600 ||
      (!sameBytes(current.bytes, encode(serializeWalRecordV2(record))) &&
        !sameWalRecordIgnoringReplacedStage(current.bytes, record))
    ) {
      return failure('cleanup');
    }
    const retained =
      'mode' in reservation
        ? await port.retainReservedStagedDirectoryForRecovery({
            lock,
            reservation,
            snapshot: current.snapshot,
          })
        : await port.retainReservedStagedWriteForRecovery({
            lock,
            reservation,
            snapshot: current.snapshot,
          });
    return retained.state === 'completed' ? undefined : failure('cleanup');
  } catch {
    return failure('cleanup');
  } finally {
    current?.bytes.fill(0);
  }
}
async function retainStagedWriteForRecovery(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: WalRecordV2 | undefined,
  stage: LifecycleStagedWrite,
): Promise<LifecycleTransactionFailure | undefined> {
  if (record === undefined) {
    return failure('cleanup');
  }

  let current: WalObservation | undefined;
  try {
    current = await observeWal(port, lock, walPath);
    if (
      current === undefined ||
      current.mode !== 0o600 ||
      (!sameBytes(current.bytes, encode(serializeWalRecordV2(record))) &&
        !sameWalRecordIgnoringReplacedStage(current.bytes, record))
    ) {
      return failure('cleanup');
    }
    return (await port.retainStagedWriteForRecovery({ lock, stage, snapshot: current.snapshot }))
      .state === 'completed'
      ? undefined
      : failure('cleanup');
  } catch {
    return failure('cleanup');
  } finally {
    current?.bytes.fill(0);
  }
}

async function discardDirectoryReservation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  reservation: LifecycleReservedStagedDirectory,
): Promise<LifecycleTransactionFailure | undefined> {
  try {
    const discarded = await port.discardReservedStagedDirectory({ lock, reservation });
    await finalizeExactMutation(port, lock, 'cleanup', discarded);
    return undefined;
  } catch {
    return failure('indeterminate');
  }
}
async function discardUnpublishedSetupReservations(
  authority: InternalSetupAuthority,
): Promise<readonly LifecycleTransactionFailure[]> {
  const failures: LifecycleTransactionFailure[] = [];
  if (authority.credentialReservation !== undefined) {
    const cleanup = await discardReservation(
      authority.port,
      authority.lock,
      authority.credentialReservation,
    );
    if (cleanup !== undefined) {
      failures.push(cleanup);
    }
  }
  for (const reservation of [...authority.directoryReservations].reverse()) {
    const cleanup = await discardDirectoryReservation(authority.port, authority.lock, reservation);
    if (cleanup !== undefined) {
      failures.push(cleanup);
    }
  }
  return Object.freeze(failures);
}

async function retainOpenedSetupReservations(
  authority: InternalSetupAuthority,
): Promise<readonly LifecycleTransactionFailure[]> {
  const failures: LifecycleTransactionFailure[] = [];
  if (authority.credentialReservation !== undefined) {
    const retained = await retainReservationForRecovery(
      authority.port,
      authority.lock,
      authority.walPath,
      authority.record,
      authority.credentialReservation,
    );
    if (retained !== undefined) {
      failures.push(retained);
    }
  }
  for (const reservation of [...authority.directoryReservations].reverse()) {
    const retained = await retainReservationForRecovery(
      authority.port,
      authority.lock,
      authority.walPath,
      authority.record,
      reservation,
    );
    if (retained !== undefined) {
      failures.push(retained);
    }
  }
  return Object.freeze(failures);
}

function isBoundCredentialReservation(
  authority: InternalSetupAuthority,
  reservation: LifecycleReservedStagedWrite,
): boolean {
  return (
    authority.record?.mutations.some(
      (mutation) =>
        mutation.kind === 'credential' &&
        mutation.stagingPath === reservation.path &&
        sameIdentity(mutation.stagingIdentity, reservation.identity),
    ) ?? false
  );
}

async function discardStage(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  stage: LifecycleExactContentFile | LifecycleStagedWrite,
): Promise<LifecycleTransactionFailure | undefined> {
  try {
    const result =
      'state' in stage
        ? await port.discardStagedWrite({ lock, stage })
        : await port.removeExactStagedFile({ lock, current: stage });
    await finalizeExactMutation(port, lock, 'cleanup', result);
    return result.state === 'completed' ? undefined : failure('cleanup');
  } catch {
    return failure('cleanup');
  }
}

async function discardPreparedStages(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  prepared: readonly PreparedOrdinaryMutation[],
): Promise<readonly LifecycleTransactionFailure[]> {
  const failures: LifecycleTransactionFailure[] = [];
  for (const item of prepared) {
    if (item.action !== 'write') {
      continue;
    }
    const cleanup = await discardStage(port, lock, item.stage ?? exactResultStage(item.mutation));
    if (cleanup !== undefined) {
      failures.push(cleanup);
    }
  }
  return Object.freeze(failures);
}
async function retainPreparedStagesForRecovery(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  walPath: string,
  record: WalRecordV2,
  prepared: readonly PreparedOrdinaryMutation[],
): Promise<readonly LifecycleTransactionFailure[]> {
  const failures: LifecycleTransactionFailure[] = [];
  for (const item of prepared) {
    if (item.stage === undefined) {
      continue;
    }
    const retained = await retainStagedWriteForRecovery(port, lock, walPath, record, item.stage);
    if (retained !== undefined) {
      failures.push(retained);
    }
  }
  return Object.freeze(failures);
}

async function boundary<T>(
  port: LifecycleTransactionPort,
  point: LifecycleFailurePoint,
  action: () => Promise<T>,
): Promise<T> {
  try {
    await port.failurePoint(point);
  } catch {
    throw bounded(point);
  }
  return action();
}
async function exactMutationBoundary(
  port: LifecycleTransactionPort,
  point: LifecycleFailurePoint,
  action: () => Promise<LifecycleExactMutationResult>,
): Promise<LifecycleExactMutationResult> {
  await boundary(port, point, async () => undefined);
  try {
    return await action();
  } catch {
    throw bounded('indeterminate');
  }
}

async function finalizeExactMutation(
  port: LifecycleTransactionPort,
  lock: LifecycleAdvisoryLock,
  point: LifecycleFailurePoint,
  result: LifecycleExactMutationResult | undefined,
): Promise<void> {
  if (result === undefined) {
    return;
  }
  if (result.state !== 'completed') {
    throw bounded('indeterminate');
  }
  if (result.quarantine === undefined) {
    return;
  }
  const finalized = await exactMutationBoundary(port, point, () =>
    port.finalizeQuarantine({ lock, quarantine: result.quarantine! }),
  );
  if (finalized.state !== 'completed') {
    throw bounded('indeterminate');
  }
}
function requireQuarantineRetained(result: LifecycleExactMutationResult): void {
  if (result.state !== 'completed' || result.quarantine === undefined) {
    throw bounded('indeterminate');
  }
}

class CleanupFailure extends Error {
  public constructor(
    readonly source: unknown,
    readonly cleanupFailures: readonly LifecycleTransactionFailure[],
    readonly cleanupCause?: unknown,
  ) {
    super('lifecycle cleanup failed');
    this.name = 'CleanupFailure';
  }
}

function cleanupFailuresFrom(error: unknown): readonly LifecycleTransactionFailure[] {
  if (!(error instanceof CleanupFailure)) {
    return Object.freeze([]);
  }
  return Object.freeze([...cleanupFailuresFrom(error.source), ...error.cleanupFailures]);
}

class WalPublicationFailure extends Error {
  public constructor(readonly source: unknown) {
    super('lifecycle WAL publication is unresolved');
    this.name = 'WalPublicationFailure';
  }
}

class BoundedFailure extends Error {
  public constructor(readonly stage: string) {
    super(stage);
  }
}

function bounded(stage: string): BoundedFailure {
  return new BoundedFailure(stage);
}
function isRetainedOrIndeterminate(error: unknown): boolean {
  if (error instanceof CleanupFailure || error instanceof WalPublicationFailure) {
    return true;
  }
  return (
    error instanceof BoundedFailure &&
    (error.stage === 'preimage-retained' || error.stage === 'indeterminate')
  );
}

function failureStage(error: unknown, fallback: string): string {
  if (error instanceof WalPublicationFailure) {
    return 'indeterminate';
  }
  if (error instanceof CleanupFailure) {
    return failureStage(error.source, fallback);
  }
  return error instanceof BoundedFailure ? error.stage : fallback;
}

function transactionError(
  operation: 'setup' | 'uninstall' | 'recovery',
  error: unknown,
  fallback: string,
): LifecycleTransactionError {
  return new LifecycleTransactionError(operation, failuresFromError(error, fallback));
}
function convergedTransactionError(
  operation: 'setup' | 'uninstall' | 'recovery',
  error: unknown,
  fallback: string,
  convergence: 'never-installed',
): LifecycleTransactionError {
  const result = transactionError(operation, error, fallback);
  lifecycleTransactionConvergences.set(result, convergence);
  return result;
}

function failuresFromError(
  error: unknown,
  fallback: string,
): readonly LifecycleTransactionFailure[] {
  return Object.freeze([failure(failureStage(error, fallback)), ...cleanupFailuresFrom(error)]);
}

function failure(stage: string): LifecycleTransactionFailure {
  return Object.freeze({ stage });
}

function completed(state: LifecycleTransactionResult['state']): LifecycleTransactionResult {
  return Object.freeze({ state, failures: Object.freeze([]) });
}

function recoveryRequired(
  failures: readonly LifecycleTransactionFailure[],
): LifecycleTransactionResult {
  return Object.freeze({ state: 'recovery-required', failures: Object.freeze([...failures]) });
}

function withFailure(
  result: LifecycleTransactionResult,
  item: LifecycleTransactionFailure,
): LifecycleTransactionResult {
  return Object.freeze({
    state: result.state,
    failures: Object.freeze([...result.failures, item]),
  });
}
function releasePending(
  result: LifecycleTransactionResult,
  item: LifecycleTransactionFailure,
): LifecycleTransactionResult {
  return result.state === 'recovery-required'
    ? withFailure(result, item)
    : recoveryRequired([...result.failures, item]);
}
function withFailures(
  result: LifecycleTransactionResult,
  failures: readonly LifecycleTransactionFailure[],
): LifecycleTransactionResult {
  return Object.freeze({
    state: result.state,
    failures: Object.freeze([...result.failures, ...failures]),
  });
}

function fingerprint(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
function fingerprintBytes(value: Uint8Array): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
function recoveryId(value: string): string {
  return `scg-${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 48)}`;
}

function encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function validPath(path: string): boolean {
  return (
    typeof path === 'string' &&
    Buffer.byteLength(path, 'utf8') <= 4096 &&
    isAbsolute(path) &&
    path !== '/' &&
    !path.endsWith('/') &&
    normalize(path) === path &&
    !path.includes('\0')
  );
}

function validId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
}

function validMode(mode: number): boolean {
  return Number.isSafeInteger(mode) && mode >= 0 && mode <= 0o777;
}

function validIdentity(identity: LifecycleFileIdentity): boolean {
  return (
    /^0$|^[1-9][0-9]{0,31}$/.test(identity.device) && /^0$|^[1-9][0-9]{0,31}$/.test(identity.inode)
  );
}
