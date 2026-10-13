import type { ViteSnapshotAuthority } from '../vite/index.js';
import type { CredentialAuthorityRegistryEntry } from '../credential-authority.js';
import type { ProjectConfigV1, ServerConfigV1 } from '@scene-glass/contracts';

/** The lifecycle schema is intentionally independent of on-disk JSON formatting. */
export const LIFECYCLE_SCHEMA_VERSION = 1 as const;

export type LifecycleState =
  'never-installed' | 'active' | 'recovery-required' | 'uninstalled' | 'lost-provenance';

export type LifecycleJsonPrimitive = boolean | null | number | string;
export type LifecycleJsonValue =
  | LifecycleJsonPrimitive
  | readonly LifecycleJsonValue[]
  | { readonly [key: string]: LifecycleJsonValue };

export type LifecycleArtifactKind =
  'file' | 'config' | 'credential' | 'credential-authority-registry' | 'directory';
export type LifecycleOperationKind =
  | 'create-file'
  | 'create-directory'
  | 'update-config'
  | 'update-credential-authority-registry'
  | 'move-config'
  | 'delete-created-file'
  | 'delete-created-credential'
  | 'delete-created-directory'
  | 'restore-config'
  | 'restore-owned-file'
  | 'restore-credential-authority-registry-entry'
  | 'remove-config-hunks'
  | 'none';

/**
 * Opaque lifecycle identifiers are bounded, URL/file-name safe values. They
 * identify a transaction, never authentication material.
 */
export type LifecycleId = string;

export interface OwnedHunk {
  readonly id: LifecycleId;
  /** A non-secret content fingerprint for exactly this owned hunk. */
  readonly fingerprint: string;
  /** Structural description only; this is never source text. */
  readonly operation: 'insert' | 'update';
  readonly subject: string;
}

/**
 * A semantic image contains only the projects this lifecycle operation owns.
 * It intentionally does not capture unrelated config projects or file bytes.
 */
export interface SemanticConfigImage {
  readonly schemaVersion: 1;
  readonly projects: readonly ProjectConfigV1[];
}
/**
 * This image has zero or one entry for the selected project only. It never
 * persists unrelated registry entries, credential bytes, or token digests.
 */
export interface SemanticCredentialAuthorityRegistryImage {
  readonly schemaVersion: 1;
  readonly projects: readonly CredentialAuthorityRegistryEntry[];
}

export interface DeleteCreatedFileInverseOperation {
  readonly kind: 'delete-created-file';
  readonly path: string;
  readonly expectedFingerprint: string;
}
export interface RestoreOwnedFileInverseOperation {
  readonly kind: 'restore-owned-file';
  readonly path: string;
  /** SHA-256 of the original bytes; source bytes are never persisted. */
  readonly preimageFingerprint: string;
  /** SHA-256 of the bytes written by setup. */
  readonly postimageFingerprint: string;
  /**
   * The exact owned insertion shape. This makes uninstall authority local to
   * the loader line and its `</head>` anchor rather than the whole postimage.
   */
  readonly ownedInsertion: 'line' | 'preceding-newline-line';
  /** Bounded structural metadata for the deterministic owned transformation. */
  readonly hunks: readonly OwnedHunk[];
}

export interface DeleteCreatedCredentialInverseOperation {
  readonly kind: 'delete-created-credential';
  readonly path: string;
  /**
   * These fields are absent only from a preapproval plan. A persisted manifest
   * always carries the exact credential authority.
   */
  readonly projectId?: LifecycleId;
  readonly identity?: WalFileIdentityV2;
  readonly mode?: 0o600;
  readonly linkCount?: 1;
}
export interface DeleteCreatedDirectoryInverseOperation {
  readonly kind: 'delete-created-directory';
  readonly path: string;
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  readonly emptyOnly: true;
}
export interface RestoreConfigInverseOperation {
  readonly kind: 'restore-config';
  readonly path: string;
  readonly preimage: SemanticConfigImage;
  readonly postimage: SemanticConfigImage;
}
export interface RemoveConfigHunksInverseOperation {
  readonly kind: 'remove-config-hunks';
  readonly path: string;
  readonly hunks: readonly OwnedHunk[];
  readonly preimage: SemanticConfigImage;
  readonly postimage: SemanticConfigImage;
}
export interface RestoreCredentialAuthorityRegistryEntryInverseOperation {
  readonly kind: 'restore-credential-authority-registry-entry';
  readonly path: string;
  readonly preimage: SemanticCredentialAuthorityRegistryImage;
  readonly postimage: SemanticCredentialAuthorityRegistryImage;
}
export interface NoopInverseOperation {
  readonly kind: 'none';
}
export type InverseOperation =
  | DeleteCreatedFileInverseOperation
  | RestoreOwnedFileInverseOperation
  | DeleteCreatedCredentialInverseOperation
  | DeleteCreatedDirectoryInverseOperation
  | RestoreConfigInverseOperation
  | RemoveConfigHunksInverseOperation
  | RestoreCredentialAuthorityRegistryEntryInverseOperation
  | NoopInverseOperation;

export interface OwnedFileArtifact {
  readonly path: string;
  readonly kind: 'file';
  readonly fingerprint: string;
  readonly hunks: readonly OwnedHunk[];
  /**
   * `none` is permitted only in a preapproval plan and is never parseable in a
   * persisted setup manifest.
   */
  readonly inverse:
    DeleteCreatedFileInverseOperation | RestoreOwnedFileInverseOperation | NoopInverseOperation;
}

export interface OwnedConfigArtifact {
  readonly path: string;
  readonly kind: 'config';
  readonly fingerprint: string;
  readonly hunks: readonly OwnedHunk[];
  readonly preimage: SemanticConfigImage;
  readonly postimage: SemanticConfigImage;
  readonly inverse: RestoreConfigInverseOperation | RemoveConfigHunksInverseOperation;
}
/**
 * A semantic registry artifact owns only one selected entry. Its fingerprint
 * attests the exact non-secret bytes published by setup.
 */
export interface OwnedCredentialAuthorityRegistryArtifact {
  readonly path: string;
  readonly kind: 'credential-authority-registry';
  readonly fingerprint: string;
  readonly preimage: SemanticCredentialAuthorityRegistryImage;
  readonly postimage: SemanticCredentialAuthorityRegistryImage;
  readonly inverse: RestoreCredentialAuthorityRegistryEntryInverseOperation;
}
/**
 * Preapproval candidates have only a path. A persisted manifest always carries
 * the exact authority fields populated after the credential postimage exists.
 */
export interface SetupCreatedCredentialArtifact {
  readonly path: string;
  readonly kind: 'credential';
  readonly ownership: 'setup-created';
  readonly projectId?: LifecycleId;
  readonly identity?: WalFileIdentityV2;
  readonly mode?: 0o600;
  readonly linkCount?: 1;
  readonly inverse: DeleteCreatedCredentialInverseOperation;
}

/** An exact setup-created directory may be removed only after all owned children. */
export interface OwnedDirectoryArtifact {
  readonly path: string;
  readonly kind: 'directory';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  readonly inverse: DeleteCreatedDirectoryInverseOperation;
}

/** An adopted credential is observed authority and is never deleted. */
export interface AdoptedCredentialArtifact {
  readonly path: string;
  readonly kind: 'credential';
  readonly ownership: 'adopted';
  readonly inverse: NoopInverseOperation;
}

export type OwnedArtifact =
  | OwnedFileArtifact
  | OwnedConfigArtifact
  | SetupCreatedCredentialArtifact
  | OwnedCredentialAuthorityRegistryArtifact
  | OwnedDirectoryArtifact
  | AdoptedCredentialArtifact;

export interface SetupManifestV1 {
  readonly schemaVersion: 1;
  readonly kind: 'scene-glass-setup-manifest';
  readonly installId: LifecycleId;
  readonly state: 'active';
  readonly artifacts: readonly OwnedArtifact[];
}

export interface LifecycleReceiptV1 {
  readonly schemaVersion: 1;
  readonly kind: 'scene-glass-lifecycle-receipt';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly terminalState: 'active' | 'uninstalled' | 'recovery-required';
  readonly manifestFingerprint: string;
}

export interface WalRecordV1 {
  readonly schemaVersion: 1;
  readonly kind: 'scene-glass-lifecycle-wal';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly operation: 'setup' | 'uninstall';
  readonly phase: 'prepared' | 'applied';
  readonly manifestFingerprint: string;
}
/**
 * Disk-authoritative WAL v2 carries only the exact non-secret authority needed
 * to finish or compensate a lifecycle operation after a process restart.
 */
export type WalDirectionV2 = 'rollback' | 'commit';
export type SetupWalPhaseV2 = 'prepared' | 'finalized' | 'commit-decided';
export type UninstallWalPhaseV2 = 'prepared' | 'commit-decided';

export interface WalFileIdentityV2 {
  readonly device: string;
  readonly inode: string;
}
export interface WalReplacedStageLineage {
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  readonly authorityFingerprint: string;
}

export interface WalAbsentPreimageV2 {
  readonly path: string;
  readonly kind: 'absent';
}

export interface WalFilePreimageV2 {
  readonly path: string;
  readonly kind: 'file';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  /** Canonical base64 for a bounded noncredential file image. */
  readonly bytes: string;
}
export interface WalDirectoryPreimageV2 {
  readonly path: string;
  readonly kind: 'directory';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
}

/**
 * Identity-only credential recovery authority. Credential content, content
 * fingerprints, tokens, and token digests are deliberately not representable.
 */
export interface WalCredentialPreimageV2 {
  readonly path: string;
  readonly kind: 'credential';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
}

export type WalPreimageV2 =
  WalAbsentPreimageV2 | WalFilePreimageV2 | WalDirectoryPreimageV2 | WalCredentialPreimageV2;

export interface WalAbsentResultV2 {
  readonly kind: 'absent';
}

export interface WalFileResultV2 {
  readonly kind: 'file';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  /** Canonical base64 for a bounded noncredential file image. */
  readonly bytes: string;
}
export interface WalDirectoryResultV2 {
  readonly kind: 'directory';
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
}

export type WalOrdinaryResultV2 = WalAbsentResultV2 | WalFileResultV2 | WalDirectoryResultV2;

/**
 * A durable creation intent grants validation/removal authority for one
 * staged resource before its final stage identity exists. File intents bind
 * an exact target preimage (absent or file); credential/directory targets
 * must be absent.
 */
export interface WalCreationIntentV2 {
  /** The next contiguous mutation step the completed creation will occupy. */
  readonly step: number;
  readonly kind: 'credential' | 'directory' | 'file';
  readonly targetPath: string;
  readonly stagingPath: string;
  readonly mode: number;
  /** A non-secret high-entropy canary for the native creation boundary. */
  readonly validationToken: string;
  /** Exact target preimage authority. */
  readonly targetPreimage: number;
  /** Exact absent-preimage authority for stagingPath. */
  readonly stagingPreimage: number;
}

/**
 * A noncredential mutation names every physical path it may touch. Its
 * preimage is an index into the record's ordered preimage authority.
 */
export interface WalOrdinaryMutationV2 {
  readonly step: number;
  readonly kind: 'ordinary';
  readonly targetPath: string;
  readonly sourcePath: string;
  readonly stagingPath: string;
  readonly preimage: number;
  readonly result: WalOrdinaryResultV2;
}

/**
 * Credential mutation authority is intentionally structural and identity-only.
 * It cannot encode credential bytes or a credential-content fingerprint.
 */
export interface WalCredentialMutationV2 {
  readonly step: number;
  readonly kind: 'credential';
  readonly projectId: LifecycleId;
  readonly path: string;
  readonly mode: number;
  readonly stagingPath: string;
  readonly stagingIdentity: WalFileIdentityV2;
  readonly targetIdentity: WalFileIdentityV2;
}

export type WalMutationV2 = WalOrdinaryMutationV2 | WalCredentialMutationV2;

interface SetupWalRecordV2Base {
  readonly schemaVersion: 2;
  readonly kind: 'scene-glass-lifecycle-wal';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly operation: 'setup';
  readonly lockPath: string;
  readonly manifestPath: string;
  /** Number of ordered mutation steps durably completed. */
  readonly cursor: number;
  readonly preimages: readonly WalPreimageV2[];
  readonly mutations: readonly WalMutationV2[];
  /**
   * Pending intent-authorized resources. This field is omitted when empty so
   * legacy v2 WAL records retain their exact canonical bytes.
   */
  readonly creationIntents?: readonly WalCreationIntentV2[];
  /** Non-secret integrity binding for the persisted recovery authority. */
  readonly authorityFingerprint: string;
  /** Exact transport lineage for a staged replacement of the current WAL image. */
  readonly replacedWalStage?: WalReplacedStageLineage;
}

export type SetupWalRecordV2 =
  | (SetupWalRecordV2Base & {
      readonly direction: 'rollback';
      readonly phase: 'prepared' | 'finalized';
    })
  | (SetupWalRecordV2Base & {
      readonly direction: 'commit';
      readonly phase: 'commit-decided';
    });

interface UninstallWalRecordV2Base {
  readonly schemaVersion: 2;
  readonly kind: 'scene-glass-lifecycle-wal';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly operation: 'uninstall';
  readonly lockPath: string;
  readonly manifestPath: string;
  /** Number of ordered mutation steps durably completed. */
  readonly cursor: number;
  readonly preimages: readonly WalPreimageV2[];
  readonly mutations: readonly WalMutationV2[];
  /** Pending intent-authorized ordinary file stage creation. */
  readonly creationIntents?: readonly WalCreationIntentV2[];
  /** Non-secret integrity binding for the persisted recovery authority. */
  readonly authorityFingerprint: string;
  /** Exact transport lineage for a staged replacement of the current WAL image. */
  readonly replacedWalStage?: WalReplacedStageLineage;
  readonly receiptPath: string;
  /** The exact active manifest needed to complete an uninstall from disk alone. */
  readonly manifest: SetupManifestV1;
}

export type UninstallWalRecordV2 =
  | (UninstallWalRecordV2Base & {
      readonly direction: 'rollback';
      readonly phase: 'prepared';
    })
  | (UninstallWalRecordV2Base & {
      readonly direction: 'commit';
      readonly phase: 'commit-decided';
    });

export type WalRecordV2 = SetupWalRecordV2 | UninstallWalRecordV2;
export const LIFECYCLE_HOST_SCHEMA_VERSION = 3 as const;

interface HostSetupManifestV2Base {
  readonly schemaVersion: 2;
  readonly kind: 'scene-glass-host-setup-manifest';
  readonly installId: LifecycleId;
  readonly state: 'active';
  readonly hostRoot: string;
  readonly stateRoot: string;
  readonly artifacts: readonly OwnedArtifact[];
}

export type HostSetupManifestV2 =
  | (HostSetupManifestV2Base & {
      readonly compactViteAuthority: ViteSnapshotAuthority;
      readonly fullCommitmentBinding: FullCommitmentBindingV3;
    })
  | (HostSetupManifestV2Base & {
      readonly compactViteAuthority?: never;
      readonly fullCommitmentBinding?: never;
    });

export interface HostLifecycleReceiptV2 {
  readonly schemaVersion: 2;
  readonly kind: 'scene-glass-host-lifecycle-receipt';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly terminalState: 'active' | 'uninstalled' | 'recovery-required';
  readonly hostRoot: string;
  readonly stateRoot: string;
  readonly manifestFingerprint: string;
}

export type CompactViteAuthorityV3 = ViteSnapshotAuthority;

export interface FullCommitmentBindingV3 {
  readonly path: string;
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
  readonly linkCount: number;
  readonly byteLength: number;
  readonly sha256: string;
}
export interface HostLifecycleContextV3 {
  readonly hostRoot: string;
  readonly checkoutRoot: string;
  readonly homeDir: string;
  readonly selectedConfigDir: string;
  readonly installId: LifecycleId;
}

export type V2AuthoritySourceKind =
  | 'preimage'
  | 'mutation'
  | 'creation-intent'
  | 'replaced-wal-stage'
  | 'manifest-artifact'
  | 'manifest-inverse';

export interface V2ToV3AuthorityMapEntry {
  readonly sourceKind: V2AuthoritySourceKind;
  readonly sourceIndex: number;
  readonly destinationKind: V2AuthoritySourceKind;
  readonly destinationIndex: number;
}

export interface V2ToV3CursorTransition {
  readonly sourceMutationIndex: number;
  readonly destinationMutationIndex: number;
}

export interface V2ToV3AuthorityMap {
  readonly entries: readonly V2ToV3AuthorityMapEntry[];
  readonly cursorTransitions: readonly V2ToV3CursorTransition[];
}

export interface LegacyWalV2SourceFileFacts {
  readonly path: string;
  readonly identity: WalFileIdentityV2;
  readonly owner: string;
  readonly mode: number;
  readonly byteLength: number;
  readonly sha256: string;
  readonly parserVersion: string;
  readonly authorityFingerprint: string;
  readonly authorityMap: V2ToV3AuthorityMap;
}

interface HostWalRecordV3Base {
  readonly schemaVersion: typeof LIFECYCLE_HOST_SCHEMA_VERSION;
  readonly kind: 'scene-glass-host-lifecycle-wal';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly hostRoot: string;
  readonly stateRoot: string;
  readonly cursor: number;
  readonly preimages: readonly WalPreimageV2[];
  readonly mutations: readonly WalMutationV2[];
  readonly creationIntents?: readonly WalCreationIntentV2[];
  readonly authorityFingerprint: string;
  readonly replacedWalStage?: WalReplacedStageLineage;
  readonly compactViteAuthority?: ViteSnapshotAuthority;
  readonly fullCommitmentBinding?: FullCommitmentBindingV3;
}

export type HostWalRecordV3 =
  | (HostWalRecordV3Base & {
      readonly operation: 'setup';
      readonly direction: 'rollback';
      readonly phase: 'prepared' | 'finalized';
    })
  | (HostWalRecordV3Base & {
      readonly operation: 'setup';
      readonly direction: 'commit';
      readonly phase: 'commit-decided';
    })
  | (HostWalRecordV3Base & {
      readonly operation: 'uninstall';
      readonly direction: 'rollback';
      readonly phase: 'prepared';
      readonly receiptPath: string;
      readonly manifest: HostSetupManifestV2;
    })
  | (HostWalRecordV3Base & {
      readonly operation: 'uninstall';
      readonly direction: 'commit';
      readonly phase: 'commit-decided';
      readonly receiptPath: string;
      readonly manifest: HostSetupManifestV2;
    });

export interface MigratedHostWalRecordV3 {
  readonly schemaVersion: typeof LIFECYCLE_HOST_SCHEMA_VERSION;
  readonly kind: 'scene-glass-host-lifecycle-wal';
  readonly operation: 'migration';
  readonly phase: 'source-bound';
  readonly sourceOperation: 'setup' | 'uninstall';
  readonly direction: 'rollback' | 'commit';
  readonly operationId: LifecycleId;
  readonly installId: LifecycleId;
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly hostRoot: string;
  readonly stateRoot: string;
  readonly cursor: number;
  readonly preimages: readonly WalPreimageV2[];
  readonly mutations: readonly WalMutationV2[];
  readonly creationIntents?: readonly WalCreationIntentV2[];
  readonly authorityFingerprint: string;
  readonly replacedWalStage?: WalReplacedStageLineage;
  readonly receiptPath?: string;
  readonly manifest?: HostSetupManifestV2;
}

export interface LegacyWalV2MigrationImage {
  readonly schemaVersion: 3;
  readonly kind: 'scene-glass-host-lifecycle-wal-migration';
  readonly operation: 'migration';
  readonly phase: 'source-bound';
  readonly source: LegacyWalV2SourceFileFacts;
  readonly sourceRecord: WalRecordV2;
  readonly translatedRecord: MigratedHostWalRecordV3;
  readonly authorityMap: V2ToV3AuthorityMap;
}
export type WalRecord = WalRecordV1 | WalRecordV2;

/** Legacy v1 records are recognized but must never grant mutation authority. */
export interface LegacyWalRecordV1 {
  readonly classification: 'legacy-v1-recovery-required';
  readonly record: WalRecordV1;
}

/** Only this branch contains sufficient persisted authority for mutation. */
export interface AuthoritativeWalRecordV2 {
  readonly classification: 'v2-recovery-authority';
  readonly record: WalRecordV2;
}

export type ParsedWalRecord = LegacyWalRecordV1 | AuthoritativeWalRecordV2;

export interface RedactedPreviewOperation {
  readonly kind: LifecycleOperationKind;
  readonly path: string;
  readonly hunkCount: number;
  readonly hunkSubjects: readonly string[];
}

/** Preview data has no content fields, tokens, token digests, or browser data. */
export interface RedactedSetupPreview {
  readonly state: LifecycleState;
  readonly operations: readonly RedactedPreviewOperation[];
}

export interface SetupPlan {
  readonly schemaVersion: 1;
  readonly installId: LifecycleId;
  readonly state: 'active';
  readonly config: ServerConfigV1;
  readonly artifacts: readonly OwnedArtifact[];
  /**
   * Preapproval display data only. Transactions derive uninstall solely from
   * the finalized manifest's per-artifact inverse ledger.
   */
  readonly inverse: readonly InverseOperation[];
  readonly preview: RedactedSetupPreview;
}

export type LifecycleTerminalReceipt = LifecycleReceiptV1;
