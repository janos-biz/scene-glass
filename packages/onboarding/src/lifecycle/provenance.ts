import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, normalize } from 'node:path';

import {
  parseCredentialAuthorityRegistryJsonV1,
  parseCredentialAuthorityRegistrySelectionV1,
  parseCredentialAuthorityRegistryV1,
  serializeCredentialAuthorityRegistryV1,
} from '../credential-authority.js';
import {
  parseProjectConfigV1,
  parseServerConfigV1,
  type ProjectConfigV1,
  type ServerConfigV1,
} from '@scene-glass/contracts';
import {
  parseViteSnapshotAuthorityJson,
  serializeViteSnapshotAuthorityJson,
  VITE_SNAPSHOT_COMMITMENT_DIRECTORY,
  VITE_SNAPSHOT_COMMITMENT_MAX_BYTES,
  VITE_SNAPSHOT_ROOT_DIRECTORY,
  type ViteSnapshotAuthority,
} from '../vite/index.js';
import type {
  AuthoritativeWalRecordV2,
  FullCommitmentBindingV3,
  HostLifecycleReceiptV2,
  HostSetupManifestV2,
  HostWalRecordV3,
  InverseOperation,
  HostLifecycleContextV3,
  LegacyWalRecordV1,
  LegacyWalV2MigrationImage,
  LegacyWalV2SourceFileFacts,
  MigratedHostWalRecordV3,
  LifecycleReceiptV1,
  OwnedArtifact,
  OwnedConfigArtifact,
  OwnedCredentialAuthorityRegistryArtifact,
  OwnedHunk,
  ParsedWalRecord,
  RestoreOwnedFileInverseOperation,
  SemanticConfigImage,
  SemanticCredentialAuthorityRegistryImage,
  SetupManifestV1,
  WalDirectoryResultV2,
  WalFileIdentityV2,
  WalReplacedStageLineage,
  WalFileResultV2,
  WalMutationV2,
  WalCreationIntentV2,
  WalCredentialMutationV2,
  WalOrdinaryMutationV2,
  WalOrdinaryResultV2,
  WalPreimageV2,
  WalRecord,
  WalRecordV1,
  WalRecordV2,
  V2ToV3AuthorityMap,
  V2AuthoritySourceKind,
} from './types.js';

const MAX_PROVENANCE_BYTES = 1024 * 1024;
const MAX_WAL_JSON_BYTES = 32 * 1024 * 1024;
const MAX_WAL_IMAGES = 256;
const MAX_WAL_IMAGE_BYTES = 1024 * 1024;
const MAX_WAL_IMAGE_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_WAL_PATH_BYTES = 4096;
const DECIMAL_ID_PATTERN = /^(?:0|[1-9][0-9]{0,31})$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const WAL_CREATION_INTENT_TOKEN_PATTERN = /^[a-f0-9]{32}$/;
const SETUP_WAL_V2_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'operationId',
  'installId',
  'operation',
  'direction',
  'phase',
  'lockPath',
  'manifestPath',
  'cursor',
  'preimages',
  'mutations',
  'authorityFingerprint',
] as const);
const SETUP_WAL_V2_WITH_CREATION_INTENTS_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'operationId',
  'installId',
  'operation',
  'direction',
  'phase',
  'lockPath',
  'manifestPath',
  'cursor',
  'preimages',
  'mutations',
  'creationIntents',
  'authorityFingerprint',
] as const);
const UNINSTALL_WAL_V2_KEYS = Object.freeze([
  ...SETUP_WAL_V2_KEYS,
  'receiptPath',
  'manifest',
] as const);
const UNINSTALL_WAL_V2_WITH_CREATION_INTENTS_KEYS = Object.freeze([
  ...SETUP_WAL_V2_WITH_CREATION_INTENTS_KEYS,
  'receiptPath',
  'manifest',
] as const);
function walRecordV2Keys(
  operation: 'setup' | 'uninstall',
  record: { readonly [key: string]: unknown },
): readonly string[] {
  const base =
    operation === 'setup'
      ? hasOwn(record, 'creationIntents')
        ? SETUP_WAL_V2_WITH_CREATION_INTENTS_KEYS
        : SETUP_WAL_V2_KEYS
      : hasOwn(record, 'creationIntents')
        ? UNINSTALL_WAL_V2_WITH_CREATION_INTENTS_KEYS
        : UNINSTALL_WAL_V2_KEYS;
  return hasOwn(record, 'replacedWalStage') ? Object.freeze([...base, 'replacedWalStage']) : base;
}
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const FINGERPRINT_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MANIFEST_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'installId',
  'state',
  'artifacts',
] as const);
const WAL_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'operationId',
  'installId',
  'operation',
  'phase',
  'manifestFingerprint',
] as const);
const RECEIPT_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'operationId',
  'installId',
  'terminalState',
  'manifestFingerprint',
] as const);
const HUNK_KEYS = Object.freeze(['id', 'fingerprint', 'operation', 'subject'] as const);
const IMAGE_KEYS = Object.freeze(['schemaVersion', 'projects'] as const);

export interface ObservedOwnedHunk {
  readonly id: string;
  readonly fingerprint: string;
}

/** Host-supplied observations used solely for a no-write uninstall preflight. */
export interface ObservedOwnedTarget {
  readonly path: string;
  readonly fingerprint: string | undefined;
  readonly hunks: readonly ObservedOwnedHunk[];
  /** Parsed config facts; only owned postimage projects are compared. */
  readonly semanticConfig: unknown | undefined;
  /** Parsed registry facts; only the owned selected entry is compared. */
  readonly semanticCredentialAuthorityRegistry?: unknown;
}

export type OwnedArtifactIssueCode =
  | 'artifact-duplicate'
  | 'target-missing'
  | 'target-duplicate'
  | 'target-changed'
  | 'hunk-missing'
  | 'hunk-duplicate'
  | 'hunk-changed'
  | 'semantic-config-missing'
  | 'semantic-config-changed'
  | 'semantic-credential-authority-registry-missing'
  | 'semantic-credential-authority-registry-changed';

export interface OwnedArtifactIssue {
  readonly code: OwnedArtifactIssueCode;
  readonly path: string;
  readonly hunkId: string | undefined;
}

export interface OwnedArtifactsValidation {
  readonly valid: boolean;
  readonly issues: readonly OwnedArtifactIssue[];
}

export interface OwnedArtifactsValidationInput {
  readonly artifacts: readonly OwnedArtifact[];
  readonly observed: readonly ObservedOwnedTarget[];
}

export type UninstallPreflightIssueCode =
  OwnedArtifactIssueCode | 'provenance-absent' | 'provenance-invalid';

export interface UninstallPreflightIssue {
  readonly code: UninstallPreflightIssueCode;
  readonly path: string | undefined;
  readonly hunkId: string | undefined;
}

export interface UninstallPreflight {
  readonly canUninstall: boolean;
  /** Always empty: preflight itself never schedules or performs writes. */
  readonly writes: readonly [];
  /** Inverses are exposed only after every owned target validates. */
  readonly inverse: readonly InverseOperation[];
  readonly issues: readonly UninstallPreflightIssue[];
}

export interface UninstallPreflightInput {
  readonly manifest: unknown | undefined;
  readonly observed: readonly ObservedOwnedTarget[];
}

export class LifecycleProvenanceError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LifecycleProvenanceError';
  }
}

/** Parses an active setup manifest with exact own keys and canonical field order. */
export function parseSetupManifestV1(value: unknown): SetupManifestV1 {
  const record = exactRecord(value, MANIFEST_KEYS, 'setup manifest');
  if (
    record.schemaVersion !== 1 ||
    record.kind !== 'scene-glass-setup-manifest' ||
    record.state !== 'active'
  ) {
    throw new LifecycleProvenanceError('setup manifest has unsupported fixed fields');
  }
  const installId = parseId(record.installId, 'installId');
  const artifacts = parseArtifacts(record.artifacts);
  return Object.freeze({
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId,
    state: 'active',
    artifacts,
  });
}

export function serializeSetupManifestV1(value: unknown): string {
  const manifest = parseSetupManifestV1(value);
  return serializeCanonical(manifest);
}

export function parseSetupManifestJsonV1(value: unknown): SetupManifestV1 {
  return parseCanonicalJson(
    value,
    'setup manifest',
    parseSetupManifestV1,
    serializeSetupManifestV1,
  );
}
export interface FinalizedSetupCredentialBinding {
  readonly projectId: string;
  readonly path: string;
  readonly identity: WalFileIdentityV2;
  readonly mode: 0o600;
}
export interface FinalizedSetupDirectoryBinding {
  readonly path: string;
  readonly identity: WalFileIdentityV2;
  readonly mode: number;
}
export interface FinalizeSetupManifestInput {
  readonly manifest: unknown;
  readonly operations: readonly unknown[];
  readonly credential: FinalizedSetupCredentialBinding | undefined;
  readonly directories: readonly FinalizedSetupDirectoryBinding[];
}
/**
 * Converts the secretless, preapproval manifest proposal into the only
 * persisted manifest form. Planning cannot supply credential or directory
 * identity authority; both are derived from retained native results.
 */
export function finalizeSetupManifestV1(input: FinalizeSetupManifestInput): SetupManifestV1 {
  const record = exactRecord(input.manifest, MANIFEST_KEYS, 'setup manifest proposal');
  if (
    record.schemaVersion !== 1 ||
    record.kind !== 'scene-glass-setup-manifest' ||
    record.state !== 'active'
  ) {
    throw new LifecycleProvenanceError('setup manifest proposal has unsupported fixed fields');
  }
  const installId = parseId(record.installId, 'installId');
  if (!Array.isArray(record.artifacts)) {
    throw new LifecycleProvenanceError('setup manifest proposal artifacts must be an array');
  }
  const operationPaths = new Set(
    input.operations.map((value) => {
      const operation = ordinaryRecord(value, 'setup manifest proposal operation');
      if (
        operation.kind !== 'write-file' &&
        operation.kind !== 'write-config' &&
        operation.kind !== 'move-config' &&
        operation.kind !== 'apply-credential-authority-registry'
      ) {
        throw new LifecycleProvenanceError('setup manifest proposal operation is unsupported');
      }
      return parseOwnedPath(operation.path);
    }),
  );
  const artifacts: unknown[] = [];
  let proposedCredentialCount = 0;
  for (let index = 0; index < record.artifacts.length; index += 1) {
    if (!hasOwn(record.artifacts, index)) {
      throw new LifecycleProvenanceError('setup manifest proposal artifacts must not be sparse');
    }
    const artifact = ordinaryRecord(record.artifacts[index], 'setup manifest proposal artifact');
    if (artifact.kind === 'directory') {
      throw new LifecycleProvenanceError(
        'setup manifest proposal cannot self-authorize directories',
      );
    }
    if (artifact.kind === 'credential' && artifact.ownership === 'setup-created') {
      proposedCredentialCount += 1;
      const credential = input.credential;
      if (hasOwn(artifact, 'projectId')) {
        const persisted = parseArtifact(artifact);
        if (
          credential === undefined ||
          persisted.kind !== 'credential' ||
          persisted.ownership !== 'setup-created' ||
          persisted.path !== credential.path ||
          persisted.projectId !== credential.projectId ||
          persisted.identity === undefined ||
          !sameWalIdentity(persisted.identity, credential.identity) ||
          persisted.mode !== 0o600 ||
          persisted.linkCount !== 1
        ) {
          throw new LifecycleProvenanceError(
            'setup-created credential proposal authority is invalid',
          );
        }
        artifacts.push(persisted);
        continue;
      }
      const candidate = exactRecord(
        artifact,
        ['path', 'kind', 'ownership', 'inverse'],
        'setup-created credential proposal',
      );
      const path = parseOwnedPath(candidate.path);
      const inverse = exactRecord(
        candidate.inverse,
        ['kind', 'path'],
        'credential proposal inverse',
      );
      if (
        credential === undefined ||
        path !== credential.path ||
        inverse.kind !== 'delete-created-credential' ||
        inverse.path !== path
      ) {
        throw new LifecycleProvenanceError(
          'setup-created credential proposal lacks exact authority',
        );
      }
      artifacts.push(
        Object.freeze({
          path,
          kind: 'credential' as const,
          ownership: 'setup-created' as const,
          projectId: parseId(credential.projectId, 'created credential projectId'),
          identity: freezeWalIdentity(credential.identity),
          mode: 0o600,
          linkCount: 1,
          inverse: Object.freeze({
            kind: 'delete-created-credential' as const,
            path,
            projectId: parseId(credential.projectId, 'created credential inverse projectId'),
            identity: freezeWalIdentity(credential.identity),
            mode: 0o600,
            linkCount: 1,
          }),
        }),
      );
      continue;
    }
    if (artifact.kind === 'credential-authority-registry' && !hasOwn(artifact, 'fingerprint')) {
      throw new LifecycleProvenanceError(
        'credential authority registry proposal requires an exact physical fingerprint',
      );
    }
    if (
      artifact.kind === 'file' &&
      ordinaryRecord(artifact.inverse, 'file proposal inverse').kind === 'none' &&
      !operationPaths.has(parseOwnedPath(artifact.path))
    ) {
      continue;
    }
    artifacts.push(artifact);
  }
  if (
    (input.credential === undefined && proposedCredentialCount !== 0) ||
    (input.credential !== undefined && proposedCredentialCount !== 1)
  ) {
    throw new LifecycleProvenanceError('setup manifest proposal credential cardinality is invalid');
  }
  const finalizedArtifacts = artifacts.map((artifact) => parseArtifact(artifact));
  const removesOwnedTarget = (artifact: OwnedArtifact): boolean =>
    artifact.inverse.kind === 'delete-created-file' ||
    artifact.inverse.kind === 'delete-created-credential' ||
    artifact.inverse.kind === 'delete-created-directory';
  for (const directory of [...input.directories].reverse()) {
    const directoryPath = parseCanonicalAbsolutePath(directory.path);
    if (directoryPath.endsWith('/.scene-glass')) {
      continue;
    }
    const path = parseOwnedPath(directoryPath);
    if (
      finalizedArtifacts.some(
        (artifact) =>
          walPathIsStrictDescendant(artifact.path, path) && !removesOwnedTarget(artifact),
      )
    ) {
      continue;
    }
    const identity = freezeWalIdentity(directory.identity);
    const mode = parseWalMode(directory.mode, 'created directory mode');
    const artifact = Object.freeze({
      path,
      kind: 'directory' as const,
      identity,
      mode,
      inverse: Object.freeze({
        kind: 'delete-created-directory' as const,
        path,
        identity,
        mode,
        emptyOnly: true as const,
      }),
    });
    artifacts.push(artifact);
    finalizedArtifacts.push(parseArtifact(artifact));
  }
  return parseSetupManifestV1({
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId,
    state: 'active',
    artifacts,
  });
}
export interface FinalizedSetupProvenanceInput {
  readonly manifest: SetupManifestV1;
  readonly operations: readonly unknown[];
  readonly preimages: readonly unknown[];
  readonly credential: FinalizedSetupCredentialBinding | undefined;
  readonly directories: readonly FinalizedSetupDirectoryBinding[];
}
/**
 * Rejects independently supplied finalization collections. Every physical
 * write has one exact artifact and preimage, while native-created resources
 * have one exact persisted artifact and inverse.
 */
export function validateFinalizedSetupProvenance(input: FinalizedSetupProvenanceInput): void {
  const artifacts = new Map(input.manifest.artifacts.map((artifact) => [artifact.path, artifact]));
  const preimages = new Map<string, PlainDataObject>();
  for (const value of input.preimages) {
    const preimage = ordinaryRecord(value, 'finalization preimage');
    const path = parseOwnedPath(preimage.path);
    if (preimages.has(path)) {
      throw new LifecycleProvenanceError('finalization preimages must be one-to-one');
    }
    preimages.set(path, preimage);
  }
  const consumedPreimages = new Set<string>();
  const matchedArtifacts = new Set<string>();
  const requirePreimage = (path: string): PlainDataObject => {
    const preimage = preimages.get(path);
    if (preimage === undefined || consumedPreimages.has(path)) {
      throw new LifecycleProvenanceError('finalization operation lacks one exact preimage');
    }
    if (preimage.state !== 'absent' && preimage.state !== 'file') {
      throw new LifecycleProvenanceError('finalization operation has an unsupported preimage kind');
    }
    consumedPreimages.add(path);
    return preimage;
  };
  const match = (path: string, kind: OwnedArtifact['kind'], bytes: Uint8Array): OwnedArtifact => {
    const artifact = artifacts.get(path);
    if (artifact === undefined || artifact.kind !== kind || matchedArtifacts.has(path)) {
      throw new LifecycleProvenanceError('finalization operation/artifact cardinality is invalid');
    }
    const fingerprint = fingerprintBytes(bytes);
    if (!('fingerprint' in artifact) || artifact.fingerprint !== fingerprint) {
      throw new LifecycleProvenanceError(
        'finalization artifact fingerprint is not its exact postimage',
      );
    }
    if (
      artifact.kind === 'file' &&
      artifact.hunks.some((hunk) => hunk.fingerprint !== fingerprint)
    ) {
      throw new LifecycleProvenanceError('owned file hunk fingerprint is not its exact postimage');
    }
    matchedArtifacts.add(path);
    return artifact;
  };
  for (const value of input.operations) {
    const operation = ordinaryRecord(value, 'finalization operation');
    if (operation.kind === 'write-file' || operation.kind === 'write-config') {
      const path = parseOwnedPath(operation.path);
      if (!(operation.bytes instanceof Uint8Array)) {
        throw new LifecycleProvenanceError('finalization write bytes are invalid');
      }
      const artifact = match(
        path,
        operation.kind === 'write-file' ? 'file' : 'config',
        operation.bytes,
      );
      const preimage = requirePreimage(path);
      if (
        artifact.kind === 'file' &&
        ((artifact.inverse.kind === 'delete-created-file' && preimage.state !== 'absent') ||
          (artifact.inverse.kind === 'restore-owned-file' &&
            (preimage.state !== 'file' ||
              !(preimage.bytes instanceof Uint8Array) ||
              fingerprintBytes(preimage.bytes) !== artifact.inverse.preimageFingerprint)))
      ) {
        throw new LifecycleProvenanceError('file inverse does not bind its exact typed preimage');
      }
      continue;
    }
    if (operation.kind === 'move-config') {
      const path = parseOwnedPath(operation.path);
      const sourcePath = parseOwnedPath(operation.sourcePath);
      if (path === sourcePath || !(operation.bytes instanceof Uint8Array)) {
        throw new LifecycleProvenanceError('finalization config move is invalid');
      }
      match(path, 'config', operation.bytes);
      requirePreimage(path);
      requirePreimage(sourcePath);
      continue;
    }
    if (operation.kind === 'apply-credential-authority-registry') {
      const path = parseOwnedPath(operation.path);
      const preimage = parseSemanticCredentialAuthorityRegistryImage(operation.preimage);
      const postimage = parseSemanticCredentialAuthorityRegistryImage(operation.postimage);
      const bytes = mergedCredentialAuthorityRegistryPostimageBytes(
        requirePreimage(path),
        preimage,
        postimage,
      );
      const artifact = match(path, 'credential-authority-registry', bytes);
      if (
        artifact.kind !== 'credential-authority-registry' ||
        !sameCredentialAuthorityRegistryImage(artifact.preimage, preimage) ||
        !sameCredentialAuthorityRegistryImage(artifact.postimage, postimage) ||
        (operation.fingerprint !== undefined && operation.fingerprint !== artifact.fingerprint)
      ) {
        throw new LifecycleProvenanceError(
          'registry operation fingerprint does not match its artifact',
        );
      }
      continue;
    }
    throw new LifecycleProvenanceError('finalization operation has an unsupported kind');
  }
  const expectedCreatedPaths = new Set<string>();
  if (input.credential !== undefined) {
    const credential = input.credential;
    const artifact = artifacts.get(credential.path);
    if (
      artifact?.kind !== 'credential' ||
      artifact.ownership !== 'setup-created' ||
      artifact.projectId !== credential.projectId ||
      artifact.mode !== 0o600 ||
      artifact.linkCount !== 1 ||
      artifact.identity === undefined ||
      !sameWalIdentity(artifact.identity, credential.identity)
    ) {
      throw new LifecycleProvenanceError('created credential artifact lacks exact authority');
    }
    expectedCreatedPaths.add(credential.path);
  }
  for (const directory of input.directories) {
    const artifact = artifacts.get(directory.path);
    if (
      artifact?.kind !== 'directory' ||
      artifact.mode !== directory.mode ||
      !sameWalIdentity(artifact.identity, directory.identity)
    ) {
      throw new LifecycleProvenanceError('created directory artifact lacks exact authority');
    }
    expectedCreatedPaths.add(directory.path);
  }
  for (const artifact of input.manifest.artifacts) {
    if (artifact.kind === 'credential' && artifact.ownership === 'adopted') {
      continue;
    }
    if (expectedCreatedPaths.has(artifact.path)) {
      continue;
    }
    if (!matchedArtifacts.has(artifact.path)) {
      throw new LifecycleProvenanceError('finalization manifest contains unbound provenance');
    }
  }
  if (consumedPreimages.size !== preimages.size) {
    throw new LifecycleProvenanceError('finalization contains an unbound preimage');
  }
}

export function parseWalRecordV1(value: unknown): WalRecordV1 {
  const record = exactRecord(value, WAL_KEYS, 'WAL record');
  if (record.schemaVersion !== 1 || record.kind !== 'scene-glass-lifecycle-wal') {
    throw new LifecycleProvenanceError('WAL record has unsupported fixed fields');
  }
  if (record.operation !== 'setup' && record.operation !== 'uninstall') {
    throw new LifecycleProvenanceError('WAL operation must be setup or uninstall');
  }
  if (record.phase !== 'prepared' && record.phase !== 'applied') {
    throw new LifecycleProvenanceError('WAL phase must be prepared or applied');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'scene-glass-lifecycle-wal',
    operationId: parseId(record.operationId, 'operationId'),
    installId: parseId(record.installId, 'installId'),
    operation: record.operation,
    phase: record.phase,
    manifestFingerprint: parseFingerprint(record.manifestFingerprint, 'manifestFingerprint'),
  });
}

export function serializeWalRecordV1(value: unknown): string {
  return serializeCanonical(parseWalRecordV1(value));
}

export function parseWalRecordJsonV1(value: unknown): WalRecordV1 {
  return parseCanonicalJson(value, 'WAL record', parseWalRecordV1, serializeWalRecordV1);
}
export function parseWalRecordV2(value: unknown): WalRecordV2 {
  const candidate = ordinaryRecord(value, 'WAL record');
  if (
    !hasOwn(candidate, 'schemaVersion') ||
    !hasOwn(candidate, 'kind') ||
    !hasOwn(candidate, 'operation') ||
    candidate.schemaVersion !== 2 ||
    candidate.kind !== 'scene-glass-lifecycle-wal'
  ) {
    throw new LifecycleProvenanceError('WAL record has unsupported fixed fields');
  }
  if (candidate.operation === 'setup') {
    const record = exactRecord(
      candidate,
      walRecordV2Keys('setup', candidate),
      'setup WAL v2 record',
    );
    const common = parseWalRecordV2Common(record, 'setup');
    assertSetupWalPhaseDirection(
      common.direction,
      common.phase,
      common.cursor,
      common.mutations.length,
    );
    assertWalCreationIntentPhase(common);
    assertWalV2Paths(common);
    if (
      common.direction === 'rollback' &&
      (common.phase === 'prepared' || common.phase === 'finalized')
    ) {
      return Object.freeze({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: common.operationId,
        installId: common.installId,
        operation: 'setup',
        direction: 'rollback',
        phase: common.phase,
        lockPath: common.lockPath,
        manifestPath: common.manifestPath,
        cursor: common.cursor,
        preimages: common.preimages,
        mutations: common.mutations,
        ...(common.creationIntents === undefined
          ? {}
          : { creationIntents: common.creationIntents }),
        authorityFingerprint: common.authorityFingerprint,
        ...(common.replacedWalStage === undefined
          ? {}
          : { replacedWalStage: common.replacedWalStage }),
      });
    }
    if (common.direction === 'commit' && common.phase === 'commit-decided') {
      return Object.freeze({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: common.operationId,
        installId: common.installId,
        operation: 'setup',
        direction: 'commit',
        phase: 'commit-decided',
        lockPath: common.lockPath,
        manifestPath: common.manifestPath,
        cursor: common.cursor,
        preimages: common.preimages,
        mutations: common.mutations,
        ...(common.creationIntents === undefined
          ? {}
          : { creationIntents: common.creationIntents }),
        authorityFingerprint: common.authorityFingerprint,
        ...(common.replacedWalStage === undefined
          ? {}
          : { replacedWalStage: common.replacedWalStage }),
      });
    }
    throw new LifecycleProvenanceError('setup WAL v2 phase and direction are incompatible');
  }
  if (candidate.operation === 'uninstall') {
    const record = exactRecord(
      candidate,
      walRecordV2Keys('uninstall', candidate),
      'uninstall WAL v2 record',
    );
    const common = parseWalRecordV2Common(record, 'uninstall');
    assertUninstallWalPhaseDirection(
      common.direction,
      common.phase,
      common.cursor,
      common.mutations.length,
    );
    assertWalCreationIntentPhase(common);
    const receiptPath = parseWalPath(record.receiptPath, 'receiptPath');
    const manifest = parseSetupManifestV1(record.manifest);
    if (manifest.installId !== common.installId) {
      throw new LifecycleProvenanceError('uninstall WAL manifest installId must match the WAL');
    }
    assertWalV2Paths(common, legacyUninstallTerminalBinding(common, receiptPath, manifest));
    if (common.direction === 'rollback' && common.phase === 'prepared') {
      return Object.freeze({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: common.operationId,
        installId: common.installId,
        operation: 'uninstall',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: common.lockPath,
        manifestPath: common.manifestPath,
        cursor: common.cursor,
        preimages: common.preimages,
        mutations: common.mutations,
        ...(common.creationIntents === undefined
          ? {}
          : { creationIntents: common.creationIntents }),
        authorityFingerprint: common.authorityFingerprint,
        receiptPath,
        manifest,
        ...(common.replacedWalStage === undefined
          ? {}
          : { replacedWalStage: common.replacedWalStage }),
      });
    }
    if (common.direction === 'commit' && common.phase === 'commit-decided') {
      return Object.freeze({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: common.operationId,
        installId: common.installId,
        operation: 'uninstall',
        direction: 'commit',
        phase: 'commit-decided',
        lockPath: common.lockPath,
        manifestPath: common.manifestPath,
        cursor: common.cursor,
        preimages: common.preimages,
        mutations: common.mutations,
        ...(common.creationIntents === undefined
          ? {}
          : { creationIntents: common.creationIntents }),
        authorityFingerprint: common.authorityFingerprint,
        receiptPath,
        manifest,
        ...(common.replacedWalStage === undefined
          ? {}
          : { replacedWalStage: common.replacedWalStage }),
      });
    }
    throw new LifecycleProvenanceError('uninstall WAL v2 phase and direction are incompatible');
  }
  throw new LifecycleProvenanceError('WAL v2 operation must be setup or uninstall');
}

export function serializeWalRecordV2(value: unknown): string {
  return serializeCanonical(parseWalRecordV2(value));
}

export function parseWalRecordJsonV2(value: unknown): WalRecordV2 {
  return parseCanonicalJson(
    value,
    'WAL v2 record',
    parseWalRecordV2,
    serializeWalRecordV2,
    MAX_WAL_JSON_BYTES,
  );
}
export function parseHostSetupManifestV2(value: unknown): HostSetupManifestV2 {
  const candidate = ordinaryRecord(value, 'host setup manifest');
  const hasCompact = hasOwn(candidate, 'compactViteAuthority');
  const hasCommitment = hasOwn(candidate, 'fullCommitmentBinding');
  if (hasCompact !== hasCommitment) {
    throw new LifecycleProvenanceError(
      'host setup manifest Vite authority must be a complete pair',
    );
  }
  const record = exactRecord(
    candidate,
    [
      'schemaVersion',
      'kind',
      'installId',
      'state',
      'hostRoot',
      'stateRoot',
      'artifacts',
      ...(hasCompact ? ['compactViteAuthority', 'fullCommitmentBinding'] : []),
    ],
    'host setup manifest',
  );
  if (
    record.schemaVersion !== 2 ||
    record.kind !== 'scene-glass-host-setup-manifest' ||
    record.state !== 'active'
  ) {
    throw new LifecycleProvenanceError('host setup manifest has unsupported fixed fields');
  }
  const hostRoot = parseCanonicalAbsolutePath(record.hostRoot);
  const installId = parseId(record.installId, 'installId');
  const compactViteAuthority = hasCompact
    ? parseCompactViteAuthorityV3(record.compactViteAuthority, hostRoot, installId)
    : undefined;
  const fullCommitmentBinding = hasCommitment
    ? parseFullCommitmentBindingV3(record.fullCommitmentBinding, hostRoot, installId)
    : undefined;
  return Object.freeze({
    schemaVersion: 2,
    kind: 'scene-glass-host-setup-manifest',
    installId,
    state: 'active',
    hostRoot,
    stateRoot: parseHostStateRoot(record.stateRoot, hostRoot),
    artifacts: parseArtifacts(record.artifacts),
    ...(compactViteAuthority === undefined ? {} : { compactViteAuthority }),
    ...(fullCommitmentBinding === undefined ? {} : { fullCommitmentBinding }),
  }) as HostSetupManifestV2;
}
export function serializeHostSetupManifestV2(value: unknown): string {
  return serializeCanonical(parseHostSetupManifestV2(value));
}
export function parseHostSetupManifestJsonV2(value: unknown): HostSetupManifestV2 {
  return parseCanonicalJson(
    value,
    'host setup manifest',
    parseHostSetupManifestV2,
    serializeHostSetupManifestV2,
  );
}

export function parseHostLifecycleReceiptV2(value: unknown): HostLifecycleReceiptV2 {
  const record = exactRecord(
    value,
    [
      'schemaVersion',
      'kind',
      'operationId',
      'installId',
      'terminalState',
      'hostRoot',
      'stateRoot',
      'manifestFingerprint',
    ],
    'host lifecycle receipt',
  );
  if (
    record.schemaVersion !== 2 ||
    record.kind !== 'scene-glass-host-lifecycle-receipt' ||
    (record.terminalState !== 'active' &&
      record.terminalState !== 'uninstalled' &&
      record.terminalState !== 'recovery-required')
  ) {
    throw new LifecycleProvenanceError('host lifecycle receipt has unsupported fixed fields');
  }
  const hostRoot = parseCanonicalAbsolutePath(record.hostRoot);
  return Object.freeze({
    schemaVersion: 2,
    kind: 'scene-glass-host-lifecycle-receipt',
    operationId: parseId(record.operationId, 'operationId'),
    installId: parseId(record.installId, 'installId'),
    terminalState: record.terminalState,
    hostRoot,
    stateRoot: parseHostStateRoot(record.stateRoot, hostRoot),
    manifestFingerprint: parseFingerprint(record.manifestFingerprint, 'manifestFingerprint'),
  });
}

export function serializeHostLifecycleReceiptV2(value: unknown): string {
  return serializeCanonical(parseHostLifecycleReceiptV2(value));
}
export function parseHostLifecycleReceiptJsonV2(value: unknown): HostLifecycleReceiptV2 {
  return parseCanonicalJson(
    value,
    'host lifecycle receipt',
    parseHostLifecycleReceiptV2,
    serializeHostLifecycleReceiptV2,
  );
}

export function parseHostWalRecordV3(
  value: unknown,
  context: HostLifecycleContextV3,
): HostWalRecordV3 {
  const parsedContext = parseHostLifecycleContextV3(context);
  const candidate = ordinaryRecord(value, 'host WAL record');
  if (
    candidate.schemaVersion !== 3 ||
    candidate.kind !== 'scene-glass-host-lifecycle-wal' ||
    (candidate.operation !== 'setup' && candidate.operation !== 'uninstall')
  ) {
    throw new LifecycleProvenanceError('host WAL record has unsupported fixed fields');
  }
  const record = exactRecord(candidate, hostWalRecordV3Keys(candidate), 'host WAL record');
  const hostRoot = parseCanonicalAbsolutePath(record.hostRoot);
  if (hostRoot !== parsedContext.hostRoot) {
    throw new LifecycleProvenanceError('host WAL hostRoot must match the current host root');
  }
  const stateRoot = parseHostStateRoot(record.stateRoot, hostRoot);
  if (record.operation === 'uninstall') {
    const common = parseWalRecordV2Common(record, 'uninstall');
    assertUninstallWalPhaseDirection(
      common.direction,
      common.phase,
      common.cursor,
      common.mutations.length,
    );
    assertWalCreationIntentPhase(common);
    const receiptPath = parseWalPath(record.receiptPath, 'receiptPath');
    const manifest = parseHostSetupManifestV2(record.manifest);
    if (manifest.installId !== common.installId) {
      throw new LifecycleProvenanceError(
        'host uninstall WAL manifest installId must match the WAL',
      );
    }
    assertWalV2Paths(common, hostUninstallTerminalBinding(common, receiptPath, manifest));
    if (common.installId !== parsedContext.installId) {
      throw new LifecycleProvenanceError('host WAL installId must match the current install');
    }
    const hasCompact = hasOwn(record, 'compactViteAuthority');
    const hasCommitment = hasOwn(record, 'fullCommitmentBinding');
    if (hasCompact !== hasCommitment) {
      throw new LifecycleProvenanceError('host WAL Vite authority must be a complete pair');
    }
    const compactViteAuthority = hasCompact
      ? parseCompactViteAuthorityV3(record.compactViteAuthority, hostRoot, common.installId)
      : undefined;
    const fullCommitmentBinding = hasCommitment
      ? parseFullCommitmentBindingV3(record.fullCommitmentBinding, hostRoot, common.installId)
      : undefined;
    if (
      manifest.hostRoot !== hostRoot ||
      manifest.stateRoot !== stateRoot ||
      manifest.compactViteAuthority?.commitmentDigest !== compactViteAuthority?.commitmentDigest ||
      manifest.fullCommitmentBinding?.sha256 !== fullCommitmentBinding?.sha256
    ) {
      throw new LifecycleProvenanceError('host uninstall WAL manifest must bind the host WAL');
    }
    const parsed = Object.freeze({
      schemaVersion: 3 as const,
      kind: 'scene-glass-host-lifecycle-wal' as const,
      operationId: common.operationId,
      installId: common.installId,
      operation: 'uninstall' as const,
      direction: common.direction,
      phase: common.phase,
      lockPath: common.lockPath,
      manifestPath: common.manifestPath,
      cursor: common.cursor,
      preimages: common.preimages,
      mutations: common.mutations,
      ...(common.creationIntents === undefined ? {} : { creationIntents: common.creationIntents }),
      authorityFingerprint: common.authorityFingerprint,
      receiptPath,
      manifest,
      ...(common.replacedWalStage === undefined
        ? {}
        : { replacedWalStage: common.replacedWalStage }),
      hostRoot,
      stateRoot,
      ...(compactViteAuthority === undefined ? {} : { compactViteAuthority }),
      ...(fullCommitmentBinding === undefined ? {} : { fullCommitmentBinding }),
    }) as HostWalRecordV3;
    assertHostLifecycleWalTargets(parsed, parsedContext);
    return parsed;
  }
  const v2Record = parseWalRecordV2(hostWalV3AsV2Record(record));
  if (v2Record.installId !== parsedContext.installId) {
    throw new LifecycleProvenanceError('host WAL installId must match the current install');
  }
  assertHostLifecycleWalTargets(v2Record, parsedContext);
  const hasCompact = hasOwn(record, 'compactViteAuthority');
  const hasCommitment = hasOwn(record, 'fullCommitmentBinding');
  if (hasCompact !== hasCommitment) {
    throw new LifecycleProvenanceError('host WAL Vite authority must be a complete pair');
  }
  const compactViteAuthority = hasCompact
    ? parseCompactViteAuthorityV3(record.compactViteAuthority, hostRoot, v2Record.installId)
    : undefined;
  const fullCommitmentBinding = hasCommitment
    ? parseFullCommitmentBindingV3(record.fullCommitmentBinding, hostRoot, v2Record.installId)
    : undefined;
  return Object.freeze({
    ...v2Record,
    schemaVersion: 3,
    kind: 'scene-glass-host-lifecycle-wal',
    hostRoot,
    stateRoot,
    ...(compactViteAuthority === undefined ? {} : { compactViteAuthority }),
    ...(fullCommitmentBinding === undefined ? {} : { fullCommitmentBinding }),
  }) as HostWalRecordV3;
}

export function serializeHostWalRecordV3(value: unknown, context: HostLifecycleContextV3): string {
  return serializeCanonical(parseHostWalRecordV3(value, context));
}
export function parseHostWalRecordJsonV3(
  value: unknown,
  context: HostLifecycleContextV3,
): HostWalRecordV3 {
  return parseCanonicalJson(
    value,
    'host WAL record',
    (candidate) => parseHostWalRecordV3(candidate, context),
    (parsed) => serializeHostWalRecordV3(parsed, context),
    MAX_WAL_JSON_BYTES,
  );
}

export function translateLegacyWalV2ToHostV3(
  record: WalRecordV2,
  context: HostLifecycleContextV3,
  sourceFileFacts: LegacyWalV2SourceFileFacts,
): LegacyWalV2MigrationImage {
  const parsedContext = parseHostLifecycleContextV3(context);
  const parsed = parseWalRecordV2(record);
  assertLegacyLifecycleWalTargets(parsed, parsedContext);
  const source = parseLegacyWalV2SourceFileFacts(sourceFileFacts, parsedContext);
  const authorityMap = parseV2ToV3AuthorityMap(source.authorityMap, parsed);
  const translatedRecord = translateLegacyRecordToHostV3(parsed, parsedContext);
  return Object.freeze({
    schemaVersion: 3,
    kind: 'scene-glass-host-lifecycle-wal-migration',
    operation: 'migration',
    phase: 'source-bound',
    source: Object.freeze({ ...source, authorityMap }),
    sourceRecord: parsed,
    translatedRecord,
    authorityMap,
  });
}

/**
 * Parses either persisted WAL version into a discriminated recovery decision.
 * The v1 branch is recognition-only and carries no mutation authority.
 */
export function parseWalRecord(value: unknown): ParsedWalRecord {
  const record = parseWalRecordValue(value);
  if (record.schemaVersion === 1) {
    const legacy: LegacyWalRecordV1 = {
      classification: 'legacy-v1-recovery-required',
      record,
    };
    return Object.freeze(legacy);
  }
  const authoritative: AuthoritativeWalRecordV2 = {
    classification: 'v2-recovery-authority',
    record,
  };
  return Object.freeze(authoritative);
}

/** Canonically serializes either exact persisted WAL version. */
export function serializeWalRecord(value: unknown): string {
  return serializeCanonical(parseWalRecordValue(value));
}

export function parseWalRecordJson(value: unknown): ParsedWalRecord {
  return parseCanonicalJson(
    value,
    'WAL record',
    parseWalRecord,
    (parsed: ParsedWalRecord) => serializeWalRecord(parsed.record),
    MAX_WAL_JSON_BYTES,
  );
}

export function parseLifecycleReceiptV1(value: unknown): LifecycleReceiptV1 {
  const record = exactRecord(value, RECEIPT_KEYS, 'lifecycle receipt');
  if (record.schemaVersion !== 1 || record.kind !== 'scene-glass-lifecycle-receipt') {
    throw new LifecycleProvenanceError('lifecycle receipt has unsupported fixed fields');
  }
  if (
    record.terminalState !== 'active' &&
    record.terminalState !== 'uninstalled' &&
    record.terminalState !== 'recovery-required'
  ) {
    throw new LifecycleProvenanceError('lifecycle receipt has an unsupported terminal state');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'scene-glass-lifecycle-receipt',
    operationId: parseId(record.operationId, 'operationId'),
    installId: parseId(record.installId, 'installId'),
    terminalState: record.terminalState,
    manifestFingerprint: parseFingerprint(record.manifestFingerprint, 'manifestFingerprint'),
  });
}

export function serializeLifecycleReceiptV1(value: unknown): string {
  return serializeCanonical(parseLifecycleReceiptV1(value));
}

export function parseLifecycleReceiptJsonV1(value: unknown): LifecycleReceiptV1 {
  return parseCanonicalJson(
    value,
    'lifecycle receipt',
    parseLifecycleReceiptV1,
    serializeLifecycleReceiptV1,
  );
}

/** Terminal receipt naming is retained at this module boundary for host callers. */
export const parseTerminalReceiptV1 = parseLifecycleReceiptV1;
export const serializeTerminalReceiptV1 = serializeLifecycleReceiptV1;
export const parseTerminalReceiptJsonV1 = parseLifecycleReceiptJsonV1;

/**
 * Validates all owned targets before an uninstall is allowed. Hunked config
 * targets deliberately compare owned hunks and semantic projects, not whole
 * file bytes, so unrelated edits remain intact.
 */
export function validateOwnedArtifacts(
  input: OwnedArtifactsValidationInput | readonly OwnedArtifact[],
  observedArgument?: readonly ObservedOwnedTarget[],
): OwnedArtifactsValidation {
  let artifacts: readonly OwnedArtifact[];
  let observed: readonly ObservedOwnedTarget[] | undefined;
  if (isOwnedArtifactArray(input)) {
    artifacts = input;
    observed = observedArgument;
  } else {
    artifacts = input.artifacts;
    observed = input.observed;
  }
  if (!Array.isArray(artifacts) || !Array.isArray(observed)) {
    throw new LifecycleProvenanceError(
      'owned artifact validation requires artifact and observed arrays',
    );
  }

  const issues: OwnedArtifactIssue[] = [];
  const artifactPaths = new Map<string, number>();
  for (const artifact of artifacts) {
    const current = artifactPaths.get(artifact.path) ?? 0;
    artifactPaths.set(artifact.path, current + 1);
  }
  for (const [path, count] of artifactPaths) {
    if (count > 1) {
      issues.push(issue('artifact-duplicate', path));
    }
  }

  for (const artifact of artifacts) {
    const targets = observed.filter((target) => target.path === artifact.path);
    if (targets.length === 0) {
      /*
       * Empty-only directories are revalidated by the lock-held transaction;
       * callers that can only read regular files do not gain weaker authority.
       */
      if (artifact.kind === 'directory') {
        continue;
      }
      issues.push(issue('target-missing', artifact.path));
      continue;
    }
    if (targets.length > 1) {
      issues.push(issue('target-duplicate', artifact.path));
      continue;
    }
    const target = targets[0];
    if (target === undefined) {
      continue;
    }
    validateTarget(artifact, target, issues);
  }

  return Object.freeze({ valid: issues.length === 0, issues: Object.freeze(issues) });
}
function isOwnedArtifactArray(
  value: OwnedArtifactsValidationInput | readonly OwnedArtifact[],
): value is readonly OwnedArtifact[] {
  return Array.isArray(value);
}

/**
 * Produces no write operations. It either returns every inverse operation after
 * complete validation or returns no inverses at all.
 */
export function validateUninstallPreflight(input: UninstallPreflightInput): UninstallPreflight {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new LifecycleProvenanceError('uninstall preflight input must be an object');
  }
  if (!Array.isArray(input.observed)) {
    throw new LifecycleProvenanceError('uninstall preflight observed facts must be an array');
  }
  if (input.manifest === undefined) {
    return freezePreflight([{ code: 'provenance-absent', path: undefined, hunkId: undefined }]);
  }

  let manifest: SetupManifestV1;
  try {
    manifest = parseSetupManifestV1(input.manifest);
  } catch {
    return freezePreflight([{ code: 'provenance-invalid', path: undefined, hunkId: undefined }]);
  }

  const validation = validateOwnedArtifacts({
    artifacts: manifest.artifacts,
    observed: input.observed,
  });
  if (!validation.valid) {
    return freezePreflight(
      validation.issues.map((item) => ({
        code: item.code,
        path: item.path,
        hunkId: item.hunkId,
      })),
    );
  }

  return Object.freeze({
    canUninstall: true,
    writes: Object.freeze([]) as readonly [],
    inverse: Object.freeze(manifest.artifacts.map((artifact) => artifact.inverse)),
    issues: Object.freeze([]),
  });
}

function parseArtifacts(value: unknown): readonly OwnedArtifact[] {
  if (!Array.isArray(value)) {
    throw new LifecycleProvenanceError('artifacts must be an array');
  }
  const artifacts: OwnedArtifact[] = [];
  const paths = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    if (!hasOwn(value, index)) {
      throw new LifecycleProvenanceError('artifacts must not be sparse');
    }
    const artifact = parseArtifact(value[index]);
    if (paths.has(artifact.path)) {
      throw new LifecycleProvenanceError('owned artifact paths must be unique');
    }
    paths.add(artifact.path);
    artifacts.push(artifact);
  }
  assertDependencySafeArtifactOrder(artifacts);
  return Object.freeze(artifacts);
}
function assertDependencySafeArtifactOrder(artifacts: readonly OwnedArtifact[]): void {
  for (let index = 0; index < artifacts.length; index += 1) {
    const parent = artifacts[index];
    if (parent?.kind !== 'directory') {
      continue;
    }
    for (const child of artifacts.slice(index + 1)) {
      if (isOwnedDescendantPath(child.path, parent.path)) {
        throw new LifecycleProvenanceError(
          'owned artifacts must list children before an empty-only directory inverse',
        );
      }
    }
  }
}
function isOwnedDescendantPath(path: string, directory: string): boolean {
  const prefix = directory === '/' ? '/' : `${directory}/`;
  return path.startsWith(prefix) && path !== directory;
}

function parseArtifact(value: unknown): OwnedArtifact {
  const candidate = ordinaryRecord(value, 'owned artifact');
  const kind = candidate.kind;
  if (kind === 'file') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'fingerprint', 'hunks', 'inverse'],
      'file artifact',
    );
    const path = parseOwnedPath(record.path);
    const fingerprint = parseFingerprint(record.fingerprint, 'artifact fingerprint');
    const hunks = parseHunks(record.hunks);
    const inverse = parseInverse(record.inverse);
    if (inverse.kind !== 'delete-created-file' && inverse.kind !== 'restore-owned-file') {
      throw new LifecycleProvenanceError('file artifact has an unsupported inverse');
    }
    if (
      inverse.kind === 'delete-created-file' &&
      (inverse.path !== path || inverse.expectedFingerprint !== fingerprint)
    ) {
      throw new LifecycleProvenanceError('file deletion inverse does not match its artifact');
    }
    if (
      inverse.kind === 'restore-owned-file' &&
      (inverse.path !== path ||
        inverse.postimageFingerprint !== fingerprint ||
        !sameHunks(inverse.hunks, hunks) ||
        !isSupportedOwnedFileRestore(inverse))
    ) {
      throw new LifecycleProvenanceError('file restoration inverse does not match its artifact');
    }
    return Object.freeze({ path, kind: 'file', fingerprint, hunks, inverse });
  }

  if (kind === 'config') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'fingerprint', 'hunks', 'preimage', 'postimage', 'inverse'],
      'config artifact',
    );
    const path = parseOwnedPath(record.path);
    const fingerprint = parseFingerprint(record.fingerprint, 'artifact fingerprint');
    const hunks = parseHunks(record.hunks);
    const preimage = parseSemanticConfigImage(record.preimage);
    const postimage = parseSemanticConfigImage(record.postimage);
    const inverse = parseInverse(record.inverse);
    if (inverse.kind !== 'restore-config' && inverse.kind !== 'remove-config-hunks') {
      throw new LifecycleProvenanceError('config artifact has an unsupported inverse');
    }
    if (
      inverse.path !== path ||
      !sameImage(inverse.preimage, preimage) ||
      !sameImage(inverse.postimage, postimage) ||
      (inverse.kind === 'remove-config-hunks' && !sameHunks(inverse.hunks, hunks))
    ) {
      throw new LifecycleProvenanceError('config inverse does not match its artifact');
    }
    return Object.freeze({
      path,
      kind: 'config',
      fingerprint,
      hunks,
      preimage,
      postimage,
      inverse,
    });
  }

  if (kind === 'credential-authority-registry') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'fingerprint', 'preimage', 'postimage', 'inverse'],
      'credential authority registry artifact',
    );
    const path = parseOwnedPath(record.path);
    const fingerprint = parseFingerprint(
      record.fingerprint,
      'credential authority registry fingerprint',
    );
    const preimage = parseSemanticCredentialAuthorityRegistryImage(record.preimage);
    const postimage = parseSemanticCredentialAuthorityRegistryImage(record.postimage);
    const inverse = parseInverse(record.inverse);
    if (
      inverse.kind !== 'restore-credential-authority-registry-entry' ||
      inverse.path !== path ||
      !sameCredentialAuthorityRegistryImage(inverse.preimage, preimage) ||
      !sameCredentialAuthorityRegistryImage(inverse.postimage, postimage)
    ) {
      throw new LifecycleProvenanceError(
        'credential authority registry inverse does not match its artifact',
      );
    }
    assertSelectedCredentialAuthorityRegistryTransition(preimage, postimage);
    return Object.freeze({
      path,
      kind: 'credential-authority-registry' as const,
      fingerprint,
      preimage,
      postimage,
      inverse,
    });
  }
  if (kind === 'credential') {
    const ownership = candidate.ownership;
    if (ownership === 'setup-created') {
      const record = exactRecord(
        candidate,
        ['path', 'kind', 'ownership', 'projectId', 'identity', 'mode', 'linkCount', 'inverse'],
        'created credential artifact',
      );
      const path = parseOwnedPath(record.path);
      const projectId = parseId(record.projectId, 'created credential projectId');
      const identity = parseWalFileIdentity(record.identity, 'created credential identity');
      const mode = parseCredentialWalMode(record.mode, 'created credential mode');
      if (record.linkCount !== 1) {
        throw new LifecycleProvenanceError('created credential must have exactly one link');
      }
      const inverse = parseInverse(record.inverse);
      if (
        inverse.kind !== 'delete-created-credential' ||
        inverse.path !== path ||
        inverse.projectId !== projectId ||
        inverse.identity === undefined ||
        !sameWalIdentity(inverse.identity, identity) ||
        inverse.mode !== mode ||
        inverse.linkCount !== 1
      ) {
        throw new LifecycleProvenanceError(
          'created credential must have its own exact delete inverse',
        );
      }
      return Object.freeze({
        path,
        kind: 'credential',
        ownership,
        projectId,
        identity,
        mode,
        linkCount: 1,
        inverse,
      });
    }
    if (ownership === 'adopted') {
      const record = exactRecord(
        candidate,
        ['path', 'kind', 'ownership', 'inverse'],
        'adopted credential artifact',
      );
      const path = parseOwnedPath(record.path);
      const inverse = parseInverse(record.inverse);
      if (inverse.kind !== 'none') {
        throw new LifecycleProvenanceError('adopted credential must not have a delete inverse');
      }
      return Object.freeze({ path, kind: 'credential', ownership, inverse });
    }
  }
  if (kind === 'directory') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'identity', 'mode', 'inverse'],
      'created directory artifact',
    );
    const path = parseOwnedPath(record.path);
    const identity = parseWalFileIdentity(record.identity, 'created directory identity');
    const mode = parseWalMode(record.mode, 'created directory mode');
    const inverse = parseInverse(record.inverse);
    if (
      inverse.kind !== 'delete-created-directory' ||
      inverse.path !== path ||
      !sameWalIdentity(inverse.identity, identity) ||
      inverse.mode !== mode ||
      inverse.emptyOnly !== true
    ) {
      throw new LifecycleProvenanceError(
        'created directory must have its own exact empty delete inverse',
      );
    }
    return Object.freeze({ path, kind: 'directory', identity, mode, inverse });
  }

  throw new LifecycleProvenanceError('owned artifact has an unsupported kind');
}

function parseHunks(value: unknown): readonly OwnedHunk[] {
  if (!Array.isArray(value)) {
    throw new LifecycleProvenanceError('owned hunks must be an array');
  }
  const hunks: OwnedHunk[] = [];
  const ids = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    if (!hasOwn(value, index)) {
      throw new LifecycleProvenanceError('owned hunks must not be sparse');
    }
    const record = exactRecord(value[index], HUNK_KEYS, 'owned hunk');
    const id = parseId(record.id, 'hunk id');
    if (ids.has(id)) {
      throw new LifecycleProvenanceError('owned hunk ids must be unique');
    }
    ids.add(id);
    if (record.operation !== 'insert' && record.operation !== 'update') {
      throw new LifecycleProvenanceError('owned hunk operation must be insert or update');
    }
    hunks.push(
      Object.freeze({
        id,
        fingerprint: parseFingerprint(record.fingerprint, 'hunk fingerprint'),
        operation: record.operation,
        subject: parseSubject(record.subject),
      }),
    );
  }
  return Object.freeze(hunks);
}

function parseSemanticConfigImage(value: unknown): SemanticConfigImage {
  const record = exactRecord(value, IMAGE_KEYS, 'semantic config image');
  if (record.schemaVersion !== 1 || !Array.isArray(record.projects)) {
    throw new LifecycleProvenanceError('semantic config image must use schema version 1 projects');
  }
  const projects: ProjectConfigV1[] = [];
  for (let index = 0; index < record.projects.length; index += 1) {
    if (!hasOwn(record.projects, index)) {
      throw new LifecycleProvenanceError('semantic config image projects must not be sparse');
    }
    projects.push(parseProjectConfigV1(record.projects[index]));
  }
  const parsed = parseServerConfigV1({ schemaVersion: 1, projects });
  return Object.freeze({ schemaVersion: 1, projects: parsed.projects });
}
function parseSemanticCredentialAuthorityRegistryImage(
  value: unknown,
): SemanticCredentialAuthorityRegistryImage {
  try {
    const parsed = parseCredentialAuthorityRegistrySelectionV1(value);
    return Object.freeze({ schemaVersion: 1, projects: parsed.projects });
  } catch {
    throw new LifecycleProvenanceError('semantic credential authority registry image is invalid');
  }
}
function mergedCredentialAuthorityRegistryPostimageBytes(
  preimage: PlainDataObject,
  selectedPreimage: SemanticCredentialAuthorityRegistryImage,
  selectedPostimage: SemanticCredentialAuthorityRegistryImage,
): Uint8Array {
  const selectedProjectId = selectedCredentialAuthorityRegistryProjectId(
    selectedPreimage,
    selectedPostimage,
  );
  let current: ReturnType<typeof parseCredentialAuthorityRegistryV1>;
  if (preimage.state === 'absent') {
    current = parseCredentialAuthorityRegistryV1({ schemaVersion: 1, projects: [] });
  } else if (preimage.state === 'file' && preimage.bytes instanceof Uint8Array) {
    try {
      current = parseCredentialAuthorityRegistryJsonV1(
        new TextDecoder('utf-8', { fatal: true }).decode(preimage.bytes),
      );
    } catch {
      throw new LifecycleProvenanceError(
        'credential authority registry preimage is not canonical registry data',
      );
    }
  } else {
    throw new LifecycleProvenanceError(
      'credential authority registry operation requires an exact absent or file preimage',
    );
  }

  const currentSelected = current.projects.find((entry) => entry.projectId === selectedProjectId);
  const observedSelection: SemanticCredentialAuthorityRegistryImage = Object.freeze({
    schemaVersion: 1,
    projects: Object.freeze(currentSelected === undefined ? [] : [currentSelected]),
  });
  if (!sameCredentialAuthorityRegistryImage(observedSelection, selectedPreimage)) {
    throw new LifecycleProvenanceError(
      'credential authority registry preimage does not bind the selected entry',
    );
  }

  const selectedPostimageEntry = selectedPostimage.projects[0];
  const projects = [
    ...current.projects.filter((entry) => entry.projectId !== selectedProjectId),
    ...(selectedPostimageEntry === undefined ? [] : [selectedPostimageEntry]),
  ].sort((left, right) => left.projectId.localeCompare(right.projectId));
  return Buffer.from(
    serializeCredentialAuthorityRegistryV1({ schemaVersion: 1, projects }),
    'utf8',
  );
}

function parseInverse(value: unknown): InverseOperation {
  const candidate = ordinaryRecord(value, 'inverse operation');
  switch (candidate.kind) {
    case 'none':
      exactRecord(candidate, ['kind'], 'no-op inverse');
      return Object.freeze({ kind: 'none' });
    case 'delete-created-file': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'expectedFingerprint'],
        'file delete inverse',
      );
      return Object.freeze({
        kind: 'delete-created-file',
        path: parseOwnedPath(record.path),
        expectedFingerprint: parseFingerprint(record.expectedFingerprint, 'expectedFingerprint'),
      });
    }
    case 'restore-owned-file': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'preimageFingerprint', 'postimageFingerprint', 'ownedInsertion', 'hunks'],
        'owned file restore inverse',
      );
      if (record.ownedInsertion !== 'line' && record.ownedInsertion !== 'preceding-newline-line') {
        throw new LifecycleProvenanceError('owned file restore insertion is unsupported');
      }
      return Object.freeze({
        kind: 'restore-owned-file',
        path: parseOwnedPath(record.path),
        preimageFingerprint: parseFingerprint(record.preimageFingerprint, 'preimageFingerprint'),
        postimageFingerprint: parseFingerprint(record.postimageFingerprint, 'postimageFingerprint'),
        ownedInsertion: record.ownedInsertion,
        hunks: parseHunks(record.hunks),
      });
    }
    case 'delete-created-credential': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'projectId', 'identity', 'mode', 'linkCount'],
        'credential delete inverse',
      );
      const mode = parseCredentialWalMode(record.mode, 'credential delete mode');
      if (record.linkCount !== 1) {
        throw new LifecycleProvenanceError('credential delete inverse must require one link');
      }
      return Object.freeze({
        kind: 'delete-created-credential',
        path: parseOwnedPath(record.path),
        projectId: parseId(record.projectId, 'credential delete projectId'),
        identity: parseWalFileIdentity(record.identity, 'credential delete identity'),
        mode,
        linkCount: 1,
      });
    }
    case 'delete-created-directory': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'identity', 'mode', 'emptyOnly'],
        'directory delete inverse',
      );
      if (record.emptyOnly !== true) {
        throw new LifecycleProvenanceError('directory delete inverse must be empty-only');
      }
      return Object.freeze({
        kind: 'delete-created-directory',
        path: parseOwnedPath(record.path),
        identity: parseWalFileIdentity(record.identity, 'directory delete identity'),
        mode: parseWalMode(record.mode, 'directory delete mode'),
        emptyOnly: true,
      });
    }
    case 'restore-config': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'preimage', 'postimage'],
        'config restore inverse',
      );
      return Object.freeze({
        kind: 'restore-config',
        path: parseOwnedPath(record.path),
        preimage: parseSemanticConfigImage(record.preimage),
        postimage: parseSemanticConfigImage(record.postimage),
      });
    }
    case 'remove-config-hunks': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'hunks', 'preimage', 'postimage'],
        'hunk removal inverse',
      );
      return Object.freeze({
        kind: 'remove-config-hunks',
        path: parseOwnedPath(record.path),
        hunks: parseHunks(record.hunks),
        preimage: parseSemanticConfigImage(record.preimage),
        postimage: parseSemanticConfigImage(record.postimage),
      });
    }
    case 'restore-credential-authority-registry-entry': {
      const record = exactRecord(
        candidate,
        ['kind', 'path', 'preimage', 'postimage'],
        'credential authority registry restore inverse',
      );
      const preimage = parseSemanticCredentialAuthorityRegistryImage(record.preimage);
      const postimage = parseSemanticCredentialAuthorityRegistryImage(record.postimage);
      assertSelectedCredentialAuthorityRegistryTransition(preimage, postimage);
      return Object.freeze({
        kind: 'restore-credential-authority-registry-entry',
        path: parseOwnedPath(record.path),
        preimage,
        postimage,
      });
    }
    default:
      throw new LifecycleProvenanceError('inverse operation has an unsupported kind');
  }
}

function validateTarget(
  artifact: OwnedArtifact,
  target: ObservedOwnedTarget,
  issues: OwnedArtifactIssue[],
): void {
  if (artifact.kind === 'credential' || artifact.kind === 'directory') {
    /*
     * Exact credential and empty-directory identity validation requires the
     * lock-held native transaction port and is performed by uninstall.
     */
    return;
  }
  if (artifact.kind === 'credential-authority-registry') {
    validateSemanticCredentialAuthorityRegistryPostimage(artifact, target, issues);
    return;
  }
  if (artifact.kind === 'file' && artifact.inverse.kind === 'restore-owned-file') {
    return;
  }

  if (artifact.hunks.length === 0) {
    if (target.fingerprint !== artifact.fingerprint) {
      issues.push(issue('target-changed', artifact.path));
    }
  } else {
    for (const hunk of artifact.hunks) {
      const matches = target.hunks.filter((observed) => observed.id === hunk.id);
      if (matches.length === 0) {
        issues.push(issue('hunk-missing', artifact.path, hunk.id));
        continue;
      }
      if (matches.length > 1) {
        issues.push(issue('hunk-duplicate', artifact.path, hunk.id));
        continue;
      }
      const match = matches[0];
      if (match === undefined || match.fingerprint !== hunk.fingerprint) {
        issues.push(issue('hunk-changed', artifact.path, hunk.id));
      }
    }
  }

  if (artifact.kind === 'config') {
    validateSemanticPostimage(artifact, target, issues);
  }
}

function validateSemanticPostimage(
  artifact: OwnedConfigArtifact,
  target: ObservedOwnedTarget,
  issues: OwnedArtifactIssue[],
): void {
  if (target.semanticConfig === undefined) {
    issues.push(issue('semantic-config-missing', artifact.path));
    return;
  }
  let observed: ServerConfigV1;
  try {
    observed = parseServerConfigV1(target.semanticConfig);
  } catch {
    issues.push(issue('semantic-config-changed', artifact.path));
    return;
  }
  for (const expected of artifact.postimage.projects) {
    const actual = observed.projects.find(
      (candidate) => candidate.projectId === expected.projectId,
    );
    if (actual === undefined || !sameProject(actual, expected)) {
      issues.push(issue('semantic-config-changed', artifact.path));
      return;
    }
  }
}
function validateSemanticCredentialAuthorityRegistryPostimage(
  artifact: OwnedCredentialAuthorityRegistryArtifact,
  target: ObservedOwnedTarget,
  issues: OwnedArtifactIssue[],
): void {
  if (target.semanticCredentialAuthorityRegistry === undefined) {
    issues.push(issue('semantic-credential-authority-registry-missing', artifact.path));
    return;
  }

  let observed: ReturnType<typeof parseCredentialAuthorityRegistryV1>;
  try {
    observed = parseCredentialAuthorityRegistryV1(target.semanticCredentialAuthorityRegistry);
  } catch {
    issues.push(issue('semantic-credential-authority-registry-changed', artifact.path));
    return;
  }

  const selectedProjectId = selectedCredentialAuthorityRegistryProjectId(
    artifact.preimage,
    artifact.postimage,
  );
  const expected = artifact.postimage.projects[0];
  const actual = observed.projects.find((entry) => entry.projectId === selectedProjectId);
  if (
    (expected === undefined && actual !== undefined) ||
    (expected !== undefined && (actual === undefined || !sameRegistryEntry(actual, expected)))
  ) {
    issues.push(issue('semantic-credential-authority-registry-changed', artifact.path));
  }
}

interface ParsedWalRecordV2Common {
  readonly operationId: string;
  readonly installId: string;
  readonly direction: 'rollback' | 'commit';
  readonly phase: 'prepared' | 'finalized' | 'commit-decided';
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly cursor: number;
  readonly preimages: readonly WalPreimageV2[];
  readonly mutations: readonly WalMutationV2[];
  readonly creationIntents: readonly WalCreationIntentV2[] | undefined;
  readonly authorityFingerprint: string;
  readonly replacedWalStage: WalReplacedStageLineage | undefined;
}

interface WalImageBudget {
  decodedBytes: number;
}
type PlainDataObject = { readonly [key: string]: unknown };

function parseWalRecordValue(value: unknown): WalRecord {
  const candidate = ordinaryRecord(value, 'WAL record');
  if (!hasOwn(candidate, 'schemaVersion')) {
    throw new LifecycleProvenanceError('WAL record has an unsupported schema version');
  }
  if (candidate.schemaVersion === 1) {
    return parseWalRecordV1(candidate);
  }
  if (candidate.schemaVersion === 2) {
    return parseWalRecordV2(candidate);
  }
  throw new LifecycleProvenanceError('WAL record has an unsupported schema version');
}

function parseWalRecordV2Common(
  record: PlainDataObject,
  operation: 'setup' | 'uninstall',
): ParsedWalRecordV2Common {
  const budget: WalImageBudget = { decodedBytes: 0 };
  const preimages = parseWalPreimages(record.preimages, budget);
  const mutations = parseWalMutations(record.mutations, preimages, budget, operation);
  const creationIntents = hasOwn(record, 'creationIntents')
    ? parseWalCreationIntents(record.creationIntents, preimages, mutations, operation)
    : undefined;
  const replacedWalStage = hasOwn(record, 'replacedWalStage')
    ? parseWalReplacedStageLineage(record.replacedWalStage)
    : undefined;
  return {
    operationId: parseId(record.operationId, 'operationId'),
    installId: parseId(record.installId, 'installId'),
    direction: parseWalDirection(record.direction),
    phase: parseWalPhase(record.phase),
    lockPath: parseWalPath(record.lockPath, 'lockPath'),
    manifestPath: parseWalPath(record.manifestPath, 'manifestPath'),
    cursor: parseWalCursor(record.cursor, mutations.length),
    preimages,
    mutations,
    creationIntents,
    authorityFingerprint: parseFingerprint(record.authorityFingerprint, 'authorityFingerprint'),
    replacedWalStage,
  };
}
function parseWalReplacedStageLineage(value: unknown): WalReplacedStageLineage {
  const record = exactRecord(
    value,
    ['identity', 'mode', 'authorityFingerprint'],
    'WAL replaced stage lineage',
  );
  const mode = parseWalMode(record.mode, 'WAL replaced stage mode');
  if (mode !== 0o600) {
    throw new LifecycleProvenanceError('WAL replaced stage mode must be 0600');
  }
  return Object.freeze({
    identity: parseWalFileIdentity(record.identity, 'WAL replaced stage identity'),
    mode,
    authorityFingerprint: parseFingerprint(
      record.authorityFingerprint,
      'WAL replaced stage authorityFingerprint',
    ),
  });
}

function parseWalDirection(value: unknown): 'rollback' | 'commit' {
  if (value === 'rollback' || value === 'commit') {
    return value;
  }
  throw new LifecycleProvenanceError('WAL v2 direction must be rollback or commit');
}

function parseWalPhase(value: unknown): 'prepared' | 'finalized' | 'commit-decided' {
  if (value === 'prepared' || value === 'finalized' || value === 'commit-decided') {
    return value;
  }
  throw new LifecycleProvenanceError('WAL v2 phase is unsupported');
}

function parseWalCursor(value: unknown, mutationCount: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > mutationCount
  ) {
    throw new LifecycleProvenanceError('WAL v2 cursor must index the ordered mutation steps');
  }
  return value;
}

function hasOnlyArrayIndexKeys(value: readonly unknown[]): boolean {
  for (const key of Reflect.ownKeys(value)) {
    if (key === 'length') {
      continue;
    }
    if (typeof key !== 'string') {
      return false;
    }
    const index = Number(key);
    if (
      !Number.isSafeInteger(index) ||
      index < 0 ||
      String(index) !== key ||
      index >= value.length
    ) {
      return false;
    }
  }
  return true;
}

function parseWalPreimages(value: unknown, budget: WalImageBudget): readonly WalPreimageV2[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    !hasOnlyArrayIndexKeys(value)
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 preimages must be a plain array without extra properties',
    );
  }
  if (value.length > MAX_WAL_IMAGES) {
    throw new LifecycleProvenanceError('WAL v2 preimages must be a bounded array');
  }
  const preimages: WalPreimageV2[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) {
      throw new LifecycleProvenanceError('WAL v2 preimages must not be sparse');
    }
    if (!descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      throw new LifecycleProvenanceError(
        'WAL v2 preimages must be a dense array of enumerable data values',
      );
    }
    preimages.push(parseWalPreimage(descriptor.value, budget));
  }
  return Object.freeze(preimages);
}

function parseWalPreimage(value: unknown, budget: WalImageBudget): WalPreimageV2 {
  const candidate = ordinaryRecord(value, 'WAL v2 preimage');
  if (!hasOwn(candidate, 'kind')) {
    throw new LifecycleProvenanceError('WAL v2 preimage has no own kind');
  }
  if (candidate.kind === 'absent') {
    const record = exactRecord(candidate, ['path', 'kind'], 'absent WAL v2 preimage');
    return Object.freeze({ path: parseWalPath(record.path, 'preimage path'), kind: 'absent' });
  }
  if (candidate.kind === 'file') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'identity', 'mode', 'bytes'],
      'file WAL v2 preimage',
    );
    return Object.freeze({
      path: parseWalPath(record.path, 'preimage path'),
      kind: 'file',
      identity: parseWalFileIdentity(record.identity, 'preimage identity'),
      mode: parseWalMode(record.mode, 'preimage mode'),
      bytes: parseWalImageBytes(record.bytes, budget, 'preimage bytes'),
    });
  }
  if (candidate.kind === 'directory') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'identity', 'mode'],
      'directory WAL v2 preimage',
    );
    return Object.freeze({
      path: parseWalPath(record.path, 'directory preimage path'),
      kind: 'directory',
      identity: parseWalFileIdentity(record.identity, 'directory preimage identity'),
      mode: parseWalMode(record.mode, 'directory preimage mode'),
    });
  }
  if (candidate.kind === 'credential') {
    const record = exactRecord(
      candidate,
      ['path', 'kind', 'identity', 'mode'],
      'credential WAL v2 preimage',
    );
    return Object.freeze({
      path: parseWalPath(record.path, 'credential preimage path'),
      kind: 'credential',
      identity: parseWalFileIdentity(record.identity, 'credential preimage identity'),
      mode: parseCredentialWalMode(record.mode, 'credential preimage mode'),
    });
  }
  throw new LifecycleProvenanceError('WAL v2 preimage has an unsupported kind');
}
function parseWalCreationIntents(
  value: unknown,
  preimages: readonly WalPreimageV2[],
  mutations: readonly WalMutationV2[],
  operation: 'setup' | 'uninstall',
): readonly WalCreationIntentV2[] | undefined {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    !hasOnlyArrayIndexKeys(value)
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 creationIntents must be a plain array without extra properties',
    );
  }
  if (value.length > MAX_WAL_IMAGES) {
    throw new LifecycleProvenanceError('WAL v2 creationIntents must be a bounded array');
  }
  if (value.length === 0) {
    return undefined;
  }

  const intents: WalCreationIntentV2[] = [];
  const paths = new Set<string>();
  const validationTokens = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      throw new LifecycleProvenanceError(
        'WAL v2 creationIntents must be a dense array of enumerable data values',
      );
    }
    const intent = parseWalCreationIntent(
      descriptor.value,
      mutations.length + index,
      preimages,
      operation,
    );
    if (
      paths.has(intent.targetPath) ||
      paths.has(intent.stagingPath) ||
      validationTokens.has(intent.validationToken)
    ) {
      throw new LifecycleProvenanceError(
        'WAL v2 creationIntents must have unique target, staging, and validation-token authority',
      );
    }
    paths.add(intent.targetPath);
    paths.add(intent.stagingPath);
    validationTokens.add(intent.validationToken);
    intents.push(intent);
  }
  return Object.freeze(intents);
}

function parseWalCreationIntent(
  value: unknown,
  expectedStep: number,
  preimages: readonly WalPreimageV2[],
  operation: 'setup' | 'uninstall',
): WalCreationIntentV2 {
  const record = exactRecord(
    value,
    [
      'step',
      'kind',
      'targetPath',
      'stagingPath',
      'mode',
      'validationToken',
      'targetPreimage',
      'stagingPreimage',
    ],
    'WAL v2 creation intent',
  );
  if (
    typeof record.step !== 'number' ||
    !Number.isSafeInteger(record.step) ||
    record.step !== expectedStep
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 creation intent steps must be contiguous after completed mutations',
    );
  }
  if (record.kind !== 'credential' && record.kind !== 'directory' && record.kind !== 'file') {
    throw new LifecycleProvenanceError('WAL v2 creation intent kind is unsupported');
  }
  if (operation === 'uninstall' && record.kind !== 'file') {
    throw new LifecycleProvenanceError('uninstall WAL v2 creation intent must be a file intent');
  }

  const targetPath = parseWalPath(record.targetPath, 'creation intent targetPath');
  const stagingPath = parseWalPath(record.stagingPath, 'creation intent stagingPath');
  if (targetPath === stagingPath || dirname(targetPath) !== dirname(stagingPath)) {
    throw new LifecycleProvenanceError(
      'WAL v2 creation intent target and staging paths must be distinct same-parent paths',
    );
  }

  const targetPreimage = parseWalPreimageIndex(record.targetPreimage, preimages.length);
  const stagingPreimage = parseWalPreimageIndex(record.stagingPreimage, preimages.length);
  const target = preimages[targetPreimage];
  const staging = preimages[stagingPreimage];
  if (
    targetPreimage === stagingPreimage ||
    target === undefined ||
    staging === undefined ||
    staging.kind !== 'absent' ||
    staging.path !== stagingPath ||
    (record.kind === 'file' ? target.kind === 'credential' : target.kind !== 'absent') ||
    target.path !== targetPath
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 creation intent requires exact target and absent staging preimage authority',
    );
  }

  return Object.freeze({
    step: record.step,
    kind: record.kind,
    targetPath,
    stagingPath,
    mode:
      record.kind === 'credential'
        ? parseCredentialWalMode(record.mode, 'credential creation intent mode')
        : parseWalMode(record.mode, 'file or directory creation intent mode'),
    validationToken: parseWalCreationIntentValidationToken(record.validationToken),
    targetPreimage,
    stagingPreimage,
  });
}

function parseWalMutations(
  value: unknown,
  preimages: readonly WalPreimageV2[],
  budget: WalImageBudget,
  operation: 'setup' | 'uninstall',
): readonly WalMutationV2[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    !hasOnlyArrayIndexKeys(value)
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 mutations must be a plain array without extra properties',
    );
  }
  if (value.length > MAX_WAL_IMAGES) {
    throw new LifecycleProvenanceError('WAL v2 mutations must be a bounded array');
  }
  const mutations: WalMutationV2[] = [];
  let credentialMutationCount = 0;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) {
      throw new LifecycleProvenanceError('WAL v2 mutations must not be sparse');
    }
    if (!descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      throw new LifecycleProvenanceError(
        'WAL v2 mutations must be a dense array of enumerable data values',
      );
    }
    const mutation = parseWalMutation(descriptor.value, index, preimages, budget, operation);
    if (mutation.kind === 'credential' && ++credentialMutationCount > 1) {
      throw new LifecycleProvenanceError('setup WAL v2 permits at most one credential mutation');
    }
    mutations.push(mutation);
  }
  return Object.freeze(mutations);
}

function parseWalMutation(
  value: unknown,
  index: number,
  preimages: readonly WalPreimageV2[],
  budget: WalImageBudget,
  operation: 'setup' | 'uninstall',
): WalMutationV2 {
  const candidate = ordinaryRecord(value, 'WAL v2 mutation');
  if (!hasOwn(candidate, 'kind')) {
    throw new LifecycleProvenanceError('WAL v2 mutation has no own kind');
  }
  if (candidate.kind === 'ordinary') {
    const record = exactRecord(
      candidate,
      ['step', 'kind', 'targetPath', 'sourcePath', 'stagingPath', 'preimage', 'result'],
      'ordinary WAL v2 mutation',
    );
    const step = parseWalStep(record.step, index);
    const targetPath = parseWalPath(record.targetPath, 'ordinary mutation targetPath');
    const preimage = parseWalPreimageIndex(record.preimage, preimages.length);
    const original = preimages[preimage];
    const result = parseWalOrdinaryResult(record.result, budget);
    if (original === undefined || original.path !== targetPath) {
      throw new LifecycleProvenanceError(
        'ordinary WAL v2 mutation must reference its exact noncredential preimage',
      );
    }
    if (result.kind === 'directory' && original.kind !== 'absent') {
      throw new LifecycleProvenanceError(
        'directory WAL v2 mutation must reference its exact absent preimage',
      );
    }
    if (original.kind === 'credential') {
      throw new LifecycleProvenanceError(
        'ordinary WAL v2 mutation must reference its exact noncredential preimage',
      );
    }
    const mutation: WalOrdinaryMutationV2 = {
      step,
      kind: 'ordinary',
      targetPath,
      sourcePath: parseWalPath(record.sourcePath, 'ordinary mutation sourcePath'),
      stagingPath: parseWalPath(record.stagingPath, 'ordinary mutation stagingPath'),
      preimage,
      result,
    };
    return Object.freeze(mutation);
  }
  if (candidate.kind === 'credential') {
    const record = exactRecord(
      candidate,
      [
        'step',
        'kind',
        'projectId',
        'path',
        'mode',
        'stagingPath',
        'stagingIdentity',
        'targetIdentity',
      ],
      'credential WAL v2 mutation',
    );
    const step = parseWalStep(record.step, index);
    const path = parseWalPath(record.path, 'credential mutation path');
    const mode = parseCredentialWalMode(record.mode, 'credential mutation mode');
    const stagingIdentity = parseWalFileIdentity(
      record.stagingIdentity,
      'credential mutation stagingIdentity',
    );
    const targetIdentity = parseWalFileIdentity(
      record.targetIdentity,
      'credential mutation targetIdentity',
    );
    const original = preimages.find((preimage) => preimage.path === path);
    if (
      operation !== 'setup' ||
      original === undefined ||
      original.kind !== 'absent' ||
      !sameWalIdentity(stagingIdentity, targetIdentity)
    ) {
      throw new LifecycleProvenanceError(
        'credential WAL v2 mutation must create one exact credential identity from an absent preimage',
      );
    }
    const mutation: WalCredentialMutationV2 = {
      step,
      kind: 'credential',
      projectId: parseId(record.projectId, 'credential mutation projectId'),
      path,
      mode,
      stagingPath: parseWalPath(record.stagingPath, 'credential mutation stagingPath'),
      stagingIdentity,
      targetIdentity,
    };
    return Object.freeze(mutation);
  }
  throw new LifecycleProvenanceError('WAL v2 mutation has an unsupported kind');
}

function parseWalStep(value: unknown, index: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value !== index) {
    throw new LifecycleProvenanceError('WAL v2 mutation steps must be contiguous and ordered');
  }
  return value;
}

function parseWalPreimageIndex(value: unknown, length: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value >= length) {
    throw new LifecycleProvenanceError('WAL v2 mutation preimage must reference a preimage');
  }
  return value;
}

function parseWalOrdinaryResult(value: unknown, budget: WalImageBudget): WalOrdinaryResultV2 {
  const candidate = ordinaryRecord(value, 'ordinary WAL v2 mutation result');
  if (!hasOwn(candidate, 'kind')) {
    throw new LifecycleProvenanceError('ordinary WAL v2 mutation result has no own kind');
  }
  if (candidate.kind === 'absent') {
    exactRecord(candidate, ['kind'], 'absent ordinary WAL v2 mutation result');
    return Object.freeze({ kind: 'absent' });
  }
  if (candidate.kind === 'file') {
    const record = exactRecord(
      candidate,
      ['kind', 'identity', 'mode', 'bytes'],
      'file ordinary WAL v2 mutation result',
    );
    const result: WalFileResultV2 = {
      kind: 'file',
      identity: parseWalFileIdentity(record.identity, 'ordinary mutation result identity'),
      mode: parseWalMode(record.mode, 'ordinary mutation result mode'),
      bytes: parseWalImageBytes(record.bytes, budget, 'ordinary mutation result bytes'),
    };
    return Object.freeze(result);
  }
  if (candidate.kind === 'directory') {
    const record = exactRecord(
      candidate,
      ['kind', 'identity', 'mode'],
      'directory ordinary WAL v2 mutation result',
    );
    const result: WalDirectoryResultV2 = {
      kind: 'directory',
      identity: parseWalFileIdentity(
        record.identity,
        'ordinary mutation directory result identity',
      ),
      mode: parseWalMode(record.mode, 'ordinary mutation directory result mode'),
    };
    return Object.freeze(result);
  }
  throw new LifecycleProvenanceError('ordinary WAL v2 mutation result has an unsupported kind');
}

function parseWalFileIdentity(value: unknown, name: string): WalFileIdentityV2 {
  const record = exactRecord(value, ['device', 'inode'], name);
  return Object.freeze({
    device: parseWalDecimalId(record.device, `${name} device`),
    inode: parseWalDecimalId(record.inode, `${name} inode`),
  });
}
function freezeWalIdentity(value: WalFileIdentityV2): WalFileIdentityV2 {
  return Object.freeze({
    device: parseWalDecimalId(value.device, 'identity device'),
    inode: parseWalDecimalId(value.inode, 'identity inode'),
  });
}
function fingerprintBytes(value: Uint8Array): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function parseWalDecimalId(value: unknown, name: string): string {
  if (typeof value !== 'string' || !DECIMAL_ID_PATTERN.test(value)) {
    throw new LifecycleProvenanceError(`${name} must be a canonical decimal identity`);
  }
  return value;
}

function parseWalMode(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 0o777) {
    throw new LifecycleProvenanceError(`${name} must be a canonical permission mode`);
  }
  return value;
}

function parseCredentialWalMode(value: unknown, name: string): 0o600 {
  const mode = parseWalMode(value, name);
  if (mode !== 0o600) {
    throw new LifecycleProvenanceError(`${name} must be mode 0600`);
  }
  return 0o600;
}

function parseWalImageBytes(value: unknown, budget: WalImageBudget, name: string): string {
  if (typeof value !== 'string' || !BASE64_PATTERN.test(value)) {
    throw new LifecycleProvenanceError(`${name} must be canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value || decoded.byteLength > MAX_WAL_IMAGE_BYTES) {
    throw new LifecycleProvenanceError(`${name} must be bounded canonical base64`);
  }
  budget.decodedBytes += decoded.byteLength;
  if (budget.decodedBytes > MAX_WAL_IMAGE_TOTAL_BYTES) {
    throw new LifecycleProvenanceError('WAL v2 ordinary images exceed the aggregate byte limit');
  }
  return value;
}
function parseWalCreationIntentValidationToken(value: unknown): string {
  if (typeof value !== 'string' || !WAL_CREATION_INTENT_TOKEN_PATTERN.test(value)) {
    throw new LifecycleProvenanceError(
      'WAL v2 creation intent validationToken must be exactly 32 lowercase hexadecimal characters',
    );
  }
  return value;
}

function parseWalPath(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_WAL_PATH_BYTES ||
    value.includes('\u0000') ||
    !isAbsolute(value) ||
    value === '/' ||
    value.endsWith('/') ||
    normalize(value) !== value
  ) {
    throw new LifecycleProvenanceError(`${name} must be a canonical absolute normalized path`);
  }
  return value;
}

function assertSetupWalPhaseDirection(
  direction: 'rollback' | 'commit',
  phase: 'prepared' | 'finalized' | 'commit-decided',
  cursor: number,
  mutationCount: number,
): void {
  if (
    (phase === 'prepared' && direction !== 'rollback') ||
    (phase === 'finalized' && direction !== 'rollback') ||
    (phase === 'commit-decided' && direction !== 'commit')
  ) {
    throw new LifecycleProvenanceError('setup WAL v2 phase and direction are incompatible');
  }
  if (phase !== 'prepared' && cursor !== mutationCount) {
    throw new LifecycleProvenanceError('finalized setup WAL v2 must complete every mutation step');
  }
}
function assertWalCreationIntentPhase(common: ParsedWalRecordV2Common): void {
  if (
    common.creationIntents !== undefined &&
    (common.direction !== 'rollback' ||
      common.phase !== 'prepared' ||
      common.cursor !== common.mutations.length)
  ) {
    throw new LifecycleProvenanceError(
      'WAL v2 creation intents require a fully advanced prepared rollback record',
    );
  }
}

function assertUninstallWalPhaseDirection(
  direction: 'rollback' | 'commit',
  phase: 'prepared' | 'finalized' | 'commit-decided',
  cursor: number,
  mutationCount: number,
): void {
  if (
    (phase === 'prepared' && direction !== 'rollback') ||
    (phase === 'commit-decided' && direction !== 'commit') ||
    phase === 'finalized'
  ) {
    throw new LifecycleProvenanceError('uninstall WAL v2 phase and direction are incompatible');
  }
  if (phase === 'commit-decided' && cursor !== mutationCount) {
    throw new LifecycleProvenanceError(
      'committed uninstall WAL v2 must complete every mutation step',
    );
  }
}

interface UninstallWalTerminalBinding {
  readonly receiptPath: string;
  readonly manifestInstallId: string;
  readonly manifestBytes: string;
  readonly receiptBytes: string;
  readonly manifestArtifactPaths: readonly string[];
  readonly assertStaleReceipt: (preimage: WalPreimageV2, installId: string) => void;
}

function legacyUninstallTerminalBinding(
  common: ParsedWalRecordV2Common,
  receiptPath: string,
  manifest: SetupManifestV1,
): UninstallWalTerminalBinding {
  const manifestBytes = serializeSetupManifestV1(manifest);
  return {
    receiptPath,
    manifestInstallId: manifest.installId,
    manifestBytes,
    manifestArtifactPaths: manifest.artifacts.map((artifact) => artifact.path),
    receiptBytes: serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: common.operationId,
      installId: common.installId,
      terminalState: 'uninstalled',
      manifestFingerprint: fingerprintBytes(Buffer.from(manifestBytes, 'utf8')),
    }),
    assertStaleReceipt: assertStaleReceiptPreimage,
  };
}

function hostUninstallTerminalBinding(
  common: ParsedWalRecordV2Common,
  receiptPath: string,
  manifest: HostSetupManifestV2,
): UninstallWalTerminalBinding {
  const manifestBytes = serializeHostSetupManifestV2(manifest);
  return {
    receiptPath,
    manifestInstallId: manifest.installId,
    manifestBytes,
    manifestArtifactPaths: manifest.artifacts.map((artifact) => artifact.path),
    receiptBytes: serializeHostLifecycleReceiptV2({
      schemaVersion: 2,
      kind: 'scene-glass-host-lifecycle-receipt',
      operationId: common.operationId,
      installId: common.installId,
      terminalState: 'uninstalled',
      hostRoot: manifest.hostRoot,
      stateRoot: manifest.stateRoot,
      manifestFingerprint: fingerprintBytes(Buffer.from(manifestBytes, 'utf8')),
    }),
    assertStaleReceipt: assertStaleHostReceiptPreimage,
  };
}

function assertWalV2Paths(
  common: ParsedWalRecordV2Common,
  uninstall: UninstallWalTerminalBinding | undefined = undefined,
): void {
  const paths = new Map<string, string>();
  const addUnique = (path: string, name: string): void => {
    const existing = paths.get(path);
    if (existing !== undefined) {
      throw new LifecycleProvenanceError(`WAL v2 path collision between ${existing} and ${name}`);
    }
    paths.set(path, name);
  };
  addUnique(common.lockPath, 'lockPath');
  addUnique(common.manifestPath, 'manifestPath');
  if (uninstall !== undefined) {
    addUnique(uninstall.receiptPath, 'receiptPath');
  }

  const preimagesByPath = new Map<string, WalPreimageV2>();
  let receiptPreimageIndex: number | undefined;
  let manifestPreimageIndex: number | undefined;
  for (let index = 0; index < common.preimages.length; index += 1) {
    const preimage = common.preimages[index];
    if (preimage === undefined) {
      throw new LifecycleProvenanceError('WAL v2 preimages must not be sparse');
    }
    if (uninstall !== undefined && preimage.path === uninstall.receiptPath) {
      if (receiptPreimageIndex !== undefined) {
        throw new LifecycleProvenanceError('uninstall WAL v2 receipt preimage must be unique');
      }
      if (preimage.kind !== 'absent') {
        uninstall.assertStaleReceipt(preimage, uninstall.manifestInstallId);
      }
      receiptPreimageIndex = index;
    } else if (uninstall !== undefined && preimage.path === common.manifestPath) {
      if (manifestPreimageIndex !== undefined) {
        throw new LifecycleProvenanceError('uninstall WAL v2 manifest preimage must be unique');
      }
      if (
        preimage.kind !== 'file' ||
        preimage.mode !== 0o600 ||
        preimage.bytes !== Buffer.from(uninstall.manifestBytes, 'utf8').toString('base64')
      ) {
        throw new LifecycleProvenanceError(
          'uninstall WAL v2 manifest preimage must bind the exact active manifest',
        );
      }
      manifestPreimageIndex = index;
    } else {
      addUnique(preimage.path, `preimage ${index}`);
    }
    preimagesByPath.set(preimage.path, preimage);
  }

  const ordinaryTargets = new Set<string>();
  const ordinaryMutations: WalOrdinaryMutationV2[] = [];
  const credentialTargets = new Set<string>();
  const credentialProjects = new Set<string>();
  for (const mutation of common.mutations) {
    if (mutation.kind === 'ordinary') {
      if (
        ordinaryTargets.has(mutation.targetPath) ||
        mutation.targetPath === mutation.sourcePath ||
        mutation.targetPath === mutation.stagingPath
      ) {
        throw new LifecycleProvenanceError('ordinary WAL v2 mutation targets must be unique');
      }
      ordinaryTargets.add(mutation.targetPath);
      ordinaryMutations.push(mutation);
      addUnique(mutation.sourcePath, `ordinary mutation ${mutation.step} sourcePath`);
      addUnique(mutation.stagingPath, `ordinary mutation ${mutation.step} stagingPath`);
      continue;
    }
    if (
      credentialTargets.size !== 0 ||
      credentialTargets.has(mutation.path) ||
      credentialProjects.has(mutation.projectId)
    ) {
      throw new LifecycleProvenanceError(
        'setup WAL v2 credential mutation target and project must be unique',
      );
    }
    const preimage = preimagesByPath.get(mutation.path);
    if (preimage === undefined) {
      throw new LifecycleProvenanceError(
        'credential WAL v2 mutation path lacks preimage authority',
      );
    }
    credentialTargets.add(mutation.path);
    credentialProjects.add(mutation.projectId);
    addUnique(mutation.stagingPath, `credential mutation ${mutation.step} stagingPath`);
  }
  for (const mutation of ordinaryMutations) {
    if (ordinaryTargets.has(mutation.sourcePath) || ordinaryTargets.has(mutation.stagingPath)) {
      throw new LifecycleProvenanceError(
        'ordinary WAL v2 mutation target must not overlap another mutation authority path',
      );
    }
  }
  for (const mutation of ordinaryMutations) {
    if (
      credentialTargets.has(mutation.targetPath) ||
      credentialTargets.has(mutation.sourcePath) ||
      credentialTargets.has(mutation.stagingPath)
    ) {
      throw new LifecycleProvenanceError(
        'ordinary WAL v2 mutation must not overlap credential mutation authority',
      );
    }
  }
  assertWalCreationIntentPaths(common);

  if (uninstall === undefined) {
    return;
  }

  const receiptMutations = ordinaryMutations.filter(
    (mutation) => mutation.targetPath === uninstall.receiptPath,
  );
  const manifestMutations = ordinaryMutations.filter(
    (mutation) => mutation.targetPath === common.manifestPath,
  );
  const expectedReceipt = uninstall.receiptBytes;
  const receiptMutation = receiptMutations[0];
  if (
    receiptPreimageIndex === undefined ||
    manifestPreimageIndex === undefined ||
    receiptMutations.length > 1 ||
    manifestMutations.length > 1 ||
    (receiptMutation !== undefined &&
      (receiptMutation.preimage !== receiptPreimageIndex ||
        receiptMutation.result.kind !== 'file' ||
        receiptMutation.result.mode !== 0o600 ||
        receiptMutation.result.bytes !== Buffer.from(expectedReceipt, 'utf8').toString('base64')))
  ) {
    throw new LifecycleProvenanceError(
      'uninstall WAL v2 terminal receipt mutation lacks exact authority',
    );
  }
  const manifestMutation = manifestMutations[0];
  if (
    manifestMutation !== undefined &&
    (manifestMutation.preimage !== manifestPreimageIndex ||
      manifestMutation.result.kind !== 'absent')
  ) {
    throw new LifecycleProvenanceError(
      'uninstall WAL v2 terminal manifest mutation lacks exact authority',
    );
  }
  if (
    common.direction === 'commit' &&
    common.phase === 'commit-decided' &&
    (receiptMutation === undefined || manifestMutation === undefined)
  ) {
    throw new LifecycleProvenanceError(
      'committed uninstall WAL v2 requires exact terminal receipt and manifest mutations',
    );
  }

  for (const rawArtifactPath of uninstall.manifestArtifactPaths) {
    const artifactPath = parseWalPath(rawArtifactPath, 'uninstall manifest artifact path');
    if (artifactPath === uninstall.receiptPath) {
      throw new LifecycleProvenanceError(
        'uninstall WAL v2 receipt path must not collide with a manifest artifact',
      );
    }
    if (!preimagesByPath.has(artifactPath)) {
      throw new LifecycleProvenanceError(
        'uninstall WAL v2 manifest artifact lacks exact preimage authority',
      );
    }
  }
}
function assertWalCreationIntentPaths(common: ParsedWalRecordV2Common): void {
  const intents = common.creationIntents;
  if (intents === undefined) {
    return;
  }

  const protectedPaths = [common.lockPath, common.manifestPath];
  for (let index = 0; index < intents.length; index += 1) {
    const intent = intents[index];
    if (intent === undefined) {
      throw new LifecycleProvenanceError('WAL v2 creationIntents must not be sparse');
    }
    const intentPaths = [intent.targetPath, intent.stagingPath];
    for (const protectedPath of protectedPaths) {
      if (intentPaths.some((path) => walPathsOverlap(path, protectedPath))) {
        throw new LifecycleProvenanceError(
          'WAL v2 creation intent must not overlap a protected WAL authority path',
        );
      }
    }

    for (let preimageIndex = 0; preimageIndex < common.preimages.length; preimageIndex += 1) {
      if (preimageIndex === intent.targetPreimage || preimageIndex === intent.stagingPreimage) {
        continue;
      }
      const preimage = common.preimages[preimageIndex];
      const ownedDirectory = common.mutations.find(
        (mutation) =>
          mutation.kind === 'ordinary' &&
          mutation.result.kind === 'directory' &&
          mutation.preimage === preimageIndex &&
          mutation.targetPath === preimage?.path &&
          mutation.step < common.cursor &&
          intentPaths.every((path) => walPathIsStrictDescendant(path, mutation.targetPath)),
      );
      const exactDirectoryDescendant =
        preimage?.kind === 'directory' &&
        intentPaths.every((path) => walPathIsStrictDescendant(path, preimage.path));
      const plannedDirectoryDescendant =
        preimage?.kind === 'absent' &&
        intent.kind === 'directory' &&
        walPathIsStrictDescendant(preimage.path, intent.targetPath);
      if (
        preimage === undefined ||
        (intentPaths.some((path) => walPathsOverlap(path, preimage.path)) &&
          ownedDirectory === undefined &&
          !exactDirectoryDescendant &&
          !plannedDirectoryDescendant)
      ) {
        throw new LifecycleProvenanceError(
          'WAL v2 creation intent must not overlap unrelated preimage authority',
        );
      }
    }

    for (const mutation of common.mutations) {
      const mutationPaths =
        mutation.kind === 'ordinary'
          ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
          : [mutation.path, mutation.stagingPath];
      const overlap = intentPaths.some((path) =>
        mutationPaths.some((other) => walPathsOverlap(path, other)),
      );
      const ownedDirectoryAncestor =
        mutation.kind === 'ordinary' &&
        mutation.result.kind === 'directory' &&
        mutation.step < common.cursor &&
        intentPaths.every((path) => walPathIsStrictDescendant(path, mutation.targetPath));
      if (overlap && !ownedDirectoryAncestor) {
        throw new LifecycleProvenanceError(
          'WAL v2 creation intent must not overlap mutation authority',
        );
      }
    }

    for (let previousIndex = 0; previousIndex < index; previousIndex += 1) {
      const previous = intents[previousIndex];
      if (
        previous === undefined ||
        intentPaths.some(
          (path) =>
            walPathsOverlap(path, previous.targetPath) ||
            walPathsOverlap(path, previous.stagingPath),
        )
      ) {
        throw new LifecycleProvenanceError('WAL v2 creation intents must not overlap each other');
      }
    }
  }
}

function walPathIsStrictDescendant(path: string, directory: string): boolean {
  return path.startsWith(`${directory}/`);
}
function walPathsOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
}

function assertStaleReceiptPreimage(preimage: WalPreimageV2, installId: string): void {
  if (preimage.kind !== 'file' || preimage.mode !== 0o600) {
    throw new LifecycleProvenanceError('uninstall WAL v2 receipt preimage must be one exact file');
  }
  const bytes = Buffer.from(preimage.bytes, 'base64');
  try {
    const receipt = parseLifecycleReceiptJsonV1(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    );
    if (receipt.terminalState !== 'uninstalled' || receipt.installId === installId) {
      throw new LifecycleProvenanceError(
        'uninstall WAL v2 receipt preimage must be a different-install uninstalled receipt',
      );
    }
  } finally {
    bytes.fill(0);
  }
}
function assertStaleHostReceiptPreimage(preimage: WalPreimageV2, installId: string): void {
  if (preimage.kind !== 'file' || preimage.mode !== 0o600) {
    throw new LifecycleProvenanceError(
      'host uninstall WAL receipt preimage must be one exact file',
    );
  }
  const bytes = Buffer.from(preimage.bytes, 'base64');
  try {
    const receipt = parseHostLifecycleReceiptJsonV2(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    );
    if (receipt.terminalState !== 'uninstalled' || receipt.installId === installId) {
      throw new LifecycleProvenanceError(
        'host uninstall WAL receipt preimage must be a different-install uninstalled receipt',
      );
    }
  } finally {
    bytes.fill(0);
  }
}

function sameWalIdentity(left: WalFileIdentityV2, right: WalFileIdentityV2): boolean {
  return left.device === right.device && left.inode === right.inode;
}
function exactRecord(value: unknown, keys: readonly string[], name: string): PlainDataObject {
  const record = ordinaryRecord(value, name);
  const ownKeys = Reflect.ownKeys(record);
  if (ownKeys.length !== keys.length || ownKeys.some((key, index) => key !== keys[index])) {
    throw new LifecycleProvenanceError(`${name} must have exact canonical own keys`);
  }
  return record;
}

function ordinaryRecord(value: unknown, name: string): PlainDataObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LifecycleProvenanceError(`${name} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new LifecycleProvenanceError(`${name} must be an ordinary object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      throw new LifecycleProvenanceError(`${name} must have enumerable data own properties`);
    }
  }
  return value as PlainDataObject;
}

function parseCanonicalJson<T>(
  value: unknown,
  name: string,
  parse: (parsed: unknown) => T,
  serialize: (parsed: T) => string,
  maxBytes: number = MAX_PROVENANCE_BYTES,
): T {
  if (typeof value !== 'string') {
    throw new LifecycleProvenanceError(`${name} JSON must be a string`);
  }
  if (new TextEncoder().encode(value).byteLength > maxBytes) {
    throw new LifecycleProvenanceError(`${name} JSON exceeds its byte limit`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new LifecycleProvenanceError(`${name} JSON must be valid JSON`);
  }
  const result = parse(parsed);
  if (serialize(result) !== value) {
    throw new LifecycleProvenanceError(
      `${name} JSON must use canonical two-space LF serialization`,
    );
  }
  return result;
}

function serializeCanonical(value: object): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function parseId(value: unknown, name: string): string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new LifecycleProvenanceError(`${name} must be a bounded canonical identifier`);
  }
  return value;
}

function parseFingerprint(value: unknown, name: string): string {
  if (typeof value !== 'string' || !FINGERPRINT_PATTERN.test(value)) {
    throw new LifecycleProvenanceError(`${name} must be a sha256 content fingerprint`);
  }
  return value;
}

function parseSubject(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 128 ||
    !ID_PATTERN.test(value)
  ) {
    throw new LifecycleProvenanceError('hunk subject must be a bounded identifier');
  }
  return value;
}

function parseCanonicalAbsolutePath(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_WAL_PATH_BYTES ||
    value.includes('\u0000') ||
    !isAbsolute(value) ||
    value === '/' ||
    value.endsWith('/') ||
    normalize(value) !== value
  ) {
    throw new LifecycleProvenanceError('owned path must be a canonical absolute normalized path');
  }
  return value;
}

function parseOwnedPath(value: unknown): string {
  const path = parseCanonicalAbsolutePath(value);
  if (
    path.endsWith('/.scene-glass') ||
    path.endsWith('/.scg/annotations') ||
    path.includes('/.scg/annotations/')
  ) {
    throw new LifecycleProvenanceError('checkout and annotation roots are never lifecycle-owned');
  }
  return path;
}
function parseHostStateRoot(value: unknown, hostRoot: string): string {
  const stateRoot = parseCanonicalAbsolutePath(value);
  if (stateRoot !== `${hostRoot}/.scg/onboarding`) {
    throw new LifecycleProvenanceError('host stateRoot must be <host>/.scg/onboarding');
  }
  return stateRoot;
}

function hostWalRecordV3Keys(record: PlainDataObject): readonly string[] {
  const base = walRecordV2Keys(record.operation as 'setup' | 'uninstall', record);
  return Object.freeze([
    ...base,
    'hostRoot',
    'stateRoot',
    ...(hasOwn(record, 'compactViteAuthority') ? ['compactViteAuthority'] : []),
    ...(hasOwn(record, 'fullCommitmentBinding') ? ['fullCommitmentBinding'] : []),
  ]);
}

function hostWalV3AsV2Record(record: PlainDataObject): PlainDataObject {
  const base: { [key: string]: unknown } = {
    schemaVersion: 2,
    kind: 'scene-glass-lifecycle-wal',
    operationId: record.operationId,
    installId: record.installId,
    operation: record.operation,
    direction: record.direction,
    phase: record.phase,
    lockPath: record.lockPath,
    manifestPath: record.manifestPath,
    cursor: record.cursor,
    preimages: record.preimages,
    mutations: record.mutations,
  };
  if (hasOwn(record, 'creationIntents')) base.creationIntents = record.creationIntents;
  base.authorityFingerprint = record.authorityFingerprint;
  if (hasOwn(record, 'replacedWalStage')) base.replacedWalStage = record.replacedWalStage;
  return base;
}

function parseCompactViteAuthorityV3(
  value: unknown,
  hostRoot: string,
  installId: string,
): ViteSnapshotAuthority {
  const expectedSyntheticRoot = `${hostRoot}/${VITE_SNAPSHOT_ROOT_DIRECTORY}/${installId}`;
  let serialized: string;
  try {
    serialized = serializeViteSnapshotAuthorityJson(value as ViteSnapshotAuthority);
  } catch {
    throw new LifecycleProvenanceError('compact Vite authority must use the canonical transport');
  }
  try {
    return parseViteSnapshotAuthorityJson(serialized, expectedSyntheticRoot);
  } catch {
    throw new LifecycleProvenanceError(
      'compact Vite authority must bind the current synthetic root',
    );
  }
}

function parseFullCommitmentBindingV3(
  value: unknown,
  hostRoot: string,
  installId: string,
): FullCommitmentBindingV3 {
  const record = exactRecord(
    value,
    ['path', 'identity', 'mode', 'linkCount', 'byteLength', 'sha256'],
    'full commitment binding',
  );
  const expectedPath = `${hostRoot}/${VITE_SNAPSHOT_COMMITMENT_DIRECTORY}/${installId}.json`;
  const byteLength = record.byteLength;
  if (
    record.path !== expectedPath ||
    record.mode !== 0o600 ||
    record.linkCount !== 1 ||
    typeof byteLength !== 'number' ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0 ||
    byteLength > VITE_SNAPSHOT_COMMITMENT_MAX_BYTES
  ) {
    throw new LifecycleProvenanceError(
      'full commitment binding must use the canonical commitment role',
    );
  }
  return Object.freeze({
    path: expectedPath,
    identity: parseWalFileIdentity(record.identity, 'full commitment binding identity'),
    mode: 0o600,
    linkCount: 1,
    byteLength,
    sha256: parseFingerprint(record.sha256, 'full commitment binding sha256'),
  });
}

function assertHostLifecycleWalTargets(
  record: WalRecordV2 | HostWalRecordV3,
  context: HostLifecycleContextV3,
): void {
  const stateRoot = `${context.hostRoot}/.scg/onboarding`;
  const lockPath = `${context.homeDir}/.scg/onboarding/lifecycle.lock`;
  if (record.lockPath !== lockPath || record.manifestPath !== `${stateRoot}/manifest.v2.json`) {
    throw new LifecycleProvenanceError(
      'host WAL lock and manifest paths must use their current roles',
    );
  }
  if (record.operation === 'uninstall' && record.receiptPath !== `${stateRoot}/receipt.v2.json`) {
    throw new LifecycleProvenanceError('host WAL receipt path must use its current role');
  }
  for (const path of lifecycleRecordPaths(record)) {
    assertLifecycleTarget(path, context);
  }
}

function assertLegacyLifecycleWalTargets(
  record: WalRecordV2,
  context: HostLifecycleContextV3,
): void {
  const stateRoot = `${context.checkoutRoot}/.scene-glass/onboarding`;
  if (
    record.lockPath !== `${context.homeDir}/.scene-glass-onboarding.lock` ||
    record.manifestPath !== `${stateRoot}/manifest.v1.json` ||
    (record.operation === 'uninstall' && record.receiptPath !== `${stateRoot}/receipt.v1.json`)
  ) {
    throw new LifecycleProvenanceError('legacy WAL paths must use deployed lifecycle roles');
  }
  for (const path of lifecycleRecordPaths(record)) assertLifecycleTarget(path, context);
}

function translateLegacyRecordToHostV3(
  record: WalRecordV2,
  context: HostLifecycleContextV3,
): MigratedHostWalRecordV3 {
  const stateRoot = `${context.hostRoot}/.scg/onboarding`;
  return Object.freeze({
    schemaVersion: 3 as const,
    kind: 'scene-glass-host-lifecycle-wal' as const,
    operation: 'migration' as const,
    phase: 'source-bound' as const,
    sourceOperation: record.operation,
    direction: record.direction,
    operationId: record.operationId,
    installId: record.installId,
    lockPath: `${context.homeDir}/.scg/onboarding/lifecycle.lock`,
    manifestPath: `${stateRoot}/manifest.v2.json`,
    hostRoot: context.hostRoot,
    stateRoot,
    cursor: record.cursor,
    preimages: record.preimages,
    mutations: record.mutations,
    ...(record.creationIntents === undefined ? {} : { creationIntents: record.creationIntents }),
    authorityFingerprint: record.authorityFingerprint,
    ...(record.replacedWalStage === undefined ? {} : { replacedWalStage: record.replacedWalStage }),
    ...(record.operation === 'uninstall'
      ? {
          receiptPath: `${stateRoot}/receipt.v2.json`,
          manifest: Object.freeze({
            schemaVersion: 2 as const,
            kind: 'scene-glass-host-setup-manifest' as const,
            installId: record.manifest.installId,
            state: 'active' as const,
            hostRoot: context.hostRoot,
            stateRoot,
            artifacts: record.manifest.artifacts,
          }),
        }
      : {}),
  });
}
function lifecycleRecordPaths(record: WalRecordV2 | HostWalRecordV3): readonly string[] {
  const paths = [record.lockPath, record.manifestPath];
  for (const preimage of record.preimages) paths.push(preimage.path);
  for (const mutation of record.mutations) {
    if (mutation.kind === 'ordinary') {
      paths.push(mutation.targetPath, mutation.sourcePath, mutation.stagingPath);
    } else {
      paths.push(mutation.path, mutation.stagingPath);
    }
  }
  for (const intent of record.creationIntents ?? [])
    paths.push(intent.targetPath, intent.stagingPath);
  if (record.operation === 'uninstall') {
    paths.push(record.receiptPath);
    for (const artifact of record.manifest.artifacts) paths.push(artifact.path);
  }
  return paths;
}

export function assertLifecycleTarget(value: unknown, context?: HostLifecycleContextV3): string {
  const path = parseCanonicalAbsolutePath(value);
  if (
    path.endsWith('/.scg/annotations') ||
    path.includes('/.scg/annotations/') ||
    path.endsWith('/.scg') ||
    path.endsWith('/.scg/onboarding')
  ) {
    throw new LifecycleProvenanceError(
      'annotation and host lifecycle roots are never lifecycle targets',
    );
  }
  if (context !== undefined) {
    const allowedRoots = [
      context.hostRoot,
      context.checkoutRoot,
      context.homeDir,
      context.selectedConfigDir,
    ];
    if (!allowedRoots.some((root) => path === root || path.startsWith(`${root}/`))) {
      throw new LifecycleProvenanceError('lifecycle target is outside its current host role');
    }
    const annotationRoot = `${context.hostRoot}/.scg/annotations`;
    if (
      path === annotationRoot ||
      annotationRoot.startsWith(`${path}/`) ||
      path.startsWith(`${annotationRoot}/`)
    ) {
      throw new LifecycleProvenanceError('annotation ancestry is never lifecycle-owned');
    }
  }
  return path;
}

function parseHostLifecycleContextV3(value: HostLifecycleContextV3): HostLifecycleContextV3 {
  const hostRoot = parseCanonicalAbsolutePath(value.hostRoot);
  const checkoutRoot = parseCanonicalAbsolutePath(value.checkoutRoot);
  const homeDir = parseCanonicalAbsolutePath(value.homeDir);
  const selectedConfigDir = parseCanonicalAbsolutePath(value.selectedConfigDir);
  return Object.freeze({
    hostRoot,
    checkoutRoot,
    homeDir,
    selectedConfigDir,
    installId: parseId(value.installId, 'installId'),
  });
}

function parseV2ToV3AuthorityMap(
  value: V2ToV3AuthorityMap,
  record: WalRecordV2,
): V2ToV3AuthorityMap {
  assertDenseAuthorityMapArray(value.entries, 'V2-to-V3 authority map entries');
  assertDenseAuthorityMapArray(
    value.cursorTransitions,
    'V2-to-V3 authority map cursor transitions',
  );
  const expected = expectedV2AuthorityKeys(record);
  const source = new Set<string>();
  const destination = new Set<string>();
  const entries = value.entries.map((entry, index) => {
    const candidate = exactRecord(
      entry,
      ['sourceKind', 'sourceIndex', 'destinationKind', 'destinationIndex'],
      `V2-to-V3 authority map entry ${index}`,
    );
    const sourceIndex = candidate.sourceIndex;
    const destinationIndex = candidate.destinationIndex;
    if (
      !isV2AuthoritySourceKind(candidate.sourceKind) ||
      !isV2AuthoritySourceKind(candidate.destinationKind) ||
      typeof sourceIndex !== 'number' ||
      typeof destinationIndex !== 'number' ||
      !Number.isSafeInteger(sourceIndex) ||
      !Number.isSafeInteger(destinationIndex) ||
      sourceIndex < 0 ||
      destinationIndex < 0
    ) {
      throw new LifecycleProvenanceError('V2-to-V3 authority map entry is invalid');
    }
    if (candidate.sourceKind !== candidate.destinationKind || sourceIndex !== destinationIndex) {
      throw new LifecycleProvenanceError(
        'V2-to-V3 authority map must preserve deterministic authority identity',
      );
    }
    const sourceKey = authorityMapKey(candidate.sourceKind, sourceIndex);
    const destinationKey = authorityMapKey(candidate.destinationKind, destinationIndex);
    if (
      !expected.has(sourceKey) ||
      !expected.has(destinationKey) ||
      source.has(sourceKey) ||
      destination.has(destinationKey)
    ) {
      throw new LifecycleProvenanceError(
        'V2-to-V3 authority map contains duplicate or foreign authority',
      );
    }
    source.add(sourceKey);
    destination.add(destinationKey);
    return Object.freeze({
      sourceKind: candidate.sourceKind,
      sourceIndex,
      destinationKind: candidate.destinationKind,
      destinationIndex,
    });
  });
  if ([...expected].some((key) => !source.has(key) || !destination.has(key))) {
    throw new LifecycleProvenanceError(
      'V2-to-V3 authority map must cover every source and destination authority exactly once',
    );
  }
  const transitions = value.cursorTransitions.map((transition, index) => {
    const candidate = exactRecord(
      transition,
      ['sourceMutationIndex', 'destinationMutationIndex'],
      `V2-to-V3 cursor transition ${index}`,
    );
    const sourceMutationIndex = candidate.sourceMutationIndex;
    const destinationMutationIndex = candidate.destinationMutationIndex;
    if (
      typeof sourceMutationIndex !== 'number' ||
      typeof destinationMutationIndex !== 'number' ||
      !Number.isSafeInteger(sourceMutationIndex) ||
      !Number.isSafeInteger(destinationMutationIndex) ||
      sourceMutationIndex < 0 ||
      destinationMutationIndex < 0 ||
      sourceMutationIndex >= record.cursor ||
      destinationMutationIndex >= record.cursor
    ) {
      throw new LifecycleProvenanceError(
        'V2-to-V3 cursor transition must bind a completed source mutation',
      );
    }
    if (sourceMutationIndex !== destinationMutationIndex) {
      throw new LifecycleProvenanceError(
        'V2-to-V3 cursor transitions must preserve deterministic mutation identity',
      );
    }
    return Object.freeze({ sourceMutationIndex, destinationMutationIndex });
  });
  if (
    transitions.length !== record.cursor ||
    new Set(transitions.map((transition) => transition.sourceMutationIndex)).size !==
      transitions.length ||
    new Set(transitions.map((transition) => transition.destinationMutationIndex)).size !==
      transitions.length
  ) {
    throw new LifecycleProvenanceError(
      'V2-to-V3 cursor transitions must cover every completed source mutation exactly once',
    );
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    cursorTransitions: Object.freeze(transitions),
  });
}

function assertDenseAuthorityMapArray(value: unknown, name: string): void {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    !hasOnlyArrayIndexKeys(value)
  ) {
    throw new LifecycleProvenanceError(`${name} must be a plain array without extra properties`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) {
      throw new LifecycleProvenanceError(`${name} must not be sparse`);
    }
    if (!descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      throw new LifecycleProvenanceError(`${name} must be a dense array of enumerable data values`);
    }
  }
}

function expectedV2AuthorityKeys(record: WalRecordV2): Set<string> {
  const keys = new Set<string>();
  const add = (kind: V2AuthoritySourceKind, length: number): void => {
    for (let index = 0; index < length; index += 1) keys.add(authorityMapKey(kind, index));
  };
  add('preimage', record.preimages.length);
  add('mutation', record.mutations.length);
  add('creation-intent', record.creationIntents?.length ?? 0);
  if (record.replacedWalStage !== undefined) add('replaced-wal-stage', 1);
  if (record.operation === 'uninstall') {
    add('manifest-artifact', record.manifest.artifacts.length);
    add('manifest-inverse', record.manifest.artifacts.length);
  }
  return keys;
}

function authorityMapKey(kind: V2AuthoritySourceKind, index: number): string {
  return `${kind}:${index}`;
}

function isV2AuthoritySourceKind(value: unknown): value is V2AuthoritySourceKind {
  return (
    value === 'preimage' ||
    value === 'mutation' ||
    value === 'creation-intent' ||
    value === 'replaced-wal-stage' ||
    value === 'manifest-artifact' ||
    value === 'manifest-inverse'
  );
}

function parseLegacyWalV2SourceFileFacts(
  value: LegacyWalV2SourceFileFacts,
  context: HostLifecycleContextV3,
): LegacyWalV2SourceFileFacts {
  const path = parseCanonicalAbsolutePath(value.path);
  if (path !== `${context.checkoutRoot}/.scene-glass/onboarding/lifecycle.wal.v1.json`) {
    throw new LifecycleProvenanceError(
      'legacy WAL source path must use the deployed checkout role',
    );
  }
  if (
    typeof value.owner !== 'string' ||
    value.owner.length === 0 ||
    !Number.isSafeInteger(value.byteLength) ||
    value.byteLength < 0 ||
    typeof value.parserVersion !== 'string' ||
    value.parserVersion.length === 0
  ) {
    throw new LifecycleProvenanceError('legacy WAL source facts are invalid');
  }
  return Object.freeze({
    path,
    identity: parseWalFileIdentity(value.identity, 'legacy WAL source identity'),
    owner: value.owner,
    mode: parseWalMode(value.mode, 'legacy WAL source mode'),
    byteLength: value.byteLength,
    sha256: parseFingerprint(value.sha256, 'legacy WAL source sha256'),
    parserVersion: value.parserVersion,
    authorityFingerprint: parseFingerprint(
      value.authorityFingerprint,
      'legacy WAL authority fingerprint',
    ),
    authorityMap: value.authorityMap,
  });
}

function sameProject(left: ProjectConfigV1, right: ProjectConfigV1): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameImage(left: SemanticConfigImage, right: SemanticConfigImage): boolean {
  if (left.projects.length !== right.projects.length) {
    return false;
  }
  return left.projects.every((project, index) => {
    const other = right.projects[index];
    return other !== undefined && sameProject(project, other);
  });
}
function sameCredentialAuthorityRegistryImage(
  left: SemanticCredentialAuthorityRegistryImage,
  right: SemanticCredentialAuthorityRegistryImage,
): boolean {
  if (left.projects.length !== right.projects.length) {
    return false;
  }
  return left.projects.every((entry, index) => {
    const other = right.projects[index];
    return other !== undefined && sameRegistryEntry(entry, other);
  });
}

function assertSelectedCredentialAuthorityRegistryTransition(
  preimage: SemanticCredentialAuthorityRegistryImage,
  postimage: SemanticCredentialAuthorityRegistryImage,
): void {
  selectedCredentialAuthorityRegistryProjectId(preimage, postimage);
}

function selectedCredentialAuthorityRegistryProjectId(
  preimage: SemanticCredentialAuthorityRegistryImage,
  postimage: SemanticCredentialAuthorityRegistryImage,
): string {
  if (preimage.projects.length > 1 || postimage.projects.length > 1) {
    throw new LifecycleProvenanceError(
      'semantic credential authority registry images must contain at most one entry',
    );
  }
  const preimageEntry = preimage.projects[0];
  const postimageEntry = postimage.projects[0];
  const selected = preimageEntry ?? postimageEntry;
  if (
    selected === undefined ||
    (preimageEntry !== undefined &&
      postimageEntry !== undefined &&
      preimageEntry.projectId !== postimageEntry.projectId)
  ) {
    throw new LifecycleProvenanceError(
      'semantic credential authority registry images must describe one selected project',
    );
  }
  return selected.projectId;
}

function sameRegistryEntry(
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

function sameHunks(left: readonly OwnedHunk[], right: readonly OwnedHunk[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((hunk, index) => {
    const other = right[index];
    return (
      other !== undefined &&
      hunk.id === other.id &&
      hunk.fingerprint === other.fingerprint &&
      hunk.operation === other.operation &&
      hunk.subject === other.subject
    );
  });
}
function isSupportedOwnedFileRestore(inverse: RestoreOwnedFileInverseOperation): boolean {
  const [hunk] = inverse.hunks;
  return (
    inverse.preimageFingerprint !== inverse.postimageFingerprint &&
    inverse.hunks.length === 1 &&
    hunk !== undefined &&
    hunk.operation === 'insert' &&
    (hunk.subject === 'scg-html-loader' ||
      hunk.subject === 'scg-vue3-loader' ||
      hunk.subject === 'scg-react-loader') &&
    hunk.fingerprint === inverse.postimageFingerprint
  );
}

function issue(
  code: OwnedArtifactIssueCode,
  path: string,
  hunkId: string | undefined = undefined,
): OwnedArtifactIssue {
  return Object.freeze({ code, path, hunkId });
}

function freezePreflight(issues: readonly UninstallPreflightIssue[]): UninstallPreflight {
  return Object.freeze({
    canUninstall: false,
    writes: Object.freeze([]) as readonly [],
    inverse: Object.freeze([]),
    issues: Object.freeze([...issues]),
  });
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}
