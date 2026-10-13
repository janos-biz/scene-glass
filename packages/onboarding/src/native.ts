import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import type { CredentialAuthority, FileIdentity } from './types.js';
import {
  VITE_CACHE_DIRECTORY_MODE,
  VITE_CACHE_MAX_BYTES,
  VITE_CACHE_MAX_DEPTH,
  VITE_CACHE_MAX_ENTRIES,
  VITE_CACHE_MAX_FILES,
  VITE_CACHE_ROOT_DIRECTORY,
  type CacheNativeSession,
  type CacheRuntimeFilesystemPort,
  type CacheRootRecord,
  type CacheTreeEntry,
  type CacheTreeScan,
  type CacheTreeWatcher,
  type ViteCacheLimits,
  type ViteCacheProvenance,
} from './vite/cache.js';
import type { CacheCanaryScanResult, CacheCanaryScannerPort } from './vite/cache-monitor.js';

export const NATIVE_UNAVAILABLE_CODE = 'SCG_NATIVE_UNAVAILABLE' as const;
export const NATIVE_FAILURE_CODE = 'SCG_NATIVE_FAILURE' as const;

export type OnboardingNativeErrorCode =
  | typeof NATIVE_UNAVAILABLE_CODE
  | typeof NATIVE_FAILURE_CODE
  | 'SCG_NATIVE_PATH_DENIED'
  | 'SCG_NATIVE_IDENTITY_MISMATCH'
  | 'SCG_NATIVE_READ_LIMIT'
  | 'SCG_CREDENTIAL_AUTHORITY_INVALID';

export const MAX_NATIVE_READ_BYTES = 16 * 1024 * 1024;
export const MAX_NATIVE_LIFECYCLE_WRITE_BYTES = 32 * 1024 * 1024;
const MAX_NATIVE_PATH_BYTES = 4 * 1024;
const MAX_NATIVE_PATH_COMPONENTS = 256;
const MAX_NATIVE_PATH_COMPONENT_BYTES = 255;
const MAX_NATIVE_IDENTITY_DECIMAL_BYTES = 20;
const MAX_NATIVE_IDENTITY_DECIMAL_VALUE = '18446744073709551615';
const MAX_DENIED_IDENTITIES = 1_024;
export const MAX_CREDENTIAL_AUTHORITIES = 64;
export const MAX_ACTIVE_VITE_SNAPSHOT_SESSIONS = 8;
export const MAX_ACTIVE_VITE_SNAPSHOT_STAGINGS = 64;
export const MAX_ACTIVE_VITE_SNAPSHOT_PUBLISHED = 64;
export const MAX_ACTIVE_VITE_CACHE_SESSIONS = 8;
export const MAX_ACTIVE_VITE_RECOVERY_DIRECTORY_SESSIONS = 16;
export const MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES = 8;
export const MAX_ACTIVE_LIFECYCLE_LOCKS = 16;
export const MAX_ACTIVE_LIFECYCLE_RESERVATIONS = 64;
export const MAX_ACTIVE_LIFECYCLE_QUARANTINES = 64;
const MAX_ACTIVE_CREDENTIAL_CAPABILITIES = 64;
const MAX_CREDENTIAL_PROJECT_ID_BYTES = 128;
const DECIMAL_IDENTITY_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_NATIVE_VITE_SNAPSHOT_BYTES = 64 * 1024 * 1024;
const MAX_NATIVE_VITE_SNAPSHOT_DEPTH = 8;
const MAX_NATIVE_VITE_SNAPSHOT_COMMITMENT_BYTES = 1024 * 1024;
const nativeRequire = createRequire(import.meta.url);
const typedArrayFill = Uint8Array.prototype.fill;
const stringSlice = String.prototype.slice;
const reflectApply = Reflect.apply;
const isBuffer = Buffer.isBuffer;
const credentialCapabilities = new WeakMap<CredentialReadCapability, CredentialCapabilityState>();
const activeCredentialCapabilities = new Set<CredentialReadCapability>();
const capabilitiesByAuthorityKey = new Map<string, Set<CredentialReadCapability>>();
const nativeLifecycleLocks = new WeakSet<NativeLifecycleLock>();
const nativeLifecycleCreationIntents = new WeakSet<NativeLifecycleCreationIntent>();
const nativeLifecycleStagedFileReservations = new WeakSet<NativeLifecycleStagedFileReservation>();
const nativeLifecycleStagedDirectoryReservations =
  new WeakSet<NativeLifecycleStagedDirectoryReservation>();
type NativeLifecycleHandleKind = 'lock' | 'reservation' | 'quarantine';
interface NativeLifecycleHandleState {
  readonly kind: NativeLifecycleHandleKind;
  released: boolean;
}
const nativeLifecycleHandleStates = new WeakMap<object, NativeLifecycleHandleState>();
let activeNativeLifecycleLocks = 0;
let activeNativeLifecycleReservations = 0;
let activeNativeLifecycleQuarantines = 0;
const nativeLifecycleHandleFinalizer = new FinalizationRegistry<NativeLifecycleHandleState>(
  (state) => {
    releaseNativeLifecycleHandleState(state);
  },
);
function registerNativeLifecycleHandle(value: object, kind: NativeLifecycleHandleKind): void {
  if (nativeLifecycleHandleStates.has(value)) {
    return;
  }
  if (
    (kind === 'lock' && activeNativeLifecycleLocks >= MAX_ACTIVE_LIFECYCLE_LOCKS) ||
    (kind === 'reservation' &&
      activeNativeLifecycleReservations >= MAX_ACTIVE_LIFECYCLE_RESERVATIONS) ||
    (kind === 'quarantine' && activeNativeLifecycleQuarantines >= MAX_ACTIVE_LIFECYCLE_QUARANTINES)
  ) {
    throw nativeFailure();
  }
  const state: NativeLifecycleHandleState = { kind, released: false };
  nativeLifecycleHandleStates.set(value, state);
  nativeLifecycleHandleFinalizer.register(value, state, state);
  if (kind === 'lock') {
    activeNativeLifecycleLocks += 1;
  } else if (kind === 'reservation') {
    activeNativeLifecycleReservations += 1;
  } else {
    activeNativeLifecycleQuarantines += 1;
  }
}
function releaseNativeLifecycleHandle(value: object): void {
  const state = nativeLifecycleHandleStates.get(value);
  if (state === undefined) {
    return;
  }
  nativeLifecycleHandleFinalizer.unregister(state);
  releaseNativeLifecycleHandleState(state);
}
function releaseNativeLifecycleHandleState(state: NativeLifecycleHandleState): void {
  if (state.released) {
    return;
  }
  state.released = true;
  if (state.kind === 'lock') {
    activeNativeLifecycleLocks -= 1;
  } else if (state.kind === 'reservation') {
    activeNativeLifecycleReservations -= 1;
  } else {
    activeNativeLifecycleQuarantines -= 1;
  }
}

declare const credentialReadCapabilityBrand: unique symbol;
declare const nativeViteSnapshotSessionBrand: unique symbol;
declare const nativeViteSnapshotStagingBrand: unique symbol;
declare const nativeViteSnapshotPublishedBrand: unique symbol;
declare const nativeViteRecoveryDirectorySessionBrand: unique symbol;
declare const nativeLifecycleQuarantineBrand: unique symbol;
declare const nativeLifecycleLockBrand: unique symbol;
declare const nativeLifecycleStagedFileReservationBrand: unique symbol;
declare const nativeLifecycleStagedDirectoryReservationBrand: unique symbol;
declare const nativeLifecycleCreationIntentBrand: unique symbol;

export class OnboardingNativeError extends Error {
  public readonly code: OnboardingNativeErrorCode;
  public readonly cause?: unknown;

  public constructor(code: OnboardingNativeErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'OnboardingNativeError';
    this.code = code;
    if (cause !== undefined) {
      Object.defineProperty(this, 'cause', {
        configurable: true,
        enumerable: false,
        value: cause,
      });
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface SecureReadBeneathOptions {
  readonly root: string;
  readonly expectedRoot: FileIdentity;
  readonly relativePath: string;
  readonly deniedIdentities: readonly FileIdentity[];
  readonly maxBytes: number;
}

export interface SecureReadResult {
  readonly bytes: Buffer;
  readonly identity: FileIdentity;
  readonly linkCount: number;
  readonly mode: number;
}

export interface CredentialReadOptions {
  readonly expectedOwnerUid: number;
  readonly maxBytes: number;
}

export interface CredentialReadCapability {
  readonly [credentialReadCapabilityBrand]: never;
}

export interface NativeViteSnapshotSession {
  readonly [nativeViteSnapshotSessionBrand]: never;
}

export interface NativeViteSnapshotStaging {
  readonly [nativeViteSnapshotStagingBrand]: never;
}

export interface NativeViteSnapshotPublished {
  readonly [nativeViteSnapshotPublishedBrand]: never;
}
export interface NativeViteRecoveryDirectorySession {
  readonly [nativeViteRecoveryDirectorySessionBrand]: never;
}
export interface ManagedViteChildLaunchAuthority {
  release(): Promise<void>;
}

export interface NativeViteRecoveryDirectoryPort {
  openDirectory(input: {
    readonly projectRoot: string;
    readonly expectedProjectRootIdentity: FileIdentity;
    readonly stateRoot: string;
    readonly expectedStateRootIdentity: FileIdentity;
    readonly expectedOwnerUid: number;
  }): NativeViteRecoveryDirectorySession;
  tryLock(input: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly lockName: string;
  }): boolean;
  createChildAuthority(input: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly launchId: string;
  }): { readonly fd: number; readonly launchId: string };
  closeChildAuthority(input: { readonly fd: number }): void;
  readManifest(input: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly manifestName: string;
  }): Buffer | undefined;
  replaceManifest(input: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly manifestName: string;
    readonly temporaryName: string;
    readonly bytes: Buffer;
  }): void;
  closeDirectory(input: { readonly session: NativeViteRecoveryDirectorySession }): void;
}

export interface NativeViteSnapshotPublicationPort {
  openSession(input: {
    readonly projectRoot: string;
    readonly approvedRootIdentity: FileIdentity;
    readonly expectedOwnerUid: number;
  }): NativeViteSnapshotSession;
  createStaging(input: {
    readonly session: NativeViteSnapshotSession;
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
    readonly stagingName: string;
  }): NativeViteSnapshotStaging;
  writeStagingFile(input: {
    readonly staging: NativeViteSnapshotStaging;
    readonly relativePath: string;
    readonly bytes: Uint8Array;
    readonly mode: number;
  }): void;
  publishStaging(input: {
    readonly staging: NativeViteSnapshotStaging;
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
  }): { readonly published: NativeViteSnapshotPublished; readonly rootIdentity: FileIdentity };
  persistCommitment(input: {
    readonly published: NativeViteSnapshotPublished;
    readonly installId: string;
    readonly bytes: Uint8Array;
  }): void;
  discardStaging(input: { readonly staging: NativeViteSnapshotStaging }): void;
  removePublished(input: { readonly published: NativeViteSnapshotPublished }): void;
  closeSession(input: { readonly session: NativeViteSnapshotSession }): void;
}

interface NativeSecureReadBeneathOptions {
  readonly root: string;
  readonly expectedRoot: FileIdentity | null;
  readonly relativePath: string;
  readonly expectedAuthority: FileIdentity | null;
  readonly deniedIdentities: readonly FileIdentity[];
  readonly maxBytes: number;
  readonly readContent: boolean;
}
export type NativeLifecycleMutationState = 'completed' | 'indeterminate';

export interface NativeLifecycleMutationResult {
  readonly state: NativeLifecycleMutationState;
  readonly targetIdentity?: FileIdentity;
  readonly quarantineIdentity?: FileIdentity;
}

export interface NativeLifecycleLock {
  readonly [nativeLifecycleLockBrand]: never;
}

export interface NativeLifecycleQuarantine {
  readonly [nativeLifecycleQuarantineBrand]: never;
}

export interface NativeLifecycleCreationIntent {
  readonly [nativeLifecycleCreationIntentBrand]: never;
}
export interface NativeLifecycleCreationIntentResult {
  readonly state: NativeLifecycleMutationState;
  readonly intent: NativeLifecycleCreationIntent;
}
export interface NativeLifecycleStagedFileReservation {
  readonly [nativeLifecycleStagedFileReservationBrand]: never;
}

export interface NativeLifecycleStagedDirectoryReservation {
  readonly [nativeLifecycleStagedDirectoryReservationBrand]: never;
}

export interface NativeLifecycleQuarantineResult extends NativeLifecycleMutationResult {
  readonly quarantine?: NativeLifecycleQuarantine;
}

export interface NativeLifecycleCreateResult {
  readonly state: 'completed' | 'indeterminate';
  readonly identity: FileIdentity;
}

export interface NativeLifecycleStagedFileReservationCreateResult extends NativeLifecycleCreateResult {
  readonly reservation: NativeLifecycleStagedFileReservation;
}

export interface NativeLifecycleStagedDirectoryReservationCreateResult extends NativeLifecycleCreateResult {
  readonly reservation: NativeLifecycleStagedDirectoryReservation;
}

export type NativeLifecycleWalReadResult =
  | Readonly<{
      state: 'completed';
      bytes: Buffer;
      identity: FileIdentity;
      size: number;
      digest: string;
      stat: string;
    }>
  | Readonly<{ state: 'indeterminate' }>;
interface SecureReadBinding {
  readonly secureReadBeneath: (options: NativeSecureReadBeneathOptions) => unknown;
}

interface LifecycleNativeBinding extends SecureReadBinding {
  readonly acquireLifecycleLock: (options: { readonly path: string }) => unknown;
  readonly releaseLifecycleLock: (options: { readonly lock: NativeLifecycleLock }) => unknown;
  readonly releaseLifecycleLockSession: (options: {
    readonly lock: NativeLifecycleLock;
  }) => unknown;
  readonly revalidateLifecycleLock: (options: { readonly lock: NativeLifecycleLock }) => unknown;
  readonly validateExactCredential: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleExactFile;
  }) => unknown;
  readonly validateExactDirectory: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleExactFile;
  }) => unknown;
  readonly readExactLifecycleWal: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleExactFile;
  }) => unknown;
  readonly prepareLifecycleCreationIntent: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly markerPath: string;
    readonly kind: 'credential' | 'file' | 'directory';
    readonly parentDirectoryReservation?: NativeLifecycleStagedDirectoryReservation;
  }) => unknown;
  readonly recoverLifecycleCreationIntent: (options: {
    readonly lock: NativeLifecycleLock;
    readonly stagePath: string;
    readonly markerPath: string;
    readonly kind: 'credential' | 'file' | 'directory';
    readonly mode: number;
  }) => unknown;
  readonly reserveCredentialFromIntent: (options: {
    readonly lock: NativeLifecycleLock;
    readonly intent: NativeLifecycleCreationIntent;
    readonly mode: number;
  }) => unknown;
  readonly reserveLifecycleFileFromIntent: (options: {
    readonly lock: NativeLifecycleLock;
    readonly intent: NativeLifecycleCreationIntent;
    readonly mode: number;
  }) => unknown;
  readonly reserveDirectoryFromIntent: (options: {
    readonly lock: NativeLifecycleLock;
    readonly intent: NativeLifecycleCreationIntent;
    readonly mode: number;
  }) => unknown;
  readonly retainReservationForRecovery: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation:
      NativeLifecycleStagedFileReservation | NativeLifecycleStagedDirectoryReservation;
  }) => unknown;
  readonly createLifecycleStagedFile: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly mode: number;
    readonly bytes: Buffer;
  }) => unknown;
  readonly reserveLifecycleStagedFile: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly mode: number;
  }) => unknown;
  readonly writeLifecycleStagedFile: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
    readonly expectedSize: number;
    readonly bytes: Buffer;
  }) => unknown;
  readonly validateLifecycleStagedFileReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
  }) => unknown;
  readonly syncLifecycleStagedFileReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
  }) => unknown;
  readonly publishReservedLifecycleStagedFileNoReplace: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
    readonly targetPath: string;
  }) => unknown;
  readonly closeLifecycleStagedFileReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
  }) => unknown;
  readonly discardLifecycleStagedFileReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
  }) => unknown;
  readonly publishLifecycleStagedFileNoReplace: (options: {
    readonly lock: NativeLifecycleLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
  }) => unknown;
  readonly replaceLifecycleStagedFileExact: (options: {
    readonly lock: NativeLifecycleLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
    readonly targetIdentity: FileIdentity;
    readonly targetMode: number;
    readonly targetSize?: number;
    readonly targetDigest?: string;
  }) => unknown;
  readonly replaceReservedLifecycleFileExact: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
    readonly targetPath: string;
    readonly targetIdentity: FileIdentity;
    readonly targetMode: number;
    readonly targetSize: number;
    readonly targetDigest: string;
    readonly targetStat: string;
    readonly discardReplacedTarget: boolean;
  }) => unknown;
  readonly replaceReservedLifecycleOrdinaryFileExact: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedFileReservation;
    readonly targetPath: string;
    readonly targetIdentity: FileIdentity;
    readonly targetMode: number;
    readonly targetSize: number;
    readonly targetDigest: string;
  }) => unknown;
  readonly quarantineLifecycleExactFile: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly quarantinePath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
    readonly expectedSize?: number;
    readonly expectedDigest?: string;
  }) => unknown;
  readonly quarantineLifecycleExactCredential: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly quarantinePath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
  }) => unknown;
  readonly createLifecycleStagedDirectory: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly mode: number;
  }) => unknown;
  readonly publishReservedLifecycleStagedDirectoryNoReplace: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedDirectoryReservation;
    readonly targetPath: string;
  }) => unknown;
  readonly closeLifecycleStagedDirectoryReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedDirectoryReservation;
  }) => unknown;
  readonly syncLifecycleStagedDirectoryReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedDirectoryReservation;
  }) => unknown;
  readonly discardLifecycleStagedDirectoryReservation: (options: {
    readonly lock: NativeLifecycleLock;
    readonly reservation: NativeLifecycleStagedDirectoryReservation;
  }) => unknown;
  readonly publishLifecycleStagedDirectoryNoReplace: (options: {
    readonly lock: NativeLifecycleLock;
    readonly stagingPath: string;
    readonly targetPath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
  }) => unknown;
  readonly quarantineLifecycleExactDirectory: (options: {
    readonly lock: NativeLifecycleLock;
    readonly path: string;
    readonly quarantinePath: string;
    readonly identity: FileIdentity;
    readonly mode: number;
  }) => unknown;
  readonly finalizeLifecycleQuarantine: (options: {
    readonly lock: NativeLifecycleLock;
    readonly quarantine: NativeLifecycleQuarantine;
  }) => unknown;
  readonly restoreLifecycleQuarantine: (options: {
    readonly lock: NativeLifecycleLock;
    readonly quarantine: NativeLifecycleQuarantine;
  }) => unknown;
  readonly removeExactWal: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleWalExactFile;
  }) => unknown;
  readonly removeExactCredential: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleExactFile;
  }) => unknown;
  readonly removeExactStagedFile: (options: {
    readonly lock: NativeLifecycleLock;
    readonly target: NativeLifecycleContentExactFile;
  }) => unknown;
}
export interface NativeLifecycleExactFile {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly mode: number;
}
export interface NativeLifecycleContentExactFile extends NativeLifecycleExactFile {
  readonly size: number;
  readonly digest: string;
}
export interface NativeLifecycleWalExactFile extends NativeLifecycleContentExactFile {
  readonly stat: string;
}

interface ViteCacheNativeBinding extends SecureReadBinding {
  readonly openViteCacheSession: (options: { readonly provenance: ViteCacheProvenance }) => unknown;
  readonly scanViteCacheTree: (options: {
    readonly session: CacheNativeSession;
    readonly limits: ViteCacheLimits;
  }) => unknown;
  readonly scanViteCacheCanaries: (options: {
    readonly session: CacheNativeSession;
    readonly limits: ViteCacheLimits;
    readonly tokenHashes: readonly string[];
  }) => unknown;
  readonly watchViteCacheTree: (options: {
    readonly session: CacheNativeSession;
    readonly onEvent: (event: unknown) => void;
    readonly onFailure: (error: unknown) => void;
  }) => unknown;
  readonly closeViteCacheWatcher: (options: { readonly watcher: object }) => unknown;
  readonly closeViteCacheSession: (options: { readonly session: CacheNativeSession }) => unknown;
  readonly openViteSnapshotSession: (options: {
    readonly projectRoot: string;
    readonly approvedRootIdentity: FileIdentity;
    readonly expectedOwnerUid: number;
  }) => unknown;
  readonly createViteSnapshotStaging: (options: {
    readonly session: NativeViteSnapshotSession;
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
    readonly stagingName: string;
  }) => unknown;
  readonly writeViteSnapshotStagingFile: (options: {
    readonly staging: NativeViteSnapshotStaging;
    readonly relativePath: string;
    readonly bytes: Buffer;
    readonly mode: number;
  }) => unknown;
  readonly publishViteSnapshotStaging: (options: {
    readonly staging: NativeViteSnapshotStaging;
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
  }) => unknown;
  readonly persistViteSnapshotCommitment: (options: {
    readonly published: NativeViteSnapshotPublished;
    readonly installId: string;
    readonly bytes: Buffer;
  }) => unknown;
  readonly discardViteSnapshotStaging: (options: {
    readonly staging: NativeViteSnapshotStaging;
  }) => unknown;
  readonly removeViteSnapshotPublished: (options: {
    readonly published: NativeViteSnapshotPublished;
  }) => unknown;
  readonly closeViteSnapshotSession: (options: {
    readonly session: NativeViteSnapshotSession;
  }) => unknown;
}
interface ViteRecoveryNativeBinding extends SecureReadBinding {
  readonly openViteRecoveryDirectorySession: (options: {
    readonly projectRoot: string;
    readonly expectedProjectRootIdentity: FileIdentity;
    readonly stateRoot: string;
    readonly expectedStateRootIdentity: FileIdentity;
    readonly expectedOwnerUid: number;
  }) => unknown;
  readonly tryLockViteRecoveryDirectorySession: (options: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly lockName: string;
  }) => unknown;
  readonly createViteRecoveryChildAuthority: (options: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly launchId: string;
  }) => unknown;
  readonly closeViteRecoveryChildAuthority: (options: { readonly fd: number }) => unknown;
  readonly verifyManagedViteChildLaunchAuthority: (options: {
    readonly fd: number;
    readonly launchId: string;
    readonly installId: string;
    readonly expectedStateRootIdentity: FileIdentity;
    readonly expectedOwnerUid: number;
  }) => unknown;
  readonly releaseManagedViteChildLaunchAuthority: (options: {
    readonly authority: object;
  }) => unknown;
  readonly readViteRecoveryManifest: (options: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly manifestName: string;
  }) => unknown;
  readonly replaceViteRecoveryManifest: (options: {
    readonly session: NativeViteRecoveryDirectorySession;
    readonly manifestName: string;
    readonly temporaryName: string;
    readonly bytes: Buffer;
  }) => unknown;
  readonly closeViteRecoveryDirectorySession: (options: {
    readonly session: NativeViteRecoveryDirectorySession;
  }) => unknown;
}

export interface NativeViteCacheOpenedSession {
  readonly nativeSession: CacheNativeSession;
  readonly root: CacheRootRecord;
  readonly parent: CacheRootRecord;
}

export interface NativeViteCacheRuntimePort
  extends CacheRuntimeFilesystemPort, CacheCanaryScannerPort {}

interface NativeViteCacheSessionState {
  readonly provenance: ViteCacheProvenance;
  closed: boolean;
}

const nativeViteCacheSessions = new WeakMap<object, NativeViteCacheSessionState>();
const activeNativeViteCacheSessions = new Set<CacheNativeSession>();
interface NativeViteSnapshotSessionState {
  readonly approvedRootIdentity: FileIdentity;
  readonly expectedOwnerUid: number;
  closed: boolean;
}

interface NativeViteSnapshotStagingState {
  readonly session: NativeViteSnapshotSession;
  readonly installId: string;
  readonly stagingName: string;
  active: boolean;
}

interface NativeViteSnapshotPublishedState {
  readonly session: NativeViteSnapshotSession;
  readonly installId: string;
  active: boolean;
}

const nativeViteSnapshotSessions = new WeakMap<object, NativeViteSnapshotSessionState>();
const nativeViteSnapshotStagings = new WeakMap<object, NativeViteSnapshotStagingState>();
const nativeViteSnapshotPublished = new WeakMap<object, NativeViteSnapshotPublishedState>();
const activeNativeViteSnapshotSessions = new Set<NativeViteSnapshotSession>();
const activeNativeViteSnapshotStagings = new Set<NativeViteSnapshotStaging>();
const activeNativeViteSnapshotPublished = new Set<NativeViteSnapshotPublished>();
const nativeViteSnapshotStagingsBySession = new Map<
  NativeViteSnapshotSession,
  Set<NativeViteSnapshotStaging>
>();
const nativeViteSnapshotPublishedBySession = new Map<
  NativeViteSnapshotSession,
  Set<NativeViteSnapshotPublished>
>();
interface NativeViteRecoveryDirectorySessionState {
  readonly expectedOwnerUid: number;
  closed: boolean;
}

const nativeViteRecoveryDirectorySessions = new WeakMap<
  NativeViteRecoveryDirectorySession,
  NativeViteRecoveryDirectorySessionState
>();
const activeNativeViteRecoveryDirectorySessions = new Set<NativeViteRecoveryDirectorySession>();
const activeNativeViteRecoveryChildAuthorities = new Map<
  number,
  NativeViteRecoveryDirectorySession
>();

interface VerifiedAuthority {
  readonly projectId: string;
  readonly path: string;
  readonly identity: FileIdentity;
  readonly expectedOwnerUid: number;
  readonly maxBytes: number;
}

interface CredentialCapabilityState {
  authority: VerifiedAuthority | undefined;
  authorityKeys: readonly string[] | undefined;
  active: boolean;
}

let binding: SecureReadBinding | undefined;

export function isSecureReadNativePlatform(platform: NodeJS.Platform = process.platform): boolean {
  return platform === 'darwin' || platform === 'linux';
}

export function assertSecureReadNativeAvailable(
  platform: NodeJS.Platform = process.platform,
): void {
  if (!isSecureReadNativePlatform(platform)) {
    throw nativeUnavailable();
  }
  getBinding();
}
export function assertViteCacheNativeAvailable(platform: NodeJS.Platform = process.platform): void {
  if (!isSecureReadNativePlatform(platform)) {
    throw viteCacheNativeUnavailable();
  }
  getViteCacheBinding();
}
export function assertViteSnapshotNativeAvailable(
  platform: NodeJS.Platform = process.platform,
): void {
  if (!isSecureReadNativePlatform(platform)) {
    throw viteSnapshotNativeUnavailable();
  }
  getViteSnapshotBinding();
}

export function createNativeViteCacheRuntimePort(): NativeViteCacheRuntimePort {
  assertViteCacheNativeAvailable();

  const port: NativeViteCacheRuntimePort = {
    async openCacheSession({ provenance }): Promise<NativeViteCacheOpenedSession> {
      const parsedProvenance = parseViteCacheProvenance(provenance);
      if (activeNativeViteCacheSessions.size >= MAX_ACTIVE_VITE_CACHE_SESSIONS) {
        throw viteCacheNativeFailure();
      }
      const opened = parseNativeViteCacheOpenedSession(
        invokeViteCacheNative(() =>
          getViteCacheBinding().openViteCacheSession({ provenance: parsedProvenance }),
        ),
        parsedProvenance,
      );
      nativeViteCacheSessions.set(opened.nativeSession, {
        provenance: parsedProvenance,
        closed: false,
      });
      activeNativeViteCacheSessions.add(opened.nativeSession);
      return opened;
    },

    async scanCacheTree({ session, provenance, limits }): Promise<CacheTreeScan> {
      const parsedProvenance = parseViteCacheProvenance(provenance);
      const nativeSession = requireNativeViteCacheSession(session, parsedProvenance);
      const parsedLimits = parseViteCacheLimits(limits);
      return parseNativeViteCacheTreeScan(
        invokeViteCacheNative(() =>
          getViteCacheBinding().scanViteCacheTree({
            session: nativeSession,
            limits: parsedLimits,
          }),
        ),
        parsedLimits,
      );
    },

    async scanCacheCanaries({
      session,
      provenance,
      limits,
      tokenHashes,
    }): Promise<CacheCanaryScanResult> {
      const parsedProvenance = parseViteCacheProvenance(provenance);
      const nativeSession = requireNativeViteCacheSession(session, parsedProvenance);
      const parsedLimits = parseViteCacheLimits(limits);
      const hashes = parseViteCacheTokenHashes(tokenHashes);
      return parseNativeViteCacheCanaryScan(
        invokeViteCacheNative(() =>
          getViteCacheBinding().scanViteCacheCanaries({
            session: nativeSession,
            limits: parsedLimits,
            tokenHashes: hashes,
          }),
        ),
      );
    },

    async watchCacheTree({ session, provenance, onEvent, onFailure }): Promise<CacheTreeWatcher> {
      const parsedProvenance = parseViteCacheProvenance(provenance);
      const nativeSession = requireNativeViteCacheSession(session, parsedProvenance);
      if (typeof onEvent !== 'function' || typeof onFailure !== 'function') {
        throw viteCacheNativeFailure();
      }

      let closed = false;
      let terminal = false;
      let failureReported = false;
      let closing: Promise<void> | undefined;
      const reportFailure = (): void => {
        if (failureReported) {
          return;
        }
        failureReported = true;
        onFailure();
      };
      const closeNative = async (): Promise<void> => {
        if (closed) {
          return;
        }
        if (closing !== undefined) {
          return closing;
        }
        closing = Promise.resolve().then(() => {
          const nativeWatcher = watcher;
          if (nativeWatcher === undefined) {
            throw viteCacheNativeFailure();
          }
          invokeViteCacheNative(() =>
            getViteCacheBinding().closeViteCacheWatcher({ watcher: nativeWatcher }),
          );
          closed = true;
        });
        try {
          await closing;
        } finally {
          closing = undefined;
        }
      };
      const terminate = (): void => {
        if (terminal) {
          return;
        }
        terminal = true;
        void closeNative().then(reportFailure, reportFailure);
      };
      const watcher = parseNativeViteCacheWatcher(
        invokeViteCacheNative(() =>
          getViteCacheBinding().watchViteCacheTree({
            session: nativeSession,
            onEvent: (event) => {
              if (closed || terminal) {
                return;
              }
              try {
                onEvent(parseNativeViteCacheWatchEvent(event));
              } catch {
                terminate();
              }
            },
            onFailure: () => {
              terminate();
            },
          }),
        ),
      );

      return Object.freeze({
        async close(): Promise<void> {
          terminal = true;
          await closeNative();
        },
      });
    },

    async closeCacheSession({ session }): Promise<void> {
      const nativeSession = requireNativeViteCacheSessionForClose(session);
      invokeViteCacheNative(() =>
        getViteCacheBinding().closeViteCacheSession({ session: nativeSession }),
      );
      const state = nativeViteCacheSessions.get(nativeSession);
      if (state !== undefined) {
        state.closed = true;
        activeNativeViteCacheSessions.delete(nativeSession);
      }
    },
  };
  return Object.freeze(port);
}
export function createNativeViteRecoveryDirectoryPort(): NativeViteRecoveryDirectoryPort {
  const binding = getViteRecoveryBinding();
  const port: NativeViteRecoveryDirectoryPort = {
    openDirectory({
      projectRoot,
      expectedProjectRootIdentity,
      stateRoot,
      expectedStateRootIdentity,
      expectedOwnerUid,
    }): NativeViteRecoveryDirectorySession {
      const parsedProjectRoot = parseCanonicalAbsolutePath(projectRoot, viteRecoveryNativeFailure);
      const parsedProjectRootIdentity = parseIdentity(
        expectedProjectRootIdentity,
        viteRecoveryNativeFailure,
      );
      const parsedStateRoot = parseCanonicalAbsolutePath(stateRoot, viteRecoveryNativeFailure);
      const parsedStateRootIdentity = parseIdentity(
        expectedStateRootIdentity,
        viteRecoveryNativeFailure,
      );
      const expectedStateRoot = `${parsedProjectRoot}/${VITE_CACHE_ROOT_DIRECTORY}`;
      if (parsedStateRoot !== expectedStateRoot) {
        throw viteRecoveryNativeFailure();
      }
      const ownerUid = parseViteRecoveryOwnerUid(expectedOwnerUid);
      if (
        activeNativeViteRecoveryDirectorySessions.size >=
        MAX_ACTIVE_VITE_RECOVERY_DIRECTORY_SESSIONS
      ) {
        throw viteRecoveryNativeFailure();
      }
      const session = parseNativeViteRecoveryDirectorySession(
        invokeViteRecoveryNative(() =>
          binding.openViteRecoveryDirectorySession({
            projectRoot: parsedProjectRoot,
            expectedProjectRootIdentity: parsedProjectRootIdentity,
            stateRoot: parsedStateRoot,
            expectedStateRootIdentity: parsedStateRootIdentity,
            expectedOwnerUid: ownerUid,
          }),
        ),
      );
      nativeViteRecoveryDirectorySessions.set(session, {
        expectedOwnerUid: ownerUid,
        closed: false,
      });
      activeNativeViteRecoveryDirectorySessions.add(session);
      return session;
    },
    tryLock({ session, lockName }): boolean {
      const nativeSession = requireNativeViteRecoveryDirectorySession(session);
      const parsedLockName = parseViteRecoveryFileName(lockName, '.recovery.v1.lock');
      const result = invokeViteRecoveryNative(() =>
        binding.tryLockViteRecoveryDirectorySession({
          session: nativeSession,
          lockName: parsedLockName,
        }),
      );
      if (typeof result !== 'boolean') {
        throw viteRecoveryNativeFailure();
      }
      return result;
    },
    createChildAuthority({ session, launchId }): {
      readonly fd: number;
      readonly launchId: string;
    } {
      const nativeSession = requireNativeViteRecoveryDirectorySession(session);
      const parsedLaunchId = parseViteRecoveryLaunchId(launchId);
      if (
        activeNativeViteRecoveryChildAuthorities.size >= MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES
      ) {
        throw viteRecoveryNativeFailure();
      }
      const result = invokeViteRecoveryNative(() =>
        binding.createViteRecoveryChildAuthority({
          session: nativeSession,
          launchId: parsedLaunchId,
        }),
      );
      if (!hasExactEnumerableKeys(result, ['fd', 'launchId'])) {
        throw viteRecoveryNativeFailure();
      }
      const fd = result.fd;
      const nativeLaunchId = result.launchId;
      if (
        typeof fd !== 'number' ||
        !Number.isSafeInteger(fd) ||
        fd < 0 ||
        fd > 0x7fff_ffff ||
        typeof nativeLaunchId !== 'string' ||
        nativeLaunchId !== parsedLaunchId
      ) {
        throw viteRecoveryNativeFailure();
      }
      activeNativeViteRecoveryChildAuthorities.set(fd, nativeSession);
      return Object.freeze({ fd, launchId: nativeLaunchId });
    },
    closeChildAuthority({ fd }): void {
      if (!Number.isSafeInteger(fd) || fd < 0 || fd > 0x7fff_ffff) {
        throw viteRecoveryNativeFailure();
      }
      if (!activeNativeViteRecoveryChildAuthorities.has(fd)) {
        throw viteRecoveryNativeFailure();
      }
      invokeViteRecoveryNative(() => binding.closeViteRecoveryChildAuthority({ fd }));
      activeNativeViteRecoveryChildAuthorities.delete(fd);
    },
    readManifest({ session, manifestName }): Buffer | undefined {
      const nativeSession = requireNativeViteRecoveryDirectorySession(session);
      const parsedManifestName = parseViteRecoveryFileName(manifestName, '.recovery.v1.json');
      const result = invokeViteRecoveryNative(() =>
        binding.readViteRecoveryManifest({
          session: nativeSession,
          manifestName: parsedManifestName,
        }),
      );
      if (result === null) {
        return undefined;
      }
      if (!isBuffer(result) || result.byteLength === 0 || result.byteLength > 512) {
        throw viteRecoveryNativeFailure();
      }
      return result;
    },
    replaceManifest({ session, manifestName, temporaryName, bytes }): void {
      const nativeSession = requireNativeViteRecoveryDirectorySession(session);
      const parsedManifestName = parseViteRecoveryFileName(manifestName, '.recovery.v1.json');
      const parsedTemporaryName = parseViteRecoveryTemporaryName(temporaryName);
      if (!isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > 512) {
        throw viteRecoveryNativeFailure();
      }
      invokeViteRecoveryNative(() =>
        binding.replaceViteRecoveryManifest({
          session: nativeSession,
          manifestName: parsedManifestName,
          temporaryName: parsedTemporaryName,
          bytes,
        }),
      );
    },
    closeDirectory({ session }): void {
      const nativeSession = requireNativeViteRecoveryDirectorySession(session);
      const state = nativeViteRecoveryDirectorySessions.get(nativeSession);
      if (state === undefined || state.closed) {
        return;
      }
      invokeViteRecoveryNative(() =>
        binding.closeViteRecoveryDirectorySession({ session: nativeSession }),
      );
      state.closed = true;
      activeNativeViteRecoveryDirectorySessions.delete(nativeSession);
      for (const [fd, childSession] of activeNativeViteRecoveryChildAuthorities) {
        if (childSession === nativeSession) {
          activeNativeViteRecoveryChildAuthorities.delete(fd);
        }
      }
    },
  };
  return Object.freeze(port);
}
export function verifyManagedViteChildLaunchAuthority(input: {
  readonly fd: number;
  readonly launchId: string;
  readonly installId: string;
  readonly expectedStateRootIdentity: FileIdentity;
  readonly expectedOwnerUid: number;
}): ManagedViteChildLaunchAuthority {
  if (!isRecord(input)) {
    throw viteRecoveryNativeFailure();
  }
  const fd = input.fd;
  if (!Number.isSafeInteger(fd) || fd < 0 || fd > 0x7fff_ffff) {
    throw viteRecoveryNativeFailure();
  }
  const launchId = parseViteRecoveryLaunchId(input.launchId);
  const installId = parseViteRecoveryInstallId(input.installId);
  const expectedStateRootIdentity = parseIdentity(
    input.expectedStateRootIdentity,
    viteRecoveryNativeFailure,
  );
  const expectedOwnerUid = parseViteRecoveryOwnerUid(input.expectedOwnerUid);
  const nativeAuthority = invokeViteRecoveryNative(() =>
    getViteRecoveryBinding().verifyManagedViteChildLaunchAuthority({
      fd,
      launchId,
      installId,
      expectedStateRootIdentity,
      expectedOwnerUid,
    }),
  );
  if (!hasExactEnumerableKeys(nativeAuthority, [])) {
    throw viteRecoveryNativeFailure();
  }

  let released = false;
  let releaseOperation: Promise<void> | undefined;
  const release = async (): Promise<void> => {
    if (released) {
      return;
    }
    if (releaseOperation !== undefined) {
      return releaseOperation;
    }
    releaseOperation = Promise.resolve().then(() => {
      invokeViteRecoveryNative(() =>
        getViteRecoveryBinding().releaseManagedViteChildLaunchAuthority({
          authority: nativeAuthority,
        }),
      );
      released = true;
    });
    try {
      await releaseOperation;
    } finally {
      releaseOperation = undefined;
    }
  };
  return Object.freeze({ release });
}
export function createNativeViteSnapshotPublicationPort(): NativeViteSnapshotPublicationPort {
  assertViteSnapshotNativeAvailable();

  const port: NativeViteSnapshotPublicationPort = {
    openSession({
      projectRoot,
      approvedRootIdentity,
      expectedOwnerUid,
    }): NativeViteSnapshotSession {
      const parsedProjectRoot = parseCanonicalAbsolutePath(projectRoot, viteSnapshotNativeFailure);
      const parsedRootIdentity = parseIdentity(approvedRootIdentity, viteSnapshotNativeFailure);
      const parsedOwnerUid = parseViteSnapshotExpectedOwnerUid(expectedOwnerUid);
      if (activeNativeViteSnapshotSessions.size >= MAX_ACTIVE_VITE_SNAPSHOT_SESSIONS) {
        throw viteSnapshotNativeFailure();
      }
      const session = parseNativeViteSnapshotSession(
        invokeViteSnapshotNative(() =>
          getViteSnapshotBinding().openViteSnapshotSession({
            projectRoot: parsedProjectRoot,
            approvedRootIdentity: parsedRootIdentity,
            expectedOwnerUid: parsedOwnerUid,
          }),
        ),
      );
      nativeViteSnapshotSessions.set(session, {
        approvedRootIdentity: parsedRootIdentity,
        expectedOwnerUid: parsedOwnerUid,
        closed: false,
      });
      activeNativeViteSnapshotSessions.add(session);
      return session;
    },

    createStaging({
      session,
      approvedRootIdentity,
      installId,
      stagingName,
    }): NativeViteSnapshotStaging {
      const nativeSession = requireNativeViteSnapshotSession(session);
      const state = nativeViteSnapshotSessions.get(nativeSession);
      const rootIdentity = parseIdentity(approvedRootIdentity, viteSnapshotNativeFailure);
      const parsedInstallId = parseViteSnapshotInstallId(installId);
      const parsedStagingName = parseViteSnapshotStagingName(stagingName, parsedInstallId);
      if (
        state === undefined ||
        !sameNativeFileIdentity(rootIdentity, state.approvedRootIdentity)
      ) {
        throw viteSnapshotNativeFailure();
      }
      if (activeNativeViteSnapshotStagings.size >= MAX_ACTIVE_VITE_SNAPSHOT_STAGINGS) {
        throw viteSnapshotNativeFailure();
      }
      const staging = parseNativeViteSnapshotStaging(
        invokeViteSnapshotNative(() =>
          getViteSnapshotBinding().createViteSnapshotStaging({
            session: nativeSession,
            approvedRootIdentity: rootIdentity,
            installId: parsedInstallId,
            stagingName: parsedStagingName,
          }),
        ),
      );
      nativeViteSnapshotStagings.set(staging, {
        session: nativeSession,
        installId: parsedInstallId,
        stagingName: parsedStagingName,
        active: true,
      });
      registerNativeViteSnapshotStaging(staging, nativeSession);
      return staging;
    },

    writeStagingFile({ staging, relativePath, bytes, mode }): void {
      const nativeStaging = requireNativeViteSnapshotStaging(staging);
      const parsedPath = parseViteSnapshotRelativePath(relativePath);
      if (mode !== 0o600) {
        throw viteSnapshotNativeFailure();
      }
      const copied = copyViteSnapshotWriteBytes(bytes, MAX_NATIVE_VITE_SNAPSHOT_BYTES);
      try {
        invokeViteSnapshotNative(() =>
          getViteSnapshotBinding().writeViteSnapshotStagingFile({
            staging: nativeStaging,
            relativePath: parsedPath,
            bytes: copied,
            mode,
          }),
        );
      } finally {
        zeroizeBuffer(copied);
      }
    },

    publishStaging({ staging, approvedRootIdentity, installId }): {
      readonly published: NativeViteSnapshotPublished;
      readonly rootIdentity: FileIdentity;
    } {
      const nativeStaging = requireNativeViteSnapshotStaging(staging);
      const stagingState = nativeViteSnapshotStagings.get(nativeStaging);
      const rootIdentity = parseIdentity(approvedRootIdentity, viteSnapshotNativeFailure);
      const parsedInstallId = parseViteSnapshotInstallId(installId);
      const sessionState =
        stagingState === undefined
          ? undefined
          : nativeViteSnapshotSessions.get(stagingState.session);
      if (
        stagingState === undefined ||
        sessionState === undefined ||
        !sameNativeFileIdentity(rootIdentity, sessionState.approvedRootIdentity) ||
        parsedInstallId !== stagingState.installId
      ) {
        throw viteSnapshotNativeFailure();
      }
      if (activeNativeViteSnapshotPublished.size >= MAX_ACTIVE_VITE_SNAPSHOT_PUBLISHED) {
        throw viteSnapshotNativeFailure();
      }
      const published = parseNativeViteSnapshotPublished(
        invokeViteSnapshotNative(() =>
          getViteSnapshotBinding().publishViteSnapshotStaging({
            staging: nativeStaging,
            approvedRootIdentity: rootIdentity,
            installId: parsedInstallId,
          }),
        ),
      );
      releaseNativeViteSnapshotStaging(nativeStaging, stagingState);
      nativeViteSnapshotPublished.set(published.published, {
        session: stagingState.session,
        installId: parsedInstallId,
        active: true,
      });
      registerNativeViteSnapshotPublished(published.published, stagingState.session);
      return published;
    },

    persistCommitment({ published, installId, bytes }): void {
      const nativePublished = requireNativeViteSnapshotPublished(published);
      const publishedState = nativeViteSnapshotPublished.get(nativePublished);
      const parsedInstallId = parseViteSnapshotInstallId(installId);
      if (publishedState === undefined || publishedState.installId !== parsedInstallId) {
        throw viteSnapshotNativeFailure();
      }
      const copied = copyViteSnapshotWriteBytes(bytes, MAX_NATIVE_VITE_SNAPSHOT_COMMITMENT_BYTES);
      try {
        invokeViteSnapshotNative(() =>
          getViteSnapshotBinding().persistViteSnapshotCommitment({
            published: nativePublished,
            installId: parsedInstallId,
            bytes: copied,
          }),
        );
      } finally {
        zeroizeBuffer(copied);
      }
    },

    discardStaging({ staging }): void {
      const nativeStaging = requireNativeViteSnapshotStaging(staging);
      invokeViteSnapshotNative(() =>
        getViteSnapshotBinding().discardViteSnapshotStaging({ staging: nativeStaging }),
      );
      const state = nativeViteSnapshotStagings.get(nativeStaging);
      if (state !== undefined) {
        releaseNativeViteSnapshotStaging(nativeStaging, state);
      }
    },

    removePublished({ published }): void {
      const nativePublished = requireNativeViteSnapshotPublished(published);
      invokeViteSnapshotNative(() =>
        getViteSnapshotBinding().removeViteSnapshotPublished({ published: nativePublished }),
      );
      const state = nativeViteSnapshotPublished.get(nativePublished);
      if (state !== undefined) {
        releaseNativeViteSnapshotPublished(nativePublished, state);
      }
    },

    closeSession({ session }): void {
      if (!isNativeViteSnapshotSession(session)) {
        throw viteSnapshotNativeFailure();
      }
      const state = nativeViteSnapshotSessions.get(session);
      if (state === undefined || state.closed) {
        return;
      }
      invokeViteSnapshotNative(() =>
        getViteSnapshotBinding().closeViteSnapshotSession({ session }),
      );
      releaseNativeViteSnapshotSession(session, state);
    },
  };
  return Object.freeze(port);
}

export function secureReadBeneath(options: SecureReadBeneathOptions): SecureReadResult {
  assertSecureReadNativeAvailable();
  if (!isRecord(options)) {
    throw pathDenied();
  }

  const root = parseCanonicalAbsolutePath(options.root);
  const expectedRoot = parseIdentity(options.expectedRoot);
  const relativePath = parseRelativePath(options.relativePath);
  const deniedIdentities = parseDeniedIdentities(options.deniedIdentities);
  const maxBytes = parseMaximumBytes(options.maxBytes);
  return invokeNative({
    root,
    expectedRoot,
    relativePath,
    expectedAuthority: null,
    deniedIdentities,
    maxBytes,
    readContent: true,
  });
}
export function acquireLifecycleLock(path: string): NativeLifecycleLock {
  const lock = invokeLifecycleNative(() =>
    getLifecycleBinding().acquireLifecycleLock({ path: parseLifecyclePath(path) }),
  );
  return parseNativeLifecycleLock(lock);
}

export function releaseLifecycleLock(lock: NativeLifecycleLock): NativeLifecycleMutationResult {
  const capability = requireNativeLifecycleLock(lock);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() => getLifecycleBinding().releaseLifecycleLock({ lock: capability })),
  );
  if (result.state === 'completed') {
    nativeLifecycleLocks.delete(lock);
    releaseNativeLifecycleHandle(lock);
  }
  return result;
}
export function releaseLifecycleLockSession(
  lock: NativeLifecycleLock,
): NativeLifecycleMutationResult {
  const capability = requireIssuedNativeLifecycleLock(lock);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().releaseLifecycleLockSession({ lock: capability }),
    ),
  );
  if (result.state === 'completed') {
    nativeLifecycleLocks.delete(lock);
    releaseNativeLifecycleHandle(lock);
  }
  return result;
}
export function validateExactCredential(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleExactFile;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const target = parseNativeLifecycleExactFile(input.target);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() => getLifecycleBinding().validateExactCredential({ lock, target })),
  );
}
export function validateExactDirectory(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleExactFile;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const target = parseNativeLifecycleExactFile(input.target);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() => getLifecycleBinding().validateExactDirectory({ lock, target })),
  );
}
export function readExactLifecycleWal(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleExactFile;
}): NativeLifecycleWalReadResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const target = parseNativeLifecycleExactFile(input.target);
  return parseNativeLifecycleWalReadResult(
    invokeLifecycleNative(() => getLifecycleBinding().readExactLifecycleWal({ lock, target })),
  );
}
export function prepareLifecycleCreationIntent(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly markerPath?: string;
  readonly parentDirectoryReservation?: NativeLifecycleStagedDirectoryReservation;
  readonly kind: 'credential' | 'file' | 'directory';
}): NativeLifecycleCreationIntentResult {
  const lock = requireNativeLifecycleLock(input.lock);
  if (input.kind !== 'credential' && input.kind !== 'file' && input.kind !== 'directory') {
    throw pathDenied();
  }
  const path = parseLifecyclePath(input.path);
  const markerPath = parseLifecyclePath(
    input.markerPath ?? join(dirname(path), `.scg-creation-intent-${basename(path)}`),
  );
  const parentDirectoryReservation =
    input.parentDirectoryReservation === undefined
      ? undefined
      : requireNativeLifecycleStagedDirectoryReservation(input.parentDirectoryReservation);
  return parseNativeLifecycleCreationIntentResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().prepareLifecycleCreationIntent({
        lock,
        path,
        markerPath,
        kind: input.kind,
        ...(parentDirectoryReservation === undefined ? {} : { parentDirectoryReservation }),
      }),
    ),
  );
}
export function recoverLifecycleCreationIntent(input: {
  readonly lock: NativeLifecycleLock;
  readonly stagePath: string;
  readonly markerPath: string;
  readonly kind: 'credential' | 'file' | 'directory';
  readonly mode: number;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  if (input.kind !== 'credential' && input.kind !== 'file' && input.kind !== 'directory') {
    throw pathDenied();
  }
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().recoverLifecycleCreationIntent({
        lock,
        stagePath: parseLifecyclePath(input.stagePath),
        markerPath: parseLifecyclePath(input.markerPath),
        kind: input.kind,
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}
export function reserveCredentialFromIntent(input: {
  readonly lock: NativeLifecycleLock;
  readonly intent: NativeLifecycleCreationIntent;
  readonly mode: number;
}): NativeLifecycleStagedFileReservationCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const intent = requireNativeLifecycleCreationIntent(input.intent);
  const result = parseNativeLifecycleStagedFileReservationCreateResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().reserveCredentialFromIntent({
        lock,
        intent,
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
  nativeLifecycleCreationIntents.delete(input.intent);
  return result;
}
export function reserveLifecycleFileFromIntent(input: {
  readonly lock: NativeLifecycleLock;
  readonly intent: NativeLifecycleCreationIntent;
  readonly mode: number;
}): NativeLifecycleStagedFileReservationCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const intent = requireNativeLifecycleCreationIntent(input.intent);
  const result = parseNativeLifecycleStagedFileReservationCreateResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().reserveLifecycleFileFromIntent({
        lock,
        intent,
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
  nativeLifecycleCreationIntents.delete(input.intent);
  return result;
}
export function reserveDirectoryFromIntent(input: {
  readonly lock: NativeLifecycleLock;
  readonly intent: NativeLifecycleCreationIntent;
  readonly mode: number;
}): NativeLifecycleStagedDirectoryReservationCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const intent = requireNativeLifecycleCreationIntent(input.intent);
  const result = parseNativeLifecycleStagedDirectoryReservationCreateResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().reserveDirectoryFromIntent({
        lock,
        intent,
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
  nativeLifecycleCreationIntents.delete(input.intent);
  return result;
}
export function retainReservationForRecovery(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation:
    NativeLifecycleStagedFileReservation | NativeLifecycleStagedDirectoryReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleReservation(input.reservation);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().retainReservationForRecovery({ lock, reservation }),
    ),
  );
  if (result.state === 'completed') {
    if (isNativeLifecycleStagedFileReservationHandle(input.reservation)) {
      nativeLifecycleStagedFileReservations.delete(input.reservation);
    } else {
      nativeLifecycleStagedDirectoryReservations.delete(input.reservation);
    }
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}
export function revalidateLifecycleLock(lock: NativeLifecycleLock): NativeLifecycleMutationResult {
  const capability = requireNativeLifecycleLock(lock);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().revalidateLifecycleLock({ lock: capability }),
    ),
  );
}

export function createLifecycleStagedFile(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly mode: number;
  readonly bytes: Uint8Array;
}): NativeLifecycleCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const path = parseLifecyclePath(input.path);
  const mode = parseLifecycleMode(input.mode);
  const bytes = copyLifecycleBytes(input.bytes);
  return invokeLifecycleWithZeroizedBytes(bytes, () =>
    parseNativeLifecycleCreateResult(
      invokeLifecycleNative(() =>
        getLifecycleBinding().createLifecycleStagedFile({ lock, path, mode, bytes }),
      ),
    ),
  );
}

export function reserveLifecycleStagedFile(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly mode: number;
}): NativeLifecycleStagedFileReservationCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleStagedFileReservationCreateResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().reserveLifecycleStagedFile({
        lock,
        path: parseLifecyclePath(input.path),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function writeLifecycleStagedFile(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
  readonly expectedSize: number;
  readonly bytes: Uint8Array;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  const expectedSize = parseLifecycleSize(input.expectedSize);
  const bytes = copyLifecycleBytes(input.bytes);
  return invokeLifecycleWithZeroizedBytes(bytes, () =>
    parseNativeLifecycleMutationResult(
      invokeLifecycleNative(() =>
        getLifecycleBinding().writeLifecycleStagedFile({ lock, reservation, expectedSize, bytes }),
      ),
    ),
  );
}
export function validateLifecycleStagedFileReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().validateLifecycleStagedFileReservation({ lock, reservation }),
    ),
  );
}
export function syncLifecycleStagedFileReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().syncLifecycleStagedFileReservation({ lock, reservation }),
    ),
  );
}

export function publishReservedLifecycleStagedFileNoReplace(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
  readonly targetPath: string;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().publishReservedLifecycleStagedFileNoReplace({
        lock,
        reservation,
        targetPath: parseLifecyclePath(input.targetPath),
      }),
    ),
  );
}

export function closeLifecycleStagedFileReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireIssuedNativeLifecycleStagedFileReservation(input.reservation);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().closeLifecycleStagedFileReservation({ lock, reservation }),
    ),
  );
  if (result.state === 'completed') {
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}

export function discardLifecycleStagedFileReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireIssuedNativeLifecycleStagedFileReservation(input.reservation);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().discardLifecycleStagedFileReservation({ lock, reservation }),
    ),
  );
  if (result.state === 'completed') {
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}

export function publishLifecycleStagedFileNoReplace(input: {
  readonly lock: NativeLifecycleLock;
  readonly stagingPath: string;
  readonly targetPath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().publishLifecycleStagedFileNoReplace({
        lock,
        stagingPath: parseLifecyclePath(input.stagingPath),
        targetPath: parseLifecyclePath(input.targetPath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function replaceLifecycleStagedFileExact(input: {
  readonly lock: NativeLifecycleLock;
  readonly stagingPath: string;
  readonly targetPath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
  readonly targetIdentity: FileIdentity;
  readonly targetMode: number;
  readonly targetSize?: number;
  readonly targetDigest?: string;
}): NativeLifecycleQuarantineResult {
  if ((input.targetSize === undefined) !== (input.targetDigest === undefined)) {
    throw nativeFailure();
  }
  if (input.targetDigest !== undefined && !isSha256Digest(input.targetDigest)) {
    throw pathDenied();
  }
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().replaceLifecycleStagedFileExact({
        lock,
        stagingPath: parseLifecyclePath(input.stagingPath),
        targetPath: parseLifecyclePath(input.targetPath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
        targetIdentity: parseIdentity(input.targetIdentity),
        targetMode: parseLifecycleMode(input.targetMode),
        ...(input.targetSize === undefined || input.targetDigest === undefined
          ? {}
          : {
              targetSize: parseLifecycleSize(input.targetSize),
              targetDigest: input.targetDigest,
            }),
      }),
    ),
  );
}
export function replaceReservedLifecycleFileExact(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
  readonly targetPath: string;
  readonly targetIdentity: FileIdentity;
  readonly targetMode: number;
  readonly targetSize: number;
  readonly targetDigest: string;
  readonly targetStat: string;
  readonly discardReplacedTarget?: boolean;
}): NativeLifecycleQuarantineResult {
  if (
    input.discardReplacedTarget !== undefined &&
    typeof input.discardReplacedTarget !== 'boolean'
  ) {
    throw nativeFailure();
  }
  if (!isSha256Digest(input.targetDigest) || !isLifecycleStatSnapshot(input.targetStat)) {
    throw pathDenied();
  }
  const targetSnapshot = Object.freeze({
    targetSize: parseLifecycleSize(input.targetSize),
    targetDigest: input.targetDigest,
    targetStat: input.targetStat,
  });
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  const result = parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().replaceReservedLifecycleFileExact({
        lock,
        reservation,
        targetPath: parseLifecyclePath(input.targetPath),
        targetIdentity: parseIdentity(input.targetIdentity),
        targetMode: parseLifecycleMode(input.targetMode),
        ...targetSnapshot,
        discardReplacedTarget: input.discardReplacedTarget ?? false,
      }),
    ),
  );
  if (result.quarantine !== undefined || result.state === 'completed') {
    nativeLifecycleStagedFileReservations.delete(input.reservation);
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}
export function replaceReservedLifecycleOrdinaryFileExact(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedFileReservation;
  readonly targetPath: string;
  readonly targetIdentity: FileIdentity;
  readonly targetMode: number;
  readonly targetSize: number;
  readonly targetDigest: string;
}): NativeLifecycleQuarantineResult {
  if (!isSha256Digest(input.targetDigest)) {
    throw pathDenied();
  }
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedFileReservation(input.reservation);
  const result = parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().replaceReservedLifecycleOrdinaryFileExact({
        lock,
        reservation,
        targetPath: parseLifecyclePath(input.targetPath),
        targetIdentity: parseIdentity(input.targetIdentity),
        targetMode: parseLifecycleMode(input.targetMode),
        targetSize: parseLifecycleSize(input.targetSize),
        targetDigest: input.targetDigest,
      }),
    ),
  );
  if (result.quarantine !== undefined || result.state === 'completed') {
    nativeLifecycleStagedFileReservations.delete(input.reservation);
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}
export function removeExactWal(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleWalExactFile;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().removeExactWal({
        lock,
        target: parseNativeLifecycleWalExactFile(input.target),
      }),
    ),
  );
}
export function removeExactCredential(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleExactFile;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().removeExactCredential({
        lock,
        target: parseNativeLifecycleExactFile(input.target),
      }),
    ),
  );
}

export function removeExactStagedFile(input: {
  readonly lock: NativeLifecycleLock;
  readonly target: NativeLifecycleContentExactFile;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().removeExactStagedFile({
        lock,
        target: parseNativeLifecycleContentExactFile(input.target),
      }),
    ),
  );
}

export function quarantineLifecycleExactFile(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly quarantinePath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
  readonly expectedSize?: number;
  readonly expectedDigest?: string;
}): NativeLifecycleQuarantineResult {
  if ((input.expectedSize === undefined) !== (input.expectedDigest === undefined)) {
    throw nativeFailure();
  }
  if (input.expectedDigest !== undefined && !isSha256Digest(input.expectedDigest)) {
    throw pathDenied();
  }
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().quarantineLifecycleExactFile({
        lock,
        path: parseLifecyclePath(input.path),
        quarantinePath: parseLifecyclePath(input.quarantinePath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
        ...(input.expectedSize === undefined || input.expectedDigest === undefined
          ? {}
          : {
              expectedSize: parseLifecycleSize(input.expectedSize),
              expectedDigest: input.expectedDigest,
            }),
      }),
    ),
  );
}
export function quarantineLifecycleExactCredential(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly quarantinePath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().quarantineLifecycleExactCredential({
        lock,
        path: parseLifecyclePath(input.path),
        quarantinePath: parseLifecyclePath(input.quarantinePath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function createLifecycleStagedDirectory(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly mode: number;
}): NativeLifecycleStagedDirectoryReservationCreateResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleStagedDirectoryReservationCreateResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().createLifecycleStagedDirectory({
        lock,
        path: parseLifecyclePath(input.path),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function publishReservedLifecycleStagedDirectoryNoReplace(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedDirectoryReservation;
  readonly targetPath: string;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedDirectoryReservation(input.reservation);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().publishReservedLifecycleStagedDirectoryNoReplace({
        lock,
        reservation,
        targetPath: parseLifecyclePath(input.targetPath),
      }),
    ),
  );
}

export function closeLifecycleStagedDirectoryReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedDirectoryReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireIssuedNativeLifecycleStagedDirectoryReservation(input.reservation);
  const result = parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().closeLifecycleStagedDirectoryReservation({ lock, reservation }),
    ),
  );
  if (result.state === 'completed') {
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}
export function syncLifecycleStagedDirectoryReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedDirectoryReservation;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireNativeLifecycleStagedDirectoryReservation(input.reservation);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().syncLifecycleStagedDirectoryReservation({ lock, reservation }),
    ),
  );
}

export function discardLifecycleStagedDirectoryReservation(input: {
  readonly lock: NativeLifecycleLock;
  readonly reservation: NativeLifecycleStagedDirectoryReservation;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const reservation = requireIssuedNativeLifecycleStagedDirectoryReservation(input.reservation);
  const result = parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().discardLifecycleStagedDirectoryReservation({ lock, reservation }),
    ),
  );
  if (result.state === 'completed' || result.quarantine !== undefined) {
    releaseNativeLifecycleHandle(input.reservation);
  }
  return result;
}

export function publishLifecycleStagedDirectoryNoReplace(input: {
  readonly lock: NativeLifecycleLock;
  readonly stagingPath: string;
  readonly targetPath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
}): NativeLifecycleMutationResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleMutationResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().publishLifecycleStagedDirectoryNoReplace({
        lock,
        stagingPath: parseLifecyclePath(input.stagingPath),
        targetPath: parseLifecyclePath(input.targetPath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function quarantineLifecycleExactDirectory(input: {
  readonly lock: NativeLifecycleLock;
  readonly path: string;
  readonly quarantinePath: string;
  readonly identity: FileIdentity;
  readonly mode: number;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  return parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().quarantineLifecycleExactDirectory({
        lock,
        path: parseLifecyclePath(input.path),
        quarantinePath: parseLifecyclePath(input.quarantinePath),
        identity: parseIdentity(input.identity),
        mode: parseLifecycleMode(input.mode),
      }),
    ),
  );
}

export function finalizeLifecycleQuarantine(input: {
  readonly lock: NativeLifecycleLock;
  readonly quarantine: NativeLifecycleQuarantine;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const quarantine = requireIssuedNativeLifecycleQuarantine(input.quarantine);
  const result = parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().finalizeLifecycleQuarantine({ lock, quarantine }),
    ),
  );
  if (result.state === 'completed') {
    releaseNativeLifecycleHandle(input.quarantine);
  }
  return result;
}

export function restoreLifecycleQuarantine(input: {
  readonly lock: NativeLifecycleLock;
  readonly quarantine: NativeLifecycleQuarantine;
}): NativeLifecycleQuarantineResult {
  const lock = requireNativeLifecycleLock(input.lock);
  const quarantine = requireIssuedNativeLifecycleQuarantine(input.quarantine);
  const result = parseNativeLifecycleQuarantineResult(
    invokeLifecycleNative(() =>
      getLifecycleBinding().restoreLifecycleQuarantine({ lock, quarantine }),
    ),
  );
  if (result.state === 'completed') {
    releaseNativeLifecycleHandle(input.quarantine);
  }
  return result;
}

export function assertNativeLifecycleMutationCompleted(
  result: NativeLifecycleMutationResult,
  operation: string,
): void {
  if (result.state === 'completed') {
    return;
  }
  throw new OnboardingNativeError(
    NATIVE_FAILURE_CODE,
    `${operation} reached a recovery-required terminal state.`,
  );
}

export function verifyCredentialAuthority(
  authority: CredentialAuthority,
  options: CredentialReadOptions,
): void {
  assertSecureReadNativeAvailable();
  validateCredentialAuthority(
    parseCredentialAuthority(authority, parseCredentialReadOptions(options)),
  );
}

export function verifyCredentialAuthoritySet(
  authorities: readonly CredentialAuthority[],
  selectedProjectId: string,
  options: CredentialReadOptions,
): CredentialReadCapability {
  assertSecureReadNativeAvailable();
  if (!Array.isArray(authorities)) {
    throw credentialAuthorityInvalid();
  }
  const authorityCount = authorities.length;
  const boundedSelectedProjectId = parseCredentialProjectId(selectedProjectId);
  if (authorityCount === 0 || authorityCount > MAX_CREDENTIAL_AUTHORITIES) {
    throw credentialAuthorityInvalid();
  }

  const credentialOptions = parseCredentialReadOptions(options);
  const projectIds = new Set<string>();
  const paths = new Set<string>();
  const identities = new Set<string>();
  const authorityKeys: string[] = [];
  let selected: VerifiedAuthority | undefined;
  for (let index = 0; index < authorityCount; index += 1) {
    const source = authorities[index];
    if (source === undefined) {
      throw credentialAuthorityInvalid();
    }
    const verified = parseCredentialAuthority(source, credentialOptions);
    const identityKey = `${verified.identity.device}:${verified.identity.inode}`;
    if (
      projectIds.has(verified.projectId) ||
      paths.has(verified.path) ||
      identities.has(identityKey)
    ) {
      throw credentialAuthorityInvalid();
    }
    projectIds.add(verified.projectId);
    paths.add(verified.path);
    identities.add(identityKey);
    authorityKeys.push(credentialAuthorityKey(verified));
    validateCredentialAuthority(verified);
    if (verified.projectId === boundedSelectedProjectId) {
      selected = verified;
    }
  }
  if (selected === undefined) {
    throw credentialAuthorityInvalid();
  }
  const frozenAuthorityKeys = Object.freeze([...authorityKeys]);
  revokeCapabilitiesForAuthorityKeys(frozenAuthorityKeys);
  if (activeCredentialCapabilities.size >= MAX_ACTIVE_CREDENTIAL_CAPABILITIES) {
    throw credentialAuthorityInvalid();
  }

  const capability = Object.freeze(Object.create(null)) as CredentialReadCapability;
  const state: CredentialCapabilityState = {
    authority: selected,
    authorityKeys: frozenAuthorityKeys,
    active: true,
  };
  credentialCapabilities.set(capability, state);
  activeCredentialCapabilities.add(capability);
  registerCapability(capability, state);
  return capability;
}

export function revokeCredentialReadCapability(capability: unknown): void {
  if (!isRecord(capability)) {
    throw credentialAuthorityInvalid();
  }
  const state = credentialCapabilities.get(capability as unknown as CredentialReadCapability);
  if (state === undefined) {
    throw credentialAuthorityInvalid();
  }
  revokeCapability(capability as unknown as CredentialReadCapability, state);
}

export function secureReadCredential(capability: unknown, options?: CredentialReadOptions): Buffer {
  assertSecureReadNativeAvailable();
  if (!isRecord(capability)) {
    throw credentialAuthorityInvalid();
  }
  const typedCapability = capability as unknown as CredentialReadCapability;
  const state = credentialCapabilities.get(typedCapability);
  const authority = state?.authority;
  if (state === undefined || !state.active || authority === undefined) {
    throw credentialAuthorityInvalid();
  }

  const requested = options === undefined ? authority : parseCredentialReadOptions(options);
  if (
    requested.expectedOwnerUid !== authority.expectedOwnerUid ||
    requested.maxBytes > authority.maxBytes ||
    typeof process.geteuid !== 'function' ||
    process.geteuid() !== authority.expectedOwnerUid
  ) {
    revokeCapability(typedCapability, state);
    throw credentialAuthorityInvalid();
  }
  const relativePath = sliceCredentialPath(authority.path);

  if (
    credentialCapabilities.get(typedCapability) !== state ||
    !state.active ||
    state.authority !== authority
  ) {
    throw credentialAuthorityInvalid();
  }

  return invokeNative({
    root: '/',
    expectedRoot: null,
    relativePath,
    expectedAuthority: authority.identity,
    deniedIdentities: [],
    maxBytes: requested.maxBytes,
    readContent: true,
  }).bytes;
}

export function zeroizeBuffer(value: Buffer): void {
  if (!isBuffer(value)) {
    throw credentialAuthorityInvalid();
  }
  try {
    reflectApply(typedArrayFill, value, [0]);
  } catch {
    throw credentialBufferZeroizationFailed();
  }
}

function getBinding(): SecureReadBinding {
  if (!isSecureReadNativePlatform()) {
    throw nativeUnavailable();
  }
  if (binding !== undefined) {
    return binding;
  }

  try {
    const candidate: unknown = nativeRequire('../build/Release/secure_read.node');
    if (!isSecureReadBinding(candidate)) {
      throw new TypeError('Invalid secure native binding.');
    }
    binding = candidate;
    return binding;
  } catch (error: unknown) {
    throw nativeUnavailable(error);
  }
}
function getLifecycleBinding(): LifecycleNativeBinding {
  try {
    const candidate = getBinding();
    if (!isLifecycleBinding(candidate)) {
      throw nativeUnavailable();
    }
    return candidate;
  } catch (error) {
    throw nativeUnavailable(error);
  }
}

function invokeLifecycleNative(operation: () => unknown): unknown {
  try {
    return operation();
  } catch (error: unknown) {
    throw nativeErrorFrom(error);
  }
}

function getViteCacheBinding(): ViteCacheNativeBinding {
  try {
    const candidate = getBinding();
    if (!isViteCacheBinding(candidate)) {
      throw viteCacheNativeUnavailable();
    }
    return candidate;
  } catch {
    throw viteCacheNativeUnavailable();
  }
}
function getViteRecoveryBinding(): ViteRecoveryNativeBinding {
  try {
    const candidate = getBinding();
    if (!isViteRecoveryBinding(candidate)) {
      throw viteRecoveryNativeUnavailable();
    }
    return candidate;
  } catch {
    throw viteRecoveryNativeUnavailable();
  }
}

function getViteSnapshotBinding(): ViteCacheNativeBinding {
  try {
    const candidate = getBinding();
    if (!isViteSnapshotBinding(candidate)) {
      throw viteSnapshotNativeUnavailable();
    }
    return candidate;
  } catch {
    throw viteSnapshotNativeUnavailable();
  }
}

function invokeViteSnapshotNative(operation: () => unknown): unknown {
  try {
    return operation();
  } catch (error: unknown) {
    throw nativeErrorFrom(error);
  }
}

function invokeViteCacheNative(operation: () => unknown): unknown {
  try {
    return operation();
  } catch (error: unknown) {
    throw nativeErrorFrom(error);
  }
}
function invokeViteRecoveryNative(operation: () => unknown): unknown {
  try {
    return operation();
  } catch (error: unknown) {
    throw nativeErrorFrom(error);
  }
}

function parseViteCacheProvenance(value: unknown): ViteCacheProvenance {
  if (!isRecord(value) || value.version !== 1 || typeof value.installId !== 'string') {
    throw viteCacheNativeFailure();
  }
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(value.installId)) {
    throw viteCacheNativeFailure();
  }

  const canonicalParentPath = parseCanonicalAbsolutePath(
    value.canonicalParentPath,
    viteCacheNativeFailure,
  );
  const root = parseViteCacheRootRecord(value.root);
  const parent = parseViteCacheRootRecord(value.parent);
  const parentIdentity = parseIdentity(value.parentIdentity, viteCacheNativeFailure);
  const inverse = parseViteCacheInverse(value.inverse);
  if (
    parent.canonicalPath !== canonicalParentPath ||
    !isCanonicalViteCacheChildPath(canonicalParentPath, root.canonicalPath) ||
    sameNativeFileIdentity(root.identity, parent.identity) ||
    !sameNativeFileIdentity(parent.identity, parentIdentity) ||
    root.device !== root.identity.device ||
    parent.device !== parent.identity.device ||
    root.device !== parent.device ||
    root.owner.uid !== parent.owner.uid ||
    root.owner.gid !== parent.owner.gid ||
    root.mode !== VITE_CACHE_DIRECTORY_MODE ||
    parent.mode !== VITE_CACHE_DIRECTORY_MODE ||
    inverse.canonicalPath !== root.canonicalPath ||
    !sameNativeFileIdentity(inverse.rootIdentity, root.identity) ||
    !sameNativeFileIdentity(inverse.parentIdentity, parentIdentity)
  ) {
    throw viteCacheNativeFailure();
  }

  return Object.freeze({
    version: 1,
    installId: value.installId,
    canonicalParentPath,
    root,
    parent,
    parentIdentity,
    inverse,
  });
}

function parseViteCacheRootRecord(value: unknown): CacheRootRecord {
  if (!isRecord(value)) {
    throw viteCacheNativeFailure();
  }
  const identity = parseIdentity(value.identity, viteCacheNativeFailure);
  const canonicalPath = parseCanonicalAbsolutePath(value.canonicalPath, viteCacheNativeFailure);
  const device = parseNativeDecimalIdentity(value.device);
  const owner = parseViteCacheOwner(value.owner);
  const mode = parseNativeCacheInteger(value.mode, 0, 0o7777);
  if (device !== identity.device || mode !== VITE_CACHE_DIRECTORY_MODE) {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({ identity, canonicalPath, device, owner, mode });
}

function parseViteCacheOwner(value: unknown): { readonly uid: number; readonly gid: number } {
  if (!isRecord(value)) {
    throw viteCacheNativeFailure();
  }
  const uid = parseNativeCacheInteger(value.uid, 0, 0xffff_ffff);
  const gid = parseNativeCacheInteger(value.gid, 0, 0xffff_ffff);
  return Object.freeze({ uid, gid });
}

function parseViteCacheInverse(value: unknown): ViteCacheProvenance['inverse'] {
  if (!isRecord(value) || value.kind !== 'remove-created-vite-cache') {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({
    kind: 'remove-created-vite-cache',
    rootIdentity: parseIdentity(value.rootIdentity, viteCacheNativeFailure),
    parentIdentity: parseIdentity(value.parentIdentity, viteCacheNativeFailure),
    canonicalPath: parseCanonicalAbsolutePath(value.canonicalPath, viteCacheNativeFailure),
  });
}

function parseViteCacheLimits(value: unknown): ViteCacheLimits {
  if (!isRecord(value)) {
    throw viteCacheNativeFailure();
  }
  const maxEntries = parseNativeCacheInteger(value.maxEntries, 1, VITE_CACHE_MAX_ENTRIES);
  const maxFiles = parseNativeCacheInteger(value.maxFiles, 1, VITE_CACHE_MAX_FILES);
  const maxBytes = parseNativeCacheInteger(value.maxBytes, 1, VITE_CACHE_MAX_BYTES);
  const maxDepth = parseNativeCacheInteger(value.maxDepth, 0, VITE_CACHE_MAX_DEPTH);
  return Object.freeze({ maxEntries, maxFiles, maxBytes, maxDepth });
}

function parseViteCacheTokenHashes(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 1024) {
    throw viteCacheNativeFailure();
  }
  const hashes = value.map((hash) => {
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) {
      throw viteCacheNativeFailure();
    }
    return hash;
  });
  if (new Set(hashes).size !== hashes.length) {
    throw viteCacheNativeFailure();
  }
  return Object.freeze(hashes);
}

function parseNativeViteCacheOpenedSession(
  value: unknown,
  provenance: ViteCacheProvenance,
): NativeViteCacheOpenedSession {
  if (!hasExactEnumerableKeys(value, ['session', 'root', 'parent'])) {
    throw viteCacheNativeFailure();
  }
  const root = parseNativeViteCacheRootRecord(value.root);
  const parent = parseNativeViteCacheRootRecord(value.parent);
  if (
    !sameNativeViteCacheRootRecord(root, provenance.root) ||
    !sameNativeViteCacheRootRecord(parent, provenance.parent) ||
    !isNativeViteCacheSessionHandle(value.session)
  ) {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({
    nativeSession: value.session,
    root,
    parent,
  });
}

function parseNativeViteCacheRootRecord(value: unknown): CacheRootRecord {
  if (!hasExactEnumerableKeys(value, ['identity', 'canonicalPath', 'device', 'owner', 'mode'])) {
    throw viteCacheNativeFailure();
  }
  const identity = parseStrictNativeViteCacheIdentity(value.identity);
  const canonicalPath = parseCanonicalAbsolutePath(value.canonicalPath, viteCacheNativeFailure);
  const device = parseNativeDecimalIdentity(value.device);
  const owner = parseStrictNativeViteCacheOwner(value.owner);
  const mode = parseNativeCacheInteger(value.mode, 0, 0o7777);
  if (device !== identity.device || mode !== VITE_CACHE_DIRECTORY_MODE) {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({ identity, canonicalPath, device, owner, mode });
}

function parseNativeViteCacheTreeScan(value: unknown, limits: ViteCacheLimits): CacheTreeScan {
  if (
    !hasExactEnumerableKeys(value, ['rootIdentity', 'entries']) ||
    !Array.isArray(value.entries)
  ) {
    throw viteCacheNativeFailure();
  }
  if (value.entries.length > limits.maxEntries) {
    throw viteCacheNativeFailure();
  }
  const rootIdentity = parseStrictNativeViteCacheIdentity(value.rootIdentity);
  const entries = value.entries.map((entry) => parseNativeViteCacheTreeEntry(entry, limits));
  return Object.freeze({
    rootIdentity,
    entries: Object.freeze(entries),
  });
}

function parseNativeViteCacheTreeEntry(value: unknown, limits: ViteCacheLimits): CacheTreeEntry {
  if (
    !hasExactEnumerableKeys(value, [
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
    ])
  ) {
    throw viteCacheNativeFailure();
  }
  const identity = parseStrictNativeViteCacheIdentity(value.identity);
  const parentIdentity =
    value.parentIdentity === null ? null : parseStrictNativeViteCacheIdentity(value.parentIdentity);
  const device = parseNativeDecimalIdentity(value.device);
  const owner = parseStrictNativeViteCacheOwner(value.owner);
  const mode = parseNativeCacheInteger(value.mode, 0, 0o7777);
  const depth = parseNativeCacheInteger(value.depth, 0, limits.maxDepth);
  const sizeBytes = parseNativeCacheInteger(value.sizeBytes, 0, limits.maxBytes);
  const linkCount = parseNativeCacheInteger(value.linkCount, 0, Number.MAX_SAFE_INTEGER);
  if (
    device !== identity.device ||
    typeof value.escaped !== 'boolean' ||
    !isNativeViteCacheEntryKind(value.kind)
  ) {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({
    identity,
    parentIdentity,
    device,
    owner,
    mode,
    kind: value.kind,
    depth,
    sizeBytes,
    linkCount,
    escaped: value.escaped,
  });
}

function parseNativeViteCacheCanaryScan(value: unknown): CacheCanaryScanResult {
  if (!hasExactEnumerableKeys(value, ['detected']) || typeof value.detected !== 'boolean') {
    throw viteCacheNativeFailure();
  }
  return Object.freeze({ detected: value.detected });
}

function parseNativeViteCacheWatcher(value: unknown): object {
  if (!isRecord(value) || Object.keys(value).length !== 0) {
    throw viteCacheNativeFailure();
  }
  return value;
}

function parseNativeViteCacheWatchEvent(
  value: unknown,
): 'created' | 'changed' | 'removed' | 'unknown' {
  if (value === 'created' || value === 'changed' || value === 'removed' || value === 'unknown') {
    return value;
  }
  throw viteCacheNativeFailure();
}

function requireNativeViteCacheSession(
  value: unknown,
  provenance: ViteCacheProvenance,
): CacheNativeSession {
  if (!isOpaqueNativeViteCacheSession(value)) {
    throw viteCacheNativeFailure();
  }
  const state = nativeViteCacheSessions.get(value);
  if (
    state === undefined ||
    state.closed ||
    !sameNativeViteCacheProvenance(state.provenance, provenance)
  ) {
    throw viteCacheNativeFailure();
  }
  return value;
}

function requireNativeViteCacheSessionForClose(value: unknown): CacheNativeSession {
  if (!isOpaqueNativeViteCacheSession(value) || nativeViteCacheSessions.get(value) === undefined) {
    throw viteCacheNativeFailure();
  }
  return value;
}
function isNativeViteCacheSessionHandle(value: unknown): value is CacheNativeSession {
  return isRecord(value) && Object.keys(value).length === 0;
}

function isOpaqueNativeViteCacheSession(value: unknown): value is CacheNativeSession {
  return isRecord(value) && nativeViteCacheSessions.has(value);
}
function parseNativeViteRecoveryDirectorySession(
  value: unknown,
): NativeViteRecoveryDirectorySession {
  if (!isRecord(value) || Object.keys(value).length !== 0) {
    throw viteRecoveryNativeFailure();
  }
  return value as unknown as NativeViteRecoveryDirectorySession;
}

function requireNativeViteRecoveryDirectorySession(
  value: unknown,
): NativeViteRecoveryDirectorySession {
  if (!isRecord(value)) {
    throw viteRecoveryNativeFailure();
  }
  const session = value as unknown as NativeViteRecoveryDirectorySession;
  const state = nativeViteRecoveryDirectorySessions.get(session);
  if (state === undefined || state.closed) {
    throw viteRecoveryNativeFailure();
  }
  return session;
}

function parseViteRecoveryOwnerUid(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0xffff_ffff ||
    typeof process.geteuid !== 'function' ||
    process.geteuid() !== value
  ) {
    throw viteRecoveryNativeFailure();
  }
  return value;
}
function parseViteRecoveryInstallId(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw viteRecoveryNativeFailure();
  }
  return value;
}

function parseViteRecoveryLaunchId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
  ) {
    throw viteRecoveryNativeFailure();
  }
  return value;
}

function parseViteRecoveryFileName(value: unknown, suffix: string): string {
  if (
    typeof value !== 'string' ||
    !value.endsWith(suffix) ||
    !/^[A-Za-z0-9_-]{1,128}\.recovery\.v1\.(?:lock|json)$/.test(value)
  ) {
    throw viteRecoveryNativeFailure();
  }
  return value;
}

function parseViteRecoveryTemporaryName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !/^\.[A-Za-z0-9_-]{1,128}\.recovery\.[0-9a-f-]{36}\.tmp$/.test(value)
  ) {
    throw viteRecoveryNativeFailure();
  }
  return value;
}

function parseNativeViteSnapshotSession(value: unknown): NativeViteSnapshotSession {
  if (!isNativeViteSnapshotHandle(value)) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}

function parseNativeViteSnapshotStaging(value: unknown): NativeViteSnapshotStaging {
  if (!isNativeViteSnapshotHandle(value)) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}

function parseNativeViteSnapshotPublished(value: unknown): {
  readonly published: NativeViteSnapshotPublished;
  readonly rootIdentity: FileIdentity;
} {
  if (!hasExactEnumerableKeys(value, ['published', 'rootIdentity'])) {
    throw viteSnapshotNativeFailure();
  }
  return Object.freeze({
    published: parseNativeViteSnapshotStagingOrPublished(value.published),
    rootIdentity: parseStrictNativeViteSnapshotIdentity(value.rootIdentity),
  });
}

function parseNativeViteSnapshotStagingOrPublished(value: unknown): NativeViteSnapshotPublished {
  if (!isNativeViteSnapshotHandle(value)) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}

function isNativeViteSnapshotHandle(
  value: unknown,
): value is NativeViteSnapshotSession & NativeViteSnapshotStaging & NativeViteSnapshotPublished {
  return isRecord(value) && Object.keys(value).length === 0;
}
function parseStrictNativeViteSnapshotIdentity(value: unknown): FileIdentity {
  if (!hasExactEnumerableKeys(value, ['device', 'inode'])) {
    throw viteSnapshotNativeFailure();
  }
  return parseIdentity(value, viteSnapshotNativeFailure);
}

function isNativeViteSnapshotSession(value: unknown): value is NativeViteSnapshotSession {
  return isRecord(value) && nativeViteSnapshotSessions.has(value);
}
function requireNativeViteSnapshotSession(value: unknown): NativeViteSnapshotSession {
  if (!isNativeViteSnapshotSession(value)) {
    throw viteSnapshotNativeFailure();
  }
  const state = nativeViteSnapshotSessions.get(value);
  if (state === undefined || state.closed) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}
function isNativeViteSnapshotStaging(value: unknown): value is NativeViteSnapshotStaging {
  return isRecord(value) && nativeViteSnapshotStagings.has(value);
}
function requireNativeViteSnapshotStaging(value: unknown): NativeViteSnapshotStaging {
  if (!isNativeViteSnapshotStaging(value)) {
    throw viteSnapshotNativeFailure();
  }
  const state = nativeViteSnapshotStagings.get(value);
  if (state === undefined || !state.active) {
    throw viteSnapshotNativeFailure();
  }
  requireNativeViteSnapshotSession(state.session);
  return value;
}
function isNativeViteSnapshotPublished(value: unknown): value is NativeViteSnapshotPublished {
  return isRecord(value) && nativeViteSnapshotPublished.has(value);
}
function requireNativeViteSnapshotPublished(value: unknown): NativeViteSnapshotPublished {
  if (!isNativeViteSnapshotPublished(value)) {
    throw viteSnapshotNativeFailure();
  }
  const state = nativeViteSnapshotPublished.get(value);
  if (state === undefined || !state.active) {
    throw viteSnapshotNativeFailure();
  }
  requireNativeViteSnapshotSession(state.session);
  return value;
}
function registerNativeViteSnapshotStaging(
  staging: NativeViteSnapshotStaging,
  session: NativeViteSnapshotSession,
): void {
  activeNativeViteSnapshotStagings.add(staging);
  const stagings =
    nativeViteSnapshotStagingsBySession.get(session) ?? new Set<NativeViteSnapshotStaging>();
  stagings.add(staging);
  nativeViteSnapshotStagingsBySession.set(session, stagings);
}
function registerNativeViteSnapshotPublished(
  published: NativeViteSnapshotPublished,
  session: NativeViteSnapshotSession,
): void {
  activeNativeViteSnapshotPublished.add(published);
  const publishedHandles =
    nativeViteSnapshotPublishedBySession.get(session) ?? new Set<NativeViteSnapshotPublished>();
  publishedHandles.add(published);
  nativeViteSnapshotPublishedBySession.set(session, publishedHandles);
}
function releaseNativeViteSnapshotStaging(
  staging: NativeViteSnapshotStaging,
  state: NativeViteSnapshotStagingState,
): void {
  state.active = false;
  activeNativeViteSnapshotStagings.delete(staging);
  const stagings = nativeViteSnapshotStagingsBySession.get(state.session);
  if (stagings === undefined) {
    return;
  }
  stagings.delete(staging);
  if (stagings.size === 0) {
    nativeViteSnapshotStagingsBySession.delete(state.session);
  }
}
function releaseNativeViteSnapshotPublished(
  published: NativeViteSnapshotPublished,
  state: NativeViteSnapshotPublishedState,
): void {
  state.active = false;
  activeNativeViteSnapshotPublished.delete(published);
  const publishedHandles = nativeViteSnapshotPublishedBySession.get(state.session);
  if (publishedHandles === undefined) {
    return;
  }
  publishedHandles.delete(published);
  if (publishedHandles.size === 0) {
    nativeViteSnapshotPublishedBySession.delete(state.session);
  }
}
function releaseNativeViteSnapshotSession(
  session: NativeViteSnapshotSession,
  state: NativeViteSnapshotSessionState,
): void {
  state.closed = true;
  for (const staging of [...(nativeViteSnapshotStagingsBySession.get(session) ?? [])]) {
    const stagingState = nativeViteSnapshotStagings.get(staging);
    if (stagingState !== undefined) {
      releaseNativeViteSnapshotStaging(staging, stagingState);
    }
  }
  for (const published of [...(nativeViteSnapshotPublishedBySession.get(session) ?? [])]) {
    const publishedState = nativeViteSnapshotPublished.get(published);
    if (publishedState !== undefined) {
      releaseNativeViteSnapshotPublished(published, publishedState);
    }
  }
  activeNativeViteSnapshotSessions.delete(session);
}

function parseViteSnapshotExpectedOwnerUid(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0xffff_ffff ||
    typeof process.geteuid !== 'function' ||
    value !== process.geteuid()
  ) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}
function parseViteSnapshotInstallId(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}

function parseViteSnapshotStagingName(value: unknown, installId: string): string {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9_-]{1,255}$/.test(value) ||
    !value.startsWith(`${installId}-`) ||
    value.length <= installId.length + 1 ||
    Buffer.byteLength(value, 'utf8') > MAX_NATIVE_PATH_COMPONENT_BYTES
  ) {
    throw viteSnapshotNativeFailure();
  }
  return value;
}

function parseViteSnapshotRelativePath(value: unknown): string {
  const relativePath = parseRelativePath(value);
  if (relativePath.split('/').length > MAX_NATIVE_VITE_SNAPSHOT_DEPTH) {
    throw viteSnapshotNativeFailure();
  }
  return relativePath;
}

function copyViteSnapshotWriteBytes(value: unknown, maximumBytes: number): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength > maximumBytes) {
    throw viteSnapshotNativeFailure();
  }
  try {
    const copied = Buffer.from(value);
    if (copied.byteLength !== value.byteLength) {
      zeroizeBuffer(copied);
      throw viteSnapshotNativeFailure();
    }
    return copied;
  } catch (error: unknown) {
    if (error instanceof OnboardingNativeError) {
      throw error;
    }
    throw viteSnapshotNativeFailure();
  }
}
function parseNativeCacheInteger(value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw viteCacheNativeFailure();
  }
  return value;
}

function parseNativeDecimalIdentity(value: unknown): string {
  if (typeof value !== 'string' || !DECIMAL_IDENTITY_PATTERN.test(value)) {
    throw viteCacheNativeFailure();
  }
  return value;
}
function parseStrictNativeViteCacheIdentity(value: unknown): FileIdentity {
  if (!hasExactEnumerableKeys(value, ['device', 'inode'])) {
    throw viteCacheNativeFailure();
  }
  return parseIdentity(value, viteCacheNativeFailure);
}

function parseStrictNativeViteCacheOwner(value: unknown): {
  readonly uid: number;
  readonly gid: number;
} {
  if (!hasExactEnumerableKeys(value, ['uid', 'gid'])) {
    throw viteCacheNativeFailure();
  }
  return parseViteCacheOwner(value);
}

function isNativeViteCacheEntryKind(value: unknown): value is CacheTreeEntry['kind'] {
  return (
    value === 'directory' ||
    value === 'regular-file' ||
    value === 'symlink' ||
    value === 'socket' ||
    value === 'fifo' ||
    value === 'block-device' ||
    value === 'character-device' ||
    value === 'unknown'
  );
}

function sameNativeFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameNativeViteCacheRootRecord(left: CacheRootRecord, right: CacheRootRecord): boolean {
  return (
    sameNativeFileIdentity(left.identity, right.identity) &&
    left.canonicalPath === right.canonicalPath &&
    left.device === right.device &&
    left.owner.uid === right.owner.uid &&
    left.owner.gid === right.owner.gid &&
    left.mode === right.mode
  );
}

function sameNativeViteCacheProvenance(
  left: ViteCacheProvenance,
  right: ViteCacheProvenance,
): boolean {
  return (
    left.version === right.version &&
    left.installId === right.installId &&
    left.canonicalParentPath === right.canonicalParentPath &&
    sameNativeViteCacheRootRecord(left.root, right.root) &&
    sameNativeViteCacheRootRecord(left.parent, right.parent) &&
    sameNativeFileIdentity(left.parentIdentity, right.parentIdentity) &&
    left.inverse.kind === right.inverse.kind &&
    left.inverse.canonicalPath === right.inverse.canonicalPath &&
    sameNativeFileIdentity(left.inverse.rootIdentity, right.inverse.rootIdentity) &&
    sameNativeFileIdentity(left.inverse.parentIdentity, right.inverse.parentIdentity)
  );
}

function isCanonicalViteCacheChildPath(parent: string, child: string): boolean {
  const prefix = parent === '/' ? '/' : `${parent}/`;
  const leaf = child.slice(prefix.length);
  return child.startsWith(prefix) && leaf.length > 0 && !leaf.includes('/');
}

function hasExactEnumerableKeys(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }
  const actualKeys = Object.keys(value).sort();
  const sortedExpected = [...expectedKeys].sort();
  return (
    actualKeys.length === sortedExpected.length &&
    actualKeys.every((key, index) => key === sortedExpected[index])
  );
}

function invokeNative(options: NativeSecureReadBeneathOptions): SecureReadResult {
  try {
    return parseNativeSecureReadResult(getBinding().secureReadBeneath(options));
  } catch (error: unknown) {
    throw nativeErrorFrom(error);
  }
}

function validateCredentialAuthority(authority: VerifiedAuthority): void {
  invokeNative({
    root: '/',
    expectedRoot: null,
    relativePath: authority.path.slice(1),
    expectedAuthority: authority.identity,
    deniedIdentities: [],
    maxBytes: authority.maxBytes,
    readContent: false,
  });
}
function credentialAuthorityKey(authority: VerifiedAuthority): string {
  return JSON.stringify([
    authority.projectId,
    authority.path,
    authority.identity.device,
    authority.identity.inode,
  ]);
}

function revokeCapabilitiesForAuthorityKeys(authorityKeys: readonly string[]): void {
  const capabilities = new Set<CredentialReadCapability>();
  for (const authorityKey of authorityKeys) {
    for (const capability of capabilitiesByAuthorityKey.get(authorityKey) ?? []) {
      capabilities.add(capability);
    }
  }
  for (const capability of capabilities) {
    const state = credentialCapabilities.get(capability);
    if (state !== undefined) {
      revokeCapability(capability, state);
    }
  }
}

function revokeCapability(
  capability: CredentialReadCapability,
  state: CredentialCapabilityState,
): void {
  if (!state.active) {
    return;
  }

  state.active = false;
  for (const authorityKey of state.authorityKeys ?? []) {
    const capabilities = capabilitiesByAuthorityKey.get(authorityKey);
    if (capabilities === undefined) {
      continue;
    }

    capabilities.delete(capability);
    if (capabilities.size === 0) {
      capabilitiesByAuthorityKey.delete(authorityKey);
    }
  }
  activeCredentialCapabilities.delete(capability);
  credentialCapabilities.delete(capability);
  state.authority = undefined;
  state.authorityKeys = undefined;
}

function registerCapability(
  capability: CredentialReadCapability,
  state: CredentialCapabilityState,
): void {
  for (const authorityKey of state.authorityKeys ?? []) {
    const capabilities =
      capabilitiesByAuthorityKey.get(authorityKey) ?? new Set<CredentialReadCapability>();
    capabilities.add(capability);
    capabilitiesByAuthorityKey.set(authorityKey, capabilities);
  }
}

function parseCredentialAuthority(
  authority: unknown,
  options: CredentialReadOptions,
): VerifiedAuthority {
  if (!isRecord(authority)) {
    throw credentialAuthorityInvalid();
  }
  const projectId = parseCredentialProjectId(authority.projectId);
  const rawPath = authority.path;
  const device = authority.device;
  const inode = authority.inode;
  const path = parseCanonicalAbsolutePath(rawPath, credentialAuthorityInvalid);
  if (path === '/') {
    throw credentialAuthorityInvalid();
  }
  const identity = parseIdentity(Object.freeze({ device, inode }), credentialAuthorityInvalid);
  return Object.freeze({
    projectId,
    path,
    identity,
    expectedOwnerUid: options.expectedOwnerUid,
    maxBytes: options.maxBytes,
  });
}

function parseCredentialProjectId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    Buffer.byteLength(value, 'utf8') > MAX_CREDENTIAL_PROJECT_ID_BYTES
  ) {
    throw credentialAuthorityInvalid();
  }
  return value;
}
function sliceCredentialPath(path: string): string {
  const relativePath = reflectApply(stringSlice, path, [1]);
  if (typeof relativePath !== 'string') {
    throw credentialAuthorityInvalid();
  }
  return relativePath;
}

function parseCredentialReadOptions(options: unknown): CredentialReadOptions {
  if (!isRecord(options)) {
    throw credentialAuthorityInvalid();
  }
  const expectedOwnerUid = options.expectedOwnerUid;
  const maxBytes = options.maxBytes;
  return Object.freeze({
    expectedOwnerUid: parseExpectedOwnerUid(expectedOwnerUid),
    maxBytes: parseMaximumBytes(maxBytes),
  });
}

function parseExpectedOwnerUid(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0xffff_ffff ||
    typeof process.geteuid !== 'function' ||
    value !== process.geteuid()
  ) {
    throw credentialAuthorityInvalid();
  }
  return value;
}

function parseIdentity(
  value: unknown,
  failure: () => OnboardingNativeError = pathDenied,
): FileIdentity {
  if (!isRecord(value)) {
    throw failure();
  }
  const device = value.device;
  const inode = value.inode;
  if (
    typeof device !== 'string' ||
    typeof inode !== 'string' ||
    device.length > MAX_NATIVE_IDENTITY_DECIMAL_BYTES ||
    inode.length > MAX_NATIVE_IDENTITY_DECIMAL_BYTES ||
    (device.length === MAX_NATIVE_IDENTITY_DECIMAL_BYTES &&
      device > MAX_NATIVE_IDENTITY_DECIMAL_VALUE) ||
    (inode.length === MAX_NATIVE_IDENTITY_DECIMAL_BYTES &&
      inode > MAX_NATIVE_IDENTITY_DECIMAL_VALUE) ||
    !DECIMAL_IDENTITY_PATTERN.test(device) ||
    !DECIMAL_IDENTITY_PATTERN.test(inode)
  ) {
    throw failure();
  }

  return Object.freeze({ device, inode });
}

function parseDeniedIdentities(value: unknown): readonly FileIdentity[] {
  if (!Array.isArray(value)) {
    throw pathDenied();
  }
  const deniedCount = value.length;
  if (deniedCount > MAX_DENIED_IDENTITIES) {
    throw pathDenied();
  }

  const identities: FileIdentity[] = [];
  const known = new Set<string>();
  for (let index = 0; index < deniedCount; index += 1) {
    const identity = parseIdentity(value[index]);
    const key = `${identity.device}:${identity.inode}`;
    if (known.has(key)) {
      throw pathDenied();
    }
    known.add(key);
    identities.push(identity);
  }
  return Object.freeze(identities);
}

function isBoundedPathComponent(component: string): boolean {
  return (
    component.length > 0 &&
    component !== '.' &&
    component !== '..' &&
    Buffer.byteLength(component, 'utf8') <= MAX_NATIVE_PATH_COMPONENT_BYTES
  );
}

function parseRelativePath(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_NATIVE_PATH_BYTES ||
    value.includes('\0') ||
    value.startsWith('/') ||
    value.endsWith('/')
  ) {
    throw pathDenied();
  }

  const components = value.split('/');
  if (
    components.length > MAX_NATIVE_PATH_COMPONENTS ||
    components.some((component) => !isBoundedPathComponent(component))
  ) {
    throw pathDenied();
  }
  return value;
}

function parseCanonicalAbsolutePath(
  value: unknown,
  failure: () => OnboardingNativeError = pathDenied,
): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_NATIVE_PATH_BYTES ||
    value.includes('\0') ||
    !value.startsWith('/') ||
    resolve(value) !== value
  ) {
    throw failure();
  }
  if (value === '/') {
    return value;
  }
  const components = value.slice(1).split('/');
  if (
    components.length > MAX_NATIVE_PATH_COMPONENTS ||
    components.some((component) => !isBoundedPathComponent(component))
  ) {
    throw failure();
  }
  return value;
}

function parseMaximumBytes(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_NATIVE_READ_BYTES
  ) {
    throw new OnboardingNativeError('SCG_NATIVE_READ_LIMIT', 'Secure native read limit exceeded.');
  }
  return value;
}

function parseNativeSecureReadResult(value: unknown): SecureReadResult {
  const invalidResult = (): OnboardingNativeError =>
    nativeFailure(new TypeError('Invalid secure native read result.'));
  let bytes: Buffer | undefined;

  try {
    if (!isRecord(value)) {
      throw invalidResult();
    }

    const resultBytes = value.bytes;
    if (!isBuffer(resultBytes)) {
      throw invalidResult();
    }
    bytes = resultBytes;

    const identity = parseIdentity(value.identity, invalidResult);
    const linkCount = value.linkCount;
    const mode = value.mode;
    if (
      typeof linkCount !== 'number' ||
      !Number.isSafeInteger(linkCount) ||
      linkCount < 0 ||
      typeof mode !== 'number' ||
      !Number.isSafeInteger(mode) ||
      mode < 0 ||
      mode > 0xffff_ffff
    ) {
      throw invalidResult();
    }

    return Object.freeze({
      bytes,
      identity,
      linkCount,
      mode,
    });
  } catch (error: unknown) {
    try {
      zeroizeBufferOnFailure(bytes);
    } catch (cleanupError: unknown) {
      throw credentialCleanupFailure(error, cleanupError);
    }
    throw error;
  }
}

function zeroizeBufferOnFailure(value: Buffer | undefined): void {
  if (value !== undefined) {
    zeroizeBuffer(value);
  }
}

function credentialCleanupFailure(primary: unknown, cleanup: unknown): AggregateError {
  return new AggregateError([primary, cleanup], 'Credential operation and buffer cleanup failed.', {
    cause: primary,
  });
}

function parseLifecyclePath(value: unknown): string {
  const path = parseCanonicalAbsolutePath(value);
  if (path === '/') {
    throw pathDenied();
  }
  return path;
}

function parseLifecycleMode(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 0o7777) {
    throw pathDenied();
  }
  return value;
}

function parseLifecycleSize(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_NATIVE_LIFECYCLE_WRITE_BYTES
  ) {
    throw pathDenied();
  }
  return value;
}
function isSha256Digest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
}
function isLifecycleStatSnapshot(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= 256 && /^[-0-9:]+$/.test(value)
  );
}

function copyLifecycleBytes(value: unknown): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength > MAX_NATIVE_LIFECYCLE_WRITE_BYTES) {
    throw pathDenied();
  }
  return Buffer.from(value);
}
function invokeLifecycleWithZeroizedBytes<T>(bytes: Buffer, operation: () => T): T {
  let outcome:
    | { readonly failure: unknown; readonly succeeded: false }
    | { readonly succeeded: true; readonly value: T };
  try {
    outcome = { succeeded: true, value: operation() };
  } catch (error: unknown) {
    outcome = { failure: error, succeeded: false };
  }

  let hasZeroizationFailure = false;
  let zeroizationFailure: unknown;
  try {
    zeroizeBuffer(bytes);
  } catch (error: unknown) {
    hasZeroizationFailure = true;
    zeroizationFailure = error;
  }

  if (!outcome.succeeded) {
    if (hasZeroizationFailure) {
      recordLifecycleZeroizationFailure(outcome.failure, zeroizationFailure);
    }
    throw outcome.failure;
  }
  if (hasZeroizationFailure) {
    throw zeroizationFailure;
  }
  return outcome.value;
}
function recordLifecycleZeroizationFailure(
  primaryFailure: unknown,
  zeroizationFailure: unknown,
): void {
  if (typeof primaryFailure !== 'object' || primaryFailure === null) {
    return;
  }
  try {
    Object.defineProperty(primaryFailure, 'zeroizationFailure', {
      configurable: true,
      enumerable: false,
      value: zeroizationFailure,
    });
  } catch {
    // Preserve the primary native outcome when its error object cannot be annotated.
  }
}

function parseNativeLifecycleExactFile(value: unknown): NativeLifecycleExactFile {
  if (!isRecord(value) || !hasExactEnumerableKeys(value, ['path', 'identity', 'mode'])) {
    throw pathDenied();
  }
  return Object.freeze({
    path: parseLifecyclePath(value.path),
    identity: parseIdentity(value.identity),
    mode: parseLifecycleMode(value.mode),
  });
}
function parseNativeLifecycleContentExactFile(value: unknown): NativeLifecycleContentExactFile {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['path', 'identity', 'mode', 'size', 'digest'])
  ) {
    throw pathDenied();
  }
  const digest = value.digest;
  if (!isSha256Digest(digest)) {
    throw pathDenied();
  }
  return Object.freeze({
    path: parseLifecyclePath(value.path),
    identity: parseIdentity(value.identity),
    mode: parseLifecycleMode(value.mode),
    size: parseLifecycleSize(value.size),
    digest,
  });
}
function parseNativeLifecycleWalExactFile(value: unknown): NativeLifecycleWalExactFile {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['path', 'identity', 'mode', 'size', 'digest', 'stat'])
  ) {
    throw pathDenied();
  }
  const content = parseNativeLifecycleContentExactFile({
    path: value.path,
    identity: value.identity,
    mode: value.mode,
    size: value.size,
    digest: value.digest,
  });
  const stat = value.stat;
  if (!isLifecycleStatSnapshot(stat)) {
    throw pathDenied();
  }
  return Object.freeze({ ...content, stat });
}

function parseNativeLifecycleQuarantineResult(value: unknown): NativeLifecycleQuarantineResult {
  if (!isRecord(value)) {
    throw nativeFailure();
  }
  if (value.state === 'completed') {
    if (hasExactEnumerableKeys(value, ['state'])) {
      return Object.freeze({ state: 'completed' });
    }
    if (hasExactEnumerableKeys(value, ['state', 'quarantineIdentity', 'quarantine'])) {
      const completed = value as Record<string, unknown>;
      return Object.freeze({
        state: 'completed',
        quarantineIdentity: parseIdentity(completed.quarantineIdentity),
        quarantine: parseNativeLifecycleQuarantine(completed.quarantine),
      });
    }
    throw nativeFailure();
  }
  if (value.state === 'indeterminate' && hasExactEnumerableKeys(value, ['state'])) {
    return Object.freeze({ state: 'indeterminate' });
  }
  if (
    value.state === 'indeterminate' &&
    hasExactEnumerableKeys(value, ['state', 'targetIdentity', 'quarantineIdentity', 'quarantine'])
  ) {
    const quarantine = parseNativeLifecycleQuarantine(value.quarantine);
    return Object.freeze({
      state: 'indeterminate',
      ...(value.targetIdentity === null
        ? {}
        : { targetIdentity: parseIdentity(value.targetIdentity) }),
      ...(value.quarantineIdentity === null
        ? {}
        : { quarantineIdentity: parseIdentity(value.quarantineIdentity) }),
      quarantine,
    });
  }
  throw nativeFailure();
}

function parseNativeLifecycleCreationIntent(value: unknown): NativeLifecycleCreationIntent {
  if (!isNativeLifecycleCreationIntentHandle(value)) {
    throw nativeFailure();
  }
  const intent = value as NativeLifecycleCreationIntent;
  nativeLifecycleCreationIntents.add(intent);
  return intent;
}
function requireNativeLifecycleCreationIntent(
  value: NativeLifecycleCreationIntent,
): NativeLifecycleCreationIntent {
  if (!isNativeLifecycleCreationIntentHandle(value) || !nativeLifecycleCreationIntents.has(value)) {
    throw nativeFailure();
  }
  return value;
}
function isNativeLifecycleCreationIntentHandle(
  value: unknown,
): value is NativeLifecycleCreationIntent {
  return isRecord(value) && Object.keys(value).length === 0;
}
function requireNativeLifecycleReservation(
  value: NativeLifecycleStagedFileReservation | NativeLifecycleStagedDirectoryReservation,
): NativeLifecycleStagedFileReservation | NativeLifecycleStagedDirectoryReservation {
  if (
    isNativeLifecycleStagedFileReservationHandle(value) &&
    nativeLifecycleStagedFileReservations.has(value)
  ) {
    return value;
  }
  if (
    isNativeLifecycleStagedDirectoryReservationHandle(value) &&
    nativeLifecycleStagedDirectoryReservations.has(value)
  ) {
    return value;
  }
  throw nativeFailure();
}
function parseNativeLifecycleCreationIntentResult(
  value: unknown,
): NativeLifecycleCreationIntentResult {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['state', 'intent']) ||
    (value.state !== 'completed' && value.state !== 'indeterminate')
  ) {
    throw nativeFailure();
  }
  return Object.freeze({
    state: value.state,
    intent: parseNativeLifecycleCreationIntent(value.intent),
  });
}
function parseNativeLifecycleLock(value: unknown): NativeLifecycleLock {
  if (!isNativeLifecycleLockHandle(value)) {
    throw nativeFailure();
  }
  const lock = value as NativeLifecycleLock;
  registerNativeLifecycleHandle(lock, 'lock');
  nativeLifecycleLocks.add(lock);
  return lock;
}

function requireNativeLifecycleLock(value: NativeLifecycleLock): NativeLifecycleLock {
  if (!isNativeLifecycleLockHandle(value) || !nativeLifecycleLocks.has(value)) {
    throw nativeFailure();
  }
  return value;
}
function requireIssuedNativeLifecycleLock(value: NativeLifecycleLock): NativeLifecycleLock {
  const state = nativeLifecycleHandleStates.get(value);
  if (!isNativeLifecycleLockHandle(value) || state?.kind !== 'lock') {
    throw nativeFailure();
  }
  return value;
}

function isNativeLifecycleLockHandle(value: unknown): value is NativeLifecycleLock {
  return isRecord(value) && Object.keys(value).length === 0;
}

function parseNativeLifecycleQuarantine(value: unknown): NativeLifecycleQuarantine {
  if (!isNativeLifecycleQuarantineHandle(value)) {
    throw nativeFailure();
  }
  const quarantine = value as NativeLifecycleQuarantine;
  registerNativeLifecycleHandle(quarantine, 'quarantine');
  return quarantine;
}

function requireIssuedNativeLifecycleQuarantine(
  value: NativeLifecycleQuarantine,
): NativeLifecycleQuarantine {
  const state = nativeLifecycleHandleStates.get(value);
  if (!isNativeLifecycleQuarantineHandle(value) || state?.kind !== 'quarantine') {
    throw nativeFailure();
  }
  return value;
}

function isNativeLifecycleQuarantineHandle(value: unknown): value is NativeLifecycleQuarantine {
  return isRecord(value) && Object.keys(value).length === 0;
}

function parseNativeLifecycleStagedFileReservation(
  value: unknown,
): NativeLifecycleStagedFileReservation {
  if (!isNativeLifecycleStagedFileReservationHandle(value)) {
    throw nativeFailure();
  }
  const reservation = value as NativeLifecycleStagedFileReservation;
  registerNativeLifecycleHandle(reservation, 'reservation');
  nativeLifecycleStagedFileReservations.add(reservation);
  return reservation;
}

function requireNativeLifecycleStagedFileReservation(
  value: NativeLifecycleStagedFileReservation,
): NativeLifecycleStagedFileReservation {
  if (
    !isNativeLifecycleStagedFileReservationHandle(value) ||
    !nativeLifecycleStagedFileReservations.has(value)
  ) {
    throw nativeFailure();
  }
  return value;
}
function requireIssuedNativeLifecycleStagedFileReservation(
  value: NativeLifecycleStagedFileReservation,
): NativeLifecycleStagedFileReservation {
  const state = nativeLifecycleHandleStates.get(value);
  if (!isNativeLifecycleStagedFileReservationHandle(value) || state?.kind !== 'reservation') {
    throw nativeFailure();
  }
  return value;
}

function isNativeLifecycleStagedFileReservationHandle(
  value: unknown,
): value is NativeLifecycleStagedFileReservation {
  return isRecord(value) && Object.keys(value).length === 0;
}

function parseNativeLifecycleStagedDirectoryReservation(
  value: unknown,
): NativeLifecycleStagedDirectoryReservation {
  if (!isNativeLifecycleStagedDirectoryReservationHandle(value)) {
    throw nativeFailure();
  }
  const reservation = value as NativeLifecycleStagedDirectoryReservation;
  registerNativeLifecycleHandle(reservation, 'reservation');
  nativeLifecycleStagedDirectoryReservations.add(reservation);
  return reservation;
}

function requireNativeLifecycleStagedDirectoryReservation(
  value: NativeLifecycleStagedDirectoryReservation,
): NativeLifecycleStagedDirectoryReservation {
  if (
    !isNativeLifecycleStagedDirectoryReservationHandle(value) ||
    !nativeLifecycleStagedDirectoryReservations.has(value)
  ) {
    throw nativeFailure();
  }
  return value;
}
function requireIssuedNativeLifecycleStagedDirectoryReservation(
  value: NativeLifecycleStagedDirectoryReservation,
): NativeLifecycleStagedDirectoryReservation {
  const state = nativeLifecycleHandleStates.get(value);
  if (!isNativeLifecycleStagedDirectoryReservationHandle(value) || state?.kind !== 'reservation') {
    throw nativeFailure();
  }
  return value;
}

function isNativeLifecycleStagedDirectoryReservationHandle(
  value: unknown,
): value is NativeLifecycleStagedDirectoryReservation {
  return isRecord(value) && Object.keys(value).length === 0;
}

function parseNativeLifecycleWalReadResult(value: unknown): NativeLifecycleWalReadResult {
  if (!isRecord(value)) {
    throw nativeFailure();
  }
  if (value.state === 'indeterminate' && hasExactEnumerableKeys(value, ['state'])) {
    return Object.freeze({ state: 'indeterminate' });
  }
  if (
    value.state !== 'completed' ||
    !hasExactEnumerableKeys(value, ['state', 'bytes', 'identity', 'size', 'digest', 'stat']) ||
    !isBuffer(value.bytes)
  ) {
    throw nativeFailure();
  }
  const size = parseLifecycleSize(value.size);
  if (
    size !== value.bytes.byteLength ||
    !isSha256Digest(value.digest) ||
    !isLifecycleStatSnapshot(value.stat)
  ) {
    throw nativeFailure();
  }
  return Object.freeze({
    state: 'completed',
    bytes: value.bytes,
    identity: parseIdentity(value.identity),
    size,
    digest: value.digest,
    stat: value.stat,
  });
}
function parseNativeLifecycleMutationResult(value: unknown): NativeLifecycleMutationResult {
  if (!isRecord(value)) {
    throw nativeFailure();
  }
  if (value.state === 'completed') {
    if (!hasExactEnumerableKeys(value, ['state'])) {
      throw nativeFailure();
    }
    return Object.freeze({ state: 'completed' });
  }
  if (value.state === 'indeterminate') {
    const keys = Object.keys(value).sort();
    if (keys.length === 1 && keys[0] === 'state') {
      return Object.freeze({ state: 'indeterminate' });
    }
    const expectedKeys = ['quarantineIdentity', 'state', 'targetIdentity'];
    if (
      keys.length !== expectedKeys.length ||
      !keys.every((key, index) => key === expectedKeys[index])
    ) {
      throw nativeFailure();
    }
    return Object.freeze({
      state: 'indeterminate',
      ...(value.targetIdentity === null
        ? {}
        : { targetIdentity: parseIdentity(value.targetIdentity) }),
      ...(value.quarantineIdentity === null
        ? {}
        : { quarantineIdentity: parseIdentity(value.quarantineIdentity) }),
    });
  }
  throw nativeFailure();
}

function parseNativeLifecycleCreateResult(value: unknown): NativeLifecycleCreateResult {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['state', 'identity']) ||
    (value.state !== 'completed' && value.state !== 'indeterminate')
  ) {
    throw nativeFailure();
  }
  return Object.freeze({ state: value.state, identity: parseIdentity(value.identity) });
}

function parseNativeLifecycleStagedFileReservationCreateResult(
  value: unknown,
): NativeLifecycleStagedFileReservationCreateResult {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['state', 'identity', 'reservation']) ||
    (value.state !== 'completed' && value.state !== 'indeterminate')
  ) {
    throw nativeFailure();
  }
  return Object.freeze({
    state: value.state,
    identity: parseIdentity(value.identity),
    reservation: parseNativeLifecycleStagedFileReservation(value.reservation),
  });
}

function parseNativeLifecycleStagedDirectoryReservationCreateResult(
  value: unknown,
): NativeLifecycleStagedDirectoryReservationCreateResult {
  if (
    !isRecord(value) ||
    !hasExactEnumerableKeys(value, ['state', 'identity', 'reservation']) ||
    (value.state !== 'completed' && value.state !== 'indeterminate')
  ) {
    throw nativeFailure();
  }
  return Object.freeze({
    state: value.state,
    identity: parseIdentity(value.identity),
    reservation: parseNativeLifecycleStagedDirectoryReservation(value.reservation),
  });
}

function isLifecycleBinding(value: unknown): value is LifecycleNativeBinding {
  return (
    isRecord(value) &&
    typeof value.secureReadBeneath === 'function' &&
    typeof value.acquireLifecycleLock === 'function' &&
    typeof value.releaseLifecycleLock === 'function' &&
    typeof value.releaseLifecycleLockSession === 'function' &&
    typeof value.revalidateLifecycleLock === 'function' &&
    typeof value.validateExactCredential === 'function' &&
    typeof value.validateExactDirectory === 'function' &&
    typeof value.readExactLifecycleWal === 'function' &&
    typeof value.prepareLifecycleCreationIntent === 'function' &&
    typeof value.recoverLifecycleCreationIntent === 'function' &&
    typeof value.reserveCredentialFromIntent === 'function' &&
    typeof value.reserveDirectoryFromIntent === 'function' &&
    typeof value.reserveLifecycleFileFromIntent === 'function' &&
    typeof value.retainReservationForRecovery === 'function' &&
    typeof value.createLifecycleStagedFile === 'function' &&
    typeof value.reserveLifecycleStagedFile === 'function' &&
    typeof value.writeLifecycleStagedFile === 'function' &&
    typeof value.validateLifecycleStagedFileReservation === 'function' &&
    typeof value.syncLifecycleStagedFileReservation === 'function' &&
    typeof value.publishReservedLifecycleStagedFileNoReplace === 'function' &&
    typeof value.closeLifecycleStagedFileReservation === 'function' &&
    typeof value.discardLifecycleStagedFileReservation === 'function' &&
    typeof value.publishLifecycleStagedFileNoReplace === 'function' &&
    typeof value.replaceLifecycleStagedFileExact === 'function' &&
    typeof value.replaceReservedLifecycleFileExact === 'function' &&
    typeof value.replaceReservedLifecycleOrdinaryFileExact === 'function' &&
    typeof value.quarantineLifecycleExactFile === 'function' &&
    typeof value.quarantineLifecycleExactCredential === 'function' &&
    typeof value.createLifecycleStagedDirectory === 'function' &&
    typeof value.publishReservedLifecycleStagedDirectoryNoReplace === 'function' &&
    typeof value.closeLifecycleStagedDirectoryReservation === 'function' &&
    typeof value.syncLifecycleStagedDirectoryReservation === 'function' &&
    typeof value.discardLifecycleStagedDirectoryReservation === 'function' &&
    typeof value.publishLifecycleStagedDirectoryNoReplace === 'function' &&
    typeof value.quarantineLifecycleExactDirectory === 'function' &&
    typeof value.finalizeLifecycleQuarantine === 'function' &&
    typeof value.restoreLifecycleQuarantine === 'function' &&
    typeof value.removeExactWal === 'function' &&
    typeof value.removeExactCredential === 'function' &&
    typeof value.removeExactStagedFile === 'function'
  );
}
function isSecureReadBinding(value: unknown): value is SecureReadBinding {
  return isRecord(value) && typeof value.secureReadBeneath === 'function';
}
function isViteCacheBinding(value: unknown): value is ViteCacheNativeBinding {
  return (
    isRecord(value) &&
    typeof value.secureReadBeneath === 'function' &&
    typeof value.openViteCacheSession === 'function' &&
    typeof value.scanViteCacheTree === 'function' &&
    typeof value.scanViteCacheCanaries === 'function' &&
    typeof value.watchViteCacheTree === 'function' &&
    typeof value.closeViteCacheWatcher === 'function' &&
    typeof value.closeViteCacheSession === 'function'
  );
}
function isViteRecoveryBinding(value: unknown): value is ViteRecoveryNativeBinding {
  return (
    isRecord(value) &&
    typeof value.secureReadBeneath === 'function' &&
    typeof value.openViteRecoveryDirectorySession === 'function' &&
    typeof value.tryLockViteRecoveryDirectorySession === 'function' &&
    typeof value.createViteRecoveryChildAuthority === 'function' &&
    typeof value.closeViteRecoveryChildAuthority === 'function' &&
    typeof value.verifyManagedViteChildLaunchAuthority === 'function' &&
    typeof value.releaseManagedViteChildLaunchAuthority === 'function' &&
    typeof value.readViteRecoveryManifest === 'function' &&
    typeof value.replaceViteRecoveryManifest === 'function' &&
    typeof value.closeViteRecoveryDirectorySession === 'function'
  );
}

function isViteSnapshotBinding(value: unknown): value is ViteCacheNativeBinding {
  return (
    isViteCacheBinding(value) &&
    typeof value.openViteSnapshotSession === 'function' &&
    typeof value.createViteSnapshotStaging === 'function' &&
    typeof value.writeViteSnapshotStagingFile === 'function' &&
    typeof value.publishViteSnapshotStaging === 'function' &&
    typeof value.persistViteSnapshotCommitment === 'function' &&
    typeof value.discardViteSnapshotStaging === 'function' &&
    typeof value.removeViteSnapshotPublished === 'function' &&
    typeof value.closeViteSnapshotSession === 'function'
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nativeUnavailable(cause?: unknown): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_UNAVAILABLE_CODE,
    'Secure native reads are unavailable.',
    cause,
  );
}
function viteCacheNativeUnavailable(): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_UNAVAILABLE_CODE,
    'Managed Vite cache native support is unavailable.',
  );
}
function viteRecoveryNativeUnavailable(): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_UNAVAILABLE_CODE,
    'Native Vite recovery directory support is unavailable.',
  );
}

function viteSnapshotNativeUnavailable(): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_UNAVAILABLE_CODE,
    'Native Vite snapshot support is unavailable.',
  );
}

function viteSnapshotNativeFailure(): OnboardingNativeError {
  return new OnboardingNativeError(NATIVE_FAILURE_CODE, 'Native Vite snapshot operation failed.');
}

function viteCacheNativeFailure(): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_FAILURE_CODE,
    'Managed Vite cache native operation failed.',
  );
}
function viteRecoveryNativeFailure(): OnboardingNativeError {
  return new OnboardingNativeError(
    NATIVE_FAILURE_CODE,
    'Native Vite recovery directory operation failed.',
  );
}

function nativeFailure(cause?: unknown): OnboardingNativeError {
  return new OnboardingNativeError(NATIVE_FAILURE_CODE, 'Secure native read failed.', cause);
}

function pathDenied(cause?: unknown): OnboardingNativeError {
  return new OnboardingNativeError(
    'SCG_NATIVE_PATH_DENIED',
    'Secure native read was denied.',
    cause,
  );
}

function credentialAuthorityInvalid(): OnboardingNativeError {
  return new OnboardingNativeError(
    'SCG_CREDENTIAL_AUTHORITY_INVALID',
    'Credential authority is invalid.',
  );
}
function credentialBufferZeroizationFailed(): OnboardingNativeError {
  return new OnboardingNativeError(NATIVE_FAILURE_CODE, 'Credential buffer zeroization failed.');
}

function nativeErrorFrom(error: unknown): OnboardingNativeError {
  if (error instanceof OnboardingNativeError) {
    return error;
  }
  if (!isRecord(error) || typeof error.code !== 'string') {
    return nativeFailure(error);
  }

  switch (error.code) {
    case 'SCG_NATIVE_PATH_DENIED':
      return pathDenied(error);
    case 'SCG_NATIVE_IDENTITY_MISMATCH':
      return new OnboardingNativeError(
        'SCG_NATIVE_IDENTITY_MISMATCH',
        'Secure native read identity did not match.',
        error,
      );
    case 'SCG_NATIVE_READ_LIMIT':
      return new OnboardingNativeError(
        'SCG_NATIVE_READ_LIMIT',
        'Secure native read limit exceeded.',
        error,
      );
    case NATIVE_FAILURE_CODE:
      return nativeFailure(error);
    default:
      return nativeFailure(error);
  }
}
