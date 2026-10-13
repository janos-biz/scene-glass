import { Buffer } from 'node:buffer';
import { createHash, randomFillSync, randomUUID } from 'node:crypto';
import { type Dirent, type Stats } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  opendir,
  readdir,
  realpath,
  rename,
  writeFile,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';

import {
  parseProjectConfigV1,
  parseServerConfigV1,
  type ProjectConfigV1,
  type ServerConfigV1,
} from '@scene-glass/contracts';

import {
  parseStaticHostDescriptorJsonV1,
  parseViteHostDescriptorJsonV1,
  serializeStaticHostDescriptorV1,
  serializeViteHostDescriptorV1,
  type TrustedDescriptorProject,
  type TrustedDescriptorProjectSet,
} from '../descriptors.js';
import { revokeCredentialReadCapability, secureReadBeneath } from '../native.js';
import { type DeviceDriftOutcome, repairDeviceDrift } from './device-drift.js';
import {
  CREDENTIAL_AUTHORITY_REGISTRY_FILENAME,
  MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES,
  parseCredentialAuthorityRegistryJsonV1,
  serializeCredentialAuthorityRegistryV1,
  verifyCredentialAuthorities,
  withSelectedCredential,
  type CredentialAuthorityRegistryEntry,
  type CredentialAuthorityRegistryV1,
} from '../credential-authority.js';
import type { CredentialAuthority, FileIdentity } from '../types.js';
import {
  applySetupTransaction,
  applyUninstallTransaction,
  compensateSetupTransaction,
  openSetupTransactionAuthority,
  publishSetupTransaction,
  recoverLifecycle,
  type LifecycleAbsentPreimage,
  type LifecycleAdvisoryLock,
  type LifecycleCredentialPreimage,
  type LifecycleFileSnapshot,
  type LifecycleMutationOperation,
  LifecycleTransactionError,
  lifecycleTransactionConvergence,
  type LifecyclePreimage,
  type LifecycleTransactionPort,
  type SetupReservedCredentialAuthority,
  type SetupCreatedCredentialAuthority,
  type SetupDirectoryCandidate,
  type SetupFinalization,
  type SetupTransactionReceipt,
} from './transaction.js';
import {
  createNodeLifecycleTransactionPort,
  reconstructOwnedStaticFilePreimage,
} from './node-transaction-port.js';
import {
  parseLifecycleReceiptJsonV1,
  parseSetupManifestJsonV1,
  parseWalRecordJson,
  type ObservedOwnedTarget,
} from './provenance.js';
import {
  finalizeHostIntegrationPlan,
  planHostIntegration,
  managedVitePluginFromConfig,
  resolveDeclaredViteOriginPolicy,
  STATIC_LOADER_MARKER,
  type DeclaredViteOriginPolicy,
  type FinalizedHostIntegrationPlan,
  type HostIntegrationPlan,
  type HostOverride,
  type HostPlanInput,
} from './host-plan.js';
import {
  createTransactionObservedCredentialAuthority,
  LifecyclePreparedStartUnavailableError,
  LifecycleStartDiagnosticError,
  type LifecycleBuildFacts,
  type LifecycleDataValue,
  type LifecycleEnginePort,
  type LifecycleForegroundMcp,
  type LifecycleInspection,
  type LifecyclePreparedStart,
  type LifecycleCleanupContext,
  type LifecycleSetupFacts,
  type LifecycleSetupPreflightInput,
  type LifecycleSetupTransaction,
  type LifecycleStartFacts,
  type LifecycleUninstallTransaction,
  type SetupMutationPreparation,
  type SetupMutationReceipt,
  type SetupPlanBuildReceipt,
  type TransactionObservedCredentialAuthorityIssuer,
  type UninstallObservation,
} from './engine.js';
import {
  createNodeFinalizedVerificationAuthority,
  createNodeLifecycleVerificationPorts,
  type NodeLifecycleVerificationPorts,
  type NodeLifecycleVerificationPortOptions,
  type NodeVerificationAuthority,
  type OpaqueSecretPersistenceMatcher,
} from './node-verification-port.js';
import { LiveDiagnosticError } from './verification.js';
import {
  isStrictLegacyBootstrap,
  planConfigOperation,
  projectConfigForSetup,
  type ConfigFileFact,
  type ConfigHomeFacts,
  type ConfigOperationPlan,
  type SetupProjectSeed,
} from './config.js';
import type {
  LifecycleReceiptV1,
  OwnedCredentialAuthorityRegistryArtifact,
  OwnedHunk,
  RestoreOwnedFileInverseOperation,
  SemanticConfigImage,
  SemanticCredentialAuthorityRegistryImage,
  SetupManifestV1,
  SetupPlan,
} from './types.js';

const STATE_DIRECTORY = '.scg/onboarding';
const STATE_ROOT_FILENAMES = new Set([
  'lifecycle.wal.v1.json',
  'manifest.v1.json',
  'receipt.v1.json',
]);
const MAX_SOURCE_FILES = 4_096;
const MAX_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_DECLARED_VITE_FILE_BYTES = 64 * 1024;
const MAX_DECLARED_VITE_AGGREGATE_BYTES = 8 * 1024 * 1024;
const MAX_WAL_BYTES = 32 * 1024 * 1024;
const MAX_STATE_ROOT_ENTRIES = 3;
const MAX_SOURCE_DIRECTORIES = 8_192;
const MAX_SOURCE_ENTRIES = 100_000;
const MAX_SOURCE_DEPTH = 32;
const MAX_SOURCE_PATH_BYTES = 1_024;
const MAX_TOKEN_SOURCE_BYTES = 8 * 1024;
const MAX_GITIGNORE_RULES = 1_024;
const MAX_GITIGNORE_PATTERN_BYTES = MAX_SOURCE_PATH_BYTES;
const DEFAULT_DIAGNOSTIC_TIMEOUT_MS = 30_000;
const CREDENTIAL_KEY = 'SCENE_GLASS_HOST_TOKEN';
const VITE_LOADER_URL_KEY = 'VITE_SCENE_GLASS_LOADER_URL';
const VITE_PROJECT_ID_KEY = 'VITE_SCENE_GLASS_PROJECT_ID';
const VITE_PROJECT_TOKEN_KEY = 'VITE_SCENE_GLASS_PROJECT_TOKEN';
const LOADER_URL = 'http://127.0.0.1:4175/scene-glass-loader.js';
const PLANNING_TEXT_EXTENSIONS = new Set([
  '.cjs',
  '.css',
  '.html',
  '.js',
  '.jsx',
  '.json',
  '.mjs',
  '.ts',
  '.tsx',
  '.vue',
]);

export interface NodeLifecycleFilesystem {
  readonly lstat: typeof lstat;
  readonly mkdir: typeof mkdir;
  /** Retained only for injected filesystem compatibility; secure reads never use it. */
  readonly open?: typeof open;
  readonly readdir: typeof readdir;
  readonly opendir: typeof opendir;
  readonly realpath: typeof realpath;
  readonly rename: typeof rename;
  readonly writeFile: typeof writeFile;
}

export interface NodeLifecycleRandom {
  readonly fill: (target: Uint8Array) => void;
  readonly uuid: () => string;
}

export interface NodeForegroundMcpLauncher {
  readonly launch: (
    input: Readonly<{
      readonly configPath: string;
      readonly manifest: SetupManifestV1;
      readonly selectedProjectId: string;
      readonly projects: readonly Readonly<{
        readonly projectId: string;
        readonly tokenEnv: string;
        readonly credentialAuthority: CredentialAuthority;
      }>[];
      readonly lifecycleOrigin: unknown;
    }>,
  ) => Promise<LifecycleForegroundMcp>;
}

export interface NodeLifecycleHostOptions {
  readonly rootPath?: string;
  readonly port: number;
  readonly override?: HostOverride;
  /** The host-owned, gitignored source that contains the browser/server token. */
  readonly credentialPath: string;
}

export interface NodeLifecycleEnginePortOptions {
  /** The canonical checkout recorded by the executable before lifecycle entry. */
  readonly checkoutRoot: string;
  /** The working directory supplied by the executable, never read from process implicitly. */
  readonly cwd: string;
  /** An explicit home avoids observing a user's actual home in tests. */
  readonly homeDirectory: string;
  /** Full per-host lifecycle state root; omitted callers retain the legacy checkout location. */
  readonly stateRootPath?: string;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly cliConfigPath?: string;
  readonly project: unknown;
  readonly host: NodeLifecycleHostOptions;
  readonly approval: (
    input: Readonly<{
      readonly preview: SetupPlan['preview'];
      readonly digest: Readonly<{
        readonly algorithm: 'sha256';
        readonly value: string;
        readonly operationCount: number;
      }>;
    }>,
  ) => Promise<boolean>;
  readonly verification: NodeLifecycleVerificationPorts | NodeLifecycleVerificationPortOptions;
  readonly filesystem?: Partial<NodeLifecycleFilesystem>;
  readonly random?: Partial<NodeLifecycleRandom>;
  readonly transactionPort?: LifecycleTransactionPort;
  readonly foregroundMcp?: NodeForegroundMcpLauncher;
  readonly diagnosticTimeoutMs?: number;
}

interface SetupAuthority {
  readonly receiptId: string;
  readonly config: ConfigOperationPlan;
  readonly host: HostIntegrationPlan;
  readonly plan: SetupPlan;
  readonly preimages: readonly LifecyclePreimage[];
  readonly projectRoot: string;
  readonly expectedHostRoot: FileIdentity;
  readonly registryCandidate: RegistrySetupCandidate;
  readonly predecessor: SetupPredecessorWitness;
  readonly approvalWitness: string;
}
interface SetupInspectionAuthority {
  readonly inspectionId: string;
  readonly config: ConfigOperationPlan;
  readonly host: HostIntegrationPlan;
  readonly preimages: readonly LifecyclePreimage[];
  readonly projectRoot: string;
  readonly expectedHostRoot: FileIdentity;
  readonly registryCandidate: RegistrySetupCandidate;
  readonly predecessor: SetupPredecessorWitness;
  readonly approvalWitness: string;
}
interface SetupPredecessorWitness {
  readonly state: 'absent' | 'receipt';
  readonly receipt?: LifecycleReceiptV1;
}
interface SetupApprovalAuthority {
  readonly receiptId: string;
  readonly planDigest: string;
  state: 'pending' | 'approved' | 'candidate-issued' | 'consumed';
  candidate?: Uint8Array;
}
interface AuthorityRegistryFact {
  readonly path: string;
  readonly registry: CredentialAuthorityRegistryV1 | undefined;
  readonly mode: number | undefined;
}

interface RegistrySetupCandidate {
  readonly fact: AuthorityRegistryFact;
  readonly preimage: SemanticCredentialAuthorityRegistryImage;
  readonly selectedProject: ProjectConfigV1;
  readonly config: ServerConfigV1;
}

interface FinalizedRegistryMutation {
  readonly artifact: OwnedCredentialAuthorityRegistryArtifact | undefined;
  readonly operation: LifecycleMutationOperation | undefined;
  readonly configuredProjects: TrustedDescriptorProjectSet;
}

interface StartSnapshotAuthority {
  readonly snapshotId: string;
  readonly manifest: SetupManifestV1;
  readonly facts: LifecycleStartFacts;
  readonly configPath: string;
  readonly selectedProjectId: string;
  readonly projects: TrustedDescriptorProjectSet;
  readonly viteDeclarations: readonly Readonly<{
    readonly projectId: string;
    readonly packageFingerprint: string;
    readonly viteFingerprint: string;
    readonly policy: DeclaredViteOriginPolicy;
  }>[];
}

interface PreparedStartAuthority {
  readonly authority: StartSnapshotAuthority;
  readonly lock: LifecycleAdvisoryLock;
  state: 'prepared' | 'launching';
  finalized: boolean;
  launchAttempted: boolean;
  released: boolean;
  foreground?: LifecycleForegroundMcp;
  cleanupInFlight?: Promise<void>;
}

interface PreparedSetupAuthority extends SetupAuthority {
  readonly mutationId: string;
  readonly candidate: Uint8Array | undefined;
  readonly directories: readonly SetupDirectoryCandidate[];
  readonly openingPreimages: readonly LifecyclePreimage[];
}

interface FinalizedSetupAuthority extends PreparedSetupAuthority {
  readonly finalizedHost: FinalizedHostIntegrationPlan;
  readonly configuredProjects: TrustedDescriptorProjectSet;
  readonly verificationAuthority: NodeVerificationAuthority;
  readonly createdCredential: SetupCreatedCredentialAuthority | undefined;
  readonly createdAuthority: CredentialAuthority | undefined;
}
interface PrecomputedSetupFinalization {
  readonly finalization: SetupFinalization;
  readonly finalized: FinalizedSetupAuthority;
}

interface NodePaths {
  readonly stateRoot: string;
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly walPath: string;
}

/**
 * Production filesystem adapter. Factory construction intentionally performs
 * no filesystem, process, random, lock, or credential mutation.
 */
export function createNodeLifecycleEnginePort(
  options: NodeLifecycleEnginePortOptions,
): LifecycleEnginePort {
  return new NodeLifecycleEnginePort(options);
}

class NodeLifecycleEnginePort implements LifecycleEnginePort {
  readonly #fs: NodeLifecycleFilesystem;
  readonly #random: NodeLifecycleRandom;
  readonly #transactionPort: LifecycleTransactionPort;
  readonly #verification: NodeLifecycleVerificationPorts;
  readonly #checkoutRoot: string;
  readonly #cwd: string;
  readonly #homeDirectory: string;
  readonly #project: SetupProjectSeed;
  readonly #host: Readonly<NodeLifecycleHostOptions>;
  readonly #approval: NodeLifecycleEnginePortOptions['approval'];
  readonly #foregroundMcp: NodeForegroundMcpLauncher | undefined;
  readonly #diagnosticTimeoutMs: number;
  readonly #selectedConfigPath: string;
  readonly #paths: NodePaths;
  readonly #setupInspections = new Map<string, SetupInspectionAuthority>();
  readonly #setupAuthorities = new Map<string, SetupAuthority>();
  readonly #preparedSetupAuthorities = new Map<string, PreparedSetupAuthority>();
  readonly #finalizedAuthorities = new Map<string, FinalizedSetupAuthority>();
  readonly #startSnapshots = new Map<string, StartSnapshotAuthority>();
  readonly #preparedStarts = new Map<string, PreparedStartAuthority>();
  readonly #approvedReceipts = new Map<string, SetupApprovalAuthority>();
  readonly #unconvergedDiagnosticClosures = new Set<Promise<void>>();

  public constructor(options: NodeLifecycleEnginePortOptions) {
    if (
      !isCanonicalAbsolute(options.checkoutRoot) ||
      !isCanonicalAbsolute(options.cwd) ||
      !isCanonicalAbsolute(options.homeDirectory)
    ) {
      throw new Error('Node lifecycle roots must be canonical absolute paths');
    }
    if (
      !Number.isSafeInteger(options.host.port) ||
      options.host.port < 1 ||
      options.host.port > 65_535 ||
      !isCanonicalAbsolute(options.host.credentialPath)
    ) {
      throw new Error('Node lifecycle host options are invalid');
    }
    this.#fs = Object.freeze({
      lstat: options.filesystem?.lstat ?? lstat,
      mkdir: options.filesystem?.mkdir ?? mkdir,
      readdir: options.filesystem?.readdir ?? readdir,
      opendir: options.filesystem?.opendir ?? opendir,
      realpath: options.filesystem?.realpath ?? realpath,
      rename: options.filesystem?.rename ?? rename,
      writeFile: options.filesystem?.writeFile ?? writeFile,
    });
    this.#random = Object.freeze({
      fill: options.random?.fill ?? randomFillSync,
      uuid: options.random?.uuid ?? randomUUID,
    });
    this.#transactionPort = options.transactionPort ?? createNodeLifecycleTransactionPort();
    this.#verification = isVerificationPorts(options.verification)
      ? options.verification
      : createNodeLifecycleVerificationPorts(options.verification);
    this.#checkoutRoot = options.checkoutRoot;
    this.#cwd = options.cwd;
    this.#homeDirectory = options.homeDirectory;
    this.#project = snapshotSetupProjectSeed(options.project);
    this.#host = Object.freeze({
      ...(options.host.rootPath === undefined ? {} : { rootPath: options.host.rootPath }),
      port: options.host.port,
      ...(options.host.override === undefined ? {} : { override: options.host.override }),
      credentialPath: options.host.credentialPath,
    });
    this.#approval = options.approval;
    this.#foregroundMcp = options.foregroundMcp;
    this.#diagnosticTimeoutMs = options.diagnosticTimeoutMs ?? DEFAULT_DIAGNOSTIC_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.#diagnosticTimeoutMs) || this.#diagnosticTimeoutMs < 1) {
      throw new Error('Node lifecycle diagnostic timeout is invalid');
    }
    this.#selectedConfigPath = selectedConfigPathFromValues(
      options.cliConfigPath,
      options.environment?.SCENE_GLASS_CONFIG_PATH,
      this.#homeDirectory,
    );
    const legacyStateRoot = join(this.#checkoutRoot, STATE_DIRECTORY);
    const hostStateRoot =
      options.host.rootPath === undefined
        ? undefined
        : join(options.host.rootPath, STATE_DIRECTORY);
    const stateRoot = options.stateRootPath ?? legacyStateRoot;
    if (
      stateRoot !== legacyStateRoot &&
      (hostStateRoot === undefined || stateRoot !== hostStateRoot)
    ) {
      throw new Error('Node lifecycle state root is invalid');
    }
    this.#paths = Object.freeze({
      stateRoot,
      lockPath: sharedHomeLockPath(this.#homeDirectory),
      manifestPath: join(stateRoot, 'manifest.v1.json'),
      receiptPath: join(stateRoot, 'receipt.v1.json'),
      walPath: join(stateRoot, 'lifecycle.wal.v1.json'),
    });
  }

  public async inspectLifecycle(): Promise<LifecycleInspection> {
    if (this.#unconvergedDiagnosticClosures.size !== 0) {
      return Object.freeze({ state: 'recovery-required' as const });
    }
    try {
      await this.assertCheckout();
      await this.assertStateRootAuthority();
      /*
       * Ahead of the state-root snapshot below: reconciliation stages a file
       * inside the state root, and the snapshot pair treats any entry that
       * appears mid-inspection as tampering.
       */
      await this.reconcileDeviceDrift();
      const before = await this.readStateRootEntries();
      const walExists = before.includes(basename(this.#paths.walPath));
      // A missing WAL is established read-only so preview/decline never acquires the lock.
      const [wal, manifest, receipt] = await Promise.allSettled([
        walExists ? this.readLifecycleWal() : Promise.resolve(undefined),
        this.readCanonicalJson(this.#paths.manifestPath, parseSetupManifestJsonV1),
        this.readCanonicalJson(this.#paths.receiptPath, parseLifecycleReceiptJsonV1),
      ]);
      const after = await this.readStateRootEntries();
      if (!sameStringArray(before, after)) {
        return Object.freeze({ state: 'recovery-required' as const });
      }
      if (wal.status === 'rejected' || wal.value !== undefined) {
        return wal.status === 'fulfilled' && wal.value?.authoritative
          ? Object.freeze({
              state: 'recovery-required' as const,
              authorizedWal: Object.freeze({ recoveryId: wal.value.recoveryId }),
            })
          : Object.freeze({ state: 'recovery-required' as const });
      }
      if (before.some((entry) => !STATE_ROOT_FILENAMES.has(entry))) {
        return Object.freeze({ state: 'recovery-required' as const });
      }
      if (manifest.status === 'rejected' || receipt.status === 'rejected') {
        return Object.freeze({ state: 'lost-provenance' as const });
      }
      if (manifest.value !== undefined && receipt.value !== undefined) {
        if (
          receipt.value.terminalState === 'uninstalled' &&
          receipt.value.installId !== manifest.value.installId
        ) {
          return Object.freeze({ state: 'active' as const, activeManifest: manifest.value });
        }
        return Object.freeze({ state: 'lost-provenance' as const });
      }
      if (manifest.value !== undefined) {
        return Object.freeze({ state: 'active' as const, activeManifest: manifest.value });
      }
      if (receipt.value !== undefined) {
        return Object.freeze({
          state:
            receipt.value.terminalState === 'uninstalled'
              ? ('uninstalled' as const)
              : ('recovery-required' as const),
          terminalReceipt: receipt.value,
        });
      }
      return Object.freeze({ state: 'never-installed' as const });
    } catch {
      return Object.freeze({ state: 'recovery-required' as const });
    }
  }

  public async recoverAuthorizedWal(
    input: Readonly<{ readonly recoveryId: string }>,
  ): Promise<'recovered' | 'recovery-required'> {
    if (this.#unconvergedDiagnosticClosures.size !== 0) {
      return 'recovery-required';
    }
    try {
      await this.assertCheckout();
      await this.assertStateRootAuthority();
    } catch {
      return 'recovery-required';
    }
    const wal = await this.readLifecycleWal().catch(() => undefined);
    if (wal === undefined || !wal.authoritative || wal.recoveryId !== input.recoveryId) {
      return 'recovery-required';
    }
    const result = await recoverLifecycle({
      walPath: this.#paths.walPath,
      lockPath: this.#paths.lockPath,
      manifestPath: this.#paths.manifestPath,
      receiptPath: this.#paths.receiptPath,
      port: this.#transactionPort,
      // The transaction core must compare this value after it owns the stable lock.
      expectedRecoveryId: input.recoveryId,
    });
    if (result.failures.length !== 0) {
      throw new LifecycleTransactionError('recovery', result.failures);
    }
    return result.state === 'recovery-required' ? 'recovery-required' : 'recovered';
  }

  public async inspectSetupFacts(): Promise<LifecycleSetupFacts> {
    await this.assertCheckout();
    if (
      this.#setupAuthorities.size !== 0 ||
      this.#preparedSetupAuthorities.size !== 0 ||
      this.#finalizedAuthorities.size !== 0 ||
      this.#approvedReceipts.size !== 0
    ) {
      throw new Error('a setup approval authority is already outstanding');
    }
    const seed = this.#project;
    const configHomes = await this.inspectConfigHomes();
    const registry = await this.inspectAuthorityRegistry(
      authorityRegistryPath(configHomes.newPath),
    );
    const current = await this.currentConfig(configHomes);
    const project = projectConfigForSetup(seed, current);
    await this.assertSetupRegistryEligibility(configHomes, project, current, registry);
    const rootPath = this.#host.rootPath ?? project.root;
    const canonicalRoot = await this.canonicalDirectory(rootPath);
    const predecessor = await this.readSetupPredecessorWitness();
    const installId = this.idFrom(
      JSON.stringify({ canonicalRoot, projectId: project.projectId, predecessor }),
    );
    const hostPlan = await this.inspectHostPlan(
      project,
      canonicalRoot,
      current,
      registry.registry,
      installId,
    );
    const host = planHostIntegration(hostPlan);
    const config = planConfigOperation({ homes: configHomes, project });
    const selectedRegistry = registry.registry?.projects.find(
      (entry) => entry.projectId === project.projectId,
    );
    const registryCandidate: RegistrySetupCandidate = Object.freeze({
      fact: registry,
      preimage: Object.freeze({
        schemaVersion: 1,
        projects: Object.freeze(selectedRegistry === undefined ? [] : [selectedRegistry]),
      }),
      selectedProject: project,
      config: config.config,
    });
    const preimages = await this.captureSetupPreimages(config, host, registry.path);
    const inspectionId = this.idFrom(
      `inspection:${canonicalRoot}:${JSON.stringify(config)}:${JSON.stringify(host)}:${JSON.stringify(
        registryCandidate,
      )}`,
    );
    for (const authority of this.#setupInspections.values()) {
      for (const preimage of authority.preimages) {
        if (preimage.state === 'file') preimage.bytes.fill(0);
      }
    }
    this.#setupInspections.clear();
    this.#setupInspections.set(
      inspectionId,
      Object.freeze({
        inspectionId,
        config,
        host,
        preimages,
        projectRoot: canonicalRoot,
        expectedHostRoot: await this.identity(canonicalRoot),
        registryCandidate,
        predecessor,
        approvalWitness: this.setupApprovalWitness(config, host, registryCandidate),
      }),
    );
    return Object.freeze({
      configHomes,
      project,
      hostPlan,
      build: Object.freeze({
        inspectionId,
        registryPath: registry.path,
        registry:
          registry.registry === undefined ? null : lifecycleRegistrySnapshot(registry.registry),
      }),
    });
  }

  public async buildSetupPlan(
    input: Readonly<{
      readonly config: ConfigOperationPlan;
      readonly host: HostIntegrationPlan;
      readonly build: LifecycleBuildFacts;
    }>,
  ): Promise<SetupPlanBuildReceipt> {
    await this.assertCheckout();
    const build = input.build as Readonly<{
      readonly inspectionId?: unknown;
      readonly registryPath?: unknown;
      readonly registry?: unknown;
    }>;
    if (typeof build.inspectionId !== 'string') {
      throw new Error('setup build facts lack an inspection authority');
    }
    const inspection = this.#setupInspections.get(build.inspectionId);
    if (
      inspection === undefined ||
      JSON.stringify(inspection.config) !== JSON.stringify(input.config) ||
      JSON.stringify(inspection.host) !== JSON.stringify(input.host) ||
      build.registryPath !== inspection.registryCandidate.fact.path ||
      JSON.stringify(build.registry) !==
        JSON.stringify(
          inspection.registryCandidate.fact.registry === undefined
            ? null
            : lifecycleRegistrySnapshot(inspection.registryCandidate.fact.registry),
        )
    ) {
      throw new Error('setup build facts differ from the inspection authority');
    }
    await this.assertSetupInspectionFacts(inspection);
    this.#setupInspections.delete(inspection.inspectionId);
    const receiptId = this.idFrom(
      `setup:${inspection.projectRoot}:${JSON.stringify(input.config.config)}:${input.host.installId}`,
    );
    const configArtifacts = this.configArtifacts(input.config, inspection.preimages);
    const artifacts = [
      ...configArtifacts,
      ...input.host.artifacts.map((item) => item.artifact),
      input.host.credential.artifact,
    ];
    const plan: SetupPlan = Object.freeze({
      schemaVersion: 1,
      installId: input.host.installId,
      state: 'active',
      config: input.config.config,
      artifacts: Object.freeze(artifacts),
      inverse: Object.freeze(artifacts.map((artifact) => artifact.inverse)),
      preview: Object.freeze({
        state: 'active',
        operations: Object.freeze([
          ...input.config.writes.map((write) =>
            Object.freeze({
              kind:
                write.kind === 'move-config'
                  ? ('move-config' as const)
                  : ('update-config' as const),
              path: 'config',
              hunkCount: 1,
              hunkSubjects: Object.freeze(['scg-config']),
            }),
          ),
          ...(this.registryMutationIsExpected(inspection.registryCandidate, input.host)
            ? [
                Object.freeze({
                  kind: 'update-credential-authority-registry' as const,
                  path: 'credential-authority-registry',
                  hunkCount: 1,
                  hunkSubjects: Object.freeze([this.#project.projectId]),
                }),
              ]
            : []),
          ...input.host.artifacts.map(({ artifact }) =>
            Object.freeze({
              kind: 'create-file' as const,
              path: 'host-artifact',
              hunkCount: artifact.hunks.length,
              hunkSubjects: artifact.hunks.map((hunk) => hunk.subject),
            }),
          ),
          Object.freeze({
            kind:
              input.host.credential.kind === 'setup-created-candidate'
                ? ('create-file' as const)
                : ('none' as const),
            path: 'credential',
            hunkCount: 0,
            hunkSubjects: Object.freeze([]),
          }),
        ]),
      }),
    });
    const authority: SetupAuthority = Object.freeze({
      receiptId,
      config: inspection.config,
      host: inspection.host,
      plan,
      preimages: inspection.preimages,
      projectRoot: inspection.projectRoot,
      expectedHostRoot: inspection.expectedHostRoot,
      registryCandidate: inspection.registryCandidate,
      predecessor: inspection.predecessor,
      approvalWitness: inspection.approvalWitness,
    });
    this.#setupAuthorities.set(receiptId, authority);
    return Object.freeze({ plan, receiptId });
  }

  public async requestSetupApproval(
    input: Readonly<{
      readonly receiptId: string;
      readonly preview: SetupPlan['preview'];
      readonly digest: Readonly<{
        readonly algorithm: 'sha256';
        readonly value: string;
        readonly operationCount: number;
      }>;
    }>,
  ): Promise<boolean> {
    const authority = this.#setupAuthorities.get(input.receiptId);
    if (authority === undefined || this.#approvedReceipts.has(input.receiptId)) {
      throw new Error('setup approval does not match an authorized receipt');
    }
    const expectedDigest = this.previewDigest(authority.plan.preview);
    if (
      input.digest.algorithm !== 'sha256' ||
      JSON.stringify(authority.plan.preview) !== JSON.stringify(input.preview) ||
      expectedDigest.value !== input.digest.value ||
      expectedDigest.operationCount !== input.digest.operationCount
    ) {
      throw new Error('setup approval does not match an authorized receipt');
    }
    const reservation: SetupApprovalAuthority = {
      receiptId: input.receiptId,
      planDigest: expectedDigest.value,
      state: 'pending',
    };
    this.#approvedReceipts.set(input.receiptId, reservation);
    let approved: boolean;
    try {
      approved = await this.#approval({ preview: input.preview, digest: input.digest });
    } catch (error) {
      this.revokeSetupAuthority(input.receiptId);
      throw error;
    }
    if (
      this.#approvedReceipts.get(input.receiptId) !== reservation ||
      reservation.state !== 'pending' ||
      reservation.planDigest !== expectedDigest.value
    ) {
      this.revokeSetupAuthority(input.receiptId);
      throw new Error('setup approval reservation was revoked or replaced');
    }
    if (approved !== true) {
      this.revokeSetupAuthority(input.receiptId);
      return false;
    }
    reservation.state = 'approved';
    return true;
  }

  public async revokeSetupApproval(input: Readonly<{ readonly receiptId: string }>): Promise<void> {
    this.revokeSetupAuthority(input.receiptId);
  }

  public async runNativeSelfTest(): Promise<void> {
    await this.#verification.runNativeSelfTest();
  }

  public async runEmptyChromiumSmoke(): Promise<void> {
    await this.#verification.runBootstrapSmoke(this.diagnosticContext());
  }

  public async generateCredentialToken(
    input: Readonly<{
      readonly receiptId: string;
      readonly requestId: string;
      readonly bits: 256;
      readonly projectId: string;
      readonly path: string;
    }>,
  ): Promise<Uint8Array> {
    const authority = this.#setupAuthorities.get(input.receiptId);
    const approval = this.#approvedReceipts.get(input.receiptId);
    const credential = authority?.host.credential;
    if (
      authority === undefined ||
      approval === undefined ||
      approval.state !== 'approved' ||
      approval.planDigest !== this.previewDigest(authority.plan.preview).value ||
      credential?.kind !== 'setup-created-candidate' ||
      input.bits !== 256 ||
      credential.requestId !== input.requestId ||
      credential.projectId !== input.projectId ||
      credential.path !== input.path
    ) {
      throw new Error('credential generation does not match an approved receipt');
    }
    const candidate = new Uint8Array(32);
    try {
      this.#random.fill(candidate);
      approval.candidate = candidate;
      approval.state = 'candidate-issued';
      return candidate;
    } catch (error) {
      candidate.fill(0);
      this.revokeSetupAuthority(input.receiptId);
      throw error;
    }
  }

  public async zeroizeCredentialToken(
    input: Readonly<{ readonly token: Uint8Array }>,
  ): Promise<void> {
    for (const [receiptId, approval] of this.#approvedReceipts) {
      if (approval.candidate === input.token) {
        this.revokeSetupAuthority(receiptId);
      }
    }
    input.token.fill(0);
  }

  public async prepareSetupMutation(
    input: Readonly<{
      readonly receiptId: string;
      readonly plan: SetupPlan;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<SetupMutationPreparation> {
    await this.assertCheckout();
    const authority = this.requireSetupAuthority(input.receiptId, input.plan);
    const approval = this.#approvedReceipts.get(input.receiptId);
    try {
      this.assertSetupCandidate(authority, input.candidate, approval);
      if (approval === undefined) {
        throw new Error('setup mutation requires a recorded approval');
      }
      approval.state = 'consumed';
      const mutationId = this.safeId(this.#random.uuid());
      const directories = await this.discoverSetupDirectories(
        this.setupTargetPaths(authority),
        mutationId,
      );
      const openingPreimages = Object.freeze([
        ...authority.preimages,
        ...directories.map((candidate) =>
          Object.freeze({ path: candidate.path, state: 'absent' as const }),
        ),
      ]);
      this.assertSetupPathTopology(authority, directories, mutationId);
      const prepared: PreparedSetupAuthority = Object.freeze({
        ...authority,
        mutationId,
        candidate: input.candidate,
        directories,
        openingPreimages,
      });
      this.#setupAuthorities.delete(input.receiptId);
      this.#preparedSetupAuthorities.set(mutationId, prepared);
      return Object.freeze({ mutationId });
    } catch (error) {
      this.revokeSetupAuthority(input.receiptId);
      throw error;
    }
  }

  public async preflightSetup(input: LifecycleSetupPreflightInput): Promise<void> {
    await this.assertCheckout();
    if (input.stage === 3) {
      this.requireFinalizedAuthorityWithCandidate(
        input.mutationId,
        input.plan,
        input.finalizedHost,
        input.candidate,
      );
      return;
    }
    const authority = this.requirePreparedAuthority(
      input.mutationId,
      input.plan,
      input.plannedHost,
      input.candidate,
    );
    await (input.stage === 2
      ? this.assertOpenedSetupFacts(authority)
      : this.assertPreparedSetupFacts(authority));
  }
  public async openSetupTransaction(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly plannedHost: HostIntegrationPlan;
      readonly mutationId: string;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<LifecycleSetupTransaction> {
    await this.assertCheckout();
    const authority = this.requirePreparedAuthority(
      input.mutationId,
      input.plan,
      input.plannedHost,
      input.candidate,
    );
    await this.assertPreparedSetupFacts(authority);
    await this.ensureStateRoot();
    await this.ensureSharedHomeLock();
    const credential = this.setupCredentialCandidate(authority);
    const handle = await openSetupTransactionAuthority({
      port: this.#transactionPort,
      lockPath: this.#paths.lockPath,
      walPath: this.#paths.walPath,
      manifestPath: this.#paths.manifestPath,
      operationId: authority.mutationId,
      installId: authority.plan.installId,
      preimages: authority.openingPreimages,
      directories: authority.directories,
      ...(credential === undefined ? {} : { credential }),
    });
    let precomputed: PrecomputedSetupFinalization | undefined;
    try {
      await this.assertOpenedSetupFacts(authority);
      precomputed = await this.precomputeSetupFinalization(
        authority,
        handle.reservedCreatedCredential,
      );
    } catch (primary) {
      let cleanupFailure: LifecycleTransactionError | undefined;
      try {
        const cleanup = await compensateSetupTransaction(handle);
        if (cleanup.state !== 'never-installed' || cleanup.failures.length !== 0) {
          cleanupFailure = new LifecycleTransactionError(
            'setup',
            cleanup.failures.length === 0
              ? Object.freeze([{ stage: 'cleanup' }])
              : cleanup.failures,
          );
        }
      } catch (cleanup) {
        cleanupFailure =
          cleanup instanceof LifecycleTransactionError
            ? cleanup
            : new LifecycleTransactionError('setup', Object.freeze([{ stage: 'cleanup' }]));
      }
      if (cleanupFailure !== undefined) {
        throw primaryWithCleanup(
          primary,
          [cleanupFailure],
          'Setup revalidation and finalization cleanup failed.',
        );
      }
      throw primary;
    }

    if (precomputed === undefined) {
      throw new Error('setup finalization was not precomputed');
    }
    const finalizedSetup = precomputed;
    let receipt: SetupTransactionReceipt | undefined;
    let transactionState:
      | 'open'
      | 'applying'
      | 'receipt-pending'
      | 'published'
      | 'compensating'
      | 'recovered'
      | 'recovery-required' = 'open';
    let compensationResult: 'recovered' | 'recovery-required' | undefined;
    let compensationFailure: LifecycleTransactionError | undefined;
    const compensate = async (): Promise<'recovered' | 'recovery-required'> => {
      if (this.#unconvergedDiagnosticClosures.size !== 0) {
        compensationResult = 'recovery-required';
        transactionState = 'recovery-required';
        this.revokeSetupAuthority(authority.receiptId);
        return compensationResult;
      }
      if (compensationFailure !== undefined) {
        throw compensationFailure;
      }
      if (transactionState === 'recovered' || transactionState === 'recovery-required') {
        return compensationResult ?? 'recovery-required';
      }
      if (
        transactionState === 'applying' ||
        transactionState === 'compensating' ||
        transactionState === 'published'
      ) {
        return 'recovery-required';
      }
      transactionState = 'compensating';
      try {
        const result = await compensateSetupTransaction(handle);
        compensationResult = result.state === 'never-installed' ? 'recovered' : 'recovery-required';
        transactionState = compensationResult;
        if (result.failures.length !== 0 || compensationResult !== 'recovered') {
          compensationFailure = new LifecycleTransactionError(
            'setup',
            result.failures.length === 0 ? Object.freeze([{ stage: 'cleanup' }]) : result.failures,
          );
          throw compensationFailure;
        }
        return compensationResult;
      } catch (error) {
        compensationResult = 'recovery-required';
        transactionState = 'recovery-required';
        compensationFailure =
          error instanceof LifecycleTransactionError
            ? error
            : new LifecycleTransactionError('setup', Object.freeze([{ stage: 'cleanup' }]));
        throw compensationFailure;
      } finally {
        this.revokeSetupAuthority(authority.receiptId);
      }
    };
    return Object.freeze({
      apply: async (
        input: Readonly<{
          readonly observedAuthorityIssuer: TransactionObservedCredentialAuthorityIssuer;
        }>,
      ): Promise<SetupMutationReceipt> => {
        if (transactionState !== 'open') {
          throw new Error('setup transaction has already settled');
        }
        if (
          input === null ||
          typeof input !== 'object' ||
          input.observedAuthorityIssuer === null ||
          typeof input.observedAuthorityIssuer !== 'object'
        ) {
          throw new Error('setup transaction requires an engine-issued observation authority');
        }
        let contentBytes: Uint8Array | undefined;
        try {
          const credential = this.setupCredentialCandidate(authority);
          contentBytes =
            authority.candidate === undefined
              ? undefined
              : this.encodeCredentialEnvironment(
                  authority.candidate,
                  credential?.projectId ??
                    (() => {
                      throw new Error('created credential candidate is unavailable');
                    })(),
                );
          transactionState = 'applying';
          const result = await applySetupTransaction({
            authority: handle,
            operationId: authority.mutationId,
            installId: authority.plan.installId,
            directories: authority.directories,
            ...(credential === undefined || contentBytes === undefined
              ? {}
              : { credential: Object.freeze({ ...credential, contentBytes }) }),
            finalization: finalizedSetup.finalization,
          });
          if (!('manifest' in result)) {
            compensationResult =
              result.state === 'never-installed' ? 'recovered' : 'recovery-required';
            transactionState = compensationResult;
            this.revokeSetupAuthority(authority.receiptId);
            throw new LifecycleTransactionError(
              'setup',
              result.failures.length === 0 && result.state !== 'never-installed'
                ? Object.freeze([{ stage: 'cleanup' }])
                : result.failures,
            );
          }
          transactionState = 'receipt-pending';
          receipt = result;
          this.#preparedSetupAuthorities.delete(authority.mutationId);
          this.#finalizedAuthorities.set(authority.mutationId, finalizedSetup.finalized);
          const finalized = finalizedSetup.finalized;
          const observedCreatedAuthority =
            finalized.createdCredential === undefined
              ? undefined
              : await this.observeCreatedCredentialAuthority(
                  finalized.createdCredential,
                  authority.candidate,
                  result,
                  input.observedAuthorityIssuer,
                );
          return Object.freeze({
            ...(finalized.createdAuthority === undefined
              ? {}
              : { createdAuthority: finalized.createdAuthority }),
            observedCreatedAuthority,
            ...(observedCreatedAuthority === undefined ? {} : { transactionReceipt: result }),
          });
        } catch (error) {
          if (transactionState === 'open') {
            try {
              await compensate();
            } catch (cleanup) {
              throw primaryWithCleanup(error, [cleanup], 'Setup apply and cleanup failed.');
            }
          } else if (transactionState === 'applying') {
            if (lifecycleTransactionConvergence(error) === 'never-installed') {
              compensationResult = 'recovered';
              transactionState = 'recovered';
              this.revokeSetupAuthority(authority.receiptId);
              throw error;
            }
            compensationResult = 'recovery-required';
            transactionState = 'recovery-required';
            this.revokeSetupAuthority(authority.receiptId);
            compensationFailure = new LifecycleTransactionError(
              'setup',
              Object.freeze([{ stage: 'cleanup' }]),
            );
            throw primaryWithCleanup(
              error,
              [compensationFailure],
              'Setup apply and cleanup failed.',
            );
          }
          throw error;
        } finally {
          contentBytes?.fill(0);
        }
      },
      publishActive: async (): Promise<'active'> => {
        if (transactionState !== 'receipt-pending' || receipt === undefined) {
          throw new Error('setup transaction is not ready for publication');
        }
        const result = await publishSetupTransaction(receipt);
        if (result.state !== 'active' || result.failures.length !== 0) {
          compensationResult = 'recovery-required';
          transactionState = 'recovery-required';
          this.revokeSetupAuthority(authority.receiptId);
          throw new LifecycleTransactionError(
            'setup',
            result.failures.length === 0
              ? Object.freeze([{ stage: 'finalization' }])
              : result.failures,
          );
        }
        transactionState = 'published';
        this.revokeSetupAuthority(authority.receiptId);
        return 'active';
      },
      compensate,
    });
  }

  public async validateFinalizedSetup(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly finalizedHost: FinalizedHostIntegrationPlan;
      readonly mutationId: string;
    }>,
  ): Promise<void> {
    const authority = this.requireFinalizedAuthority(
      input.mutationId,
      input.plan,
      input.finalizedHost,
    );
    const descriptorPath = authority.finalizedHost.artifacts.find(
      (artifact) => artifact.role === 'descriptor',
    )?.artifact.path;
    if (descriptorPath === undefined) {
      throw new Error('finalized host descriptor is absent');
    }
    const descriptorBytes = await this.readRegularFile(descriptorPath, MAX_CONFIG_BYTES);
    if (descriptorBytes === undefined) {
      throw new Error('finalized host descriptor is missing');
    }
    try {
      const descriptor = new TextDecoder('utf-8', { fatal: true }).decode(descriptorBytes);
      if (authority.finalizedHost.host === 'html') {
        parseStaticHostDescriptorJsonV1(descriptor, authority.configuredProjects);
      } else {
        parseViteHostDescriptorJsonV1(descriptor, authority.configuredProjects);
      }
    } finally {
      descriptorBytes.fill(0);
    }
    const verified = verifyCredentialAuthorities({
      authorities: authority.finalizedHost.descriptor.credentialAuthorities,
      selectedProjectId: authority.finalizedHost.descriptor.credentialProjectId,
      expectedOwnerUid: currentUid(),
      maxBytes: MAX_TOKEN_SOURCE_BYTES,
    });
    try {
      // Creating this verified authority proves same-FD identity validation.
    } finally {
      revokeCredentialReadCapability(verified.capability);
    }
  }

  public async runLiveDiagnostics(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly finalizedHost: FinalizedHostIntegrationPlan;
      readonly mutationId: string;
    }>,
  ): Promise<void> {
    const authority = this.requireFinalizedAuthority(
      input.mutationId,
      input.plan,
      input.finalizedHost,
    );
    await this.runDiagnostics(authority);
  }

  public async inspectStartFacts(
    input: Readonly<{ readonly manifest: SetupManifestV1 }>,
  ): Promise<LifecycleStartFacts> {
    await this.assertCheckout();
    const snapshot = await this.captureStartSnapshot(input.manifest);
    this.#startSnapshots.clear();
    this.#startSnapshots.set(snapshot.snapshotId, snapshot);
    return snapshot.facts;
  }

  public async prepareStart(
    input: Readonly<{ readonly manifest: SetupManifestV1; readonly facts: LifecycleStartFacts }>,
  ): Promise<LifecyclePreparedStart> {
    await this.assertCheckout();
    const snapshotId = input.facts.snapshotId;
    if (
      snapshotId === undefined ||
      input.facts.selectedProjectId === undefined ||
      input.facts.registry === undefined
    ) {
      throw new Error('start facts do not carry a prepared authority snapshot');
    }
    const snapshot = this.#startSnapshots.get(snapshotId);
    if (
      snapshot === undefined ||
      JSON.stringify(snapshot.manifest) !== JSON.stringify(input.manifest) ||
      JSON.stringify(snapshot.facts) !== JSON.stringify(input.facts)
    ) {
      throw new Error('start facts are not an adapter-owned snapshot');
    }

    const preparationId = this.idFrom(`prepared-start:${snapshot.snapshotId}`);
    const existing = this.#preparedStarts.get(preparationId);
    if (existing !== undefined) {
      if (
        existing.foreground !== undefined ||
        existing.cleanupInFlight !== undefined ||
        existing.state !== 'prepared'
      ) {
        throw new Error('prepared start authority cleanup is still required');
      }
      await this.releasePreparedStartLock(existing);
      this.#preparedStarts.delete(preparationId);
    }
    const lock = await this.#transactionPort.acquireAdvisoryLock(this.#paths.lockPath);
    try {
      const fresh = await this.captureStartSnapshot(input.manifest);
      if (
        fresh.snapshotId !== snapshot.snapshotId ||
        JSON.stringify(fresh.facts) !== JSON.stringify(snapshot.facts)
      ) {
        throw new Error('start authority changed after inspection');
      }
      this.#startSnapshots.delete(snapshot.snapshotId);
      this.#preparedStarts.set(preparationId, {
        authority: snapshot,
        lock,
        state: 'prepared',
        finalized: false,
        launchAttempted: false,
        released: false,
      });
      return Object.freeze({ preparationId });
    } catch (primary) {
      try {
        await lock.release();
      } catch (cleanup) {
        this.#preparedStarts.set(preparationId, {
          authority: snapshot,
          lock,
          state: 'prepared',
          finalized: false,
          launchAttempted: false,
          released: false,
        });
        throw primaryWithCleanup(primary, [cleanup]);
      }
      throw primary;
    }
  }
  public async finalizePreparedStart(
    input: Readonly<{ readonly preparationId: string }>,
  ): Promise<void> {
    await this.assertCheckout();
    const prepared = this.#preparedStarts.get(input.preparationId);
    if (
      prepared === undefined ||
      prepared.state !== 'prepared' ||
      prepared.finalized ||
      prepared.launchAttempted
    ) {
      throw new LifecyclePreparedStartUnavailableError(
        prepared === undefined ? 'missing' : 'reused',
      );
    }
    const fresh = await this.captureStartSnapshot(prepared.authority.manifest);
    const expected = prepared.authority.viteDeclarations;
    const actual = fresh.viteDeclarations;
    const changed = expected.find(
      (declaration, index) =>
        actual[index]?.projectId !== declaration.projectId ||
        actual[index]?.packageFingerprint !== declaration.packageFingerprint ||
        actual[index]?.viteFingerprint !== declaration.viteFingerprint,
    );
    if (changed !== undefined || actual.length !== expected.length) {
      throw new LifecycleStartDiagnosticError({
        code: 'SCG_START_VITE_INPUT_CHANGED',
        projectId:
          changed?.projectId ?? actual[expected.length]?.projectId ?? expected[0]!.projectId,
      });
    }
    if (fresh.snapshotId !== prepared.authority.snapshotId) {
      throw new Error('start authority changed after preparation');
    }
    prepared.finalized = true;
  }

  public async discardPreparedStart(
    input: Readonly<{ readonly preparationId: string; readonly cleanup?: LifecycleCleanupContext }>,
  ): Promise<void> {
    await this.cleanupPreparedStart(input.preparationId, input.cleanup);
  }

  public async launchMcpForeground(
    input: Readonly<{ readonly manifest: SetupManifestV1; readonly preparationId?: string }>,
  ): Promise<LifecycleForegroundMcp> {
    if (this.#foregroundMcp === undefined || input.preparationId === undefined) {
      throw new Error('foreground MCP prepared launcher is unavailable');
    }
    const preparationId = input.preparationId;
    const prepared = this.#preparedStarts.get(preparationId);
    if (prepared === undefined) {
      throw new LifecyclePreparedStartUnavailableError('missing');
    }
    if (
      prepared.state !== 'prepared' ||
      !prepared.finalized ||
      prepared.launchAttempted ||
      JSON.stringify(prepared.authority.manifest) !== JSON.stringify(input.manifest)
    ) {
      throw new LifecyclePreparedStartUnavailableError('reused');
    }
    prepared.launchAttempted = true;
    prepared.state = 'launching';
    let foreground: LifecycleForegroundMcp | undefined;
    try {
      const projects = prepared.authority.projects.projects.map(
        (project: TrustedDescriptorProject) =>
          Object.freeze({
            projectId: project.projectId,
            tokenEnv: project.tokenEnv,
            credentialAuthority: project.credentialAuthority,
          }),
      );
      const configSnapshot = prepared.authority.facts.config as {
        readonly schemaVersion: 1;
        readonly globalLimits?: Readonly<Record<string, number>>;
        readonly projects: readonly {
          readonly projectId: string;
          readonly tokenEnv: string;
          readonly framework: 'html' | 'vue3' | 'react';
          readonly allowedOrigins: readonly string[];
          readonly limits?: Readonly<Record<string, number>>;
        }[];
      };
      const configProjects = configSnapshot.projects;
      const lifecycleOrigin = Object.freeze({
        binding: Object.freeze({
          schemaVersion: configSnapshot.schemaVersion,
          ...(configSnapshot.globalLimits === undefined
            ? {}
            : { globalLimits: Object.freeze({ ...configSnapshot.globalLimits }) }),
          projects: Object.freeze(
            configProjects.map((configured) => {
              const project = prepared.authority.projects.projects.find(
                (candidate) => candidate.projectId === configured.projectId,
              );
              if (project === undefined) throw new Error('lifecycle config binding is invalid');
              return Object.freeze({
                projectId: configured.projectId,
                root: project.canonicalRoot,
                framework: configured.framework,
                tokenEnv: configured.tokenEnv,
                allowedOrigins: Object.freeze([...configured.allowedOrigins]),
                ...(configured.limits === undefined
                  ? {}
                  : { limits: Object.freeze({ ...configured.limits }) }),
              });
            }),
          ),
        }),
        replacements: Object.freeze(
          prepared.authority.viteDeclarations.map((declaration) =>
            Object.freeze({
              projectId: declaration.projectId,
              baseline: Object.freeze([
                ...(configProjects.find((project) => project.projectId === declaration.projectId)
                  ?.allowedOrigins ?? []),
              ]),
              origins: declaration.policy.origins,
            }),
          ),
        ),
      });
      foreground = await this.#foregroundMcp.launch({
        configPath: prepared.authority.configPath,
        manifest: input.manifest,
        selectedProjectId: prepared.authority.selectedProjectId,
        projects: Object.freeze(projects),
        lifecycleOrigin,
      });
      const launched = foreground;
      if (launched === undefined) {
        throw new Error('foreground MCP launcher returned no foreground authority');
      }
      prepared.foreground = launched;
      prepared.state = 'prepared';
      let cleaned = false;
      return Object.freeze({
        waitForExit: () => launched.waitForExit(),
        cleanup: async (cleanup?: LifecycleCleanupContext): Promise<void> => {
          if (cleaned) return;
          await this.cleanupPreparedStart(preparationId, cleanup, 'foreground MCP cleanup failed');
          cleaned = true;
        },
      });
    } catch (primary) {
      prepared.state = 'prepared';
      if (foreground !== undefined) {
        prepared.foreground = foreground;
      }
      throw primary;
    }
  }

  public async observeUninstallTargets(
    input: Readonly<{ readonly manifest: SetupManifestV1 }>,
  ): Promise<UninstallObservation> {
    await this.assertCheckout();
    const observed: ObservedOwnedTarget[] = [];
    for (const artifact of input.manifest.artifacts) {
      if (artifact.kind === 'credential') {
        if ((await this.lstatRegular(artifact.path)) === undefined) {
          return Object.freeze({ complete: false, observed: Object.freeze(observed) });
        }
        observed.push(
          Object.freeze({
            path: artifact.path,
            fingerprint: undefined,
            hunks: Object.freeze([]),
            semanticConfig: undefined,
          }),
        );
        continue;
      }
      if (artifact.kind === 'directory') {
        if ((await this.lstatDirectory(artifact.path)) === undefined) {
          return Object.freeze({ complete: false, observed: Object.freeze(observed) });
        }
        observed.push(
          Object.freeze({
            path: artifact.path,
            fingerprint: undefined,
            hunks: Object.freeze([]),
            semanticConfig: undefined,
          }),
        );
        continue;
      }
      const bytes = await this.readRegularFile(artifact.path, MAX_CONFIG_BYTES);
      if (bytes === undefined) {
        return Object.freeze({ complete: false, observed: Object.freeze(observed) });
      }
      try {
        let target: ObservedOwnedTarget | undefined;
        if (artifact.kind === 'config') {
          const semanticConfig: ObservedOwnedTarget['semanticConfig'] = lifecycleConfigSnapshot(
            parseConfigBytes(bytes),
          );
          target = Object.freeze({
            path: artifact.path,
            fingerprint: sha(bytes),
            hunks: Object.freeze(
              artifact.hunks.map((hunk) =>
                Object.freeze({
                  id: hunk.id,
                  fingerprint: hunk.fingerprint,
                }),
              ),
            ),
            semanticConfig,
          });
        } else if (artifact.kind === 'credential-authority-registry') {
          const registry = parseCredentialAuthorityRegistryJsonV1(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes),
          );
          target = Object.freeze({
            path: artifact.path,
            fingerprint: sha(bytes),
            hunks: Object.freeze([]),
            semanticConfig: undefined,
            semanticCredentialAuthorityRegistry: lifecycleRegistrySnapshot(registry),
          });
        } else if (artifact.kind === 'file') {
          target = Object.freeze({
            path: artifact.path,
            fingerprint: sha(bytes),
            hunks: Object.freeze(
              artifact.hunks.map((hunk) =>
                Object.freeze({
                  id: hunk.id,
                  fingerprint: sha(bytes),
                }),
              ),
            ),
            semanticConfig: undefined,
          });
        }
        if (target === undefined) {
          throw new Error('manifest artifact kind is unsupported');
        }
        observed.push(target);
      } finally {
        bytes.fill(0);
      }
    }
    return Object.freeze({ complete: true, observed: Object.freeze(observed) });
  }

  public async openUninstallTransaction(
    input: Readonly<{
      readonly manifest: SetupManifestV1;
      readonly preflight: import('./provenance.js').UninstallPreflight;
    }>,
  ): Promise<LifecycleUninstallTransaction> {
    await this.assertCheckout();
    await this.assertStateRootAuthority();
    let state: 'open' | 'uninstalled' | 'recovered' | 'recovery-required' | 'compensating' = 'open';
    let compensationResult: 'recovered' | 'recovery-required' | undefined;
    let compensationFailure: LifecycleTransactionError | undefined;
    return Object.freeze({
      apply: async (): Promise<'uninstalled' | 'recovery-required'> => {
        if (state !== 'open') throw new Error('uninstall transaction has already settled');
        const result = await applyUninstallTransaction({
          manifest: input.manifest,
          operationId: this.safeId(this.#random.uuid()),
          preflight: input.preflight,
          walPath: this.#paths.walPath,
          manifestPath: this.#paths.manifestPath,
          receiptPath: this.#paths.receiptPath,
          lockPath: this.#paths.lockPath,
          port: this.#transactionPort,
        });
        if (result.state !== 'uninstalled' || result.failures.length !== 0) {
          state = 'recovery-required';
          throw new LifecycleTransactionError(
            'uninstall',
            result.failures.length === 0
              ? Object.freeze([{ stage: 'finalization' }])
              : result.failures,
          );
        }
        state = 'uninstalled';
        return 'uninstalled';
      },
      compensate: async (): Promise<'recovered' | 'recovery-required'> => {
        if (compensationFailure !== undefined) throw compensationFailure;
        if (compensationResult !== undefined) return compensationResult;
        if (state === 'uninstalled' || state === 'compensating') {
          return 'recovery-required';
        }
        state = 'compensating';
        try {
          await this.assertStateRootAuthority();
          const recovered = await recoverLifecycle({
            walPath: this.#paths.walPath,
            lockPath: this.#paths.lockPath,
            manifestPath: this.#paths.manifestPath,
            receiptPath: this.#paths.receiptPath,
            port: this.#transactionPort,
          });
          if (recovered.state === 'recovery-required' || recovered.failures.length !== 0) {
            compensationResult = 'recovery-required';
            compensationFailure = new LifecycleTransactionError(
              'uninstall',
              recovered.failures.length === 0
                ? Object.freeze([{ stage: 'cleanup' }])
                : recovered.failures,
            );
            throw compensationFailure;
          }
          const inspection = await this.inspectLifecycle();
          compensationResult =
            inspection.state === 'active' &&
            inspection.activeManifest !== undefined &&
            JSON.stringify(inspection.activeManifest) === JSON.stringify(input.manifest)
              ? 'recovered'
              : 'recovery-required';
          if (compensationResult !== 'recovered') {
            compensationFailure = new LifecycleTransactionError(
              'uninstall',
              Object.freeze([{ stage: 'cleanup' }]),
            );
            throw compensationFailure;
          }
          return compensationResult;
        } catch (error) {
          compensationResult = 'recovery-required';
          compensationFailure =
            error instanceof LifecycleTransactionError
              ? error
              : new LifecycleTransactionError('uninstall', Object.freeze([{ stage: 'cleanup' }]));
          throw compensationFailure;
        } finally {
          state = compensationResult === 'recovered' ? 'recovered' : 'recovery-required';
        }
      },
    });
  }

  private async assertCheckout(): Promise<void> {
    const [checkout, cwd] = await Promise.all([
      this.#fs.realpath(this.#checkoutRoot),
      this.#fs.realpath(this.#cwd),
    ]);
    if (checkout !== this.#checkoutRoot || cwd !== checkout) {
      throw new Error('lifecycle must run from its canonical checkout');
    }
    const stat = await this.#fs.lstat(checkout);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('lifecycle checkout is not a canonical directory');
    }
  }

  private async inspectConfigHomes(): Promise<ConfigHomeFacts> {
    const newPath = this.#selectedConfigPath;
    const legacyPath = join(this.#homeDirectory, '.config/scene-glass/config.json');
    if (legacyPath === newPath) throw new Error('legacy and current config paths collide');
    return Object.freeze({
      legacyPath,
      newPath,
      legacy: await this.configFact(legacyPath),
      new: await this.configFact(newPath),
    });
  }
  private async configFact(path: string): Promise<ConfigFileFact | undefined> {
    await this.assertExistingParentCanonical(path);
    const snapshot = await this.readSecureSnapshot(path, MAX_CONFIG_BYTES);
    return snapshot === undefined
      ? undefined
      : Object.freeze({ bytes: snapshot.bytes, mode: snapshot.observation.mode });
  }

  private async inspectHostPlan(
    project: ProjectConfigV1,
    root: string,
    config: ServerConfigV1,
    registry: CredentialAuthorityRegistryV1 | undefined,
    installId: string,
  ): Promise<HostPlanInput> {
    const sources = await this.scanHostSources(root, this.#host.credentialPath);
    const rootIdentity = await this.identity(
      project.framework === 'html' ? join(root, 'public') : root,
    );
    const credential = await this.credentialFact(project, root);
    const authorities = credential.kind === 'adopt' ? [credential.authority] : [];
    if (
      config.projects.some((configured) => configured.projectId !== project.projectId) &&
      registry === undefined
    ) {
      throw new Error('configured projects require a canonical authority registry');
    }
    const packageFact = await this.packageFact(root);
    const viteConfig = await this.viteConfigFact(root, sources.sources);
    return Object.freeze({
      schemaVersion: 1,
      candidates: Object.freeze([
        Object.freeze({
          rootPath: root,
          descriptor: Object.freeze({
            projectId: project.projectId,
            port: this.#host.port,
            installId,
            approvedRootIdentity: rootIdentity,
            credentialAuthorities: authorities,
          }),
          package: packageFact,
          viteConfig,
          sourceScan: sources,
        }),
      ]),
      credential,
      ...(this.#host.override === undefined ? {} : { override: this.#host.override }),
    });
  }
  private async currentConfig(homes: ConfigHomeFacts): Promise<ServerConfigV1> {
    const selected = homes.new ?? homes.legacy;
    if (selected === undefined) return parseServerConfigV1({ schemaVersion: 1, projects: [] });
    return parseConfigBytes(selected.bytes);
  }

  private async credentialFact(
    project: ProjectConfigV1,
    root: string,
  ): Promise<HostPlanInput['credential']> {
    const path = this.#host.credentialPath;
    if (!isCanonicalAbsolute(path) || !contains(root, path))
      throw new Error('credential source must be inside the selected host root');
    await this.assertExistingParentCanonical(path);
    await this.assertGitignored(root, path);
    const snapshot = await this.readSecureSnapshot(path, MAX_TOKEN_SOURCE_BYTES);
    if (snapshot === undefined) {
      return Object.freeze({
        kind: 'create' as const,
        requestId: this.idFrom(`credential:${project.projectId}:${path}`),
        bits: 256 as const,
        projectId: project.projectId,
        path,
      });
    }
    const stat = await this.lstatRegular(path);
    if (
      stat === undefined ||
      stat.uid !== currentUid() ||
      (stat.mode & 0o7777) !== 0o600 ||
      stat.nlink !== 1
    ) {
      throw new Error('credential source must be an owner-owned mode 0600 unlinked regular file');
    }
    try {
      if (!isCredentialSource(snapshot.bytes, project.projectId)) {
        throw new Error('credential source is not canonical');
      }
    } finally {
      snapshot.bytes.fill(0);
    }
    return Object.freeze({
      kind: 'adopt' as const,
      authority: Object.freeze({
        projectId: project.projectId,
        path,
        device: snapshot.observation.identity.device,
        inode: snapshot.observation.identity.inode,
      }),
    });
  }

  private async scanHostSources(
    root: string,
    credentialPath: string,
  ): Promise<
    Readonly<{
      readonly complete: true;
      readonly sources: readonly { readonly path: string; readonly source: string }[];
    }>
  > {
    const sources: { path: string; source: string }[] = [];
    let total = 0;
    let directories = 0;
    let entries = 0;
    const walk = async (
      directory: string,
      relativeDirectory: string,
      depth: number,
    ): Promise<void> => {
      if (depth > MAX_SOURCE_DEPTH || ++directories > MAX_SOURCE_DIRECTORIES) {
        throw new Error('host source scan exceeds directory limit');
      }
      const handle = await this.#fs.opendir(directory);
      const children: Dirent[] = [];
      try {
        while (true) {
          const entry = await handle.read();
          if (entry === null) break;
          if (++entries > MAX_SOURCE_ENTRIES) {
            throw new Error('host source scan exceeds entry limit');
          }
          children.push(entry);
        }
      } finally {
        await handle.close();
      }
      children.sort((left, right) => bytewiseCompare(left.name, right.name));
      for (const entry of children) {
        // Symlinks are never followed and never read; skipping keeps the
        // outside-root guarantee without failing on unrelated tool artifacts
        // (e.g. a dotfile symlink at the project root).
        if (entry.isSymbolicLink()) continue;
        const relativePath =
          relativeDirectory.length === 0 ? entry.name : `${relativeDirectory}/${entry.name}`;
        if (Buffer.byteLength(relativePath, 'utf8') > MAX_SOURCE_PATH_BYTES) {
          throw new Error('host source scan path exceeds its byte limit');
        }
        const absolutePath = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (
            entry.name.startsWith('.') ||
            entry.name === 'node_modules' ||
            entry.name === 'dist' ||
            entry.name === 'build' ||
            entry.name === 'out' ||
            entry.name === 'coverage' ||
            entry.name === '.scg' ||
            entry.name === '.scene-glass'
          ) {
            continue;
          }
          await walk(absolutePath, relativePath, depth + 1);
          continue;
        }
        if (!entry.isFile()) {
          throw new Error('host source scan refuses nonregular entries');
        }
        if (absolutePath === credentialPath || !isPlanningRelevantTextPath(relativePath)) {
          continue;
        }
        if (sources.length >= MAX_SOURCE_FILES) {
          throw new Error('host source scan exceeds file limit');
        }
        const bytes = await this.readRegularFile(absolutePath, MAX_SOURCE_FILE_BYTES);
        if (bytes === undefined) throw new Error('host source disappeared during inspection');
        try {
          total += bytes.byteLength;
          if (total > MAX_SOURCE_BYTES) throw new Error('host source scan exceeds byte limit');
          sources.push(
            Object.freeze({
              path: relativePath,
              source: new TextDecoder('utf-8', { fatal: true }).decode(bytes),
            }),
          );
        } finally {
          bytes.fill(0);
        }
      }
    };
    await walk(root, '', 0);
    sources.sort((left, right) => bytewiseCompare(left.path, right.path));
    return Object.freeze({ complete: true as const, sources: Object.freeze(sources) });
  }

  private async packageFact(root: string): Promise<
    | {
        readonly name: string;
        readonly resolvedDependencies: readonly {
          readonly name: string;
          readonly version: string;
        }[];
      }
    | undefined
  > {
    const bytes = await this.readRegularFile(join(root, 'package.json'), MAX_CONFIG_BYTES);
    if (bytes === undefined) return undefined;
    try {
      const value = packageRecordValues(
        JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown,
        'host package',
      );
      const name = value.name;
      if (typeof name !== 'string' || !isSafePackageName(name)) {
        throw new Error('host package has no canonical name');
      }
      const names = [
        ...new Set([
          ...packageDependencyNames(value, 'dependencies'),
          ...packageDependencyNames(value, 'devDependencies'),
        ]),
      ].sort(bytewiseCompare);
      if (names.includes('next')) throw new Error('Next.js hosts are unsupported');
      if (
        names.some(
          (dependencyName) =>
            dependencyName === 'vite-plugin-pwa' || dependencyName.startsWith('workbox-'),
        )
      ) {
        throw new Error('PWA hosts are unsupported');
      }
      if (names.length > 64) throw new Error('host package dependency facts exceed their limit');
      const resolvedDependencies: { name: string; version: string }[] = [];
      for (const dependencyName of names) {
        const version = await this.resolvedPackageVersion(root, dependencyName);
        if (version !== undefined) {
          resolvedDependencies.push(Object.freeze({ name: dependencyName, version }));
        }
      }
      return Object.freeze({
        name,
        resolvedDependencies: Object.freeze(resolvedDependencies),
      });
    } finally {
      bytes.fill(0);
    }
  }
  private async resolvedPackageVersion(root: string, name: string): Promise<string | undefined> {
    const packagePath = join(root, 'node_modules', ...name.split('/'), 'package.json');
    let canonicalPackagePath: string;
    try {
      canonicalPackagePath = await this.#fs.realpath(packagePath);
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
    const dependencyRoot = join(root, 'node_modules');
    const expectedSuffix = join('node_modules', ...name.split('/'), 'package.json');
    if (
      !contains(dependencyRoot, canonicalPackagePath) ||
      !canonicalPackagePath.endsWith(expectedSuffix)
    ) {
      // Linked/file: dependencies (e.g. a sibling workspace package) resolve
      // outside the host root. Their version cannot be attested, so the fact
      // is simply omitted; nothing outside the root is ever read.
      return undefined;
    }
    const bytes = await this.readRegularFile(canonicalPackagePath, MAX_CONFIG_BYTES);
    if (bytes === undefined) throw new Error('resolved dependency disappeared during inspection');
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
        version?: unknown;
      };
      if (
        typeof value.version !== 'string' ||
        !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(value.version)
      ) {
        throw new Error('resolved dependency version is invalid');
      }
      return value.version;
    } finally {
      bytes.fill(0);
    }
  }

  private async viteConfigFact(
    root: string,
    sources: readonly { readonly path: string; readonly source: string }[],
  ): Promise<
    | {
        readonly path: 'vite.config.ts';
        readonly contract: 'g001-managed-vite-v1';
        readonly plugin: '@vitejs/plugin-vue' | '@vitejs/plugin-react';
        readonly aliases: readonly [];
      }
    | undefined
  > {
    const source = sources.find((item) => item.path === 'vite.config.ts');
    if (source === undefined) return undefined;
    const plugin = managedVitePluginFromConfig(source.source);
    if (plugin === undefined) {
      throw new Error('Vite config is outside the managed contract');
    }
    return Object.freeze({
      path: 'vite.config.ts',
      contract: 'g001-managed-vite-v1',
      plugin,
      aliases: Object.freeze<[]>([]),
    });
  }

  private configArtifacts(
    config: ConfigOperationPlan,
    preimages: readonly LifecyclePreimage[],
  ): SetupPlan['artifacts'] {
    if (config.writes.length === 0) {
      return Object.freeze([]);
    }
    const selected = this.#project;
    const preimage = this.configPreimage(config, selected.projectId, preimages);
    const postimage: SemanticConfigImage = Object.freeze({
      schemaVersion: 1,
      projects: Object.freeze(
        config.config.projects.filter((project) => project.projectId === selected.projectId),
      ),
    });
    const hunk = Object.freeze({
      id: this.idFrom(
        `config-hunk:${config.writes[0]?.path ?? selected.projectId}:${selected.projectId}`,
      ),
      fingerprint: sha(new TextEncoder().encode(JSON.stringify(postimage))),
      operation:
        config.projectOperation === 'project-update' ? ('update' as const) : ('insert' as const),
      subject: selected.projectId,
    });
    return Object.freeze(
      config.writes.map((write) => {
        const inverse = Object.freeze({
          kind: 'restore-config' as const,
          path: write.path,
          preimage,
          postimage,
        });
        return Object.freeze({
          path: write.path,
          kind: 'config' as const,
          fingerprint: sha(write.bytes),
          hunks: Object.freeze([hunk]),
          preimage,
          postimage,
          inverse,
        });
      }),
    );
  }

  private configPreimage(
    config: ConfigOperationPlan,
    projectId: string,
    preimages: readonly LifecyclePreimage[],
  ): SemanticConfigImage {
    const write = config.writes[0];
    if (write === undefined) {
      return Object.freeze({ schemaVersion: 1, projects: Object.freeze([]) });
    }
    const sourcePath = write.kind === 'move-config' ? write.sourcePath : write.path;
    if (sourcePath === undefined) {
      throw new Error('config write has no source path');
    }
    const preimage = preimages.find((candidate) => candidate.path === sourcePath);
    if (preimage === undefined || preimage.state === 'absent') {
      return Object.freeze({ schemaVersion: 1, projects: Object.freeze([]) });
    }
    if (preimage.state !== 'file') {
      throw new Error('config preimage is not a regular file');
    }
    const parsed = parseConfigBytes(preimage.bytes);
    return Object.freeze({
      schemaVersion: 1,
      projects: Object.freeze(parsed.projects.filter((project) => project.projectId === projectId)),
    });
  }

  private async captureSetupPreimages(
    config: ConfigOperationPlan,
    host: HostIntegrationPlan,
    registryPath: string,
  ): Promise<readonly LifecyclePreimage[]> {
    const paths = new Set<string>();
    for (const write of config.writes) {
      paths.add(write.path);
      if (write.kind === 'move-config') {
        const sourcePath = write.sourcePath;
        if (sourcePath === undefined) {
          throw new Error('move-config write has no source path');
        }
        paths.add(sourcePath);
      }
    }
    for (const artifact of host.artifacts) {
      paths.add(artifact.artifact.path);
    }
    paths.add(registryPath);
    const preimages: LifecyclePreimage[] = [];
    for (const path of [...paths].sort()) preimages.push(await this.capturePreimage(path));
    if (host.credential.kind === 'setup-created-candidate') {
      if (paths.has(host.credential.path)) {
        throw new Error('credential target collides with another setup target');
      }
      const credentialPreimage = await this.captureCredentialPreimage(host.credential.path);
      if (credentialPreimage.state !== 'absent') {
        throw new Error('credential source changed during inspection');
      }
      preimages.push(credentialPreimage);
    }
    return Object.freeze(preimages);
  }

  private async setupOperations(
    authority: SetupAuthority,
    finalizedHost: FinalizedHostIntegrationPlan,
    registryOperation: LifecycleMutationOperation | undefined,
    configuredProjects: TrustedDescriptorProjectSet,
  ): Promise<readonly LifecycleMutationOperation[]> {
    const operations: LifecycleMutationOperation[] = [];
    for (const write of authority.config.writes) {
      if (write.kind === 'move-config') {
        const sourcePath = write.sourcePath;
        if (sourcePath === undefined) {
          throw new Error('move-config write has no source path');
        }
        operations.push(
          Object.freeze({
            kind: 'move-config' as const,
            path: write.path,
            sourcePath,
            bytes: new Uint8Array(write.bytes),
            mode: write.mode,
          }),
        );
      } else {
        operations.push(
          Object.freeze({
            kind: 'write-config' as const,
            path: write.path,
            bytes: new Uint8Array(write.bytes),
            mode: write.mode,
          }),
        );
      }
    }
    for (const artifact of finalizedHost.artifacts) {
      const bytes = await this.hostArtifactBytes(
        artifact.role,
        finalizedHost,
        authority.projectRoot,
        configuredProjects,
      );
      const preimage = authority.preimages.find((image) => image.path === artifact.artifact.path);
      if (preimage?.state === 'file' && sameBytes(preimage.bytes, bytes)) {
        bytes.fill(0);
        continue;
      }
      operations.push(
        Object.freeze({
          kind: 'write-file' as const,
          path: artifact.artifact.path,
          bytes,
          mode: preimage?.state === 'file' ? preimage.mode : 0o600,
        }),
      );
    }
    if (registryOperation !== undefined) {
      operations.push(registryOperation);
    }
    return Object.freeze(operations);
  }
  private async precomputeSetupFinalization(
    authority: PreparedSetupAuthority,
    reservedCreatedCredential: SetupReservedCredentialAuthority | undefined,
  ): Promise<PrecomputedSetupFinalization> {
    if (
      (authority.host.credential.kind === 'setup-created-candidate') !==
      (reservedCreatedCredential !== undefined)
    ) {
      throw new Error('setup transaction reservation does not match credential authority');
    }
    const createdAuthority =
      reservedCreatedCredential === undefined
        ? undefined
        : this.credentialAuthorityFromCreated(reservedCreatedCredential);
    const finalizedHost = finalizeHostIntegrationPlan(authority.host, createdAuthority);
    const registryMutation = await this.finalizeRegistryMutation(
      authority.registryCandidate,
      finalizedHost,
      reservedCreatedCredential,
    );
    const operations = await this.setupOperations(
      authority,
      finalizedHost,
      registryMutation.operation,
      registryMutation.configuredProjects,
    );
    if (reservedCreatedCredential !== undefined && registryMutation.artifact === undefined) {
      throw new Error('created credential finalization lacks an exact registry authority');
    }
    const manifest = this.transactionPlan(
      authority.plan,
      operations,
      authority.preimages,
      registryMutation.artifact,
    );
    const finalization: SetupFinalization = Object.freeze({
      manifest,
      operations,
      preimages: this.finalizationPreimages(authority.preimages, operations),
    });
    const finalized: FinalizedSetupAuthority = Object.freeze({
      ...authority,
      finalizedHost,
      configuredProjects: registryMutation.configuredProjects,
      verificationAuthority: createNodeFinalizedVerificationAuthority({
        finalizedHost,
        configuredProjects: registryMutation.configuredProjects,
        projectRoot: authority.projectRoot,
      }),
      createdCredential: reservedCreatedCredential,
      createdAuthority,
    });
    return Object.freeze({ finalization, finalized });
  }
  private finalizationPreimages(
    preimages: readonly LifecyclePreimage[],
    operations: readonly LifecycleMutationOperation[],
  ): readonly LifecyclePreimage[] {
    const paths = new Set<string>();
    const addPath = (path: string): void => {
      if (paths.has(path)) {
        throw new Error('setup finalization has overlapping ordinary operations');
      }
      paths.add(path);
    };
    for (const operation of operations) {
      if (
        operation.kind === 'write-file' ||
        operation.kind === 'write-config' ||
        operation.kind === 'apply-credential-authority-registry'
      ) {
        addPath(operation.path);
        continue;
      }
      if (operation.kind === 'move-config') {
        addPath(operation.path);
        addPath(operation.sourcePath);
        continue;
      }
      throw new Error('setup finalization contains an invalid ordinary operation');
    }
    const selected = preimages.filter((preimage) => paths.delete(preimage.path));
    if (paths.size !== 0) {
      throw new Error('setup finalization preimages do not cover its operations');
    }
    return Object.freeze(selected);
  }
  private transactionPlan(
    plan: SetupPlan,
    operations: readonly LifecycleMutationOperation[],
    preimages: readonly LifecyclePreimage[],
    registryArtifact: OwnedCredentialAuthorityRegistryArtifact | undefined,
  ): SetupManifestV1 {
    const writtenFiles = new Map<string, Uint8Array>();
    for (const operation of operations) {
      if (operation.kind === 'write-file') {
        writtenFiles.set(operation.path, operation.bytes);
      }
    }

    const artifacts = plan.artifacts.map((artifact) => {
      if (artifact.kind !== 'file') {
        return artifact;
      }
      const preimage = preimages.find((candidate) => candidate.path === artifact.path);
      const written = writtenFiles.get(artifact.path);
      const preimageFingerprint = preimage?.state === 'file' ? sha(preimage.bytes) : undefined;
      const fingerprint = (written === undefined ? undefined : sha(written)) ?? preimageFingerprint;
      if (fingerprint === undefined) {
        throw new Error('owned host artifact has no exact content fingerprint');
      }
      const hunks = Object.freeze(
        artifact.hunks.map((hunk) => Object.freeze({ ...hunk, fingerprint })),
      );
      let inverse = artifact.inverse;
      if (artifact.inverse.kind === 'delete-created-file') {
        inverse = Object.freeze({ ...artifact.inverse, expectedFingerprint: fingerprint });
      } else if (artifact.inverse.kind === 'none' && written !== undefined) {
        if (preimageFingerprint === undefined) {
          throw new Error('modified owned host artifact has no file preimage');
        }
        if (fingerprint !== preimageFingerprint) {
          inverse = this.restoreOwnedFileInverse(
            artifact.path,
            preimage,
            written,
            fingerprint,
            hunks,
          );
        }
      }
      return Object.freeze({ ...artifact, fingerprint, hunks, inverse });
    });

    const ownedArtifacts =
      registryArtifact === undefined ? artifacts : [...artifacts, registryArtifact];
    return Object.freeze({
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest' as const,
      installId: plan.installId,
      state: 'active' as const,
      artifacts: Object.freeze(ownedArtifacts),
    });
  }
  private restoreOwnedFileInverse(
    path: string,
    preimage: LifecyclePreimage | undefined,
    postimage: Uint8Array,
    postimageFingerprint: string,
    hunks: readonly OwnedHunk[],
  ) {
    if (preimage?.state !== 'file') {
      throw new Error('owned host artifact restoration is unsupported');
    }
    const ownedInsertion = ownedStaticLoaderInsertion(
      preimage.bytes,
      postimage,
      postimageFingerprint,
      hunks,
    );
    if (ownedInsertion === undefined) {
      throw new Error('owned host artifact restoration is unsupported');
    }
    return Object.freeze({
      kind: 'restore-owned-file' as const,
      path,
      preimageFingerprint: sha(preimage.bytes),
      postimageFingerprint,
      ownedInsertion,
      hunks,
    });
  }

  private async hostArtifactBytes(
    role: 'loader' | 'descriptor' | 'helper',
    finalizedHost: FinalizedHostIntegrationPlan,
    root: string,
    configuredProjects: TrustedDescriptorProjectSet,
  ): Promise<Uint8Array> {
    if (role === 'descriptor') {
      const text =
        finalizedHost.host === 'html'
          ? serializeStaticHostDescriptorV1(finalizedHost.descriptor, configuredProjects)
          : serializeViteHostDescriptorV1(finalizedHost.descriptor, configuredProjects);
      return new TextEncoder().encode(text);
    }
    if (role === 'helper')
      return new TextEncoder().encode('export const sceneGlassHostIntegration = "v1";\n');
    if (role === 'loader') {
      const path = join(
        root,
        finalizedHost.host === 'html' ? finalizedHost.loader.targetPath : 'index.html',
      );
      const source = await this.readRegularFile(path, MAX_SOURCE_FILE_BYTES);
      if (source === undefined) throw new Error('host loader target is missing');
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(source);
        const headSearch = finalizedHost.host === 'html' ? text.toLowerCase() : text;
        const index = headSearch.indexOf('</head>');
        if (index === -1 || headSearch.indexOf('</head>', index + 1) !== -1)
          throw new Error('static template is ambiguous');
        const prefix = text.slice(0, index);
        const lineStart = prefix.lastIndexOf('\n') + 1;
        const linePrefix = prefix.slice(lineStart);
        const newline =
          (lineStart >= 2 && prefix[lineStart - 2] === '\r') || text.includes('\r\n')
            ? '\r\n'
            : '\n';
        const closingHeadIndent = /^[\t ]*$/u.test(linePrefix) ? linePrefix : '';
        const beforeMarker =
          closingHeadIndent.length > 0 || linePrefix.length === 0
            ? prefix.slice(0, lineStart)
            : `${prefix}${newline}`;
        const insertedLine =
          finalizedHost.host === 'html'
            ? STATIC_LOADER_MARKER
            : '<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>';
        return new TextEncoder().encode(
          `${beforeMarker}${insertedLine}${newline}${closingHeadIndent}${text.slice(index)}`,
        );
      } finally {
        source.fill(0);
      }
    }
    throw new Error('host artifact role is unsupported');
  }

  private async assertStateRootAuthority(): Promise<void> {
    const parent = dirname(this.#paths.stateRoot);
    let parentStat: Stats;
    try {
      parentStat = await this.#fs.lstat(parent);
    } catch (error) {
      if (isNotFound(error)) return;
      throw error;
    }
    if (
      !parentStat.isDirectory() ||
      parentStat.isSymbolicLink() ||
      (await this.#fs.realpath(parent)) !== parent
    ) {
      throw new Error('lifecycle state parent is unsafe');
    }
    let root: Stats;
    try {
      root = await this.#fs.lstat(this.#paths.stateRoot);
    } catch (error) {
      if (isNotFound(error)) return;
      throw error;
    }
    if (
      !root.isDirectory() ||
      root.isSymbolicLink() ||
      (await this.#fs.realpath(this.#paths.stateRoot)) !== this.#paths.stateRoot
    ) {
      throw new Error('lifecycle state root is unsafe');
    }
  }
  private async readStateRootEntries(): Promise<readonly string[]> {
    let stat: Stats;
    try {
      stat = await this.#fs.lstat(this.#paths.stateRoot);
    } catch (error) {
      if (isNotFound(error)) {
        return Object.freeze([]);
      }
      throw error;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('lifecycle state root is unsafe');
    }
    const directory = await this.#fs.opendir(this.#paths.stateRoot);
    const entries: string[] = [];
    try {
      while (true) {
        const entry = await directory.read();
        if (entry === null) break;
        if (entries.length >= MAX_STATE_ROOT_ENTRIES) {
          throw new Error('lifecycle state root exceeds its entry limit');
        }
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw new Error('lifecycle state root has an unsafe entry');
        }
        entries.push(entry.name);
      }
    } finally {
      await directory.close();
    }
    entries.sort(bytewiseCompare);
    return Object.freeze(entries);
  }
  private async ensureStateRoot(): Promise<void> {
    const parent = dirname(this.#paths.stateRoot);
    try {
      await this.#fs.mkdir(parent, { mode: 0o700 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw error;
    }
    const parentStat = await this.#fs.lstat(parent);
    if (
      !parentStat.isDirectory() ||
      parentStat.isSymbolicLink() ||
      (await this.#fs.realpath(parent)) !== parent
    ) {
      throw new Error('lifecycle state parent is unsafe');
    }
    try {
      await this.#fs.mkdir(this.#paths.stateRoot, { mode: 0o700 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw error;
    }
    const root = await this.#fs.lstat(this.#paths.stateRoot);
    if (
      !root.isDirectory() ||
      root.isSymbolicLink() ||
      (await this.#fs.realpath(this.#paths.stateRoot)) !== this.#paths.stateRoot
    ) {
      throw new Error('lifecycle state root is unsafe');
    }
  }

  private async ensureSharedHomeLock(): Promise<void> {
    await this.canonicalDirectory(this.#homeDirectory);
    const existing = await this.lstatRegular(this.#paths.lockPath);
    if (existing !== undefined) {
      if ((existing.mode & 0o777) !== 0o600) {
        throw new Error('lifecycle lock has an unsafe mode');
      }
      return;
    }
    try {
      await this.#fs.writeFile(this.#paths.lockPath, 'lock\n', { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw error;
    }
    const lock = await this.lstatRegular(this.#paths.lockPath);
    if (lock === undefined || (lock.mode & 0o777) !== 0o600) {
      throw new Error('lifecycle lock is unavailable');
    }
  }

  private async discoverSetupDirectories(
    targets: readonly string[],
    mutationId: string,
  ): Promise<readonly SetupDirectoryCandidate[]> {
    const missing = new Set<string>();
    for (const target of targets) {
      let cursor = dirname(target);
      while (true) {
        try {
          const stat = await this.#fs.lstat(cursor);
          if (
            !stat.isDirectory() ||
            stat.isSymbolicLink() ||
            (await this.#fs.realpath(cursor)) !== cursor
          ) {
            throw new Error('lifecycle target parent is unsafe');
          }
          break;
        } catch (error) {
          if (!isNotFound(error)) throw error;
          missing.add(cursor);
          const parent = dirname(cursor);
          if (parent === cursor) {
            throw new Error('lifecycle target has no safe parent directory');
          }
          cursor = parent;
        }
      }
    }
    return Object.freeze(
      [...missing]
        .filter((path) => !isSameOrAncestor(path, this.#paths.stateRoot))
        .sort((left, right) => pathDepth(left) - pathDepth(right) || bytewiseCompare(left, right))
        .map((path) =>
          Object.freeze({
            path,
            stagingPath: `${path}.scene-glass-${mutationId}.directory.stage`,
            mode: 0o700,
          }),
        ),
    );
  }

  private setupTargetPaths(authority: SetupAuthority): readonly string[] {
    const targets = new Set<string>([
      ...authority.config.writes.map((write) => write.path),
      authority.registryCandidate.fact.path,
      ...authority.host.artifacts.map((artifact) => artifact.artifact.path),
      ...(authority.host.credential.kind === 'setup-created-candidate'
        ? [authority.host.credential.path]
        : []),
    ]);
    if (targets.size === 0 || [...targets].some((path) => !isCanonicalAbsolute(path))) {
      throw new Error('setup target is not canonical');
    }
    return Object.freeze([...targets].sort());
  }

  private assertSetupPathTopology(
    authority: SetupAuthority,
    directories: readonly SetupDirectoryCandidate[],
    mutationId: string,
  ): void {
    const targets = this.setupTargetPaths(authority);
    const credentialStaging =
      authority.host.credential.kind === 'setup-created-candidate'
        ? [`${authority.host.credential.path}.scene-glass-${mutationId}.credential.stage`]
        : [];
    const protectedPaths = [
      this.#paths.lockPath,
      this.#paths.walPath,
      this.#paths.manifestPath,
      this.#paths.receiptPath,
    ];
    const stagingPaths = [
      ...directories.map((candidate) => candidate.stagingPath),
      ...credentialStaging,
    ];
    for (const path of [
      ...targets,
      ...directories.map((candidate) => candidate.path),
      ...stagingPaths,
    ]) {
      if (protectedPaths.some((protectedPath) => pathsOverlap(path, protectedPath))) {
        throw new Error('setup target collides with lifecycle state');
      }
    }
    for (let index = 0; index < targets.length; index += 1) {
      const target = targets[index];
      if (
        target === undefined ||
        targets.slice(index + 1).some((other) => pathsOverlap(target, other))
      ) {
        throw new Error('setup targets collide');
      }
    }
    if (
      stagingPaths.some((stagingPath) =>
        targets.some((target) => pathsOverlap(target, stagingPath)),
      )
    ) {
      throw new Error('setup staging path collides with a target');
    }
  }

  private assertSetupCandidate(
    authority: SetupAuthority,
    candidate: Uint8Array | undefined,
    approval: SetupApprovalAuthority | undefined,
  ): void {
    if (approval === undefined) {
      throw new Error('setup mutation requires a recorded approval');
    }
    if (authority.host.credential.kind === 'setup-created-candidate') {
      if (
        !(candidate instanceof Uint8Array) ||
        candidate.byteLength !== 32 ||
        approval.state !== 'candidate-issued' ||
        approval.candidate !== candidate
      ) {
        throw new Error('created credential requires its one issued 256-bit candidate');
      }
      return;
    }
    if (
      candidate !== undefined ||
      approval.state !== 'approved' ||
      approval.candidate !== undefined
    ) {
      throw new Error('adopted credential cannot receive candidate bytes');
    }
  }

  private setupCredentialCandidate(
    authority: PreparedSetupAuthority,
  ): Omit<import('./transaction.js').SetupCredentialCandidate, 'contentBytes'> | undefined {
    const credential = authority.host.credential;
    if (credential.kind !== 'setup-created-candidate') {
      return undefined;
    }
    return Object.freeze({
      projectId: credential.projectId,
      path: credential.path,
      stagingPath: `${credential.path}.scene-glass-${authority.mutationId}.credential.stage`,
      mode: 0o600,
    });
  }

  private credentialAuthorityFromCreated(
    created: SetupCreatedCredentialAuthority,
  ): CredentialAuthority {
    return Object.freeze({
      projectId: created.projectId,
      path: created.path,
      device: created.identity.device,
      inode: created.identity.inode,
    });
  }
  private async observeCreatedCredentialAuthority(
    created: SetupCreatedCredentialAuthority,
    candidate: Uint8Array | undefined,
    receipt: SetupTransactionReceipt,
    issuer: TransactionObservedCredentialAuthorityIssuer,
  ): Promise<import('./engine.js').TransactionObservedCredentialAuthority> {
    if (
      created.mode !== 0o600 ||
      !(candidate instanceof Uint8Array) ||
      candidate.byteLength !== 32
    ) {
      throw new Error('created credential does not match the transaction-issued authority');
    }
    const authority = this.credentialAuthorityFromCreated(created);
    const expectedBytes = this.encodeCredentialEnvironment(candidate, created.projectId);
    let verified: ReturnType<typeof verifyCredentialAuthorities> | undefined;
    try {
      verified = verifyCredentialAuthorities({
        authorities: Object.freeze([authority]),
        selectedProjectId: created.projectId,
        expectedOwnerUid: currentUid(),
        maxBytes: MAX_TOKEN_SOURCE_BYTES,
      });
      const matches = await withSelectedCredential(verified, (publishedBytes) =>
        sameBytes(publishedBytes, expectedBytes),
      );
      if (!matches) {
        throw new Error('created credential does not match the generated candidate');
      }
      return createTransactionObservedCredentialAuthority({
        issuer,
        receipt,
        authority,
      });
    } finally {
      expectedBytes.fill(0);
      if (verified !== undefined) {
        revokeCredentialReadCapability(verified.capability);
      }
    }
  }

  private encodeCredentialEnvironment(candidate: Uint8Array, projectId: string): Uint8Array {
    const token = encodeBase64UrlCredential(candidate);
    try {
      return Buffer.from(
        `${VITE_LOADER_URL_KEY}=${LOADER_URL}\n${VITE_PROJECT_ID_KEY}=${projectId}\n${VITE_PROJECT_TOKEN_KEY}=${Buffer.from(token).toString('ascii')}\n${CREDENTIAL_KEY}=${Buffer.from(token).toString('ascii')}\n`,
        'utf8',
      );
    } finally {
      token.fill(0);
    }
  }

  private async runDiagnostics(authority: FinalizedSetupAuthority): Promise<void> {
    const secretMatcher = await this.createSecretPersistenceMatcher(authority);
    let matcherRetained = false;
    try {
      const credentialPath =
        authority.finalizedHost.credential.kind === 'setup-created-candidate'
          ? authority.finalizedHost.credential.path
          : authority.finalizedHost.credential.authority.path;
      await this.#verification.runLiveDiagnostics({
        authority: authority.verificationAuthority,
        selectedHost: 'static',
        context: this.diagnosticContext(),
        tokenMatcher: secretMatcher,
        pathCanaries: Object.freeze([
          authority.projectRoot,
          this.#selectedConfigPath,
          credentialPath,
          authority.registryCandidate.fact.path,
          ...authority.config.writes.map((write) => write.path),
        ]),
      });
    } catch (error) {
      if (error instanceof LiveDiagnosticError && error.cleanupConvergence !== undefined) {
        matcherRetained = true;
        this.adoptDiagnosticCloseConvergence(error.cleanupConvergence, secretMatcher);
      }
      throw error;
    } finally {
      if (!matcherRetained) {
        secretMatcher.destroy();
      }
    }
  }
  private async createSecretPersistenceMatcher(
    authority: FinalizedSetupAuthority,
  ): Promise<OpaqueSecretPersistenceMatcher> {
    if (authority.candidate !== undefined) {
      const candidate = new Uint8Array(authority.candidate);
      try {
        return this.secretPersistenceMatcherFromCandidate(candidate);
      } finally {
        candidate.fill(0);
      }
    }
    if (authority.finalizedHost.credential.kind !== 'adopted-authority') {
      throw new Error('finalized credential authority has no persistence matcher source');
    }
    const snapshot = await this.readSecureSnapshot(
      authority.finalizedHost.credential.authority.path,
      MAX_TOKEN_SOURCE_BYTES,
    );
    if (snapshot === undefined) {
      throw new Error('adopted credential disappeared before diagnostics');
    }
    try {
      if (
        !isCredentialSource(snapshot.bytes, authority.finalizedHost.credential.authority.projectId)
      ) {
        throw new Error('adopted credential is not canonical');
      }
      const candidate = decodeCredentialSource(snapshot.bytes);
      try {
        return this.secretPersistenceMatcherFromCandidate(candidate);
      } finally {
        candidate.fill(0);
      }
    } finally {
      snapshot.bytes.fill(0);
    }
  }
  private secretPersistenceMatcherFromCandidate(
    candidate: Uint8Array,
  ): OpaqueSecretPersistenceMatcher {
    if (candidate.byteLength !== 32) {
      throw new Error('credential persistence matcher requires one 256-bit candidate');
    }
    const raw = new Uint8Array(candidate);
    const environment = this.encodeCredentialEnvironment(candidate, this.#project.projectId);
    const encoded = encodeBase64UrlCredential(candidate);
    environment.fill(0);
    const rawDigest = sha256HexBytes(raw);
    const encodedDigest = sha256HexBytes(encoded);
    let patterns = [
      raw,
      encoded,
      rawDigest,
      encodedDigest,
      prefixedSha256Digest(rawDigest),
      prefixedSha256Digest(encodedDigest),
    ];
    let destroyed = false;
    return Object.freeze({
      matches: (bytes: Uint8Array): boolean => {
        if (destroyed || !(bytes instanceof Uint8Array)) {
          throw new Error('lifecycle secret persistence matcher is unavailable');
        }
        return patterns.some((pattern) => containsBytes(bytes, pattern));
      },
      destroy: (): void => {
        if (destroyed) return;
        destroyed = true;
        for (const pattern of patterns) {
          pattern.fill(0);
        }
        patterns = [];
      },
    });
  }

  private diagnosticContext(): { readonly signal: AbortSignal; readonly deadline: number } {
    return Object.freeze({
      signal: new AbortController().signal,
      deadline: Date.now() + this.#diagnosticTimeoutMs,
    });
  }
  private adoptDiagnosticCloseConvergence(
    convergence: Promise<void>,
    secretMatcher: OpaqueSecretPersistenceMatcher,
  ): void {
    this.#unconvergedDiagnosticClosures.add(convergence);
    const release = (converged: boolean): void => {
      try {
        secretMatcher.destroy();
        if (converged) {
          this.#unconvergedDiagnosticClosures.delete(convergence);
        }
      } catch {
        // An undestroyed matcher retains non-clean authority.
      }
    };
    void convergence.then(
      () => release(true),
      () => release(false),
    );
  }
  private async inspectAuthorityRegistry(path: string): Promise<AuthorityRegistryFact> {
    await this.assertExistingParentCanonical(path);
    const snapshot = await this.readSecureSnapshot(path, MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES);
    if (snapshot === undefined) {
      return Object.freeze({ path, registry: undefined, mode: undefined });
    }
    try {
      const serialized = new TextDecoder('utf-8', { fatal: true }).decode(snapshot.bytes);
      return Object.freeze({
        path,
        registry: parseCredentialAuthorityRegistryJsonV1(serialized),
        mode: snapshot.observation.mode,
      });
    } finally {
      snapshot.bytes.fill(0);
    }
  }

  private async assertSetupRegistryEligibility(
    homes: ConfigHomeFacts,
    project: ProjectConfigV1,
    current: ServerConfigV1,
    registry: AuthorityRegistryFact,
  ): Promise<void> {
    if (homes.new === undefined && homes.legacy !== undefined) {
      if (
        !isStrictLegacyBootstrap({
          homes,
          selectedProject: project,
          registryPresent: registry.registry !== undefined,
        })
      ) {
        throw new Error('legacy setup requires one selected project and no registry');
      }
      return;
    }
    if (homes.new === undefined) {
      if (registry.registry !== undefined) {
        throw new Error('registry without a current config is ambiguous');
      }
      return;
    }
    if (registry.registry === undefined) {
      throw new Error('current config requires a canonical authority registry');
    }
    await this.validateRegistryAgainstConfig(current, registry.registry);
  }
  private registryMutationIsExpected(
    candidate: RegistrySetupCandidate,
    host: HostIntegrationPlan,
  ): boolean {
    if (host.credential.kind === 'setup-created-candidate') {
      return true;
    }
    const existing = candidate.preimage.projects[0];
    if (existing === undefined) {
      return true;
    }
    const authority = host.credential.authority;
    return !(
      existing.projectId === candidate.selectedProject.projectId &&
      existing.tokenEnv === candidate.selectedProject.tokenEnv &&
      existing.canonicalRoot === candidate.selectedProject.root &&
      existing.credentialPath === authority.path &&
      existing.device === authority.device &&
      existing.inode === authority.inode
    );
  }

  private async captureStartSnapshot(manifest: SetupManifestV1): Promise<StartSnapshotAuthority> {
    await this.assertStateRootAuthority();
    const currentManifest = await this.readCanonicalJson(
      this.#paths.manifestPath,
      parseSetupManifestJsonV1,
    );
    if (
      currentManifest === undefined ||
      JSON.stringify(currentManifest) !== JSON.stringify(manifest)
    ) {
      throw new Error('current lifecycle manifest differs from the inspected manifest');
    }
    const configPath = this.#selectedConfigPath;
    await this.assertExistingParentCanonical(configPath);
    const configBytes = await this.readRegularFile(configPath, MAX_CONFIG_BYTES);
    if (configBytes === undefined) {
      throw new Error('selected config is unavailable');
    }
    let config: ServerConfigV1;
    try {
      config = parseConfigBytes(configBytes);
    } finally {
      configBytes.fill(0);
    }
    const registryPath = authorityRegistryPath(configPath);
    const registryBytes = await this.readRegularFile(
      registryPath,
      MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES,
    );
    if (registryBytes === undefined) {
      throw new Error('selected credential authority registry is unavailable');
    }
    let registry: CredentialAuthorityRegistryV1;
    try {
      registry = parseCredentialAuthorityRegistryJsonV1(
        new TextDecoder('utf-8', { fatal: true }).decode(registryBytes),
      );
    } finally {
      registryBytes.fill(0);
    }
    const projects = await this.validateRegistryAgainstConfig(config, registry);
    const descriptor = this.ownedSelectedDescriptor(manifest);
    const descriptorBytes = await this.readRegularFile(descriptor.artifact.path, MAX_CONFIG_BYTES);
    if (descriptorBytes === undefined || sha(descriptorBytes) !== descriptor.artifact.fingerprint) {
      descriptorBytes?.fill(0);
      throw new Error('manifest-owned descriptor is unavailable or changed');
    }
    let selectedProjectId = '';
    let descriptorFingerprint = '';
    try {
      descriptorFingerprint = sha(descriptorBytes);
      const text = new TextDecoder('utf-8', { fatal: true }).decode(descriptorBytes);
      selectedProjectId =
        descriptor.parser === 'static'
          ? parseStaticHostDescriptorJsonV1(text, projects).projectId
          : parseViteHostDescriptorJsonV1(text, projects).projectId;
    } finally {
      descriptorBytes.fill(0);
    }
    const selectedConfig = config.projects.filter(
      (project) => project.projectId === selectedProjectId,
    );
    const selectedRegistry = registry.projects.filter(
      (entry) => entry.projectId === selectedProjectId,
    );
    const selectedProject = projects.projects.find(
      (project) => project.projectId === selectedProjectId,
    );
    const credentialArtifacts = manifest.artifacts.filter(
      (
        artifact,
      ): artifact is Extract<SetupManifestV1['artifacts'][number], { kind: 'credential' }> =>
        artifact.kind === 'credential',
    );
    const credentialArtifact = credentialArtifacts[0];
    const invocationRoot = await this.canonicalDirectory(this.#host.rootPath ?? this.#project.root);
    if (
      selectedConfig.length !== 1 ||
      selectedRegistry.length !== 1 ||
      selectedProject === undefined ||
      selectedProject.canonicalRoot !== invocationRoot ||
      credentialArtifacts.length !== 1 ||
      credentialArtifact === undefined ||
      selectedConfig[0]?.tokenEnv !== selectedRegistry[0]?.tokenEnv ||
      selectedRegistry[0]?.credentialPath !== credentialArtifact.path ||
      selectedProject.credentialAuthority.path !== credentialArtifact.path
    ) {
      throw new Error('semantic start provenance is invalid');
    }
    const viteDeclarations = await this.captureDeclaredVitePolicies(config, projects);
    const originOwners = new Map<string, string>();
    for (const project of config.projects) {
      const declaration = viteDeclarations.find(
        (candidate) => candidate.projectId === project.projectId,
      );
      for (const origin of declaration?.policy.origins ?? project.allowedOrigins) {
        const owner = originOwners.get(origin);
        if (owner !== undefined && owner !== project.projectId) {
          const viteCandidates = viteDeclarations
            .filter(
              (candidate) =>
                candidate.projectId === owner || candidate.projectId === project.projectId,
            )
            .map((candidate) => candidate.projectId)
            .sort();
          throw new LifecycleStartDiagnosticError({
            code: 'SCG_START_VITE_ORIGIN_CONFLICT',
            projectId: viteCandidates[0] ?? project.projectId,
          });
        }
        originOwners.set(origin, project.projectId);
      }
    }
    const configSnapshot = lifecycleConfigSnapshot(config);
    const registrySnapshot = lifecycleRegistrySnapshot(registry);
    const snapshotId = this.idFrom(
      `start:${manifest.installId}:${descriptor.artifact.path}:${descriptorFingerprint}:${JSON.stringify(
        configSnapshot,
      )}:${JSON.stringify(registrySnapshot)}:${JSON.stringify(viteDeclarations)}`,
    );
    const facts: LifecycleStartFacts = Object.freeze({
      snapshotId,
      selectedProjectId,
      config: configSnapshot,
      registry: registrySnapshot,
      projects: Object.freeze(
        projects.projects.map((project: TrustedDescriptorProject) =>
          Object.freeze({
            projectId: project.projectId,
            authority: lifecycleAuthoritySnapshot(project.credentialAuthority),
            descriptor: Object.freeze({
              owned: project.projectId === selectedProjectId,
              projectId: project.projectId,
            }),
            cache: Object.freeze({ canonicalRoot: project.canonicalRoot }),
          }),
        ),
      ),
    });
    return Object.freeze({
      snapshotId,
      manifest,
      facts,
      configPath,
      selectedProjectId,
      projects,
      viteDeclarations,
    });
  }

  private async captureDeclaredVitePolicies(
    config: ServerConfigV1,
    projects: TrustedDescriptorProjectSet,
  ): Promise<StartSnapshotAuthority['viteDeclarations']> {
    const trusted = new Map(projects.projects.map((project) => [project.projectId, project]));
    const declarations: StartSnapshotAuthority['viteDeclarations'][number][] = [];
    let aggregateBytes = 0;
    for (const project of [...config.projects].sort((left, right) =>
      left.projectId < right.projectId ? -1 : left.projectId > right.projectId ? 1 : 0,
    )) {
      if (project.framework === 'html') continue;
      const trustedProject = trusted.get(project.projectId);
      if (trustedProject === undefined || trustedProject.canonicalRoot !== project.root) {
        throw new Error('configured Vite project root binding is invalid');
      }
      const packageBytes = await this.readDeclaredViteSource(
        trustedProject.canonicalRoot,
        'package.json',
      );
      let viteBytes: Uint8Array | undefined;
      try {
        viteBytes = await this.readDeclaredViteSource(
          trustedProject.canonicalRoot,
          'vite.config.ts',
        );
      } catch (error) {
        packageBytes?.fill(0);
        throw error;
      }
      if (packageBytes === undefined || viteBytes === undefined) {
        packageBytes?.fill(0);
        viteBytes?.fill(0);
        throw new LifecycleStartDiagnosticError({
          code: 'SCG_START_VITE_DECLARATION_INVALID',
          projectId: project.projectId,
        });
      }
      aggregateBytes += packageBytes.byteLength + viteBytes.byteLength;
      if (aggregateBytes > MAX_DECLARED_VITE_AGGREGATE_BYTES) {
        packageBytes.fill(0);
        viteBytes.fill(0);
        throw new Error('declared Vite source aggregate exceeds the startup budget');
      }
      try {
        const resolution = resolveDeclaredViteOriginPolicy({
          allowedOrigins: project.allowedOrigins,
          framework: project.framework,
          packageJson: new TextDecoder('utf-8', { fatal: true }).decode(packageBytes),
          projectId: project.projectId,
          viteConfig: new TextDecoder('utf-8', { fatal: true }).decode(viteBytes),
        });
        if (!resolution.ok) {
          throw new LifecycleStartDiagnosticError({
            code: resolution.reason,
            projectId: project.projectId,
          });
        }
        declarations.push(
          Object.freeze({
            projectId: project.projectId,
            packageFingerprint: sha(packageBytes),
            viteFingerprint: sha(viteBytes),
            policy: resolution.policy,
          }),
        );
      } finally {
        packageBytes.fill(0);
        viteBytes.fill(0);
      }
    }
    return Object.freeze(declarations);
  }
  private async readDeclaredViteSource(
    canonicalRoot: string,
    relativePath: 'package.json' | 'vite.config.ts',
  ): Promise<Uint8Array | undefined> {
    const path = join(canonicalRoot, relativePath);
    if ((await this.lstatRegular(path)) === undefined) return undefined;
    if ((await this.canonicalDirectory(canonicalRoot)) !== canonicalRoot) {
      throw new Error('declared Vite root changed during startup');
    }
    const result = secureReadBeneath({
      root: canonicalRoot,
      expectedRoot: await this.identity(canonicalRoot),
      relativePath,
      deniedIdentities: Object.freeze([]),
      maxBytes: MAX_DECLARED_VITE_FILE_BYTES,
    });
    if (result.bytes.byteLength > MAX_DECLARED_VITE_FILE_BYTES || result.linkCount !== 1) {
      result.bytes.fill(0);
      throw new Error('declared Vite source is outside the startup budget');
    }
    return result.bytes;
  }
  private ownedSelectedDescriptor(manifest: SetupManifestV1): Readonly<{
    readonly artifact: Extract<SetupManifestV1['artifacts'][number], { kind: 'file' }>;
    readonly parser: 'static' | 'vite';
  }> {
    const descriptors = manifest.artifacts.filter(
      (artifact): artifact is Extract<SetupManifestV1['artifacts'][number], { kind: 'file' }> =>
        artifact.kind === 'file' &&
        artifact.hunks.some((hunk) => /^scg-(?:html|vue3|react)-descriptor$/u.test(hunk.subject)),
    );
    const artifact = descriptors[0];
    const descriptorHunks =
      artifact?.hunks.filter((hunk) =>
        /^scg-(?:html|vue3|react)-descriptor$/u.test(hunk.subject),
      ) ?? [];
    const subject = descriptorHunks[0]?.subject;
    if (
      descriptors.length !== 1 ||
      artifact === undefined ||
      descriptorHunks.length !== 1 ||
      subject === undefined
    ) {
      throw new Error('manifest does not own exactly one selected descriptor');
    }
    return Object.freeze({
      artifact,
      parser: subject === 'scg-html-descriptor' ? 'static' : 'vite',
    });
  }
  private async cleanupPreparedStart(
    preparationId: string,
    cleanup: LifecycleCleanupContext | undefined,
    message = 'prepared start cleanup failed',
  ): Promise<void> {
    const prepared = this.#preparedStarts.get(preparationId);
    if (prepared === undefined) {
      throw new LifecyclePreparedStartUnavailableError('missing');
    }
    if (prepared.state !== 'prepared') {
      throw new LifecyclePreparedStartUnavailableError('reused');
    }
    this.assertStartCleanupDeadline(cleanup);
    if (prepared.cleanupInFlight !== undefined) {
      return prepared.cleanupInFlight;
    }
    const attempt = this.completePreparedStartCleanup(preparationId, prepared, cleanup, message);
    prepared.cleanupInFlight = attempt;
    try {
      await attempt;
    } finally {
      if (prepared.cleanupInFlight === attempt) {
        delete prepared.cleanupInFlight;
      }
    }
  }

  private async completePreparedStartCleanup(
    preparationId: string,
    prepared: PreparedStartAuthority,
    cleanup: LifecycleCleanupContext | undefined,
    message: string,
  ): Promise<void> {
    const failures: unknown[] = [];
    if (prepared.foreground !== undefined) {
      try {
        this.assertStartCleanupDeadline(cleanup);
        await prepared.foreground.cleanup(cleanup);
        delete prepared.foreground;
      } catch (error) {
        failures.push(error);
      }
    }
    if (prepared.foreground === undefined) {
      try {
        this.assertStartCleanupDeadline(cleanup);
        await this.releasePreparedStartLock(prepared);
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length !== 0) {
      throw markRetryableStartCleanupFailure(primaryWithCleanup(new Error(message), failures));
    }
    if (this.#preparedStarts.get(preparationId) === prepared) {
      this.#preparedStarts.delete(preparationId);
    }
  }

  private assertStartCleanupDeadline(cleanup: LifecycleCleanupContext | undefined): void {
    if (cleanup === undefined) {
      return;
    }
    if (
      cleanup === null ||
      typeof cleanup !== 'object' ||
      !Number.isSafeInteger(cleanup.deadline) ||
      cleanup.deadline <= Date.now()
    ) {
      throw markRetryableStartCleanupFailure(new Error('prepared start cleanup deadline elapsed'));
    }
  }

  private async releasePreparedStartLock(prepared: PreparedStartAuthority): Promise<void> {
    if (prepared.released) {
      return;
    }
    await prepared.lock.release();
    prepared.released = true;
  }

  private requireSetupAuthority(receiptId: string, plan: SetupPlan): SetupAuthority {
    const authority = this.#setupAuthorities.get(receiptId);
    if (authority === undefined || JSON.stringify(authority.plan) !== JSON.stringify(plan))
      throw new Error('setup plan authority is unavailable');
    return authority;
  }
  private revokeSetupAuthority(receiptId: string): void {
    const zeroPreimages = (authority: SetupAuthority): void => {
      for (const preimage of authority.preimages) {
        if (preimage.state === 'file') preimage.bytes.fill(0);
      }
    };
    const approval = this.#approvedReceipts.get(receiptId);
    approval?.candidate?.fill(0);
    this.#approvedReceipts.delete(receiptId);
    const setup = this.#setupAuthorities.get(receiptId);
    if (setup !== undefined) zeroPreimages(setup);
    this.#setupAuthorities.delete(receiptId);
    for (const [mutationId, authority] of this.#preparedSetupAuthorities) {
      if (authority.receiptId === receiptId) {
        authority.candidate?.fill(0);
        zeroPreimages(authority);
        this.#preparedSetupAuthorities.delete(mutationId);
      }
    }
    for (const [mutationId, authority] of this.#finalizedAuthorities) {
      if (authority.receiptId === receiptId) {
        authority.candidate?.fill(0);
        zeroPreimages(authority);
        this.#finalizedAuthorities.delete(mutationId);
      }
    }
  }

  private requirePreparedAuthority(
    mutationId: string,
    plan: SetupPlan,
    plannedHost: HostIntegrationPlan,
    candidate: Uint8Array | undefined,
  ): PreparedSetupAuthority {
    const authority = this.#preparedSetupAuthorities.get(mutationId);
    if (
      authority === undefined ||
      authority.candidate !== candidate ||
      JSON.stringify(authority.plan) !== JSON.stringify(plan) ||
      JSON.stringify(authority.host) !== JSON.stringify(plannedHost)
    ) {
      throw new Error('prepared setup authority is unavailable');
    }
    return authority;
  }

  private async assertSetupInspectionFacts(authority: SetupInspectionAuthority): Promise<void> {
    await this.assertSetupApprovalWitness(authority);
    for (const preimage of authority.preimages) {
      await this.assertPreimage(preimage);
    }
  }
  private async assertPreparedSetupFacts(authority: PreparedSetupAuthority): Promise<void> {
    await this.assertSetupApprovalWitness(authority);
    for (const preimage of authority.openingPreimages) {
      await this.assertPreimage(preimage);
    }
  }
  private async assertOpenedSetupFacts(authority: PreparedSetupAuthority): Promise<void> {
    await this.assertSetupApprovalWitness(authority);
    const createdDirectories = new Set(authority.directories.map((candidate) => candidate.path));
    for (const preimage of authority.openingPreimages) {
      if (!createdDirectories.has(preimage.path)) {
        await this.assertPreimage(preimage);
      }
    }
  }
  private setupApprovalWitness(
    config: ConfigOperationPlan,
    host: HostIntegrationPlan,
    registryCandidate: RegistrySetupCandidate,
  ): string {
    return JSON.stringify({ config, host, registryCandidate });
  }
  private async readSetupPredecessorWitness(): Promise<SetupPredecessorWitness> {
    await this.assertStateRootAuthority();
    const receipt = await this.readCanonicalJson(
      this.#paths.receiptPath,
      parseLifecycleReceiptJsonV1,
    );
    return receipt === undefined
      ? Object.freeze({ state: 'absent' as const })
      : Object.freeze({ state: 'receipt' as const, receipt });
  }
  private async assertSetupApprovalWitness(
    authority: Readonly<{
      readonly config: ConfigOperationPlan;
      readonly host: HostIntegrationPlan;
      readonly projectRoot: string;
      readonly expectedHostRoot: FileIdentity;
      readonly registryCandidate: RegistrySetupCandidate;
      readonly predecessor: SetupPredecessorWitness;
      readonly approvalWitness: string;
    }>,
  ): Promise<void> {
    const seed = this.#project;
    const configHomes = await this.inspectConfigHomes();
    try {
      const predecessor = await this.readSetupPredecessorWitness();
      if (JSON.stringify(predecessor) !== JSON.stringify(authority.predecessor)) {
        throw new Error('lifecycle predecessor changed after inspection');
      }
      const registry = await this.inspectAuthorityRegistry(
        authorityRegistryPath(configHomes.newPath),
      );
      const current = await this.currentConfig(configHomes);
      const project = projectConfigForSetup(seed, current);
      await this.assertSetupRegistryEligibility(configHomes, project, current, registry);
      const canonicalRoot = await this.canonicalDirectory(this.#host.rootPath ?? project.root);
      if (
        canonicalRoot !== authority.projectRoot ||
        !sameIdentity(await this.identity(canonicalRoot), authority.expectedHostRoot)
      ) {
        throw new Error('host root changed after inspection');
      }
      const hostPlan = await this.inspectHostPlan(
        project,
        canonicalRoot,
        current,
        registry.registry,
        authority.host.installId,
      );
      const host = planHostIntegration(hostPlan);
      const config = planConfigOperation({ homes: configHomes, project });
      const selectedRegistry = registry.registry?.projects.find(
        (entry) => entry.projectId === project.projectId,
      );
      const registryCandidate: RegistrySetupCandidate = Object.freeze({
        fact: registry,
        preimage: Object.freeze({
          schemaVersion: 1,
          projects: Object.freeze(selectedRegistry === undefined ? [] : [selectedRegistry]),
        }),
        selectedProject: project,
        config: config.config,
      });
      if (
        this.setupApprovalWitness(config, host, registryCandidate) !== authority.approvalWitness
      ) {
        throw new Error('approved setup facts changed');
      }
    } finally {
      configHomes.legacy?.bytes.fill(0);
      configHomes.new?.bytes.fill(0);
    }
  }

  private requireFinalizedAuthority(
    mutationId: string,
    plan: SetupPlan,
    finalizedHost: FinalizedHostIntegrationPlan,
  ): FinalizedSetupAuthority {
    const authority = this.#finalizedAuthorities.get(mutationId);
    if (
      authority === undefined ||
      JSON.stringify(authority.plan) !== JSON.stringify(plan) ||
      JSON.stringify(authority.finalizedHost) !== JSON.stringify(finalizedHost)
    ) {
      throw new Error('finalized setup authority is unavailable');
    }
    return authority;
  }

  private requireFinalizedAuthorityWithCandidate(
    mutationId: string,
    plan: SetupPlan,
    finalizedHost: FinalizedHostIntegrationPlan,
    candidate: Uint8Array | undefined,
  ): FinalizedSetupAuthority {
    const authority = this.requireFinalizedAuthority(mutationId, plan, finalizedHost);
    if (authority.candidate !== candidate) {
      throw new Error('finalized setup candidate is unavailable');
    }
    return authority;
  }

  private async assertExistingParentCanonical(path: string): Promise<void> {
    let cursor = dirname(path);
    while (true) {
      try {
        const stat = await this.#fs.lstat(cursor);
        if (
          !stat.isDirectory() ||
          stat.isSymbolicLink() ||
          (await this.#fs.realpath(cursor)) !== cursor
        ) {
          throw new Error('lifecycle target parent is unsafe');
        }
        return;
      } catch (error) {
        if (!isNotFound(error)) throw error;
        const parent = dirname(cursor);
        if (parent === cursor) {
          throw new Error('lifecycle target has no safe parent directory');
        }
        cursor = parent;
      }
    }
  }
  /**
   * A volume's st_dev is assigned at mount time, so a reboot can renumber it
   * under an install that is otherwise untouched. Reconcile the recorded device
   * numbers before validation reads them. Drift that is not a plain
   * renumbering changes nothing here and is left for validation to report.
   */
  private async reconcileDeviceDrift(): Promise<DeviceDriftOutcome> {
    // Claimed on first write only; inspecting an undrifted install must stay
    // free of identifier and entropy draws.
    let stagingSuffix: string | undefined;
    return repairDeviceDrift(
      {
        lstat: (path) => this.#fs.lstat(path),
        readUtf8: async (path) => {
          const bytes = await this.readRegularFile(path, MAX_CONFIG_BYTES);
          if (bytes === undefined) return undefined;
          try {
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
          } catch {
            return undefined;
          } finally {
            bytes.fill(0);
          }
        },
        writeUtf8: async (path, text) => {
          // `wx` on a per-run staging name keeps the write off any planted symlink.
          stagingSuffix ??= `.scene-glass-${this.safeId(this.#random.uuid())}.device.stage`;
          const staging = `${path}${stagingSuffix}`;
          await this.#fs.writeFile(staging, text, { mode: 0o600, flag: 'wx' });
          await this.#fs.rename(staging, path);
        },
      },
      {
        manifestPath: this.#paths.manifestPath,
        registryPath: authorityRegistryPath(this.#selectedConfigPath),
      },
    );
  }

  private async validateRegistryAgainstConfig(
    config: ServerConfigV1,
    registry: CredentialAuthorityRegistryV1,
    reservedCreatedCredential?: SetupReservedCredentialAuthority,
  ): Promise<TrustedDescriptorProjectSet> {
    if (config.projects.length !== registry.projects.length) {
      throw new Error('config and credential authority registry project sets differ');
    }
    const entries = new Map(registry.projects.map((entry) => [entry.projectId, entry]));
    const tokenEnvs = new Set<string>();
    let validatedReservedCredential = reservedCreatedCredential === undefined;
    const projects: TrustedDescriptorProject[] = [];
    for (const project of config.projects) {
      const entry = entries.get(project.projectId);
      if (
        entry === undefined ||
        entry.tokenEnv !== project.tokenEnv ||
        tokenEnvs.has(entry.tokenEnv)
      ) {
        throw new Error('config and credential authority registry are not a bijection');
      }
      tokenEnvs.add(entry.tokenEnv);
      const canonicalRoot = await this.canonicalDirectory(project.root);
      if (entry.canonicalRoot !== canonicalRoot) {
        throw new Error('credential authority registry root is invalid');
      }
      if (
        reservedCreatedCredential !== undefined &&
        project.projectId === reservedCreatedCredential.projectId
      ) {
        if (
          reservedCreatedCredential.mode !== 0o600 ||
          entry.credentialPath !== reservedCreatedCredential.path ||
          entry.device !== reservedCreatedCredential.identity.device ||
          entry.inode !== reservedCreatedCredential.identity.inode
        ) {
          throw new Error('credential authority registry reservation is invalid');
        }
        validatedReservedCredential = true;
      } else {
        const credential = await this.lstatRegular(entry.credentialPath);
        if (
          credential === undefined ||
          String(credential.dev) !== entry.device ||
          String(credential.ino) !== entry.inode
        ) {
          throw new Error('credential authority registry identity is invalid');
        }
      }
      projects.push(
        Object.freeze({
          projectId: project.projectId,
          canonicalRoot,
          publicRootIdentity: await this.identity(
            project.framework === 'html' ? join(canonicalRoot, 'public') : canonicalRoot,
          ),
          tokenEnv: project.tokenEnv,
          credentialAuthority: credentialAuthorityFromRegistryEntry(entry),
        }),
      );
    }
    if (!validatedReservedCredential) {
      throw new Error('credential authority registry reservation is absent');
    }
    if (entries.size !== projects.length) {
      throw new Error('credential authority registry contains an extra project');
    }
    projects.sort((left, right) => bytewiseCompare(left.projectId, right.projectId));
    return Object.freeze({ projects: Object.freeze(projects) });
  }

  private async finalizeRegistryMutation(
    candidate: RegistrySetupCandidate,
    finalizedHost: FinalizedHostIntegrationPlan,
    reservedCreatedCredential: SetupReservedCredentialAuthority | undefined,
  ): Promise<FinalizedRegistryMutation> {
    const authority = finalizedHost.descriptor.credentialAuthorities[0];
    if (
      finalizedHost.descriptor.credentialAuthorities.length !== 1 ||
      authority === undefined ||
      authority.projectId !== candidate.selectedProject.projectId
    ) {
      throw new Error('finalized selected credential authority is absent');
    }
    if (
      reservedCreatedCredential !== undefined &&
      (authority.projectId !== reservedCreatedCredential.projectId ||
        authority.path !== reservedCreatedCredential.path ||
        authority.device !== reservedCreatedCredential.identity.device ||
        authority.inode !== reservedCreatedCredential.identity.inode ||
        reservedCreatedCredential.mode !== 0o600)
    ) {
      throw new Error('reserved credential authority does not match finalization');
    }
    const canonicalRoot = await this.canonicalDirectory(candidate.selectedProject.root);
    const entry: CredentialAuthorityRegistryEntry = Object.freeze({
      projectId: candidate.selectedProject.projectId,
      tokenEnv: candidate.selectedProject.tokenEnv,
      canonicalRoot,
      credentialPath: authority.path,
      device: authority.device,
      inode: authority.inode,
    });
    const projects = [
      ...(candidate.fact.registry?.projects.filter(
        (item) => item.projectId !== candidate.selectedProject.projectId,
      ) ?? []),
      entry,
    ].sort((left, right) => bytewiseCompare(left.projectId, right.projectId));
    const registry = parseCredentialAuthorityRegistryJsonV1(
      serializeCredentialAuthorityRegistryV1({ schemaVersion: 1, projects }),
    );
    const postimage: SemanticCredentialAuthorityRegistryImage = Object.freeze({
      schemaVersion: 1,
      projects: Object.freeze([entry]),
    });
    const configuredProjects = await this.validateRegistryAgainstConfig(
      candidate.config,
      registry,
      reservedCreatedCredential,
    );
    const changed = !sameRegistrySelection(candidate.preimage, postimage);
    if (!changed) {
      return Object.freeze({
        artifact: undefined,
        operation: undefined,
        configuredProjects,
      });
    }
    const fingerprint = sha(
      new TextEncoder().encode(serializeCredentialAuthorityRegistryV1(registry)),
    );
    const inverse = Object.freeze({
      kind: 'restore-credential-authority-registry-entry' as const,
      path: candidate.fact.path,
      preimage: candidate.preimage,
      postimage,
    });
    const artifact: OwnedCredentialAuthorityRegistryArtifact = Object.freeze({
      path: candidate.fact.path,
      kind: 'credential-authority-registry' as const,
      fingerprint,
      preimage: candidate.preimage,
      postimage,
      inverse,
    });
    return Object.freeze({
      artifact,
      operation: Object.freeze({
        kind: 'apply-credential-authority-registry' as const,
        path: candidate.fact.path,
        preimage: candidate.preimage,
        postimage,
        fingerprint,
        mode: candidate.fact.mode ?? 0o600,
      }),
      configuredProjects,
    });
  }

  private async assertGitignored(root: string, path: string): Promise<void> {
    const ignore = await this.readRegularFile(join(root, '.gitignore'), MAX_CONFIG_BYTES);
    if (ignore === undefined)
      throw new Error('credential source is not approved by a gitignore file');
    try {
      const relativePath = relative(root, path).replaceAll('\\', '/');
      if (
        relativePath.length === 0 ||
        relativePath.startsWith('../') ||
        relativePath === '..' ||
        Buffer.byteLength(relativePath, 'utf8') > MAX_SOURCE_PATH_BYTES
      ) {
        throw new Error('credential source is outside the gitignore root');
      }
      const rules = parseGitignoreRules(new TextDecoder('utf-8', { fatal: true }).decode(ignore));
      if (!isGitignoredCredentialPath(rules, relativePath)) {
        throw new Error('credential source is not gitignored');
      }
    } finally {
      ignore.fill(0);
    }
  }

  private async canonicalDirectory(path: string): Promise<string> {
    if (!isCanonicalAbsolute(path)) throw new Error('directory path is not canonical');
    const canonical = await this.#fs.realpath(path);
    if (canonical !== path) throw new Error('directory path is not canonical');
    const stat = await this.#fs.lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('directory is unsafe');
    return canonical;
  }

  private async identity(path: string): Promise<FileIdentity> {
    const stat = await this.#fs.lstat(path);
    if (stat.isSymbolicLink()) throw new Error('identity target is a symlink');
    return Object.freeze({ device: String(stat.dev), inode: String(stat.ino) });
  }

  private async lstatRegular(path: string): Promise<Stats | undefined> {
    try {
      const stat = await this.#fs.lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink())
        throw new Error('lifecycle target is not a regular file');
      return stat;
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }
  private async lstatDirectory(path: string): Promise<Stats | undefined> {
    try {
      const stat = await this.#fs.lstat(path);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error('lifecycle target is not a directory');
      }
      return stat;
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }

  private async readRegularFile(path: string, maximum: number): Promise<Uint8Array | undefined> {
    const snapshot = await this.readSecureSnapshot(path, maximum);
    return snapshot?.bytes;
  }
  private async readSecureSnapshot(
    path: string,
    maximum: number,
  ): Promise<LifecycleFileSnapshot | undefined> {
    if ((await this.lstatRegular(path)) === undefined) {
      return undefined;
    }
    const root = await this.secureReadRoot(path);
    const result = secureReadBeneath({
      root: root.path,
      expectedRoot: root.identity,
      relativePath: root.relativePath,
      deniedIdentities: Object.freeze([]),
      maxBytes: maximum,
    });
    if (result.bytes.byteLength > maximum || result.linkCount !== 1) {
      result.bytes.fill(0);
      throw new Error('lifecycle secure read target is invalid');
    }
    return Object.freeze({
      observation: Object.freeze({
        kind: 'file',
        identity: Object.freeze({ ...result.identity }),
        mode: result.mode & 0o7777,
      }),
      bytes: result.bytes,
    });
  }
  private async secureReadRoot(path: string): Promise<
    Readonly<{
      readonly path: string;
      readonly identity: FileIdentity;
      readonly relativePath: string;
    }>
  > {
    const configuredRoot = this.#host.rootPath ?? this.#project.root;
    const root = [this.#checkoutRoot, this.#homeDirectory, configuredRoot]
      .filter((candidate) => contains(candidate, path))
      .sort((left, right) => right.length - left.length || bytewiseCompare(left, right))[0];
    if (root === undefined) {
      throw new Error('lifecycle secure read path has no approved root');
    }
    const canonicalRoot = await this.canonicalDirectory(root);
    return Object.freeze({
      path: canonicalRoot,
      identity: await this.identity(canonicalRoot),
      relativePath: relative(canonicalRoot, path).replaceAll('\\', '/'),
    });
  }

  private async readCanonicalJson<T>(
    path: string,
    parse: (value: string) => T,
  ): Promise<T | undefined> {
    const bytes = await this.readRegularFile(path, MAX_CONFIG_BYTES);
    if (bytes === undefined) return undefined;
    try {
      return parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } finally {
      bytes.fill(0);
    }
  }
  private async readLifecycleWal(): Promise<
    Readonly<{ readonly recoveryId: string; readonly authoritative: boolean }> | undefined
  > {
    let lock: LifecycleAdvisoryLock | undefined;
    let result:
      Readonly<{ readonly recoveryId: string; readonly authoritative: boolean }> | undefined;
    let primary: unknown;
    try {
      lock = await this.#transactionPort.acquireAdvisoryLock(this.#paths.lockPath);
      await lock.revalidate();
      const snapshot = await this.#transactionPort.readWalFileNoFollow({
        lock,
        path: this.#paths.walPath,
      });
      if (snapshot !== undefined) {
        const bytes = snapshot.bytes;
        if (snapshot.observation.kind !== 'file' || bytes.byteLength > MAX_WAL_BYTES) {
          bytes.fill(0);
          throw new Error('lifecycle WAL snapshot is invalid');
        }
        try {
          const parsed = parseWalRecordJson(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes),
          );
          result = Object.freeze({
            recoveryId: this.idFromBytes(bytes),
            authoritative: parsed.classification === 'v2-recovery-authority',
          });
        } finally {
          bytes.fill(0);
        }
      }
    } catch (error) {
      primary = error;
    }

    let releaseFailure: unknown;
    if (lock !== undefined) {
      try {
        await lock.release();
      } catch (error) {
        releaseFailure = error;
      }
    }
    if (primary !== undefined) {
      if (releaseFailure !== undefined) {
        throw primaryWithCleanup(
          primary,
          [releaseFailure],
          'Lifecycle WAL read and lock release failed.',
        );
      }
      throw primary;
    }
    if (releaseFailure !== undefined) {
      throw releaseFailure;
    }
    return result;
  }

  private async captureCredentialPreimage(
    path: string,
  ): Promise<LifecycleAbsentPreimage | LifecycleCredentialPreimage> {
    const stat = await this.lstatRegular(path);
    if (stat === undefined) return Object.freeze({ path, state: 'absent' as const });
    return Object.freeze({
      path,
      state: 'credential' as const,
      identity: Object.freeze({ device: String(stat.dev), inode: String(stat.ino) }),
      mode: stat.mode & 0o7777,
    });
  }
  private async capturePreimage(path: string): Promise<LifecyclePreimage> {
    const snapshot = await this.readSecureSnapshot(path, MAX_CONFIG_BYTES);
    if (snapshot === undefined) return Object.freeze({ path, state: 'absent' as const });
    return Object.freeze({
      path,
      state: 'file' as const,
      identity: snapshot.observation.identity,
      mode: snapshot.observation.mode,
      bytes: snapshot.bytes,
    });
  }

  private async assertPreimage(preimage: LifecyclePreimage): Promise<void> {
    if (preimage.state === 'absent') {
      try {
        await this.#fs.lstat(preimage.path);
      } catch (error) {
        if (isNotFound(error)) return;
        throw error;
      }
      throw new Error('preapproval target changed');
    }
    if (preimage.state === 'directory') {
      const current = await this.lstatDirectory(preimage.path);
      if (
        current === undefined ||
        !sameIdentity(preimage.identity, {
          device: String(current.dev),
          inode: String(current.ino),
        }) ||
        preimage.mode !== (current.mode & 0o777)
      ) {
        throw new Error('preapproval target changed');
      }
      return;
    }
    const current =
      preimage.state === 'credential'
        ? await this.captureCredentialPreimage(preimage.path)
        : await this.capturePreimage(preimage.path);
    try {
      if (preimage.state === 'credential') {
        if (
          current.state !== 'credential' ||
          !sameIdentity(preimage.identity, current.identity) ||
          preimage.mode !== current.mode
        ) {
          throw new Error('preapproval target changed');
        }
        return;
      }
      if (
        current.state !== 'file' ||
        !sameIdentity(preimage.identity, current.identity) ||
        preimage.mode !== current.mode ||
        !sameBytes(preimage.bytes, current.bytes)
      ) {
        throw new Error('preapproval target changed');
      }
    } finally {
      if (current.state === 'file') current.bytes.fill(0);
    }
  }

  private safeId(value: string): string {
    const id = value.replaceAll(/[^A-Za-z0-9_-]/gu, '');
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(id))
      throw new Error('generated lifecycle identifier is invalid');
    return id;
  }
  private idFrom(value: string): string {
    return `scg-${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 48)}`;
  }
  private idFromBytes(value: Uint8Array): string {
    return `scg-${createHash('sha256').update(value).digest('hex').slice(0, 48)}`;
  }
  private previewDigest(
    preview: SetupPlan['preview'],
  ): Readonly<{ readonly value: string; readonly operationCount: number }> {
    const canonical = JSON.stringify({
      state: preview.state,
      operations: preview.operations.map((operation) => ({
        kind: operation.kind,
        path: operation.path,
        hunkCount: operation.hunkCount,
        hunkSubjects: operation.hunkSubjects,
      })),
    });
    return Object.freeze({
      value: sha(new TextEncoder().encode(canonical)),
      operationCount: preview.operations.length,
    });
  }
}

function lifecycleConfigSnapshot(config: ServerConfigV1): LifecycleDataValue {
  const globalLimits = lifecycleNumberRecordSnapshot(config.globalLimits);
  const projects: LifecycleDataValue[] = config.projects.map((project): LifecycleDataValue => {
    const limits = lifecycleNumberRecordSnapshot(project.limits);
    return Object.freeze({
      projectId: project.projectId,
      root: project.root,
      allowedOrigins: Object.freeze([...project.allowedOrigins]),
      tokenEnv: project.tokenEnv,
      framework: project.framework,
      ...(limits === undefined ? {} : { limits }),
    });
  });
  return Object.freeze({
    schemaVersion: config.schemaVersion,
    ...(globalLimits === undefined ? {} : { globalLimits }),
    projects: Object.freeze(projects),
  });
}
function lifecycleRegistrySnapshot(registry: CredentialAuthorityRegistryV1): LifecycleDataValue {
  return Object.freeze({
    schemaVersion: registry.schemaVersion,
    projects: Object.freeze(
      registry.projects.map((entry) =>
        Object.freeze({
          projectId: entry.projectId,
          tokenEnv: entry.tokenEnv,
          canonicalRoot: entry.canonicalRoot,
          credentialPath: entry.credentialPath,
          device: entry.device,
          inode: entry.inode,
        }),
      ),
    ),
  });
}

function lifecycleAuthoritySnapshot(authority: CredentialAuthority): LifecycleDataValue {
  return Object.freeze({
    projectId: authority.projectId,
    path: authority.path,
    device: authority.device,
    inode: authority.inode,
  });
}

function credentialAuthorityFromRegistryEntry(
  entry: CredentialAuthorityRegistryEntry,
): CredentialAuthority {
  return Object.freeze({
    projectId: entry.projectId,
    path: entry.credentialPath,
    device: entry.device,
    inode: entry.inode,
  });
}

function sameRegistrySelection(
  left: SemanticCredentialAuthorityRegistryImage,
  right: SemanticCredentialAuthorityRegistryImage,
): boolean {
  const leftEntry = left.projects[0];
  const rightEntry = right.projects[0];
  return (
    left.projects.length === right.projects.length &&
    (leftEntry === undefined ||
      (rightEntry !== undefined &&
        leftEntry.projectId === rightEntry.projectId &&
        leftEntry.tokenEnv === rightEntry.tokenEnv &&
        leftEntry.canonicalRoot === rightEntry.canonicalRoot &&
        leftEntry.credentialPath === rightEntry.credentialPath &&
        leftEntry.device === rightEntry.device &&
        leftEntry.inode === rightEntry.inode))
  );
}

function authorityRegistryPath(configPath: string): string {
  return join(dirname(configPath), CREDENTIAL_AUTHORITY_REGISTRY_FILENAME);
}

function sharedHomeLockPath(homeDirectory: string): string {
  return join(homeDirectory, '.scene-glass-onboarding.lock');
}

function selectedConfigPathFromValues(
  cliConfigPath: string | undefined,
  environmentConfigPath: string | undefined,
  homeDirectory: string,
): string {
  const candidate =
    cliConfigPath ?? environmentConfigPath ?? join(homeDirectory, '.scg/config.json');
  if (!isCanonicalAbsolute(candidate)) {
    throw new Error('selected config path is not canonical');
  }
  return candidate;
}

function lifecycleNumberRecordSnapshot(
  values: object | undefined,
): Readonly<Record<string, number>> | undefined {
  if (values === undefined) return undefined;
  const snapshot: Record<string, number> = {};
  for (const [key, value] of Object.entries(values)) {
    if (typeof value !== 'number') throw new Error('config limits snapshot is invalid');
    snapshot[key] = value;
  }
  return Object.freeze(snapshot);
}
function isVerificationPorts(
  value: NodeLifecycleVerificationPorts | NodeLifecycleVerificationPortOptions,
): value is NodeLifecycleVerificationPorts {
  return (
    typeof value === 'object' &&
    value !== null &&
    'runNativeSelfTest' in value &&
    'runLiveDiagnostics' in value
  );
}

function parseConfigBytes(bytes: Uint8Array): ServerConfigV1 {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return parseServerConfigV1(JSON.parse(text));
}

function isCredentialSource(bytes: Uint8Array, projectId: string): boolean {
  const prefix = Buffer.from(
    `${VITE_LOADER_URL_KEY}=${LOADER_URL}\n${VITE_PROJECT_ID_KEY}=${projectId}\n${VITE_PROJECT_TOKEN_KEY}=`,
    'utf8',
  );
  const suffix = Buffer.from(`\n${CREDENTIAL_KEY}=`, 'utf8');
  if (bytes.byteLength !== prefix.byteLength + 43 + suffix.byteLength + 43 + 1) return false;
  for (let index = 0; index < prefix.byteLength; index += 1) {
    if (bytes[index] !== prefix[index]) return false;
  }
  const firstTokenStart = prefix.byteLength;
  const suffixStart = firstTokenStart + 43;
  for (let index = 0; index < suffix.byteLength; index += 1) {
    if (bytes[suffixStart + index] !== suffix[index]) return false;
  }
  const secondTokenStart = suffixStart + suffix.byteLength;
  for (let index = 0; index < 43; index += 1) {
    const value = bytes[firstTokenStart + index];
    if (
      value === undefined ||
      base64UrlValue(value) < 0 ||
      value !== bytes[secondTokenStart + index]
    ) {
      return false;
    }
  }
  return bytes.at(-1) === 0x0a && (base64UrlValue(bytes[firstTokenStart + 42]) & 0x03) === 0;
}
function base64UrlCode(value: number): number {
  if (value < 26) return 0x41 + value;
  if (value < 52) return 0x61 + value - 26;
  if (value < 62) return 0x30 + value - 52;
  return value === 62 ? 0x2d : 0x5f;
}
function decodeCredentialSource(bytes: Uint8Array): Uint8Array {
  const marker = Buffer.from(`${VITE_PROJECT_TOKEN_KEY}=`, 'ascii');
  const markerIndex = Buffer.from(bytes).indexOf(marker);
  if (markerIndex < 0) throw new Error('credential source is not canonical');
  const start = markerIndex + marker.byteLength;
  const encodedLength = 43;
  const candidate = new Uint8Array(32);
  try {
    let source = start;
    let target = 0;
    while (source + 3 < start + encodedLength) {
      const first = base64UrlValue(bytes[source]);
      const second = base64UrlValue(bytes[source + 1]);
      const third = base64UrlValue(bytes[source + 2]);
      const fourth = base64UrlValue(bytes[source + 3]);
      if (first < 0 || second < 0 || third < 0 || fourth < 0) {
        throw new Error('credential source encoding is invalid');
      }
      candidate[target] = (first << 2) | (second >>> 4);
      candidate[target + 1] = ((second & 0x0f) << 4) | (third >>> 2);
      candidate[target + 2] = ((third & 0x03) << 6) | fourth;
      source += 4;
      target += 3;
    }
    if (source + 3 !== start + encodedLength || target !== candidate.byteLength - 2) {
      throw new Error('credential source encoding is invalid');
    }
    const first = base64UrlValue(bytes[source]);
    const second = base64UrlValue(bytes[source + 1]);
    const third = base64UrlValue(bytes[source + 2]);
    if (first < 0 || second < 0 || third < 0) {
      throw new Error('credential source encoding is invalid');
    }
    candidate[target] = (first << 2) | (second >>> 4);
    candidate[target + 1] = ((second & 0x0f) << 4) | (third >>> 2);
    return candidate;
  } catch (error) {
    candidate.fill(0);
    throw error;
  }
}
function encodeBase64UrlCredential(candidate: Uint8Array): Uint8Array {
  if (candidate.byteLength !== 32) {
    throw new Error('credential candidate has an invalid byte count');
  }
  const encoded = new Uint8Array(43);
  let source = 0;
  let target = 0;
  while (source + 2 < candidate.byteLength) {
    const first = candidate[source];
    const second = candidate[source + 1];
    const third = candidate[source + 2];
    if (first === undefined || second === undefined || third === undefined) {
      encoded.fill(0);
      throw new Error('credential candidate has an invalid byte count');
    }
    const value = (first << 16) | (second << 8) | third;
    encoded[target] = base64UrlCode((value >>> 18) & 0x3f);
    encoded[target + 1] = base64UrlCode((value >>> 12) & 0x3f);
    encoded[target + 2] = base64UrlCode((value >>> 6) & 0x3f);
    encoded[target + 3] = base64UrlCode(value & 0x3f);
    source += 3;
    target += 4;
  }
  const first = candidate[source];
  const second = candidate[source + 1];
  if (first === undefined || second === undefined || target !== encoded.byteLength - 3) {
    encoded.fill(0);
    throw new Error('credential candidate has an invalid byte count');
  }
  const value = (first << 16) | (second << 8);
  encoded[target] = base64UrlCode((value >>> 18) & 0x3f);
  encoded[target + 1] = base64UrlCode((value >>> 12) & 0x3f);
  encoded[target + 2] = base64UrlCode((value >>> 6) & 0x3f);
  return encoded;
}
function base64UrlValue(value: number | undefined): number {
  if (value === undefined) return -1;
  if (value >= 0x41 && value <= 0x5a) return value - 0x41;
  if (value >= 0x61 && value <= 0x7a) return value - 0x61 + 26;
  if (value >= 0x30 && value <= 0x39) return value - 0x30 + 52;
  if (value === 0x2d) return 62;
  return value === 0x5f ? 63 : -1;
}
function sha256HexBytes(value: Uint8Array): Uint8Array {
  const digest = createHash('sha256').update(value).digest();
  try {
    const hex = new Uint8Array(digest.byteLength * 2);
    for (let index = 0; index < digest.byteLength; index += 1) {
      const byte = digest[index];
      if (byte === undefined) {
        hex.fill(0);
        throw new Error('credential digest is invalid');
      }
      hex[index * 2] = byte >>> 4 < 10 ? 0x30 + (byte >>> 4) : 0x61 + (byte >>> 4) - 10;
      hex[index * 2 + 1] = (byte & 0x0f) < 10 ? 0x30 + (byte & 0x0f) : 0x61 + (byte & 0x0f) - 10;
    }
    return hex;
  } finally {
    digest.fill(0);
  }
}
function prefixedSha256Digest(digest: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x3a]);
  const value = new Uint8Array(prefix.byteLength + digest.byteLength);
  value.set(prefix);
  value.set(digest, prefix.byteLength);
  prefix.fill(0);
  return value;
}
function containsBytes(value: Uint8Array, pattern: Uint8Array): boolean {
  if (pattern.byteLength === 0 || pattern.byteLength > value.byteLength) {
    return false;
  }
  for (let start = 0; start <= value.byteLength - pattern.byteLength; start += 1) {
    let index = 0;
    while (index < pattern.byteLength && value[start + index] === pattern[index]) {
      index += 1;
    }
    if (index === pattern.byteLength) {
      return true;
    }
  }
  return false;
}
function bytewiseCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
interface GitignoreRule {
  readonly anchored: boolean;
  readonly directoryOnly: boolean;
  readonly hasSlash: boolean;
  readonly negated: boolean;
  readonly pattern: string;
  readonly wildcard: boolean;
}
function parseGitignoreRules(source: string): readonly GitignoreRule[] {
  const rules: GitignoreRule[] = [];
  let lineStart = 0;
  let lineCount = 0;
  for (let index = 0; index <= source.length; index += 1) {
    if (index !== source.length && source.charCodeAt(index) !== 0x0a) {
      continue;
    }
    lineCount += 1;
    if (lineCount > MAX_GITIGNORE_RULES) {
      throw new Error('gitignore has too many rules');
    }
    let line = source.slice(lineStart, index);
    if (line.endsWith('\r')) {
      line = line.slice(0, -1);
    }
    let rule: GitignoreRule | undefined;
    try {
      rule = parseGitignoreRule(line);
    } catch (error) {
      // A rule we cannot represent (for example a `*.local` glob) is skipped so a
      // standard Vite/npm `.gitignore` does not abort inspection. Credential
      // coverage relies only on literal rules; a NEGATED unsupported rule could
      // un-ignore the credential and therefore must fail closed.
      if (trimGitignoreTrailingSpaces(line).startsWith('!')) {
        throw error;
      }
      rule = undefined;
    }
    if (rule !== undefined) {
      rules.push(rule);
    }
    lineStart = index + 1;
  }
  return Object.freeze(rules);
}
function parseGitignoreRule(line: string): GitignoreRule | undefined {
  if (Buffer.byteLength(line, 'utf8') > MAX_GITIGNORE_PATTERN_BYTES) {
    throw new Error('gitignore rule exceeds its byte limit');
  }
  const trimmed = trimGitignoreTrailingSpaces(line);
  if (trimmed.length === 0 || trimmed.startsWith('#')) {
    return undefined;
  }
  let pattern = trimmed;
  let negated = false;
  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  }
  if (pattern.length === 0) {
    throw new Error('gitignore negation has no pattern');
  }
  let anchored = false;
  if (pattern.startsWith('/')) {
    anchored = true;
    pattern = pattern.slice(1);
  }
  let directoryOnly = false;
  if (pattern.endsWith('/')) {
    directoryOnly = true;
    pattern = pattern.slice(0, -1);
  }
  if (
    pattern.length === 0 ||
    pattern.startsWith('/') ||
    pattern.endsWith('/') ||
    pattern.includes('//')
  ) {
    throw new Error('gitignore pattern is unsupported');
  }
  const literal = decodeGitignoreLiteral(pattern);
  if (
    literal.length === 0 ||
    literal.startsWith('/') ||
    literal.endsWith('/') ||
    literal.includes('//') ||
    Buffer.byteLength(literal, 'utf8') > MAX_GITIGNORE_PATTERN_BYTES
  ) {
    throw new Error('gitignore pattern is unsupported');
  }
  const segments = literal.split('/');
  if (
    segments.length > MAX_SOURCE_DEPTH ||
    segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    throw new Error('gitignore pattern is unsupported');
  }
  // A single-segment basename `*` glob (for example the standard Vite/npm
  // `*.local` rule that ignores `.env.development.local`) is supported. `*`
  // matches any run of non-`/` characters. Anchored or slash-bearing wildcard
  // rules stay unsupported so their handling remains bounded and fail-closed.
  const wildcard = literal.includes('*');
  if (wildcard && (anchored || literal.includes('/'))) {
    throw new Error('gitignore pattern is unsupported');
  }
  return Object.freeze({
    anchored,
    directoryOnly,
    hasSlash: literal.includes('/'),
    negated,
    pattern: literal,
    wildcard,
  });
}
function trimGitignoreTrailingSpaces(line: string): string {
  let end = line.length;
  while (end > 0 && line.charAt(end - 1) === ' ') {
    let slashes = 0;
    for (let index = end - 2; index >= 0 && line.charAt(index) === '\\'; index -= 1) {
      slashes += 1;
    }
    if (slashes % 2 !== 0) {
      break;
    }
    end -= 1;
  }
  return line.slice(0, end);
}
function decodeGitignoreLiteral(pattern: string): string {
  let literal = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern.charAt(index);
    if (character === '\\') {
      const escaped = pattern.charAt(index + 1);
      if (escaped.length !== 1 || !' !#?[]\\'.includes(escaped)) {
        throw new Error('gitignore escape is unsupported');
      }
      literal += escaped;
      index += 1;
      continue;
    }
    if (character === '?' || character === '[' || character === ']') {
      throw new Error('gitignore glob is unsupported');
    }
    if (character === '\u0000' || character === '\r' || character === '\n') {
      throw new Error('gitignore pattern is unsupported');
    }
    literal += character;
  }
  return literal;
}
function isGitignoredCredentialPath(
  rules: readonly GitignoreRule[],
  relativePath: string,
): boolean {
  if (!gitignoreStatus(rules, relativePath, false)) {
    return false;
  }
  let separator = relativePath.indexOf('/');
  while (separator !== -1) {
    if (gitignoreStatus(rules, relativePath.slice(0, separator), true)) {
      return false;
    }
    separator = relativePath.indexOf('/', separator + 1);
  }
  return true;
}
function gitignoreStatus(
  rules: readonly GitignoreRule[],
  relativePath: string,
  directory: boolean,
): boolean {
  let ignored = false;
  for (const rule of rules) {
    if (gitignoreRuleMatches(rule, relativePath, directory)) {
      ignored = !rule.negated;
    }
  }
  return ignored;
}
function gitignoreRuleMatches(
  rule: GitignoreRule,
  relativePath: string,
  directory: boolean,
): boolean {
  if (rule.directoryOnly && !directory) {
    return false;
  }
  if (rule.anchored || rule.hasSlash) {
    return relativePath === rule.pattern;
  }
  const separator = relativePath.lastIndexOf('/');
  const basename = relativePath.slice(separator + 1);
  return rule.wildcard ? segmentMatchesGlob(basename, rule.pattern) : basename === rule.pattern;
}
/**
 * Matches a single path segment against a gitignore basename pattern whose only
 * metacharacter is `*` (any run of non-`/` characters). The segment never
 * contains `/`, so `*` matches any run of its characters.
 */
function segmentMatchesGlob(name: string, pattern: string): boolean {
  const parts = pattern.split('*');
  if (parts.length === 1) {
    return name === pattern;
  }
  const first = parts[0] ?? '';
  const last = parts[parts.length - 1] ?? '';
  if (!name.startsWith(first) || !name.endsWith(last) || first.length + last.length > name.length) {
    return false;
  }
  let cursor = first.length;
  const limit = name.length - last.length;
  for (let index = 1; index < parts.length - 1; index += 1) {
    const middle = parts[index] ?? '';
    if (middle.length === 0) {
      continue;
    }
    const found = name.indexOf(middle, cursor);
    if (found === -1 || found + middle.length > limit) {
      return false;
    }
    cursor = found + middle.length;
  }
  return true;
}

function pathDepth(path: string): number {
  return path.split('/').length;
}
function isSameOrAncestor(ancestor: string, path: string): boolean {
  return ancestor === path || path.startsWith(`${ancestor}/`);
}

function pathsOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
}

function sha(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function primaryWithCleanup(
  primary: unknown,
  cleanupFailures: readonly unknown[],
  message = 'Prepared start launch and cleanup failed.',
): Error {
  if (cleanupFailures.length === 0) {
    return primary instanceof Error ? primary : new Error(message, { cause: primary });
  }
  return new AggregateError([primary, ...cleanupFailures], message, { cause: primary });
}
function markRetryableStartCleanupFailure(error: Error): Error {
  Object.defineProperty(error, 'retryable', {
    configurable: false,
    enumerable: false,
    value: true,
    writable: false,
  });
  return error;
}
function ownedStaticLoaderInsertion(
  preimage: Uint8Array,
  postimage: Uint8Array,
  postimageFingerprint: string,
  hunks: readonly OwnedHunk[],
): RestoreOwnedFileInverseOperation['ownedInsertion'] | undefined {
  for (const ownedInsertion of ['line', 'preceding-newline-line'] as const) {
    const restored = reconstructOwnedStaticFilePreimage(
      {
        preimageFingerprint: sha(preimage),
        postimageFingerprint,
        ownedInsertion,
        hunks,
      },
      postimage,
    );
    if (restored !== undefined) {
      restored.fill(0);
      return ownedInsertion;
    }
  }
  return undefined;
}

function isCanonicalAbsolute(path: string): boolean {
  return (
    typeof path === 'string' &&
    isAbsolute(path) &&
    path !== '/' &&
    !path.includes('\0') &&
    resolve(path) === path
  );
}

function contains(root: string, path: string): boolean {
  const value = relative(root, path);
  return value.length > 0 && !value.startsWith('..') && !isAbsolute(value);
}

function isNotFound(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === 'ENOENT'
  );
}

function isAlreadyExists(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === 'EEXIST'
  );
}
function isSafePackageName(value: string): boolean {
  return (
    value.length <= 214 &&
    value !== 'node_modules' &&
    value !== 'favicon.ico' &&
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u.test(value)
  );
}
function isPlanningRelevantTextPath(path: string): boolean {
  const name = basename(path).toLowerCase();
  if (
    name.startsWith('.') ||
    /(?:^|[._-])(credential|env|key|password|secret|token)(?:[._-]|$)/u.test(name)
  ) {
    return false;
  }
  return name === 'package.json' || PLANNING_TEXT_EXTENSIONS.has(name.slice(name.lastIndexOf('.')));
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength && left.every((value, index) => value === right[index])
  );
}

function currentUid(): number {
  if (typeof process.geteuid !== 'function')
    throw new Error('Node lifecycle requires a POSIX user identity');
  return process.geteuid();
}

/** Snapshots only ordinary enumerable data records from parsed package facts. */
function packageRecordValues(value: unknown, name: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new Error(`${name} must be a plain object`);
  }
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      descriptor.enumerable !== true
    ) {
      throw new Error(`${name} must contain enumerable data properties only`);
    }
    values[key] = descriptor.value;
  }
  return values;
}

function packageDependencyNames(
  packageValue: Readonly<Record<string, unknown>>,
  field: 'dependencies' | 'devDependencies',
): readonly string[] {
  if (!Object.hasOwn(packageValue, field)) {
    return Object.freeze([]);
  }
  const dependencies = packageRecordValues(packageValue[field], `host package ${field}`);
  const names = Object.keys(dependencies);
  for (const name of names) {
    const specification = dependencies[name];
    if (
      !isSafePackageName(name) ||
      typeof specification !== 'string' ||
      specification.length === 0
    ) {
      throw new Error(`host package ${field} is invalid`);
    }
  }
  return Object.freeze(names);
}
function snapshotSetupProjectSeed(value: unknown): SetupProjectSeed {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('lifecycle project seed is invalid');
  }
  const record = value as Record<string, unknown>;
  const parsed = parseProjectConfigV1({
    projectId: record.projectId,
    root: record.root,
    framework: record.framework,
    allowedOrigins: record.allowedOrigins,
    tokenEnv: typeof record.tokenEnv === 'string' ? record.tokenEnv : 'SCENE_GLASS_HOST_TOKEN',
  });
  return Object.freeze({
    projectId: parsed.projectId,
    root: parsed.root,
    framework: parsed.framework,
    allowedOrigins: parsed.allowedOrigins,
  });
}
