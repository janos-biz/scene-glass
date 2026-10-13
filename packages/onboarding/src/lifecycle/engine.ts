import { createHash } from 'node:crypto';

import { parseServerConfigV1, type ServerConfigV1 } from '@scene-glass/contracts';

import { planConfigOperation, type ConfigHomeFacts, type ConfigOperationPlan } from './config.js';
import {
  finalizeHostIntegrationPlan,
  planHostIntegration,
  type FinalizedHostIntegrationPlan,
  type HostIntegrationPlan,
  type HostPlanInput,
} from './host-plan.js';
import {
  parseSetupManifestV1,
  parseTerminalReceiptV1,
  validateUninstallPreflight,
  type ObservedOwnedTarget,
  type UninstallPreflight,
} from './provenance.js';
import type { CredentialAuthority } from '../types.js';
import type {
  LifecycleState,
  RedactedPreviewOperation,
  RedactedSetupPreview,
  SetupManifestV1,
  SetupPlan,
} from './types.js';
import {
  LifecycleTransactionError,
  type LifecycleFailurePoint,
  type SetupTransactionReceipt,
} from './transaction.js';

/** The engine deliberately exposes only generic lifecycle outcomes. */
export type LifecycleEngineCode =
  | 'SCG_LIFECYCLE_ACTIVE'
  | 'SCG_LIFECYCLE_ALREADY_UNINSTALLED'
  | 'SCG_LIFECYCLE_DECLINED'
  | 'SCG_LIFECYCLE_FAILED'
  | 'SCG_LIFECYCLE_NOT_ACTIVE'
  | 'SCG_LIFECYCLE_PREFLIGHT_FAILED'
  | 'SCG_LIFECYCLE_RECOVERY_REQUIRED'
  | 'SCG_LIFECYCLE_START_EXITED'
  | 'SCG_LIFECYCLE_UNINSTALLED';

export type LifecycleEngineOperation = 'setup' | 'start' | 'uninstall';
export type LifecycleEngineStatus = 'success' | 'failed';

/** These are intentionally bounded labels, never adapter error text. */
export type LifecycleFailureStage =
  | 'inspection'
  | 'recovery'
  | 'planning'
  | 'approval'
  | 'native-self-test'
  | 'chromium-smoke'
  | 'token-generation'
  | 'mutation-preparation'
  | 'public-preflight-1'
  | 'transaction-open'
  | 'public-preflight-2'
  | 'transaction-apply'
  | 'authority-validation'
  | 'public-preflight-3'
  | 'diagnostics'
  | 'active-publication'
  | 'compensation'
  | 'token-zeroization'
  | 'start-manifest'
  | 'start-registry-preflight'
  | 'start-preparation-revoke'
  | 'start-foreground'
  | 'start-wait'
  | 'start-cleanup'
  | 'uninstall-manifest'
  | 'uninstall-observation'
  | 'uninstall-preflight'
  | 'uninstall-transaction-open'
  | 'uninstall-apply'
  | 'uninstall-compensation'
  | `transaction:${LifecycleFailurePoint}`;

export interface LifecycleFailureReceipt {
  readonly stage: LifecycleFailureStage;
}

export type LifecycleEventPhase =
  | 'inspection'
  | 'recovery'
  | 'planning'
  | 'preview'
  | 'approval'
  | 'native-self-test'
  | 'chromium-smoke'
  | 'entropy'
  | 'preflight'
  | 'transaction'
  | 'validation'
  | 'diagnostics'
  | 'publication'
  | 'foreground'
  | 'ready'
  | 'stopping'
  | 'cleanup'
  | 'completed'
  | 'failed';

/**
 * Event records contain no paths, values, errors, source text, browser data,
 * or credential material. The engine retains at most MAX_LIFECYCLE_EVENTS.
 */
export interface LifecycleEventReceipt {
  readonly sequence: number;
  readonly operation: LifecycleEngineOperation;
  readonly phase: LifecycleEventPhase;
  readonly code: LifecycleEngineCode;
}

export interface LifecycleResult {
  readonly operation: LifecycleEngineOperation;
  readonly status: LifecycleEngineStatus;
  readonly state: LifecycleState;
  readonly code: LifecycleEngineCode;
  readonly failures: readonly LifecycleFailureReceipt[];
  readonly events: readonly LifecycleEventReceipt[];
  /**
   * Present only when start returned recovery-required at its cleanup deadline.
   * The opaque channel retains the sole in-flight cleanup owner for late audit.
   */
  readonly cleanupConvergence?: LifecycleCleanupConvergence;
  /** Present only for a branded, validated declared-Vite start preflight failure. */
  readonly startDiagnostic?: LifecycleStartDiagnostic;
}
declare const lifecycleCleanupConvergenceBrand: unique symbol;

/**
 * Opaque, invocation-bound evidence that a start cleanup was still owned when
 * its absolute deadline elapsed. It cannot change the terminal result.
 */
export interface LifecycleCleanupConvergence {
  readonly [lifecycleCleanupConvergenceBrand]: 'scene-glass-lifecycle-cleanup-convergence';
}

export type LifecycleCleanupConvergenceState = 'converged' | 'failed';

interface LifecycleCleanupConvergenceRecord {
  readonly completion: Promise<void>;
  readonly state: Promise<LifecycleCleanupConvergenceState>;
}

const lifecycleCleanupConvergences = new WeakMap<
  LifecycleCleanupConvergence,
  LifecycleCleanupConvergenceRecord
>();

/** Observes the redacted late-cleanup outcome without exposing adapter failures. */
export function observeLifecycleCleanupConvergence(
  convergence: LifecycleCleanupConvergence,
): Promise<LifecycleCleanupConvergenceState> {
  const record = lifecycleCleanupConvergences.get(convergence);
  if (record === undefined) {
    throw new LifecycleEngineInputError('cleanup convergence capability is invalid');
  }
  return record.state;
}

export interface LifecyclePreviewDigest {
  readonly algorithm: 'sha256';
  readonly value: string;
  readonly operationCount: number;
}

/** Opaque, adapter-owned recovery authority. It is never inspected by the core. */
export interface AuthorizedWalRecovery {
  readonly recoveryId: string;
}

/**
 * A lifecycle observation is a read-only, bounded fact supplied by an adapter.
 * activeManifest and terminalReceipt are parsed by the core before use.
 */
export interface LifecycleInspection {
  readonly state: LifecycleState;
  readonly authorizedWal?: AuthorizedWalRecovery;
  readonly activeManifest?: unknown;
  readonly terminalReceipt?: unknown;
}

/** Build facts are adapter-defined, but must be plain data with no accessors. */
export type LifecycleBuildFacts = Readonly<Record<string, LifecycleDataValue>>;
export type LifecycleDataPrimitive = boolean | null | number | string | undefined;
export type LifecycleDataValue =
  | LifecycleDataPrimitive
  | Uint8Array
  | readonly LifecycleDataValue[]
  | Readonly<{ readonly [key: string]: LifecycleDataValue }>;

export interface LifecycleSetupFacts {
  readonly configHomes: ConfigHomeFacts;
  /** Desired project configuration, independent from host descriptor facts. */
  readonly project: unknown;
  readonly hostPlan: HostPlanInput;
  readonly build: LifecycleBuildFacts;
}

/** The child builder returns a secretless plan and an adapter-private receipt id. */
export interface SetupPlanBuildReceipt {
  readonly plan: SetupPlan;
  readonly receiptId: string;
}

/** Read-only preparation binds an approved builder receipt to a mutation id. */
export interface SetupMutationPreparation {
  readonly mutationId: string;
}

/**
 * A lock-held WAL apply returns the authority used to finalize a created
 * credential plus its independently observed same-FD post-write authority.
 */
declare const transactionObservedCredentialAuthorityBrand: unique symbol;
declare const transactionObservedCredentialAuthorityIssuerBrand: unique symbol;
export interface TransactionObservedCredentialAuthority {
  readonly [transactionObservedCredentialAuthorityBrand]: 'scene-glass-transaction-observed-authority';
}
export interface TransactionObservedCredentialAuthorityIssuer {
  readonly [transactionObservedCredentialAuthorityIssuerBrand]: 'scene-glass-transaction-observed-authority-issuer';
}
interface TransactionObservedCredentialAuthorityState {
  readonly authority: CredentialAuthority;
  readonly issuer: TransactionObservedCredentialAuthorityIssuer;
  readonly receipt: SetupTransactionReceipt;
}
interface TransactionObservedCredentialAuthorityIssuerState {
  active: boolean;
}
const transactionObservedCredentialAuthorities = new WeakMap<
  TransactionObservedCredentialAuthority,
  TransactionObservedCredentialAuthorityState
>();
const transactionObservedCredentialAuthorityIssuers = new WeakMap<
  TransactionObservedCredentialAuthorityIssuer,
  TransactionObservedCredentialAuthorityIssuerState
>();
function createTransactionObservedCredentialAuthorityIssuer(): TransactionObservedCredentialAuthorityIssuer {
  const issuer = Object.freeze({}) as TransactionObservedCredentialAuthorityIssuer;
  transactionObservedCredentialAuthorityIssuers.set(issuer, { active: true });
  return issuer;
}
function revokeTransactionObservedCredentialAuthorityIssuer(
  issuer: TransactionObservedCredentialAuthorityIssuer,
): void {
  const state = transactionObservedCredentialAuthorityIssuers.get(issuer);
  if (state === undefined) {
    throw new LifecycleEngineInputError('post-write credential authority issuer is invalid');
  }
  state.active = false;
}
/**
 * This capability is minted only through a live engine-issued issuer, after
 * the adapter has completed an independent same-FD post-write read, and is
 * bound to the opaque receipt returned by that transaction-core apply.
 */
export function createTransactionObservedCredentialAuthority(
  input: Readonly<{
    readonly issuer: TransactionObservedCredentialAuthorityIssuer;
    readonly receipt: SetupTransactionReceipt;
    readonly authority: CredentialAuthority;
  }>,
): TransactionObservedCredentialAuthority {
  if (input === null || typeof input !== 'object') {
    throw new LifecycleEngineInputError('post-write credential authority provenance is invalid');
  }
  const issuerState = transactionObservedCredentialAuthorityIssuers.get(input.issuer);
  if (
    issuerState === undefined ||
    !issuerState.active ||
    input.receipt === null ||
    typeof input.receipt !== 'object'
  ) {
    throw new LifecycleEngineInputError('post-write credential authority provenance is invalid');
  }
  const observed = Object.freeze({}) as TransactionObservedCredentialAuthority;
  transactionObservedCredentialAuthorities.set(observed, {
    authority: parseCreatedAuthority(input.authority),
    issuer: input.issuer,
    receipt: input.receipt,
  });
  return observed;
}
export interface SetupMutationReceipt {
  readonly createdAuthority?: CredentialAuthority;
  readonly observedCreatedAuthority: TransactionObservedCredentialAuthority | undefined;
  /** Present only with the created credential's observed post-write authority. */
  readonly transactionReceipt?: SetupTransactionReceipt;
}

export type LifecycleSetupPreflightInput =
  | Readonly<{
      readonly stage: 1 | 2;
      readonly plan: SetupPlan;
      readonly plannedHost: HostIntegrationPlan;
      readonly mutationId: string;
      readonly candidate: Uint8Array | undefined;
    }>
  | Readonly<{
      readonly stage: 3;
      readonly plan: SetupPlan;
      readonly finalizedHost: FinalizedHostIntegrationPlan;
      readonly mutationId: string;
      readonly candidate: Uint8Array | undefined;
    }>;

/**
 * Open means the adapter has acquired its transaction lock and revalidated the
 * supplied plan. The core then performs public preflight #2 before apply.
 */
export interface LifecycleSetupTransaction {
  apply(
    input: Readonly<{
      readonly observedAuthorityIssuer: TransactionObservedCredentialAuthorityIssuer;
    }>,
  ): Promise<SetupMutationReceipt>;
  publishActive(): Promise<'active'>;
  compensate(): Promise<'recovered' | 'recovery-required'>;
}

export interface LifecycleUninstallTransaction {
  apply(): Promise<'uninstalled' | 'recovery-required'>;
  compensate(): Promise<'recovered' | 'recovery-required'>;
}

export interface LifecycleStartProjectFacts {
  readonly projectId: string;
  readonly authority: LifecycleDataValue;
  readonly descriptor: LifecycleDataValue;
  readonly cache: LifecycleDataValue;
}

export interface LifecycleStartFacts {
  /** Immutable adapter snapshot that binds the selected project facts to start preparation. */
  readonly snapshotId: string;
  readonly selectedProjectId: string;
  readonly config: LifecycleDataValue;
  readonly registry?: LifecycleDataValue;
  readonly projects: readonly LifecycleStartProjectFacts[];
}

/** Closed, secretless diagnostic channel for declared Vite start policy failures. */
export interface LifecycleStartDiagnostic {
  readonly code:
    | 'SCG_START_VITE_DECLARATION_INVALID'
    | 'SCG_START_VITE_PORT_DISALLOWED'
    | 'SCG_START_VITE_ORIGIN_CONFLICT'
    | 'SCG_START_VITE_INPUT_CHANGED'
    | 'SCG_START_VITE_PERSISTED_BASELINE_INVALID';
  readonly projectId: string;
}

const START_DIAGNOSTIC_CODES = new Set<LifecycleStartDiagnostic['code']>([
  'SCG_START_VITE_DECLARATION_INVALID',
  'SCG_START_VITE_PORT_DISALLOWED',
  'SCG_START_VITE_ORIGIN_CONFLICT',
  'SCG_START_VITE_INPUT_CHANGED',
  'SCG_START_VITE_PERSISTED_BASELINE_INVALID',
]);

/** Adapter-only branded error; arbitrary adapter errors remain generic. */
export class LifecycleStartDiagnosticError extends Error {
  public constructor(public readonly diagnostic: LifecycleStartDiagnostic) {
    super('declared Vite start preflight failed');
    this.name = 'LifecycleStartDiagnosticError';
  }
}

export interface LifecyclePreparedStart {
  readonly preparationId: string;
}

export interface ForegroundMcpExit {
  readonly reason: 'signal' | 'exit';
  readonly exitCode: number;
}

/** A foreground session has no detach or daemon operation by design. */
export interface LifecycleCleanupContext {
  /** Absolute epoch milliseconds chosen once by the engine for all cleanup attempts. */
  readonly deadline: number;
}
/**
 * Cleanup is retried only when the rejecting authority explicitly marks the
 * rejection as transient. The marker is intentionally structural so adapters
 * can preserve their own error identity and aggregation evidence.
 */
export interface LifecycleRetryableStartCleanupRejection {
  readonly retryable: true;
}
/**
 * A live diagnostic failure may retain the sole cleanup owner until this
 * convergence promise settles. The engine must adopt it before compensation.
 */
export interface LifecycleDiagnosticCleanupConvergenceFailure {
  readonly cleanupConvergence: Promise<void> | undefined;
}

/**
 * An adapter reports an authority that the current start invocation cannot
 * own. Its reason remains exact so the core can distinguish cleanup
 * convergence from an unknown cleanup failure.
 */
export class LifecyclePreparedStartUnavailableError extends Error {
  public constructor(public readonly reason: 'missing' | 'reused') {
    super('prepared start authority is unavailable');
    this.name = 'LifecyclePreparedStartUnavailableError';
  }
}
export interface LifecycleForegroundMcp {
  waitForExit(): Promise<ForegroundMcpExit>;
  /**
   * Retryable cleanup rejections must carry a readonly `retryable: true`
   * marker; all other rejections are terminal for this cleanup authority.
   */
  cleanup(input?: LifecycleCleanupContext): Promise<void>;
}

export interface UninstallObservation {
  /** False means the adapter could not enumerate every target from provenance. */
  readonly complete: boolean;
  readonly observed: readonly ObservedOwnedTarget[];
}

export interface LifecycleEnginePort {
  /** Read-only lifecycle state. It is invoked before every public operation. */
  inspectLifecycle(
    input: Readonly<{ readonly operation: LifecycleEngineOperation }>,
  ): Promise<LifecycleInspection>;
  /** Used by setup only, before it plans config, host, credential, or build work. */
  recoverAuthorizedWal(
    input: Readonly<{ readonly recoveryId: string }>,
  ): Promise<'recovered' | 'recovery-required'>;
  /** Bounded, read-only config, host, credential, and build discovery for setup. */
  inspectSetupFacts(): Promise<LifecycleSetupFacts>;
  /** Private child-builder receipt; it must be read-only and secretless. */
  buildSetupPlan(
    input: Readonly<{
      readonly config: ConfigOperationPlan;
      readonly host: HostIntegrationPlan;
      readonly build: LifecycleBuildFacts;
    }>,
  ): Promise<SetupPlanBuildReceipt>;
  requestSetupApproval(
    input: Readonly<{
      readonly receiptId: string;
      readonly preview: RedactedSetupPreview;
      readonly digest: LifecyclePreviewDigest;
    }>,
  ): Promise<boolean>;
  /** Revokes an approved receipt and any candidate it issued after an aborted setup. */
  revokeSetupApproval?(input: Readonly<{ readonly receiptId: string }>): Promise<void>;
  runNativeSelfTest(): Promise<void>;
  runEmptyChromiumSmoke(): Promise<void>;
  /** Called only for a setup-created credential candidate, before its authority exists. */
  generateCredentialToken(
    input: Readonly<{
      readonly receiptId: string;
      readonly requestId: string;
      readonly bits: 256;
      readonly projectId: string;
      readonly path: string;
    }>,
  ): Promise<Uint8Array>;
  /** Receives the generated candidate object and must not retain a copy. */
  zeroizeCredentialToken(input: Readonly<{ readonly token: Uint8Array }>): Promise<void>;
  /**
   * Public read-only gates. Stages 1 and 2 receive the planned host; stage 3
   * receives the finalized host after lock-held WAL apply.
   */
  preflightSetup(input: LifecycleSetupPreflightInput): Promise<void>;
  /** Acquires a transaction lock, revalidates the planned host, and owns the candidate for apply. */
  openSetupTransaction(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly plannedHost: HostIntegrationPlan;
      readonly mutationId: string;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<LifecycleSetupTransaction>;
  /** Read-only binding of an approved builder receipt to a mutation id; it must not write. */
  prepareSetupMutation(
    input: Readonly<{
      readonly receiptId: string;
      readonly plan: SetupPlan;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<SetupMutationPreparation>;
  /** Validates the final authority after writes and before diagnostics/publication. */
  validateFinalizedSetup(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly finalizedHost: FinalizedHostIntegrationPlan;
      readonly mutationId: string;
    }>,
  ): Promise<void>;
  /**
   * May reject with LifecycleDiagnosticCleanupConvergenceFailure. A defined
   * cleanupConvergence retains the sole late cleanup owner until it settles;
   * callers must not compensate concurrently.
   */
  runLiveDiagnostics(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly finalizedHost: FinalizedHostIntegrationPlan;
      readonly mutationId: string;
    }>,
  ): Promise<void>;

  /** Parameter-free public start delegates its read-only facts to this adapter call. */
  inspectStartFacts(
    input: Readonly<{ readonly manifest: SetupManifestV1 }>,
  ): Promise<LifecycleStartFacts>;
  /** Prepares an opaque, single-use start authority from secretless facts. */
  prepareStart(
    input: Readonly<{ readonly manifest: SetupManifestV1; readonly facts: LifecycleStartFacts }>,
  ): Promise<LifecyclePreparedStart>;
  /** Final validation under the retained preparation lock establishes the policy cutoff. */
  finalizePreparedStart(input: Readonly<{ readonly preparationId: string }>): Promise<void>;
  /**
   * Reattempts cleanup of the prepared foreground and lock authority. Missing
   * or reused ids must reject with LifecyclePreparedStartUnavailableError.
   */
  discardPreparedStart(
    input: Readonly<{ readonly preparationId: string; readonly cleanup?: LifecycleCleanupContext }>,
  ): Promise<void>;
  /** Launch transfers prepared authority; cleanup retains it until foreground and lock release converge. */
  launchMcpForeground(
    input: Readonly<{ readonly manifest: SetupManifestV1; readonly preparationId: string }>,
  ): Promise<LifecycleForegroundMcp>;

  /** Reads every provenance-owned uninstall target; it must not write. */
  observeUninstallTargets(
    input: Readonly<{ readonly manifest: SetupManifestV1 }>,
  ): Promise<UninstallObservation>;
  openUninstallTransaction(
    input: Readonly<{
      readonly manifest: SetupManifestV1;
      readonly preflight: UninstallPreflight;
    }>,
  ): Promise<LifecycleUninstallTransaction>;

  /** Optional and non-authoritative: sink errors never alter lifecycle execution. */
  emitLifecycleEvent?(event: LifecycleEventReceipt): void | Promise<void>;
}

const MAX_LIFECYCLE_EVENTS = 64;
const MAX_PROJECTS = 256;
const MAX_SNAPSHOT_DEPTH = 64;
const MAX_SNAPSHOT_NODES = 50_000;
const MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024;
const START_CLEANUP_ATTEMPTS = 2;
const START_CLEANUP_TIMEOUT_MS = 30_000;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/**
 * Typed lifecycle core. It has no filesystem, process, browser, or fallback
 * capability; every effect is represented by LifecycleEnginePort.
 */
export class LifecycleEngine {
  public constructor(private readonly port: LifecycleEnginePort) {}

  public async runSetup(): Promise<LifecycleResult> {
    const events = new EventJournal(this.port, 'setup');
    let candidate: Uint8Array | undefined;
    let transaction: LifecycleSetupTransaction | undefined;
    let receiptId: string | undefined;
    let preMutationState: LifecycleState | undefined;
    let failureStage: LifecycleFailureStage | undefined;
    const failures: LifecycleFailureReceipt[] = [];

    try {
      failureStage = 'inspection';
      events.emit('inspection', 'SCG_LIFECYCLE_ACTIVE');
      let inspection = await this.inspect('setup');
      if (inspection.authorizedWal !== undefined) {
        failureStage = 'recovery';
        events.emit('recovery', 'SCG_LIFECYCLE_ACTIVE');
        const recovery = await this.recover(inspection.authorizedWal);
        if (recovery === 'recovery-required') {
          return this.result(
            'setup',
            'failed',
            'recovery-required',
            'SCG_LIFECYCLE_RECOVERY_REQUIRED',
            failures,
            events,
          );
        }
        inspection = await this.inspect('setup');
        preMutationState = inspection.state;
      }

      if (inspection.state === 'recovery-required') {
        return this.result(
          'setup',
          'failed',
          'recovery-required',
          'SCG_LIFECYCLE_RECOVERY_REQUIRED',
          failures,
          events,
        );
      }
      if (inspection.state === 'lost-provenance') {
        return this.result(
          'setup',
          'failed',
          'lost-provenance',
          'SCG_LIFECYCLE_NOT_ACTIVE',
          failures,
          events,
        );
      }
      preMutationState = inspection.state;
      if (inspection.state === 'active') {
        return this.result('setup', 'success', 'active', 'SCG_LIFECYCLE_ACTIVE', failures, events);
      }

      failureStage = 'inspection';
      const facts = parseSetupFacts(await this.port.inspectSetupFacts());
      failureStage = 'planning';
      events.emit('planning', 'SCG_LIFECYCLE_ACTIVE');
      const config = planConfigOperation({ homes: facts.configHomes, project: facts.project });
      const host = planHostIntegration(facts.hostPlan);
      const built = parseSetupBuildReceipt(
        await this.port.buildSetupPlan(
          freeze({
            config: copyForPort(config),
            host: copyForPort(host),
            build: copyForPort(facts.build),
          }),
        ),
      );
      receiptId = built.receiptId;
      const plan = validateSetupPlan(built.plan, config, host);
      const digest = digestPreview(plan.preview);

      failureStage = 'approval';
      events.emit('preview', 'SCG_LIFECYCLE_ACTIVE');
      const approved = await this.port.requestSetupApproval(
        freeze({
          receiptId: built.receiptId,
          preview: copyForPort(plan.preview),
          digest: copyForPort(digest),
        }),
      );
      if (approved !== true) {
        events.emit('approval', 'SCG_LIFECYCLE_DECLINED');
        return this.result(
          'setup',
          'success',
          inspection.state,
          'SCG_LIFECYCLE_DECLINED',
          failures,
          events,
        );
      }

      failureStage = 'native-self-test';
      events.emit('native-self-test', 'SCG_LIFECYCLE_ACTIVE');
      await this.port.runNativeSelfTest();
      failureStage = 'chromium-smoke';
      events.emit('chromium-smoke', 'SCG_LIFECYCLE_ACTIVE');
      await this.port.runEmptyChromiumSmoke();

      if (host.credential.kind === 'setup-created-candidate') {
        failureStage = 'token-generation';
        events.emit('entropy', 'SCG_LIFECYCLE_ACTIVE');
        candidate = await this.generateCandidate(built.receiptId, host);
        assertCredentialCandidate(candidate);
      }

      failureStage = 'mutation-preparation';
      const prepared = parseSetupMutationPreparation(
        await this.port.prepareSetupMutation(
          freeze({
            receiptId: built.receiptId,
            plan: copyForPort(plan),
            candidate,
          }),
        ),
      );

      failureStage = 'public-preflight-1';
      events.emit('preflight', 'SCG_LIFECYCLE_ACTIVE');
      await this.port.preflightSetup(
        freeze<LifecycleSetupPreflightInput>({
          stage: 1,
          plan: copyForPort(plan),
          plannedHost: copyForPort(host),
          mutationId: prepared.mutationId,
          candidate,
        }),
      );

      failureStage = 'transaction-open';
      events.emit('transaction', 'SCG_LIFECYCLE_ACTIVE');
      transaction = await this.port.openSetupTransaction(
        freeze({
          plan: copyForPort(plan),
          plannedHost: copyForPort(host),
          mutationId: prepared.mutationId,
          candidate,
        }),
      );
      assertSetupTransaction(transaction);

      failureStage = 'public-preflight-2';
      await this.port.preflightSetup(
        freeze<LifecycleSetupPreflightInput>({
          stage: 2,
          plan: copyForPort(plan),
          plannedHost: copyForPort(host),
          mutationId: prepared.mutationId,
          candidate,
        }),
      );
      failureStage = 'transaction-apply';
      const observedAuthorityIssuer = createTransactionObservedCredentialAuthorityIssuer();
      let mutationReceipt: SetupMutationReceipt;
      try {
        mutationReceipt = parseSetupMutationReceipt(
          await transaction.apply(freeze({ observedAuthorityIssuer })),
          observedAuthorityIssuer,
        );
      } finally {
        revokeTransactionObservedCredentialAuthorityIssuer(observedAuthorityIssuer);
      }
      const finalizedHost = finalizeHostIntegrationPlan(host, mutationReceipt.createdAuthority);
      assertObservedCreatedAuthority(
        finalizedHost,
        mutationReceipt.observedCreatedAuthority,
        mutationReceipt.transactionReceipt,
      );

      failureStage = 'authority-validation';
      events.emit('validation', 'SCG_LIFECYCLE_ACTIVE');
      await this.port.validateFinalizedSetup(
        freeze({
          plan: copyForPort(plan),
          finalizedHost: copyForPort(finalizedHost),
          mutationId: prepared.mutationId,
        }),
      );
      failureStage = 'public-preflight-3';
      await this.port.preflightSetup(
        freeze<LifecycleSetupPreflightInput>({
          stage: 3,
          plan: copyForPort(plan),
          finalizedHost: copyForPort(finalizedHost),
          mutationId: prepared.mutationId,
          candidate,
        }),
      );
      failureStage = 'diagnostics';
      events.emit('diagnostics', 'SCG_LIFECYCLE_ACTIVE');
      await this.port.runLiveDiagnostics(
        freeze({
          plan: copyForPort(plan),
          finalizedHost: copyForPort(finalizedHost),
          mutationId: prepared.mutationId,
        }),
      );

      failureStage = 'active-publication';
      events.emit('publication', 'SCG_LIFECYCLE_ACTIVE');
      const published = await transaction.publishActive();
      if (published !== 'active') {
        throw new LifecycleEngineInputError('setup publication returned an invalid state');
      }
      transaction = undefined;
      await this.zeroize(candidate, failures);
      candidate = undefined;
      events.emit('completed', 'SCG_LIFECYCLE_ACTIVE');
      return this.result('setup', 'success', 'active', 'SCG_LIFECYCLE_ACTIVE', failures, events);
    } catch (error) {
      debugLifecycleFailure('setup', failureStage, error);
      if (failureStage !== undefined) {
        addFailure(failures, failureStage);
      }
      addTransactionFailures(failures, error);
      let diagnosticCleanupConverged = true;
      if (failureStage === 'diagnostics') {
        const convergence = diagnosticCleanupConvergence(error);
        if (convergence !== undefined) {
          try {
            await this.awaitDiagnosticCleanupConvergence(convergence);
          } catch {
            addFailure(failures, 'diagnostics');
            diagnosticCleanupConverged = false;
          }
        }
      }
      let state: LifecycleState =
        !diagnosticCleanupConverged ||
        failureStage === 'recovery' ||
        containsLifecycleTransactionError(error)
          ? 'recovery-required'
          : (preMutationState ?? 'recovery-required');
      if (transaction !== undefined && diagnosticCleanupConverged) {
        events.emit('cleanup', 'SCG_LIFECYCLE_FAILED');
        try {
          const compensated = await transaction.compensate();
          if (compensated === 'recovered') {
            state = preMutationState ?? 'recovery-required';
          } else {
            if (compensated !== 'recovery-required') {
              addFailure(failures, 'compensation');
            }
            state = 'recovery-required';
          }
        } catch (error) {
          addFailure(failures, 'compensation');
          addTransactionFailures(failures, error);
          state = 'recovery-required';
        }
      }
      if (receiptId !== undefined) {
        try {
          await this.port.revokeSetupApproval?.(freeze({ receiptId }));
        } catch {
          addFailure(failures, 'token-zeroization');
        }
      }
      await this.zeroize(candidate, failures);
      candidate = undefined;
      const code =
        state === 'recovery-required' ? 'SCG_LIFECYCLE_RECOVERY_REQUIRED' : 'SCG_LIFECYCLE_FAILED';
      events.emit('failed', code);
      return this.result('setup', 'failed', state, code, failures, events);
    }
  }

  /** Start intentionally takes no parameters: no background/daemon configuration exists here. */
  public async runStart(): Promise<LifecycleResult> {
    const events = new EventJournal(this.port, 'start');
    const failures: LifecycleFailureReceipt[] = [];
    let foreground: LifecycleForegroundMcp | undefined;
    let foregroundCleanupSettled = false;
    let preparationId: string | undefined;
    let cleanupContext: LifecycleCleanupContext | undefined;
    let foregroundPhase: 'launch' | 'wait' | 'cleanup' = 'launch';
    let inspectedState: LifecycleState | undefined;
    let status: LifecycleEngineStatus = 'failed';
    let code: LifecycleEngineCode = 'SCG_LIFECYCLE_FAILED';
    let startRecoveryRequired = false;
    let cleanupConvergence: LifecycleCleanupConvergence | undefined;
    const startCleanupContext = (): LifecycleCleanupContext => {
      cleanupContext ??= freeze({ deadline: this.startCleanupDeadline() });
      return cleanupContext;
    };
    try {
      events.emit('inspection', 'SCG_LIFECYCLE_ACTIVE');
      const inspection = await this.inspect('start');
      inspectedState = inspection.state;
      if (inspection.authorizedWal !== undefined) {
        return this.result(
          'start',
          'failed',
          'recovery-required',
          'SCG_LIFECYCLE_RECOVERY_REQUIRED',
          failures,
          events,
        );
      }
      if (inspection.state === 'recovery-required' || inspection.state === 'lost-provenance') {
        return this.result(
          'start',
          'failed',
          inspection.state,
          'SCG_LIFECYCLE_RECOVERY_REQUIRED',
          failures,
          events,
        );
      }
      if (inspection.state !== 'active' || inspection.activeManifest === undefined) {
        return this.result(
          'start',
          'failed',
          inspection.state,
          'SCG_LIFECYCLE_NOT_ACTIVE',
          failures,
          events,
        );
      }

      let manifest: SetupManifestV1;
      try {
        manifest = parseSetupManifestV1(snapshot(inspection.activeManifest));
      } catch {
        addFailure(failures, 'start-manifest');
        return this.result(
          'start',
          'failed',
          'lost-provenance',
          'SCG_LIFECYCLE_NOT_ACTIVE',
          failures,
          events,
        );
      }

      let facts: LifecycleStartFacts;
      try {
        facts = parseStartFacts(
          await this.port.inspectStartFacts(freeze({ manifest: copyForPort(manifest) })),
        );
      } catch (error) {
        debugLifecycleFailure('start', 'start-registry-preflight', error);
        addFailure(failures, 'start-registry-preflight');
        return this.result(
          'start',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
          undefined,
          startDiagnosticFromError(error),
        );
      }
      events.emit('preflight', 'SCG_LIFECYCLE_ACTIVE');
      try {
        const prepared = parsePreparedStart(
          await this.port.prepareStart(
            freeze({ manifest: copyForPort(manifest), facts: copyForPort(facts) }),
          ),
        );
        preparationId = prepared.preparationId;
      } catch (error) {
        debugLifecycleFailure('start', 'start-registry-preflight', error);
        addFailure(failures, 'start-registry-preflight');
        return this.result(
          'start',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
          undefined,
          startDiagnosticFromError(error),
        );
      }
      if (preparationId === undefined) {
        addFailure(failures, 'start-registry-preflight');
        return this.result(
          'start',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }

      const preparedStartId = preparationId;
      try {
        await this.port.finalizePreparedStart(freeze({ preparationId }));
      } catch (error) {
        debugLifecycleFailure('start', 'start-registry-preflight', error);
        addFailure(failures, 'start-registry-preflight');
        return this.result(
          'start',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
          undefined,
          startDiagnosticFromError(error),
        );
      }
      events.emit('foreground', 'SCG_LIFECYCLE_ACTIVE');
      foregroundPhase = 'launch';
      const launchedForeground = await this.port.launchMcpForeground(
        freeze({ manifest: copyForPort(manifest), preparationId: preparedStartId }),
      );
      // launch transfers the sole cleanup authority away from prepared start.
      preparationId = undefined;
      try {
        assertForegroundMcp(launchedForeground);
      } catch {
        startRecoveryRequired = true;
        throw new LifecycleEngineInputError(
          'foreground MCP capability is invalid after authority transfer',
        );
      }
      foreground = launchedForeground;
      foregroundPhase = 'wait';
      await parseForegroundExit(await foreground.waitForExit());
      events.emit('cleanup', 'SCG_LIFECYCLE_ACTIVE');
      foregroundPhase = 'cleanup';
      if (foreground !== undefined) {
        const cleanupForeground = foreground;
        await this.retryStartCleanup(
          (attemptCleanupContext) => cleanupForeground.cleanup(attemptCleanupContext),
          startCleanupContext(),
        );
        foregroundCleanupSettled = true;
        foreground = undefined;
      }
      status = 'success';
      code = 'SCG_LIFECYCLE_START_EXITED';
      events.emit('completed', code);
    } catch (error) {
      const convergence = cleanupConvergenceFromError(error);
      if (convergence !== undefined) {
        cleanupConvergence ??= convergence;
      }
      const foregroundStage =
        foregroundPhase === 'cleanup'
          ? 'start-cleanup'
          : foregroundPhase === 'wait'
            ? 'start-wait'
            : 'start-foreground';
      // 이 경로만 사유를 버리고 있었다. setup·uninstall 과 같게 남긴다 — 단계 이름만으로는
      // 무엇이 거부했는지 알 수 없다.
      debugLifecycleFailure('start', foregroundStage, error);
      addFailure(failures, foregroundStage);
      if (foreground !== undefined && !foregroundCleanupSettled && foregroundPhase !== 'cleanup') {
        const cleanupForeground = foreground;
        try {
          await this.retryStartCleanup(
            (attemptCleanupContext) => cleanupForeground.cleanup(attemptCleanupContext),
            startCleanupContext(),
          );
          foregroundCleanupSettled = true;
          foreground = undefined;
        } catch (error) {
          const convergence = cleanupConvergenceFromError(error);
          if (convergence !== undefined) {
            cleanupConvergence ??= convergence;
          }
          addFailure(failures, 'start-cleanup');
          startRecoveryRequired = true;
        }
      } else if (foregroundPhase === 'cleanup') {
        // The foreground remains its sole owner after a terminal cleanup failure.
        startRecoveryRequired = true;
      }
    } finally {
      if (preparationId !== undefined) {
        const preparedStartId = preparationId;
        try {
          await this.retryStartCleanup(
            (attemptCleanupContext) =>
              this.port.discardPreparedStart(
                freeze({ preparationId: preparedStartId, cleanup: attemptCleanupContext }),
              ),
            startCleanupContext(),
          );
          preparationId = undefined;
        } catch (error) {
          const convergence = cleanupConvergenceFromError(error);
          if (convergence !== undefined) {
            cleanupConvergence ??= convergence;
          }
          if (isPreparedStartCleanupConverged(error)) {
            preparationId = undefined;
          } else {
            addFailure(failures, 'start-preparation-revoke');
            startRecoveryRequired = true;
          }
        }
      }
    }
    const terminalCode = startRecoveryRequired ? 'SCG_LIFECYCLE_RECOVERY_REQUIRED' : code;
    if (status === 'failed') {
      events.emit('failed', terminalCode);
    }
    return this.result(
      'start',
      status,
      startRecoveryRequired ? 'recovery-required' : (inspectedState ?? 'recovery-required'),
      terminalCode,
      failures,
      events,
      cleanupConvergence,
    );
  }

  public async runUninstall(): Promise<LifecycleResult> {
    const events = new EventJournal(this.port, 'uninstall');
    const failures: LifecycleFailureReceipt[] = [];
    let transaction: LifecycleUninstallTransaction | undefined;
    let inspectedState: LifecycleState | undefined;
    try {
      events.emit('inspection', 'SCG_LIFECYCLE_ACTIVE');
      const inspection = await this.inspect('uninstall');
      inspectedState = inspection.state;
      const terminal = parseTerminalState(inspection.terminalReceipt);
      if (terminal === 'uninstalled') {
        return this.result(
          'uninstall',
          'success',
          'uninstalled',
          'SCG_LIFECYCLE_ALREADY_UNINSTALLED',
          failures,
          events,
        );
      }
      if (terminal === 'invalid') {
        addFailure(failures, 'uninstall-manifest');
        return this.result(
          'uninstall',
          'failed',
          'lost-provenance',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }
      if (
        terminal === 'recovery-required' ||
        inspection.authorizedWal !== undefined ||
        inspection.state === 'recovery-required'
      ) {
        return this.result(
          'uninstall',
          'failed',
          'recovery-required',
          'SCG_LIFECYCLE_RECOVERY_REQUIRED',
          failures,
          events,
        );
      }
      if (inspection.state !== 'active' || inspection.activeManifest === undefined) {
        return this.result(
          'uninstall',
          'failed',
          inspection.state,
          'SCG_LIFECYCLE_NOT_ACTIVE',
          failures,
          events,
        );
      }

      let manifest: SetupManifestV1;
      try {
        manifest = parseSetupManifestV1(snapshot(inspection.activeManifest));
      } catch {
        addFailure(failures, 'uninstall-manifest');
        return this.result(
          'uninstall',
          'failed',
          'lost-provenance',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }

      let observation: UninstallObservation;
      try {
        observation = parseUninstallObservation(
          await this.port.observeUninstallTargets(freeze({ manifest: copyForPort(manifest) })),
        );
      } catch {
        addFailure(failures, 'uninstall-observation');
        return this.result(
          'uninstall',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }
      if (!observation.complete) {
        addFailure(failures, 'uninstall-preflight');
        return this.result(
          'uninstall',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }

      let preflight: UninstallPreflight;
      try {
        preflight = validateUninstallPreflight({ manifest, observed: observation.observed });
      } catch {
        addFailure(failures, 'uninstall-preflight');
        return this.result(
          'uninstall',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }
      if (
        !preflight.canUninstall ||
        preflight.issues.length !== 0 ||
        preflight.inverse.length !== manifest.artifacts.length
      ) {
        addFailure(failures, 'uninstall-preflight');
        return this.result(
          'uninstall',
          'failed',
          'active',
          'SCG_LIFECYCLE_PREFLIGHT_FAILED',
          failures,
          events,
        );
      }

      events.emit('transaction', 'SCG_LIFECYCLE_ACTIVE');
      transaction = await this.port.openUninstallTransaction(
        freeze({
          manifest: copyForPort(manifest),
          preflight: copyForPort(preflight),
        }),
      );
      assertUninstallTransaction(transaction);
      const terminalState = await transaction.apply();
      if (terminalState === 'recovery-required') {
        addFailure(failures, 'uninstall-apply');
        events.emit('cleanup', 'SCG_LIFECYCLE_FAILED');
        try {
          const compensation = await transaction.compensate();
          const state = compensation === 'recovered' ? 'active' : 'recovery-required';
          if (compensation !== 'recovered' && compensation !== 'recovery-required') {
            addFailure(failures, 'uninstall-compensation');
          }
          const code =
            state === 'recovery-required'
              ? 'SCG_LIFECYCLE_RECOVERY_REQUIRED'
              : 'SCG_LIFECYCLE_FAILED';
          events.emit('failed', code);
          return this.result('uninstall', 'failed', state, code, failures, events);
        } catch (error) {
          addFailure(failures, 'uninstall-compensation');
          addTransactionFailures(failures, error);
          events.emit('failed', 'SCG_LIFECYCLE_RECOVERY_REQUIRED');
          return this.result(
            'uninstall',
            'failed',
            'recovery-required',
            'SCG_LIFECYCLE_RECOVERY_REQUIRED',
            failures,
            events,
          );
        }
      }
      if (terminalState !== 'uninstalled') {
        throw new LifecycleEngineInputError('uninstall transaction returned an invalid state');
      }
      transaction = undefined;
      events.emit('completed', 'SCG_LIFECYCLE_UNINSTALLED');
      return this.result(
        'uninstall',
        'success',
        'uninstalled',
        'SCG_LIFECYCLE_UNINSTALLED',
        failures,
        events,
      );
    } catch (error) {
      addFailure(
        failures,
        transaction === undefined ? 'uninstall-transaction-open' : 'uninstall-apply',
      );
      addTransactionFailures(failures, error);
      let state: LifecycleState = containsLifecycleTransactionError(error)
        ? 'recovery-required'
        : (inspectedState ?? 'recovery-required');
      if (transaction !== undefined) {
        events.emit('cleanup', 'SCG_LIFECYCLE_FAILED');
        try {
          const compensation = await transaction.compensate();
          if (compensation === 'recovered') {
            state = 'active';
          } else {
            if (compensation !== 'recovery-required') {
              addFailure(failures, 'uninstall-compensation');
            }
            state = 'recovery-required';
          }
        } catch (error) {
          addFailure(failures, 'uninstall-compensation');
          addTransactionFailures(failures, error);
          state = 'recovery-required';
        }
      }
      const code =
        state === 'recovery-required' ? 'SCG_LIFECYCLE_RECOVERY_REQUIRED' : 'SCG_LIFECYCLE_FAILED';
      events.emit('failed', code);
      return this.result('uninstall', 'failed', state, code, failures, events);
    }
  }

  private async inspect(operation: LifecycleEngineOperation): Promise<LifecycleInspection> {
    return parseInspection(await this.port.inspectLifecycle(freeze({ operation })));
  }

  private async recover(
    recovery: AuthorizedWalRecovery,
  ): Promise<'recovered' | 'recovery-required'> {
    const result = await this.port.recoverAuthorizedWal(
      freeze({ recoveryId: recovery.recoveryId }),
    );
    if (result !== 'recovered' && result !== 'recovery-required') {
      throw new LifecycleEngineInputError('recovery returned an invalid state');
    }
    return result;
  }

  private async generateCandidate(
    receiptId: string,
    host: HostIntegrationPlan,
  ): Promise<Uint8Array> {
    const credential = host.credential;
    if (credential.kind !== 'setup-created-candidate') {
      throw new LifecycleEngineInputError(
        'candidate generation requested for an adopted credential',
      );
    }
    const candidate = await this.port.generateCredentialToken(
      freeze({
        receiptId,
        requestId: credential.requestId,
        bits: credential.bits,
        projectId: credential.projectId,
        path: credential.path,
      }),
    );
    if (!(candidate instanceof Uint8Array)) {
      throw new LifecycleEngineInputError('credential candidate is not bytes');
    }
    return candidate;
  }
  private startCleanupDeadline(): number {
    return Date.now() + START_CLEANUP_TIMEOUT_MS;
  }
  private async retryStartCleanup(
    action: (cleanup: LifecycleCleanupContext) => Promise<void>,
    cleanup: LifecycleCleanupContext,
  ): Promise<void> {
    const failures: unknown[] = [];
    for (let attempt = 0; attempt < START_CLEANUP_ATTEMPTS; attempt += 1) {
      try {
        await this.awaitStartCleanupAttempt(() => action(cleanup), cleanup.deadline);
        return;
      } catch (error) {
        failures.push(error);
        if (error instanceof LifecycleStartCleanupDeadlineError) {
          throw error;
        }
        if (!isRetryableStartCleanupRejection(error)) {
          throw error;
        }
      }
    }
    if (failures.length === 1) {
      throw failures[0];
    }
    throw new AggregateError(failures, 'Start cleanup did not converge before its deadline.', {
      cause: failures[0],
    });
  }
  private async awaitStartCleanupAttempt(
    action: () => Promise<void>,
    deadline: number,
  ): Promise<void> {
    if (deadline <= Date.now()) {
      throw new LifecycleStartCleanupDeadlineError();
    }
    const completion = Promise.resolve().then(action);
    void completion.catch(() => undefined);
    await this.awaitCleanupBeforeDeadline(
      completion,
      deadline,
      (pending) => new LifecycleStartCleanupDeadlineError(pending),
    );
  }
  private async awaitDiagnosticCleanupConvergence(convergence: Promise<void>): Promise<void> {
    await this.awaitCleanupBeforeDeadline(
      convergence,
      this.startCleanupDeadline(),
      () => new LifecycleDiagnosticCleanupDeadlineError(),
    );
  }
  private async awaitCleanupBeforeDeadline(
    completion: Promise<void>,
    deadline: number,
    timeoutError: (pending: Promise<void>) => Error,
  ): Promise<void> {
    let deadlineFailure: Error | undefined;
    const deadlineError = (): Error => {
      deadlineFailure ??= timeoutError(completion);
      return deadlineFailure;
    };
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw deadlineError();
    }
    void completion.catch(() => undefined);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    try {
      await Promise.race([
        completion,
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => {
            timedOut = true;
            reject(deadlineError());
          }, remaining);
        }),
      ]);
      if (Date.now() >= deadline) {
        throw deadlineError();
      }
    } catch (error) {
      if (timedOut) {
        throw deadlineError();
      }
      throw error;
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
    }
  }

  private async zeroize(
    candidate: Uint8Array | undefined,
    failures: LifecycleFailureReceipt[],
  ): Promise<void> {
    if (candidate === undefined) {
      return;
    }
    try {
      await this.port.zeroizeCredentialToken(freeze({ token: candidate }));
    } catch {
      addFailure(failures, 'token-zeroization');
    } finally {
      zeroBytes(candidate);
    }
  }

  private result(
    operation: LifecycleEngineOperation,
    status: LifecycleEngineStatus,
    state: LifecycleState,
    code: LifecycleEngineCode,
    failures: readonly LifecycleFailureReceipt[],
    events: EventJournal,
    cleanupConvergence: LifecycleCleanupConvergence | undefined = undefined,
    startDiagnostic: LifecycleStartDiagnostic | undefined = undefined,
  ): LifecycleResult {
    return Object.freeze({
      operation,
      status,
      state,
      code,
      failures: Object.freeze(failures.map((failure) => freeze({ stage: failure.stage }))),
      ...(cleanupConvergence === undefined ? {} : { cleanupConvergence }),
      ...(startDiagnostic === undefined ? {} : { startDiagnostic }),
      events: events.snapshot(),
    });
  }
}

/** Convenience entry points retain the same parameter-free public contract. */
export async function runSetup(port: LifecycleEnginePort): Promise<LifecycleResult> {
  return new LifecycleEngine(port).runSetup();
}

export async function runStart(port: LifecycleEnginePort): Promise<LifecycleResult> {
  return new LifecycleEngine(port).runStart();
}

export async function runUninstall(port: LifecycleEnginePort): Promise<LifecycleResult> {
  return new LifecycleEngine(port).runUninstall();
}

class EventJournal {
  private readonly events: LifecycleEventReceipt[] = [];

  public constructor(
    private readonly port: LifecycleEnginePort,
    private readonly operation: LifecycleEngineOperation,
  ) {}

  public emit(phase: LifecycleEventPhase, code: LifecycleEngineCode): void {
    if (this.events.length >= MAX_LIFECYCLE_EVENTS) {
      return;
    }
    const event = freeze({
      sequence: this.events.length + 1,
      operation: this.operation,
      phase,
      code,
    });
    this.events.push(event);
    try {
      const result = this.port.emitLifecycleEvent?.(copyForPort(event));
      if (result !== undefined) {
        void Promise.resolve(result).catch(() => undefined);
      }
    } catch {
      // Observability is explicitly non-authoritative and cannot change lifecycle state.
    }
  }

  public snapshot(): readonly LifecycleEventReceipt[] {
    return Object.freeze(this.events.map((event) => freeze({ ...event })));
  }
}

class LifecycleEngineInputError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LifecycleEngineInputError';
  }
}
class LifecycleStartCleanupDeadlineError extends Error {
  public readonly retryable = true as const;
  public readonly cleanupConvergence: LifecycleCleanupConvergence | undefined;
  public constructor(public readonly convergence: Promise<void> | undefined = undefined) {
    super('start cleanup deadline elapsed');
    this.name = 'LifecycleStartCleanupDeadlineError';
    this.cleanupConvergence =
      convergence === undefined ? undefined : createLifecycleCleanupConvergence(convergence);
  }
}
class LifecycleDiagnosticCleanupDeadlineError extends Error {
  public constructor() {
    super('diagnostic cleanup convergence deadline elapsed');
    this.name = 'LifecycleDiagnosticCleanupDeadlineError';
  }
}

function parseInspection(value: unknown): LifecycleInspection {
  const record = exactRecord(
    value,
    ['state'],
    ['authorizedWal', 'activeManifest', 'terminalReceipt'],
    'lifecycle inspection',
  );
  const state = parseLifecycleState(record.state);
  const authorizedWal =
    record.authorizedWal === undefined ? undefined : parseAuthorizedWal(record.authorizedWal);
  return freeze({
    state,
    ...(authorizedWal === undefined ? {} : { authorizedWal }),
    ...(record.activeManifest === undefined
      ? {}
      : { activeManifest: snapshot(record.activeManifest) }),
    ...(record.terminalReceipt === undefined
      ? {}
      : { terminalReceipt: snapshot(record.terminalReceipt) }),
  });
}

function parseAuthorizedWal(value: unknown): AuthorizedWalRecovery {
  const record = exactRecord(value, ['recoveryId'], [], 'authorized WAL recovery');
  return freeze({ recoveryId: parseId(record.recoveryId, 'recoveryId') });
}

function parseSetupFacts(value: unknown): LifecycleSetupFacts {
  const record = exactRecord(
    value,
    ['configHomes', 'project', 'hostPlan', 'build'],
    [],
    'setup facts',
  );
  const configHomes = snapshot(record.configHomes) as ConfigHomeFacts;
  const project = snapshot(record.project);
  const hostPlan = snapshot(record.hostPlan) as HostPlanInput;
  const build = snapshot(record.build) as LifecycleBuildFacts;
  return freeze({ configHomes, project, hostPlan, build });
}

function parseSetupBuildReceipt(value: unknown): SetupPlanBuildReceipt {
  const record = exactRecord(value, ['plan', 'receiptId'], [], 'setup plan receipt');
  return freeze({
    plan: snapshot(record.plan) as SetupPlan,
    receiptId: parseId(record.receiptId, 'receiptId'),
  });
}

function parseSetupMutationPreparation(value: unknown): SetupMutationPreparation {
  const record = exactRecord(value, ['mutationId'], [], 'setup mutation preparation');
  return freeze({ mutationId: parseId(record.mutationId, 'mutationId') });
}

function parseSetupMutationReceipt(
  value: unknown,
  issuer: TransactionObservedCredentialAuthorityIssuer,
): SetupMutationReceipt {
  const record = exactOpaqueEnvelope(
    value,
    ['observedCreatedAuthority'],
    ['createdAuthority', 'transactionReceipt'],
    'setup mutation receipt',
  );
  const createdAuthority =
    record.createdAuthority === undefined
      ? undefined
      : parseCreatedAuthority(record.createdAuthority);
  const observedCreatedAuthority =
    record.observedCreatedAuthority === undefined
      ? undefined
      : parseTransactionObservedCredentialAuthority(record.observedCreatedAuthority, issuer);
  const transactionReceipt =
    record.transactionReceipt === undefined
      ? undefined
      : parseSetupTransactionReceipt(record.transactionReceipt);
  if (
    (observedCreatedAuthority === undefined && transactionReceipt !== undefined) ||
    (observedCreatedAuthority !== undefined && transactionReceipt === undefined)
  ) {
    throw new LifecycleEngineInputError(
      'post-write credential authority and transaction receipt must be paired',
    );
  }
  return freeze({
    ...(createdAuthority === undefined ? {} : { createdAuthority }),
    observedCreatedAuthority,
    ...(transactionReceipt === undefined ? {} : { transactionReceipt }),
  });
}

function parseCreatedAuthority(value: unknown): CredentialAuthority {
  const record = exactRecord(
    value,
    ['projectId', 'path', 'device', 'inode'],
    [],
    'created credential authority',
  );
  if (
    typeof record.projectId !== 'string' ||
    typeof record.path !== 'string' ||
    typeof record.device !== 'string' ||
    typeof record.inode !== 'string'
  ) {
    throw new LifecycleEngineInputError('created credential authority is invalid');
  }
  return freeze({
    projectId: record.projectId,
    path: record.path,
    device: record.device,
    inode: record.inode,
  });
}
function parseSetupTransactionReceipt(value: unknown): SetupTransactionReceipt {
  if (value === null || typeof value !== 'object') {
    throw new LifecycleEngineInputError('post-write transaction receipt is invalid');
  }
  return value as SetupTransactionReceipt;
}
function parseTransactionObservedCredentialAuthority(
  value: unknown,
  issuer: TransactionObservedCredentialAuthorityIssuer,
): TransactionObservedCredentialAuthority {
  if (
    typeof value !== 'object' ||
    value === null ||
    transactionObservedCredentialAuthorities.get(value as TransactionObservedCredentialAuthority)
      ?.issuer !== issuer
  ) {
    throw new LifecycleEngineInputError(
      'post-write credential authority is not transaction-issued',
    );
  }
  return value as TransactionObservedCredentialAuthority;
}

function assertObservedCreatedAuthority(
  finalizedHost: FinalizedHostIntegrationPlan,
  observedReceipt: TransactionObservedCredentialAuthority | undefined,
  transactionReceipt: SetupTransactionReceipt | undefined,
): void {
  if (finalizedHost.credential.kind !== 'setup-created-candidate') {
    if (observedReceipt !== undefined || transactionReceipt !== undefined) {
      throw new LifecycleEngineInputError(
        'adopted credentials cannot have an observed post-write authority',
      );
    }
    return;
  }
  if (observedReceipt === undefined || transactionReceipt === undefined) {
    throw new LifecycleEngineInputError(
      'created credentials require an observed post-write authority',
    );
  }
  const observedState = transactionObservedCredentialAuthorities.get(observedReceipt);
  if (observedState === undefined || observedState.receipt !== transactionReceipt) {
    throw new LifecycleEngineInputError(
      'post-write credential authority is not bound to the transaction receipt',
    );
  }
  const selectedAuthorities = finalizedHost.descriptor.credentialAuthorities.filter(
    (authority) => authority.projectId === finalizedHost.descriptor.credentialProjectId,
  );
  if (
    selectedAuthorities.length !== 1 ||
    selectedAuthorities[0] === undefined ||
    !sameCredentialAuthority(selectedAuthorities[0], observedState.authority)
  ) {
    throw new LifecycleEngineInputError(
      'finalized credential authority does not match the observed post-write authority',
    );
  }
}

function sameCredentialAuthority(left: CredentialAuthority, right: CredentialAuthority): boolean {
  return (
    left.projectId === right.projectId &&
    left.path === right.path &&
    left.device === right.device &&
    left.inode === right.inode
  );
}

function validateSetupPlan(
  value: SetupPlan,
  config: ConfigOperationPlan,
  host: HostIntegrationPlan,
): SetupPlan {
  const plan = snapshot(value) as SetupPlan;
  const record = exactRecord(
    plan,
    ['schemaVersion', 'installId', 'state', 'config', 'artifacts', 'inverse', 'preview'],
    [],
    'setup plan',
  );
  if (
    record.schemaVersion !== 1 ||
    record.state !== 'active' ||
    parseId(record.installId, 'installId') !== host.installId
  ) {
    throw new LifecycleEngineInputError('setup plan is not bound to the host plan');
  }
  const plannedConfig = parseServerConfigV1(record.config) as ServerConfigV1;
  if (JSON.stringify(plannedConfig) !== JSON.stringify(config.config)) {
    throw new LifecycleEngineInputError('setup plan config differs from config plan');
  }
  if (!Array.isArray(record.artifacts) || !Array.isArray(record.inverse)) {
    throw new LifecycleEngineInputError('setup plan artifacts must be arrays');
  }
  const preview = parseRedactedPreview(record.preview);
  return freeze({
    ...(plan as SetupPlan),
    config: plannedConfig,
    artifacts: snapshot(record.artifacts) as SetupPlan['artifacts'],
    inverse: snapshot(record.inverse) as SetupPlan['inverse'],
    preview,
  });
}

function parseRedactedPreview(value: unknown): RedactedSetupPreview {
  const record = exactRecord(value, ['state', 'operations'], [], 'setup preview');
  if (
    record.state !== 'active' ||
    !Array.isArray(record.operations) ||
    record.operations.length > 1024
  ) {
    throw new LifecycleEngineInputError('setup preview is invalid');
  }
  const operations: RedactedPreviewOperation[] = [];
  for (const operation of record.operations) {
    const item = exactRecord(
      operation,
      ['kind', 'path', 'hunkCount', 'hunkSubjects'],
      [],
      'setup preview operation',
    );
    if (
      (item.kind !== 'create-file' &&
        item.kind !== 'update-config' &&
        item.kind !== 'update-credential-authority-registry' &&
        item.kind !== 'move-config' &&
        item.kind !== 'delete-created-file' &&
        item.kind !== 'delete-created-credential' &&
        item.kind !== 'restore-config' &&
        item.kind !== 'restore-credential-authority-registry-entry' &&
        item.kind !== 'remove-config-hunks' &&
        item.kind !== 'none') ||
      typeof item.path !== 'string' ||
      item.path.length === 0 ||
      item.path.length > 4096 ||
      typeof item.hunkCount !== 'number' ||
      !Number.isSafeInteger(item.hunkCount) ||
      item.hunkCount < 0 ||
      item.hunkCount > 4096 ||
      !Array.isArray(item.hunkSubjects) ||
      item.hunkSubjects.length > 4096 ||
      !item.hunkSubjects.every((subject) => typeof subject === 'string' && subject.length <= 1024)
    ) {
      throw new LifecycleEngineInputError('setup preview operation is invalid');
    }
    operations.push(
      freeze({
        kind: item.kind,
        path: item.path,
        hunkCount: item.hunkCount,
        hunkSubjects: Object.freeze([...item.hunkSubjects]),
      }),
    );
  }
  return freeze({ state: 'active', operations: Object.freeze(operations) });
}

function digestPreview(preview: RedactedSetupPreview): LifecyclePreviewDigest {
  const canonical = JSON.stringify({
    state: preview.state,
    operations: preview.operations.map((operation) => ({
      kind: operation.kind,
      path: operation.path,
      hunkCount: operation.hunkCount,
      hunkSubjects: operation.hunkSubjects,
    })),
  });
  return freeze({
    algorithm: 'sha256',
    value: `sha256:${createHash('sha256').update(canonical).digest('hex')}`,
    operationCount: preview.operations.length,
  });
}

function parseStartFacts(value: unknown): LifecycleStartFacts {
  const record = exactRecord(
    value,
    ['snapshotId', 'selectedProjectId', 'config', 'projects'],
    ['registry'],
    'start facts',
  );
  if (!Array.isArray(record.projects) || record.projects.length > MAX_PROJECTS) {
    throw new LifecycleEngineInputError('start projects are invalid');
  }
  const projects: LifecycleStartProjectFacts[] = [];
  const ids = new Set<string>();
  for (const value of record.projects) {
    const project = exactRecord(
      value,
      ['projectId', 'authority', 'descriptor', 'cache'],
      [],
      'start project',
    );
    const projectId = parseId(project.projectId, 'projectId');
    if (ids.has(projectId)) {
      throw new LifecycleEngineInputError('start projects contain a duplicate project id');
    }
    ids.add(projectId);
    projects.push(
      freeze({
        projectId,
        authority: snapshot(project.authority) as LifecycleDataValue,
        descriptor: snapshot(project.descriptor) as LifecycleDataValue,
        cache: snapshot(project.cache) as LifecycleDataValue,
      }),
    );
  }
  const snapshotId = parseId(record.snapshotId, 'start snapshotId');
  const selectedProjectId = parseId(record.selectedProjectId, 'start selectedProjectId');
  if (!ids.has(selectedProjectId)) {
    throw new LifecycleEngineInputError('start selected project is absent from the snapshot');
  }
  return freeze({
    snapshotId,
    selectedProjectId,
    config: snapshot(record.config) as LifecycleDataValue,
    ...(record.registry === undefined
      ? {}
      : { registry: snapshot(record.registry) as LifecycleDataValue }),
    projects: Object.freeze(projects),
  });
}

function parsePreparedStart(value: unknown): LifecyclePreparedStart {
  const record = exactRecord(value, ['preparationId'], [], 'prepared start');
  return freeze({ preparationId: parseId(record.preparationId, 'prepared start id') });
}

function parseForegroundExit(value: unknown): ForegroundMcpExit {
  const record = exactRecord(value, ['reason', 'exitCode'], [], 'foreground MCP exit');
  if (
    (record.reason !== 'signal' && record.reason !== 'exit') ||
    typeof record.exitCode !== 'number' ||
    !Number.isSafeInteger(record.exitCode)
  ) {
    throw new LifecycleEngineInputError('foreground MCP exit is invalid');
  }
  return freeze({ reason: record.reason, exitCode: record.exitCode });
}

function parseUninstallObservation(value: unknown): UninstallObservation {
  const record = exactRecord(value, ['complete', 'observed'], [], 'uninstall observation');
  if (typeof record.complete !== 'boolean' || !Array.isArray(record.observed)) {
    throw new LifecycleEngineInputError('uninstall observation is invalid');
  }
  return freeze({
    complete: record.complete,
    observed: snapshot(record.observed) as readonly ObservedOwnedTarget[],
  });
}

function parseTerminalState(
  value: unknown,
): 'absent' | 'active' | 'recovery-required' | 'uninstalled' | 'invalid' {
  if (value === undefined) {
    return 'absent';
  }
  try {
    return parseTerminalReceiptV1(snapshot(value)).terminalState;
  } catch {
    return 'invalid';
  }
}

function assertSetupTransaction(value: unknown): asserts value is LifecycleSetupTransaction {
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof (value as { apply?: unknown }).apply !== 'function' ||
    typeof (value as { publishActive?: unknown }).publishActive !== 'function' ||
    typeof (value as { compensate?: unknown }).compensate !== 'function'
  ) {
    throw new LifecycleEngineInputError('setup transaction capability is invalid');
  }
}

function assertUninstallTransaction(
  value: unknown,
): asserts value is LifecycleUninstallTransaction {
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof (value as { apply?: unknown }).apply !== 'function' ||
    typeof (value as { compensate?: unknown }).compensate !== 'function'
  ) {
    throw new LifecycleEngineInputError('uninstall transaction capability is invalid');
  }
}

function assertForegroundMcp(value: unknown): asserts value is LifecycleForegroundMcp {
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof (value as { waitForExit?: unknown }).waitForExit !== 'function' ||
    typeof (value as { cleanup?: unknown }).cleanup !== 'function'
  ) {
    throw new LifecycleEngineInputError('foreground MCP capability is invalid');
  }
}

function parseLifecycleState(value: unknown): LifecycleState {
  if (
    value !== 'never-installed' &&
    value !== 'active' &&
    value !== 'recovery-required' &&
    value !== 'uninstalled' &&
    value !== 'lost-provenance'
  ) {
    throw new LifecycleEngineInputError('lifecycle state is invalid');
  }
  return value;
}

function parseId(value: unknown, name: string): string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new LifecycleEngineInputError(`${name} is invalid`);
  }
  return value;
}

function assertCredentialCandidate(candidate: Uint8Array): void {
  if (candidate.byteLength !== 32) {
    throw new LifecycleEngineInputError('credential candidate must contain exactly 32 bytes');
  }
}

function zeroBytes(value: Uint8Array): void {
  value.fill(0);
}

/**
 * Opt-in operator diagnostics: failure receipts intentionally carry only the
 * stage, which makes remote triage impossible. With SCG_LIFECYCLE_DEBUG=1 the
 * caught error (message + bounded cause chain) is written to stderr. Error
 * messages in this engine are static rule descriptions and never carry token
 * material.
 */
function debugLifecycleFailure(operation: string, stage: string | undefined, error: unknown): void {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env;
  if (env?.SCG_LIFECYCLE_DEBUG !== '1') {
    return;
  }
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current !== undefined && current !== null; depth += 1) {
    const detail =
      current instanceof Error ? `${current.name}: ${current.message}` : String(current);
    console.error(
      `scene-glass-onboarding: [SCG_LIFECYCLE_DEBUG] [${operation}] stage=${stage ?? 'unknown'} ${depth === 0 ? 'error' : 'cause'}=${detail}`,
    );
    if (env.SCG_LIFECYCLE_DEBUG_STACK === '1' && current instanceof Error) {
      console.error(current.stack);
    }
    current = current instanceof Error ? current.cause : undefined;
  }
}

function addFailure(target: LifecycleFailureReceipt[], stage: LifecycleFailureStage): void {
  if (!target.some((failure) => failure.stage === stage)) {
    target.push(freeze({ stage }));
  }
}
function isRetryableStartCleanupRejection(
  error: unknown,
): error is LifecycleRetryableStartCleanupRejection {
  return (
    error instanceof Error &&
    (error as Partial<LifecycleRetryableStartCleanupRejection>).retryable === true
  );
}
function cleanupConvergenceFromError(error: unknown): LifecycleCleanupConvergence | undefined {
  return error instanceof LifecycleStartCleanupDeadlineError ? error.cleanupConvergence : undefined;
}

function createLifecycleCleanupConvergence(
  convergence: Promise<void>,
): LifecycleCleanupConvergence {
  const capability = Object.freeze({}) as LifecycleCleanupConvergence;
  const state = convergence.then(
    () => 'converged' as const,
    () => 'failed' as const,
  );
  lifecycleCleanupConvergences.set(capability, Object.freeze({ completion: convergence, state }));
  return capability;
}
function diagnosticCleanupConvergence(error: unknown): Promise<void> | undefined {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'cleanupConvergence');
  return descriptor !== undefined &&
    descriptor.enumerable === true &&
    Object.hasOwn(descriptor, 'value') &&
    descriptor.value instanceof Promise
    ? descriptor.value
    : undefined;
}

function isPreparedStartCleanupConverged(error: unknown): boolean {
  return error instanceof LifecyclePreparedStartUnavailableError && error.reason === 'missing';
}
function startDiagnosticFromError(error: unknown): LifecycleStartDiagnostic | undefined {
  if (!(error instanceof LifecycleStartDiagnosticError)) return undefined;
  try {
    return parseLifecycleStartDiagnostic(error.diagnostic);
  } catch {
    return undefined;
  }
}
function parseLifecycleStartDiagnostic(value: unknown): LifecycleStartDiagnostic {
  const record = exactRecord(value, ['code', 'projectId'], [], 'start diagnostic');
  if (
    typeof record.code !== 'string' ||
    !START_DIAGNOSTIC_CODES.has(record.code as LifecycleStartDiagnostic['code'])
  ) {
    throw new LifecycleEngineInputError('start diagnostic code is invalid');
  }
  return freeze({
    code: record.code as LifecycleStartDiagnostic['code'],
    projectId: parseId(record.projectId, 'start diagnostic projectId'),
  });
}

const TRANSACTION_FAILURE_POINTS = new Set<string>([
  'lock-acquire',
  'lock-release',
  'wal-write',
  'wal-fsync',
  'stage-write',
  'target-rename',
  'target-fsync',
  'parent-fsync',
  'manifest-write',
  'manifest-fsync',
  'diagnostics',
  'uninstall-commit-decided',
  'credential-delete',
  'receipt-write',
  'receipt-fsync',
  'cleanup',
] satisfies readonly LifecycleFailurePoint[]);
function containsLifecycleTransactionError(error: unknown, seen = new Set<object>()): boolean {
  if (error instanceof LifecycleTransactionError) {
    return true;
  }
  if (!(error instanceof AggregateError) || seen.has(error)) {
    return false;
  }
  seen.add(error);
  return error.errors.some((nested) => containsLifecycleTransactionError(nested, seen));
}

function addTransactionFailures(
  target: LifecycleFailureReceipt[],
  error: unknown,
  seen = new Set<object>(),
): void {
  if (error instanceof LifecycleTransactionError) {
    for (const failure of error.failures) {
      if (isLifecycleFailurePoint(failure.stage)) {
        addFailure(target, `transaction:${failure.stage}`);
      }
    }
    return;
  }
  if (!(error instanceof AggregateError)) {
    return;
  }
  if (seen.has(error)) {
    return;
  }
  seen.add(error);
  for (const nested of error.errors) {
    addTransactionFailures(target, nested, seen);
  }
}

function isLifecycleFailurePoint(value: string): value is LifecycleFailurePoint {
  return TRANSACTION_FAILURE_POINTS.has(value);
}

function exactOpaqueEnvelope(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  name: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LifecycleEngineInputError(`${name} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new LifecycleEngineInputError(`${name} must use a plain record`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new LifecycleEngineInputError(`${name} has unexpected keys`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (
    keys.length !==
    required.length + optional.filter((key) => Object.hasOwn(descriptors, key)).length
  ) {
    throw new LifecycleEngineInputError(`${name} has unexpected keys`);
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !allowed.has(key) ||
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')
    ) {
      throw new LifecycleEngineInputError(`${name} has unexpected keys`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(descriptors, key)) {
      throw new LifecycleEngineInputError(`${name} is missing ${key}`);
    }
  }
  return value as Readonly<Record<string, unknown>>;
}
function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  name: string,
): Readonly<Record<string, unknown>> {
  const record = snapshot(value);
  if (
    record === null ||
    typeof record !== 'object' ||
    Array.isArray(record) ||
    record instanceof Uint8Array
  ) {
    throw new LifecycleEngineInputError(`${name} must be an object`);
  }
  const keys = Object.keys(record);
  const allowed = new Set([...required, ...optional]);
  if (
    keys.length !==
    required.length + optional.filter((key) => Object.hasOwn(record, key)).length
  ) {
    throw new LifecycleEngineInputError(`${name} has unexpected keys`);
  }
  for (const key of keys) {
    if (!allowed.has(key)) {
      throw new LifecycleEngineInputError(`${name} has unexpected keys`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(record, key)) {
      throw new LifecycleEngineInputError(`${name} is missing ${key}`);
    }
  }
  return record as Readonly<Record<string, unknown>>;
}

/**
 * Clone only plain data, reject accessors/prototypes/functions, and freeze the
 * resulting graph. Aliases are cloned on every occurrence so they remain
 * mutation-isolated and count against every traversal bound; only ancestors
 * are rejected as cycles.
 */
function snapshot(value: unknown): unknown {
  const ancestors = new WeakSet<object>();
  let nodes = 0;
  let bytes = 0;

  const visit = (current: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > MAX_SNAPSHOT_NODES || depth > MAX_SNAPSHOT_DEPTH) {
      throw new LifecycleEngineInputError('lifecycle input exceeds structural limits');
    }
    if (current === null || current === undefined || typeof current === 'boolean') {
      return current;
    }
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) {
        throw new LifecycleEngineInputError('lifecycle input contains a non-finite number');
      }
      return current;
    }
    if (typeof current === 'string') {
      bytes += new TextEncoder().encode(current).byteLength;
      if (bytes > MAX_SNAPSHOT_BYTES) {
        throw new LifecycleEngineInputError('lifecycle input exceeds byte limits');
      }
      return current;
    }
    if (
      typeof current === 'function' ||
      typeof current === 'symbol' ||
      typeof current === 'bigint'
    ) {
      throw new LifecycleEngineInputError('lifecycle input contains a non-data value');
    }
    if (current instanceof Uint8Array) {
      bytes += current.byteLength;
      if (bytes > MAX_SNAPSHOT_BYTES) {
        throw new LifecycleEngineInputError('lifecycle input exceeds byte limits');
      }
      return new Uint8Array(current);
    }
    if (typeof current !== 'object') {
      throw new LifecycleEngineInputError('lifecycle input is invalid');
    }
    if (ancestors.has(current)) {
      throw new LifecycleEngineInputError('lifecycle input contains a cycle');
    }
    ancestors.add(current);
    if (Array.isArray(current)) {
      const output: unknown[] = [];
      const descriptors = Object.getOwnPropertyDescriptors(current);
      for (const key of Object.keys(descriptors)) {
        if (key === 'length') {
          continue;
        }
        const descriptor = descriptors[key];
        if (
          descriptor === undefined ||
          !descriptor.enumerable ||
          !Object.hasOwn(descriptor, 'value')
        ) {
          throw new LifecycleEngineInputError('lifecycle input contains an accessor');
        }
      }
      for (let index = 0; index < current.length; index += 1) {
        if (!Object.hasOwn(current, index)) {
          throw new LifecycleEngineInputError('lifecycle input contains a sparse array');
        }
        output.push(visit(current[index], depth + 1));
      }
      ancestors.delete(current);
      return Object.freeze(output);
    }
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new LifecycleEngineInputError('lifecycle input must use plain records');
    }
    const descriptors = Object.getOwnPropertyDescriptors(current);
    if (Object.getOwnPropertySymbols(current).length !== 0) {
      throw new LifecycleEngineInputError('lifecycle input contains symbol keys');
    }
    const output: Record<string, unknown> = {};
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new LifecycleEngineInputError('lifecycle input contains an accessor');
      }
      Object.defineProperty(output, key, {
        configurable: false,
        enumerable: true,
        writable: false,
        value: visit(descriptor.value, depth + 1),
      });
    }
    ancestors.delete(current);
    return Object.freeze(output);
  };

  return visit(value, 0);
}

function copyForPort<T>(value: T): T {
  return snapshot(value) as T;
}

function freeze<T extends object>(value: T): Readonly<T> {
  return Object.freeze(value);
}
