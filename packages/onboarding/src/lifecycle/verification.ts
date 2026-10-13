/**
 * Live verification deliberately depends on authority-bearing ports instead of
 * importing the static, Vite, MCP, or Chromium implementations. This keeps the
 * orchestrator unable to rediscover configuration, credentials, or paths.
 */

import type { LifecycleDiagnosticCleanupConvergenceFailure } from './engine.js';

export const LIVE_DIAGNOSTIC_PROTOCOL_VERSION = '2025-11-25' as const;
export const CANONICAL_LOADER_PATH = '/scene-glass-loader.js' as const;
export const MAX_DIAGNOSTIC_REQUEST_BYTES = 16 * 1024;
export const MAX_DIAGNOSTIC_RESPONSE_BYTES = 1024 * 1024;
export const MAX_DIAGNOSTIC_LOG_BYTES = 4 * 1024;
export const MAX_DIAGNOSTIC_LOG_ENTRIES = 32;
export const MAX_DIAGNOSTIC_CLOSE_RECEIPTS = 8;
export const MAX_DIAGNOSTIC_RECEIPT_RECORDS = 32;
export const MAX_DIAGNOSTIC_RECEIPT_TEXT_BYTES = 64 * 1024;
export const MAX_DIAGNOSTIC_CANARIES = 32;

export const MAX_DIAGNOSTIC_HEADERS = 32;
export const MAX_DIAGNOSTIC_HEADER_BYTES = 4 * 1024;
const MAX_SESSION_ID_BYTES = 128;
const INITIALIZE_ID = 'scene-glass-live-initialize';
const ANNOTATIONS_LIST_ID = 'scene-glass-live-annotations-list';
const PING_ID = 'scene-glass-live-ping';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const diagnosticReceiptSnapshots = new WeakSet<object>();
const MAX_DIAGNOSTIC_RECEIPT_SNAPSHOT_DEPTH = 8;
const MAX_DIAGNOSTIC_RECEIPT_SNAPSHOT_FIELDS = 16;

declare const finalizedVerificationAuthorityBrand: unique symbol;

/**
 * An already-finalized configuration and credential authority. It is opaque so
 * this module cannot inspect, serialize, or reconstruct credential material.
 * An engine adapter obtains it from the setup authority and supplies it only to
 * the host and MCP ports below.
 */
export interface FinalizedVerificationAuthority {
  readonly [finalizedVerificationAuthorityBrand]: 'scene-glass-finalized-verification-authority';
}

export type SelectedHostKind = 'static';

/** The caller owns cancellation and the absolute deadline; this module adds neither. */
export interface DiagnosticExecutionContext {
  readonly signal: AbortSignal;
  /** Epoch milliseconds. It is never extended or replaced by this module. */
  readonly deadline: number;
}

export interface DiagnosticHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: Uint8Array;
}

export interface DiagnosticJsonRpcRequest {
  readonly body: Readonly<Record<string, unknown>>;
  /** Only protocol and session headers belong here. Transport auth remains port-owned. */
  readonly headers: Readonly<Record<string, string>>;
}

export interface DiagnosticBrowserState {
  readonly localStorageKeys: readonly string[];
  readonly sessionStorageKeys: readonly string[];
  readonly indexedDbNames: readonly string[];
  readonly cacheStorageNames: readonly string[];
  readonly serviceWorkerRegistrations: readonly string[];
}

export interface DiagnosticTextReceiptRecord {
  readonly kind: 'log' | 'header';
  readonly text: string;
}

export interface DiagnosticHttpReceiptRecord {
  readonly kind: 'http-response';
  readonly path: string;
  readonly cacheControl: string;
  readonly body: string;
  /** A body may be skipped only for the canonical, transient, no-store loader response. */
  readonly transient: boolean;
}

/**
 * A host runtime emits this only after its close path has completed every
 * listed cleanup operation. It is an opaque cleanup attestation, not a
 * self-supplied empty success receipt.
 */
export interface DiagnosticStaticRuntimeCleanupRecord {
  readonly kind: 'runtime-cleanup';
  readonly runtime: 'static';
  readonly listenerClosed: true;
  readonly credentialCapabilityRevoked: true;
  readonly tokenWiped: true;
}

export interface DiagnosticManagedViteRuntimeCleanupRecord {
  readonly kind: 'runtime-cleanup';
  readonly runtime: 'managed-vite';
  readonly serverClosed: true;
  readonly cacheAuthorityClosed: true;
  readonly cacheWriterClosed: true;
  readonly credentialCapabilityRevoked: true;
  readonly signalListenersRemoved: true;
  readonly umaskRestored: true;
  readonly processLeaseReleased: true;
}

export type DiagnosticReceiptRecord =
  | DiagnosticHttpReceiptRecord
  | DiagnosticManagedViteRuntimeCleanupRecord
  | DiagnosticStaticRuntimeCleanupRecord
  | DiagnosticTextReceiptRecord;
export type DiagnosticCloseReceiptPhase =
  'browser-profile' | 'bootstrap-profile' | 'host' | 'mcp-server' | 'mcp-session';

/**
 * Close receipts are bounded evidence only. Ports must not put request headers,
 * credential authorities, filesystem paths, or session identifiers in them.
 */
export interface DiagnosticCloseReceipt {
  readonly phase: DiagnosticCloseReceiptPhase;
  readonly records: readonly DiagnosticReceiptRecord[];
  readonly browserState?: DiagnosticBrowserState;
}

export interface BrowserDiagnosticCloseReceipt extends DiagnosticCloseReceipt {
  readonly phase: 'bootstrap-profile' | 'browser-profile';
  readonly browserState: DiagnosticBrowserState;
}

/**
 * Handles are supplied only by the authority-bearing ports. Their close methods
 * are contractually idempotent; the orchestrator also invokes each at most once.
 */
export interface SelectedHostRuntimeHandle {
  readonly kind: SelectedHostKind;
  readonly foreground: true;
  readonly persistent: false;
  load(
    path: typeof CANONICAL_LOADER_PATH,
    context: DiagnosticExecutionContext,
  ): Promise<DiagnosticHttpResponse>;
  close(context: DiagnosticExecutionContext): Promise<DiagnosticCloseReceipt>;
}

export interface McpServerHandle {
  readonly loopback: true;
  readonly persistent: false;
  close(context: DiagnosticExecutionContext): Promise<DiagnosticCloseReceipt>;
}

export interface McpSessionTransportHandle {
  request(
    request: DiagnosticJsonRpcRequest,
    context: DiagnosticExecutionContext,
  ): Promise<DiagnosticHttpResponse>;
  close(context: DiagnosticExecutionContext): Promise<DiagnosticCloseReceipt>;
}

export interface LoopbackMcpRuntimeHandle {
  readonly server: McpServerHandle;
  readonly session: McpSessionTransportHandle;
}

export interface BrowserDiagnosticResult {
  readonly loaderReady: boolean;
  readonly panelReady: boolean;
  readonly logs: readonly string[];
}

export interface BrowserDiagnosticProfileHandle {
  readonly persistent: false;
  verifyHostPage(input: {
    readonly host: SelectedHostRuntimeHandle;
    readonly loaderPath: typeof CANONICAL_LOADER_PATH;
    readonly context: DiagnosticExecutionContext;
  }): Promise<BrowserDiagnosticResult>;
  close(context: DiagnosticExecutionContext): Promise<BrowserDiagnosticCloseReceipt>;
}

export interface BootstrapSmokeProfileHandle {
  readonly empty: true;
  readonly workersEnabled: true;
  readonly persistent: false;
  smoke(context: DiagnosticExecutionContext): Promise<void>;
  close(context: DiagnosticExecutionContext): Promise<BrowserDiagnosticCloseReceipt>;
}

export interface LiveDiagnosticHostPort {
  start(input: {
    readonly authority: FinalizedVerificationAuthority;
    readonly selectedHost: SelectedHostKind;
    readonly context: DiagnosticExecutionContext;
  }): Promise<SelectedHostRuntimeHandle>;
}

export interface LiveDiagnosticMcpPort {
  startLoopback(input: {
    readonly authority: FinalizedVerificationAuthority;
    readonly host: SelectedHostRuntimeHandle;
    readonly context: DiagnosticExecutionContext;
  }): Promise<LoopbackMcpRuntimeHandle>;
}

export interface LiveDiagnosticBrowserPort {
  startProfile(context: DiagnosticExecutionContext): Promise<BrowserDiagnosticProfileHandle>;
}

export interface BootstrapSmokePort {
  startEmptyWorkersEnabledProfile(
    context: DiagnosticExecutionContext,
  ): Promise<BootstrapSmokeProfileHandle>;
}

/**
 * Token matching is intentionally opaque: the verifier receives only a
 * mutable-byte predicate and cannot retain raw, encoded, or digest canaries.
 * The engine owns matcher destruction in its all-exits cleanup.
 */
export interface PersistentSecretCanaries {
  readonly tokenMatcher: {
    matches(value: Uint8Array): boolean;
  };
  readonly pathCanaries: readonly string[];
}
/** Credential-independent bootstrap smoke may use this explicit empty bundle only. */
export interface EmptyPersistentSecretCanaries {
  readonly pathCanaries: readonly [];
}
export type BootstrapPersistentSecretCanaries =
  PersistentSecretCanaries | EmptyPersistentSecretCanaries;

export interface AssertNoPersistentSecretInput {
  readonly receipts: readonly DiagnosticCloseReceipt[];
  readonly canaries: BootstrapPersistentSecretCanaries;
}

export interface RunLiveDiagnosticsInput {
  readonly authority: FinalizedVerificationAuthority;
  readonly selectedHost: SelectedHostKind;
  readonly context: DiagnosticExecutionContext;
  readonly host: LiveDiagnosticHostPort;
  readonly mcp: LiveDiagnosticMcpPort;
  readonly browser: LiveDiagnosticBrowserPort;
  readonly persistentSecretCanaries: PersistentSecretCanaries;
}

export interface LiveDiagnosticsResult {
  readonly host: SelectedHostKind;
  readonly initializeStatus: 200;
  readonly initializedStatus: 202;
  readonly loaderStatus: 200;
  readonly annotationsListStatus: 200;
  readonly persistent: false;
}

export interface RunBootstrapSmokeInput {
  readonly context: DiagnosticExecutionContext;
  readonly port: BootstrapSmokePort;
  readonly persistentSecretCanaries: BootstrapPersistentSecretCanaries;
}

export interface BootstrapSmokeResult {
  readonly persistent: false;
  readonly workersEnabled: true;
}

export type DiagnosticFailurePhase =
  | 'aborted'
  | 'bootstrap-profile-close'
  | 'bootstrap-profile-start'
  | 'bootstrap-smoke'
  | 'browser-close'
  | 'browser-diagnostic'
  | 'browser-profile-start'
  | 'annotations-list'
  | 'deadline'
  | 'host-close'
  | 'host-start'
  | 'initialized'
  | 'initialize'
  | 'loader'
  | 'mcp-server-close'
  | 'mcp-session-close'
  | 'mcp-start'
  | 'ping'
  | 'secret-receipt';

export interface RedactedDiagnosticFailure {
  readonly phase: DiagnosticFailurePhase;
  readonly status?: number;
}

/**
 * This error intentionally retains only fixed phase names and HTTP statuses.
 * It never exposes a port error, authority, response body, path, token, or MCP
 * session ID.
 */
export class LiveDiagnosticError
  extends Error
  implements LifecycleDiagnosticCleanupConvergenceFailure
{
  readonly failures: readonly RedactedDiagnosticFailure[];
  /**
   * The retained diagnostic cleanup owner settles this promise only after every
   * late receipt is snapshot-validated and secret-scanned.
   */
  readonly cleanupConvergence: Promise<void> | undefined;
  public constructor(
    failures: readonly RedactedDiagnosticFailure[],
    cleanupConvergence: Promise<void> | undefined = undefined,
  ) {
    const frozenFailures = Object.freeze(failures.map((failure) => Object.freeze({ ...failure })));
    super(formatFailures(frozenFailures));
    this.name = 'LiveDiagnosticError';
    this.stack = `${this.name}: ${this.message}`;
    this.failures = frozenFailures;
    this.cleanupConvergence = cleanupConvergence;
  }
}

class DiagnosticPhaseError extends Error {
  constructor(
    readonly phase: DiagnosticFailurePhase,
    readonly status: number | undefined = undefined,
  ) {
    super(status === undefined ? phase : `${phase}/${status}`);
    this.name = 'DiagnosticPhaseError';
    this.stack = `${this.name}: ${this.message}`;
  }
}

class DiagnosticControlError extends Error {
  constructor(readonly phase: 'aborted' | 'deadline') {
    super(phase);
    this.name = 'DiagnosticControlError';
    this.stack = `${this.name}: ${this.message}`;
  }
}
interface CleanupOutcome {
  readonly failure?: RedactedDiagnosticFailure;
  readonly late: boolean;
  readonly receipt?: DiagnosticCloseReceipt;
}

type CleanupOutcomeSet = readonly CleanupOutcome[];
/**
 * Retains a host cleanup authority when endpoint construction fails after the
 * runtime has started. The caller must route it through collectClose so the
 * original cleanup deadline and receipt validation remain authoritative.
 */
export class RetainedHostStartupError extends Error {
  public readonly close: (context: DiagnosticExecutionContext) => Promise<DiagnosticCloseReceipt>;
  public constructor(
    cause: unknown,
    close: (context: DiagnosticExecutionContext) => Promise<DiagnosticCloseReceipt>,
  ) {
    super('verification host startup failed after retaining its cleanup authority', { cause });
    this.name = 'RetainedHostStartupError';
    this.close = close;
  }
}
class LateCleanupAdoption {
  readonly #canaries: BootstrapPersistentSecretCanaries;
  readonly #convergence: Promise<void>;
  #failed = false;
  #pending = 0;
  #reject: ((reason: unknown) => void) | undefined;
  #resolve: (() => void) | undefined;
  #sealed = false;
  #settled = false;
  public constructor(canaries: BootstrapPersistentSecretCanaries) {
    this.#canaries = canaries;
    this.#convergence = new Promise<void>((resolve, reject) => {
      this.#resolve = resolve;
      this.#reject = reject;
    });
    void this.#convergence.catch(() => undefined);
  }
  public adoptPendingCleanup(cleanup: Promise<CleanupOutcomeSet>): void {
    this.adopt(
      cleanup.then((outcomes) => {
        const receipts: DiagnosticCloseReceipt[] = [];
        for (const outcome of outcomes) {
          if (outcome.failure !== undefined || outcome.receipt === undefined) {
            throw new DiagnosticPhaseError('secret-receipt');
          }
          receipts.push(outcome.receipt);
        }
        assertNoPersistentSecret({
          canaries: this.#canaries,
          receipts: Object.freeze(receipts),
        });
      }),
    );
  }
  public adoptLateOutcome(outcome: Promise<CleanupOutcome>): void {
    this.adopt(
      outcome.then((settled) => {
        if (settled.failure !== undefined || settled.receipt === undefined) {
          throw new DiagnosticPhaseError('secret-receipt');
        }
        assertNoPersistentSecret({
          canaries: this.#canaries,
          receipts: Object.freeze([settled.receipt]),
        });
      }),
    );
  }
  public markNonConvergent(): void {
    this.#failed = true;
  }
  public seal(): Promise<void> | undefined {
    this.#sealed = true;
    this.resolveIfSettled();
    return this.#settled && !this.#failed ? undefined : this.#convergence;
  }
  private adopt(task: Promise<unknown>): void {
    if (this.#settled) {
      return;
    }
    this.#pending += 1;
    void task.then(
      () => this.complete(),
      () => {
        this.#failed = true;
        this.complete();
      },
    );
  }
  private complete(): void {
    this.#pending -= 1;
    this.resolveIfSettled();
  }
  private resolveIfSettled(): void {
    if (!this.#sealed || this.#pending !== 0 || this.#settled) {
      return;
    }
    this.#settled = true;
    if (this.#failed) {
      this.#reject?.(new DiagnosticPhaseError('secret-receipt'));
    } else {
      this.#resolve?.();
    }
    this.#resolve = undefined;
    this.#reject = undefined;
  }
}

/**
 * Runs the live, foreground-only protocol in one fixed order. It owns resource
 * ordering and cleanup aggregation, while the ports own runtime authority and
 * implementation details.
 */
export async function runLiveDiagnostics(
  input: RunLiveDiagnosticsInput,
): Promise<LiveDiagnosticsResult> {
  let host: SelectedHostRuntimeHandle | undefined;
  let mcp: LoopbackMcpRuntimeHandle | undefined;
  let browser: BrowserDiagnosticProfileHandle | undefined;
  let sessionId: string | undefined;
  let primary: RedactedDiagnosticFailure | undefined;
  let phase: DiagnosticFailurePhase = 'host-start';
  let cleanupOutcomes: readonly CleanupOutcome[] = Object.freeze([]);
  let cleanupFailures: readonly RedactedDiagnosticFailure[] = Object.freeze([]);
  let receipts: readonly DiagnosticCloseReceipt[] = Object.freeze([]);
  let cleanupConvergence: Promise<void> | undefined;
  const cleanupContext = cleanupExecutionContext(input.context);
  let persistentSecretCanaries: PersistentSecretCanaries;
  try {
    persistentSecretCanaries = validateLivePersistentSecretCanaries(input.persistentSecretCanaries);
  } catch (error: unknown) {
    throw new LiveDiagnosticError([redactedFailure(error, 'secret-receipt')]);
  }
  const lateCleanupAdoption = new LateCleanupAdoption(persistentSecretCanaries);
  const recordCleanupOutcome = (outcome: CleanupOutcome): void => {
    cleanupOutcomes = Object.freeze([...cleanupOutcomes, outcome]);
  };

  try {
    assertExecutionActive(input.context);

    phase = 'host-start';
    host = await awaitResourceStartup(
      input.context,
      input.host.start({
        authority: input.authority,
        context: input.context,
        selectedHost: input.selectedHost,
      }),
      (lateHost) =>
        collectClose(
          'host-close',
          'host',
          cleanupContext,
          () => lateHost.close(cleanupContext),
          input.selectedHost,
          lateCleanupAdoption,
        ).then((outcome) => Object.freeze([outcome])),
      () =>
        recordCleanupOutcome(
          failedCleanupOutcome(new DiagnosticPhaseError('host-close'), 'host-close', true),
        ),
      lateCleanupAdoption,
      (error) =>
        error instanceof RetainedHostStartupError
          ? collectClose(
              'host-close',
              'host',
              cleanupContext,
              () => error.close(cleanupContext),
              input.selectedHost,
              lateCleanupAdoption,
            ).then((outcome) => Object.freeze([outcome]))
          : undefined,
    );
    assertExecutionActive(input.context);
    if (host.kind !== input.selectedHost || host.foreground !== true || host.persistent !== false) {
      throw new DiagnosticPhaseError('host-start');
    }

    phase = 'mcp-start';
    mcp = await awaitResourceStartup(
      input.context,
      input.mcp.startLoopback({
        authority: input.authority,
        context: input.context,
        host,
      }),
      async (lateMcp) =>
        Object.freeze([
          await collectClose(
            'mcp-session-close',
            'mcp-session',
            cleanupContext,
            () => lateMcp.session.close(cleanupContext),
            undefined,
            lateCleanupAdoption,
          ),
          await collectClose(
            'mcp-server-close',
            'mcp-server',
            cleanupContext,
            () => lateMcp.server.close(cleanupContext),
            undefined,
            lateCleanupAdoption,
          ),
        ]),
      () => {
        recordCleanupOutcome(
          failedCleanupOutcome(
            new DiagnosticPhaseError('mcp-session-close'),
            'mcp-session-close',
            true,
          ),
        );
        recordCleanupOutcome(
          failedCleanupOutcome(
            new DiagnosticPhaseError('mcp-server-close'),
            'mcp-server-close',
            true,
          ),
        );
      },
      lateCleanupAdoption,
    );
    assertExecutionActive(input.context);
    if (mcp.server.loopback !== true || mcp.server.persistent !== false) {
      throw new DiagnosticPhaseError('mcp-start');
    }

    phase = 'initialize';
    const initializeResponse = await awaitDiagnosticResponse(
      input.context,
      mcp.session.request(diagnosticRequest(initializeMessage()), input.context),
    );
    try {
      assertExecutionActive(input.context);
      sessionId = validateInitialize(initializeResponse);
    } finally {
      wipeResponseBody(initializeResponse);
    }
    assertExecutionActive(input.context);

    phase = 'initialized';
    const initializedResponse = await awaitDiagnosticResponse(
      input.context,
      mcp.session.request(diagnosticRequest(initializedMessage(), sessionId), input.context),
    );
    try {
      assertExecutionActive(input.context);
      validateInitialized(initializedResponse);
    } finally {
      wipeResponseBody(initializedResponse);
    }
    assertExecutionActive(input.context);

    phase = 'ping';
    const pingResponse = await awaitDiagnosticResponse(
      input.context,
      mcp.session.request(diagnosticRequest(pingMessage(), sessionId), input.context),
    );
    try {
      assertExecutionActive(input.context);
      validatePing(pingResponse);
    } finally {
      wipeResponseBody(pingResponse);
    }
    assertExecutionActive(input.context);
    phase = 'annotations-list';
    const annotationsListResponse = await awaitDiagnosticResponse(
      input.context,
      mcp.session.request(diagnosticRequest(annotationsListMessage(), sessionId), input.context),
    );
    try {
      assertExecutionActive(input.context);
      validateAnnotationsList(annotationsListResponse);
    } finally {
      wipeResponseBody(annotationsListResponse);
    }
    assertExecutionActive(input.context);

    phase = 'loader';
    const loaderResponse = await awaitDiagnosticResponse(
      input.context,
      host.load(CANONICAL_LOADER_PATH, input.context),
    );
    try {
      assertExecutionActive(input.context);
      validateLoader(loaderResponse);
    } finally {
      wipeResponseBody(loaderResponse);
    }
    assertExecutionActive(input.context);

    phase = 'browser-profile-start';
    browser = await awaitResourceStartup(
      input.context,
      input.browser.startProfile(input.context),
      (lateBrowser) =>
        collectClose(
          'browser-close',
          'browser-profile',
          cleanupContext,
          () => lateBrowser.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ).then((outcome) => Object.freeze([outcome])),
      () =>
        recordCleanupOutcome(
          failedCleanupOutcome(new DiagnosticPhaseError('browser-close'), 'browser-close', true),
        ),
      lateCleanupAdoption,
    );
    assertExecutionActive(input.context);
    if (browser.persistent !== false) {
      throw new DiagnosticPhaseError('browser-profile-start');
    }

    phase = 'browser-diagnostic';
    const browserResult = await awaitExecution(
      input.context,
      browser.verifyHostPage({
        context: input.context,
        host,
        loaderPath: CANONICAL_LOADER_PATH,
      }),
    );
    assertExecutionActive(input.context);
    validateBrowserResult(browserResult);
  } catch (error: unknown) {
    primary = redactedFailure(error, phase);
  } finally {
    sessionId = undefined;

    const pendingCleanup: Promise<CleanupOutcome>[] = [];
    if (browser !== undefined) {
      pendingCleanup.push(
        collectClose(
          'browser-close',
          'browser-profile',
          cleanupContext,
          () => browser!.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ),
      );
    }
    if (mcp !== undefined) {
      pendingCleanup.push(
        collectClose(
          'mcp-session-close',
          'mcp-session',
          cleanupContext,
          () => mcp!.session.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ),
      );
      pendingCleanup.push(
        collectClose(
          'mcp-server-close',
          'mcp-server',
          cleanupContext,
          () => mcp!.server.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ),
      );
    }
    if (host !== undefined) {
      pendingCleanup.push(
        collectClose(
          'host-close',
          'host',
          cleanupContext,
          () => host!.close(cleanupContext),
          input.selectedHost,
          lateCleanupAdoption,
        ),
      );
    }
    for (const outcome of await Promise.all(pendingCleanup)) {
      recordCleanupOutcome(outcome);
    }

    const finalizedCleanupOutcomes = Object.freeze([...cleanupOutcomes]);
    receipts = Object.freeze(
      finalizedCleanupOutcomes.flatMap((outcome) =>
        outcome.receipt === undefined ? [] : [outcome.receipt],
      ),
    );
    cleanupFailures = Object.freeze(
      finalizedCleanupOutcomes.flatMap((outcome) =>
        outcome.late || outcome.failure === undefined ? [] : [outcome.failure],
      ),
    );
    try {
      assertNoPersistentSecret({
        canaries: persistentSecretCanaries,
        receipts,
      });
    } catch (error: unknown) {
      lateCleanupAdoption.markNonConvergent();
      cleanupFailures = Object.freeze([
        ...cleanupFailures,
        redactedFailure(error, 'secret-receipt'),
      ]);
    } finally {
      if (
        finalizedCleanupOutcomes.some(
          (outcome) => outcome.failure !== undefined && outcome.late === false,
        )
      ) {
        lateCleanupAdoption.markNonConvergent();
      }
      cleanupConvergence = lateCleanupAdoption.seal();
    }
  }

  if (primary !== undefined || cleanupFailures.length > 0 || cleanupConvergence !== undefined) {
    const diagnosticFailures = [...(primary === undefined ? [] : [primary]), ...cleanupFailures];
    if (diagnosticFailures.length === 0) {
      diagnosticFailures.push(Object.freeze({ phase: 'deadline' as const }));
    }
    throw new LiveDiagnosticError(diagnosticFailures, cleanupConvergence);
  }

  return Object.freeze({
    host: input.selectedHost,
    initializeStatus: 200,
    initializedStatus: 202,
    annotationsListStatus: 200,
    loaderStatus: 200,
    persistent: false,
    pingStatus: 200,
  });
}

/**
 * The credential-independent smoke is intentionally separate so callers can
 * run it before generating credential candidates. Its workers-enabled profile
 * is always closed and its storage receipts are inspected.
 */
export async function runBootstrapSmoke(
  input: RunBootstrapSmokeInput,
): Promise<BootstrapSmokeResult> {
  let profile: BootstrapSmokeProfileHandle | undefined;
  let primary: RedactedDiagnosticFailure | undefined;
  let phase: DiagnosticFailurePhase = 'bootstrap-profile-start';
  let cleanupOutcomes: readonly CleanupOutcome[] = Object.freeze([]);
  let cleanupFailures: readonly RedactedDiagnosticFailure[] = Object.freeze([]);
  let receipts: readonly DiagnosticCloseReceipt[] = Object.freeze([]);
  let cleanupConvergence: Promise<void> | undefined;
  const cleanupContext = cleanupExecutionContext(input.context);
  let persistentSecretCanaries: BootstrapPersistentSecretCanaries;
  try {
    persistentSecretCanaries = validateBootstrapPersistentSecretCanaries(
      input.persistentSecretCanaries,
    );
  } catch (error: unknown) {
    throw new LiveDiagnosticError([redactedFailure(error, 'secret-receipt')]);
  }
  const lateCleanupAdoption = new LateCleanupAdoption(persistentSecretCanaries);
  const recordCleanupOutcome = (outcome: CleanupOutcome): void => {
    cleanupOutcomes = Object.freeze([...cleanupOutcomes, outcome]);
  };

  try {
    assertExecutionActive(input.context);

    phase = 'bootstrap-profile-start';
    profile = await awaitResourceStartup(
      input.context,
      input.port.startEmptyWorkersEnabledProfile(input.context),
      (lateProfile) =>
        collectClose(
          'bootstrap-profile-close',
          'bootstrap-profile',
          cleanupContext,
          () => lateProfile.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ).then((outcome) => Object.freeze([outcome])),
      () =>
        recordCleanupOutcome(
          failedCleanupOutcome(
            new DiagnosticPhaseError('bootstrap-profile-close'),
            'bootstrap-profile-close',
            true,
          ),
        ),
      lateCleanupAdoption,
    );
    assertExecutionActive(input.context);
    if (profile.empty !== true || profile.workersEnabled !== true || profile.persistent !== false) {
      throw new DiagnosticPhaseError('bootstrap-profile-start');
    }

    phase = 'bootstrap-smoke';
    await awaitExecution(input.context, profile.smoke(input.context));
    assertExecutionActive(input.context);
  } catch (error: unknown) {
    primary = redactedFailure(error, phase);
  } finally {
    if (profile !== undefined) {
      recordCleanupOutcome(
        await collectClose(
          'bootstrap-profile-close',
          'bootstrap-profile',
          cleanupContext,
          () => profile!.close(cleanupContext),
          undefined,
          lateCleanupAdoption,
        ),
      );
    }

    const finalizedCleanupOutcomes = Object.freeze([...cleanupOutcomes]);
    receipts = Object.freeze(
      finalizedCleanupOutcomes.flatMap((outcome) =>
        outcome.receipt === undefined ? [] : [outcome.receipt],
      ),
    );
    cleanupFailures = Object.freeze(
      finalizedCleanupOutcomes.flatMap((outcome) =>
        outcome.late || outcome.failure === undefined ? [] : [outcome.failure],
      ),
    );
    try {
      assertNoPersistentSecret({
        canaries: persistentSecretCanaries,
        receipts,
      });
    } catch (error: unknown) {
      lateCleanupAdoption.markNonConvergent();
      cleanupFailures = Object.freeze([
        ...cleanupFailures,
        redactedFailure(error, 'secret-receipt'),
      ]);
    } finally {
      if (
        finalizedCleanupOutcomes.some(
          (outcome) => outcome.failure !== undefined && outcome.late === false,
        )
      ) {
        lateCleanupAdoption.markNonConvergent();
      }
      cleanupConvergence = lateCleanupAdoption.seal();
    }
  }

  if (primary !== undefined || cleanupFailures.length > 0 || cleanupConvergence !== undefined) {
    const diagnosticFailures = [...(primary === undefined ? [] : [primary]), ...cleanupFailures];
    if (diagnosticFailures.length === 0) {
      diagnosticFailures.push(Object.freeze({ phase: 'deadline' as const }));
    }
    throw new LiveDiagnosticError(diagnosticFailures, cleanupConvergence);
  }

  return Object.freeze({ persistent: false, workersEnabled: true });
}

/**
 * Rejects retained secret evidence and browser persistence. The only excluded
 * text is the body of an explicitly transient, canonical loader response with
 * a no-store cache directive; its path and cache-control fields are still
 * inspected.
 */
export function assertNoPersistentSecret(input: AssertNoPersistentSecretInput): void {
  const inputRecord = receiptDataRecord(input);
  if (!hasOnlyKeys(inputRecord, ['canaries', 'receipts'])) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const receipts = snapshotDiagnosticCloseReceiptList(inputRecord.receipts);
  if (receipts.length > MAX_DIAGNOSTIC_CLOSE_RECEIPTS) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const { canaries, tokenMatcher } = collectCanaries(inputRecord.canaries, false);

  for (const receipt of receipts) {
    assertReceiptBounds(receipt);
    assertBrowserState(receipt);

    for (const record of receipt.records) {
      switch (record.kind) {
        case 'log':
        case 'header':
          assertNoCanary(record.text, canaries, tokenMatcher);
          break;
        case 'http-response':
          assertNoCanary(record.path, canaries, tokenMatcher);
          assertNoCanary(record.cacheControl, canaries, tokenMatcher);
          if (!isExcludedTransientLoaderResponse(record)) {
            assertNoCanary(record.body, canaries, tokenMatcher);
          }
          break;
        case 'runtime-cleanup':
          break;
      }
    }
  }
}

function initializeMessage(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: INITIALIZE_ID,
    jsonrpc: '2.0',
    method: 'initialize',
    params: Object.freeze({
      capabilities: Object.freeze({}),
      clientInfo: Object.freeze({ name: 'scene-glass-onboarding', version: '0.1.0' }),
      protocolVersion: LIVE_DIAGNOSTIC_PROTOCOL_VERSION,
    }),
  });
}

function initializedMessage(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    jsonrpc: '2.0',
    method: 'notifications/initialized',
    params: Object.freeze({}),
  });
}

function pingMessage(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: PING_ID,
    jsonrpc: '2.0',
    method: 'ping',
    params: Object.freeze({}),
  });
}

function annotationsListMessage(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: ANNOTATIONS_LIST_ID,
    jsonrpc: '2.0',
    method: 'tools/call',
    params: Object.freeze({ name: 'annotations.list', arguments: Object.freeze({}) }),
  });
}

function diagnosticRequest(
  body: Readonly<Record<string, unknown>>,
  sessionId: string | undefined = undefined,
): DiagnosticJsonRpcRequest {
  let encoded: Uint8Array | undefined;
  try {
    encoded = encoder.encode(JSON.stringify(body));
    if (encoded.byteLength > MAX_DIAGNOSTIC_REQUEST_BYTES) {
      throw new DiagnosticPhaseError('initialize');
    }
  } catch (error: unknown) {
    if (error instanceof DiagnosticPhaseError) {
      throw error;
    }
    throw new DiagnosticPhaseError('initialize');
  } finally {
    encoded?.fill(0);
  }

  return Object.freeze({
    body,
    headers: Object.freeze({
      'mcp-protocol-version': LIVE_DIAGNOSTIC_PROTOCOL_VERSION,
      ...(sessionId === undefined ? {} : { 'mcp-session-id': sessionId }),
    }),
  });
}

function validateInitialize(response: DiagnosticHttpResponse): string {
  try {
    const status = validateResponse(response, 'initialize', 200);
    const body = parseJsonBody(response.body, 'initialize', status);
    if (
      !isRecord(body) ||
      body.id !== INITIALIZE_ID ||
      body.jsonrpc !== '2.0' ||
      !isRecord(body.result) ||
      body.result.protocolVersion !== LIVE_DIAGNOSTIC_PROTOCOL_VERSION
    ) {
      throw new DiagnosticPhaseError('initialize', status);
    }
    const sessionId = responseHeader(response.headers, 'mcp-session-id', 'initialize', status);
    if (sessionId === undefined || !isOpaqueSessionId(sessionId)) {
      throw new DiagnosticPhaseError('initialize', status);
    }
    return sessionId;
  } finally {
    wipeResponseBody(response);
  }
}

function validateInitialized(response: DiagnosticHttpResponse): void {
  try {
    const status = validateResponse(response, 'initialized', 202);
    if (
      response.body.byteLength !== 0 ||
      responseHeader(response.headers, 'mcp-session-id', 'initialized', status) !== undefined
    ) {
      throw new DiagnosticPhaseError('initialized', status);
    }
  } finally {
    wipeResponseBody(response);
  }
}

function validatePing(response: DiagnosticHttpResponse): void {
  try {
    const status = validateResponse(response, 'ping', 200);
    const body = parseJsonBody(response.body, 'ping', status);
    if (
      !isRecord(body) ||
      body.id !== PING_ID ||
      body.jsonrpc !== '2.0' ||
      !isRecord(body.result) ||
      Object.keys(body.result).length !== 0 ||
      responseHeader(response.headers, 'mcp-session-id', 'ping', status) !== undefined
    ) {
      throw new DiagnosticPhaseError('ping', status);
    }
  } finally {
    wipeResponseBody(response);
  }
}

function validateAnnotationsList(response: DiagnosticHttpResponse): void {
  try {
    const status = validateResponse(response, 'annotations-list', 200);
    const body = parseJsonBody(response.body, 'annotations-list', status);
    if (
      !isRecord(body) ||
      body.id !== ANNOTATIONS_LIST_ID ||
      body.jsonrpc !== '2.0' ||
      (!Object.hasOwn(body, 'result') && !Object.hasOwn(body, 'error')) ||
      responseHeader(response.headers, 'mcp-session-id', 'annotations-list', status) !== undefined
    ) {
      throw new DiagnosticPhaseError('annotations-list', status);
    }
  } finally {
    wipeResponseBody(response);
  }
}

function validateLoader(response: DiagnosticHttpResponse): void {
  try {
    const status = validateResponse(response, 'loader', 200);
    if (
      response.body.byteLength === 0 ||
      !hasNoStore(responseHeader(response.headers, 'cache-control', 'loader', status))
    ) {
      throw new DiagnosticPhaseError('loader', status);
    }
  } finally {
    wipeResponseBody(response);
  }
}

function validateResponse(
  response: DiagnosticHttpResponse,
  phase: 'annotations-list' | 'initialize' | 'initialized' | 'loader' | 'ping',
  expectedStatus: 200 | 202,
): number {
  if (!isRecord(response) || !validStatus(response.status) || !validHeaders(response.headers)) {
    throw new DiagnosticPhaseError(phase);
  }
  if (
    !(response.body instanceof Uint8Array) ||
    response.body.byteLength > MAX_DIAGNOSTIC_RESPONSE_BYTES
  ) {
    throw new DiagnosticPhaseError(phase, response.status);
  }
  if (response.status !== expectedStatus) {
    throw new DiagnosticPhaseError(phase, response.status);
  }
  return response.status;
}

function parseJsonBody(
  body: Uint8Array,
  phase: 'annotations-list' | 'initialize' | 'ping',
  status: number,
): unknown {
  try {
    return JSON.parse(decoder.decode(body));
  } catch {
    throw new DiagnosticPhaseError(phase, status);
  }
}
function wipeResponseBody(response: unknown): void {
  if (isRecord(response) && response.body instanceof Uint8Array) {
    response.body.fill(0);
  }
}

function validateBrowserResult(result: BrowserDiagnosticResult): void {
  if (
    !isRecord(result) ||
    result.loaderReady !== true ||
    result.panelReady !== true ||
    !Array.isArray(result.logs)
  ) {
    throw new DiagnosticPhaseError('browser-diagnostic');
  }
  if (result.logs.length > MAX_DIAGNOSTIC_LOG_ENTRIES) {
    throw new DiagnosticPhaseError('browser-diagnostic');
  }
  for (const entry of result.logs) {
    if (typeof entry !== 'string' || byteLength(entry) > MAX_DIAGNOSTIC_LOG_BYTES) {
      throw new DiagnosticPhaseError('browser-diagnostic');
    }
  }
}

async function collectClose(
  phase: Extract<DiagnosticFailurePhase, `${string}-close`>,
  expectedReceiptPhase: DiagnosticCloseReceiptPhase,
  context: DiagnosticExecutionContext,
  close: () => Promise<DiagnosticCloseReceipt>,
  selectedHost: SelectedHostKind | undefined = undefined,
  lateCleanupAdoption: LateCleanupAdoption | undefined = undefined,
): Promise<CleanupOutcome> {
  const completion = Promise.resolve()
    .then(close)
    .then((rawReceipt) => {
      const receipt = snapshotDiagnosticCloseReceipt(rawReceipt);
      if (
        receipt.phase !== expectedReceiptPhase ||
        (expectedReceiptPhase === 'host' && !hasSelectedHostCleanupReceipt(receipt, selectedHost))
      ) {
        throw new DiagnosticPhaseError(phase);
      }
      return receipt;
    });
  const outcome = completion.then(
    (receipt) => Object.freeze({ late: false, receipt }),
    (error: unknown) => failedCleanupOutcome(error, phase, false),
  );
  void outcome.catch(() => undefined);

  try {
    return await awaitExecution(context, outcome);
  } catch {
    lateCleanupAdoption?.adoptLateOutcome(outcome);
    return failedCleanupOutcome(new DiagnosticPhaseError(phase), phase, true);
  }
}

function failedCleanupOutcome(
  error: unknown,
  phase: Extract<DiagnosticFailurePhase, `${string}-close`>,
  late: boolean,
): CleanupOutcome {
  return Object.freeze({ failure: redactedFailure(error, phase), late });
}

async function awaitResourceStartup<T>(
  context: DiagnosticExecutionContext,
  startup: Promise<T>,
  discard: (resource: T) => Promise<CleanupOutcomeSet>,
  poisonLateResource: () => void,
  lateCleanupAdoption: LateCleanupAdoption,
  discardStartupFailure:
    ((error: unknown) => Promise<CleanupOutcomeSet> | undefined) | undefined = undefined,
): Promise<T> {
  try {
    return await awaitExecution(context, startup);
  } catch (primaryError: unknown) {
    const cleanup = startup.then(
      (resource) => discard(resource),
      (error: unknown) => discardStartupFailure?.(error) ?? Object.freeze([]),
    );
    void cleanup.catch(() => undefined);
    lateCleanupAdoption.adoptPendingCleanup(cleanup);
    if (primaryError instanceof DiagnosticControlError) {
      poisonLateResource();
    }
    throw primaryError;
  }
}

async function awaitDiagnosticResponse(
  context: DiagnosticExecutionContext,
  operation: Promise<DiagnosticHttpResponse>,
): Promise<DiagnosticHttpResponse> {
  return await awaitExecution(context, operation, wipeResponseBody);
}

async function awaitExecution<T>(
  context: DiagnosticExecutionContext,
  operation: Promise<T>,
  adoptLateFulfillment: ((value: T) => void) | undefined = undefined,
): Promise<T> {
  let completed = false;
  const observed = operation.then(
    (value) => {
      if (completed) {
        try {
          adoptLateFulfillment?.(value);
        } catch {
          // Late cleanup must not create an unhandled rejection.
        }
      }
      return value;
    },
    (error: unknown) => {
      throw error;
    },
  );
  void observed.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  try {
    assertExecutionActive(context);
    const interrupted = new Promise<never>((_resolve, reject) => {
      const interrupt = (): void => {
        reject(new DiagnosticControlError(Date.now() >= context.deadline ? 'deadline' : 'aborted'));
      };
      context.signal.addEventListener('abort', interrupt, { once: true });
      removeAbortListener = () => context.signal.removeEventListener('abort', interrupt);
      timer = setTimeout(interrupt, Math.max(0, context.deadline - Date.now()));
    });
    return await Promise.race([observed, interrupted]);
  } finally {
    completed = true;
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    removeAbortListener?.();
  }
}

function cleanupExecutionContext(context: DiagnosticExecutionContext): DiagnosticExecutionContext {
  return Object.freeze({
    deadline: context.deadline,
    signal: new AbortController().signal,
  });
}

function hasSelectedHostCleanupReceipt(
  receipt: DiagnosticCloseReceipt,
  selectedHost: SelectedHostKind | undefined,
): boolean {
  if (selectedHost === undefined || receipt.phase !== 'host' || receipt.records.length !== 1) {
    return false;
  }
  const [record] = receipt.records;
  return record?.kind === 'runtime-cleanup' && record.runtime === selectedHost;
}

function assertExecutionActive(context: DiagnosticExecutionContext): void {
  if (
    !isRecord(context) ||
    !isAbortSignal(context.signal) ||
    !Number.isSafeInteger(context.deadline)
  ) {
    throw new DiagnosticControlError('deadline');
  }
  if (Date.now() >= context.deadline) {
    throw new DiagnosticControlError('deadline');
  }
  if (context.signal.aborted) {
    throw new DiagnosticControlError('aborted');
  }
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return (
    isRecord(value) &&
    typeof value.aborted === 'boolean' &&
    typeof value.addEventListener === 'function'
  );
}

function redactedFailure(
  error: unknown,
  fallback: DiagnosticFailurePhase,
): RedactedDiagnosticFailure {
  if (error instanceof DiagnosticControlError) {
    return Object.freeze({ phase: error.phase });
  }
  if (error instanceof DiagnosticPhaseError) {
    return Object.freeze(
      error.status === undefined
        ? { phase: error.phase }
        : { phase: error.phase, status: error.status },
    );
  }
  const status = statusFromError(error);
  return Object.freeze(status === undefined ? { phase: fallback } : { phase: fallback, status });
}
function statusFromError(error: unknown): number | undefined {
  try {
    return isRecord(error) && validStatus(error.status) ? error.status : undefined;
  } catch {
    return undefined;
  }
}

function responseHeader(
  headers: Readonly<Record<string, string | undefined>>,
  name: string,
  phase: 'annotations-list' | 'initialize' | 'initialized' | 'loader' | 'ping',
  status: number,
): string | undefined {
  let matched: string | undefined;
  let count = 0;
  for (const key in headers) {
    if (!Object.prototype.propertyIsEnumerable.call(headers, key)) {
      continue;
    }
    count += 1;
    if (count > MAX_DIAGNOSTIC_HEADERS) {
      throw new DiagnosticPhaseError(phase, status);
    }
    const value = headers[key];
    if (key.toLowerCase() !== name) {
      continue;
    }
    if (typeof value !== 'string' || matched !== undefined) {
      throw new DiagnosticPhaseError(phase, status);
    }
    matched = value;
  }
  return matched;
}

function validHeaders(value: unknown): value is Readonly<Record<string, string | undefined>> {
  if (!isRecord(value)) {
    return false;
  }
  let count = 0;
  for (const key in value) {
    if (!Object.prototype.propertyIsEnumerable.call(value, key)) {
      continue;
    }
    count += 1;
    if (count > MAX_DIAGNOSTIC_HEADERS || !isBoundedDiagnosticHeader(key)) {
      return false;
    }
    const header = value[key];
    if (
      header !== undefined &&
      (typeof header !== 'string' || !isBoundedDiagnosticHeader(header))
    ) {
      return false;
    }
  }
  return true;
}
function isBoundedDiagnosticHeader(value: string): boolean {
  let bytes = 0;
  for (let index = 0; index < value.length;) {
    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      return false;
    }
    bytes += codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
    if (bytes > MAX_DIAGNOSTIC_HEADER_BYTES) {
      return false;
    }
    index += codePoint > 0xffff ? 2 : 1;
  }
  return true;
}

function validStatus(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 100 && value <= 599;
}

function isOpaqueSessionId(value: string): boolean {
  return (
    value.length > 0 && value.length <= MAX_SESSION_ID_BYTES && /^[A-Za-z0-9_-]+$/u.test(value)
  );
}

function hasNoStore(value: string | undefined): boolean {
  return (
    value !== undefined &&
    value.split(',').some((directive) => directive.trim().toLowerCase() === 'no-store')
  );
}

function validateLivePersistentSecretCanaries(value: unknown): PersistentSecretCanaries {
  const canaries = collectCanaries(value, true);
  if (canaries.tokenMatcher === undefined || canaries.canaries.length === 0) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  return Object.freeze({
    pathCanaries: canaries.canaries,
    tokenMatcher: canaries.tokenMatcher,
  });
}
function validateBootstrapPersistentSecretCanaries(
  value: unknown,
): BootstrapPersistentSecretCanaries {
  const canaries = collectCanaries(value, false);
  if (canaries.tokenMatcher === undefined) {
    if (canaries.canaries.length !== 0) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    return Object.freeze({ pathCanaries: Object.freeze([]) }) as EmptyPersistentSecretCanaries;
  }
  return Object.freeze({
    pathCanaries: canaries.canaries,
    tokenMatcher: canaries.tokenMatcher,
  });
}
function collectCanaries(
  value: unknown,
  requireMatcher: boolean,
): Readonly<{
  readonly canaries: readonly string[];
  readonly tokenMatcher: PersistentSecretCanaries['tokenMatcher'] | undefined;
}> {
  const bundle = receiptDataRecord(value);
  const hasMatcher = Object.hasOwn(bundle, 'tokenMatcher');
  if (!hasOnlyKeys(bundle, hasMatcher ? ['pathCanaries', 'tokenMatcher'] : ['pathCanaries'])) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const canaries = snapshotCanaryPaths(bundle.pathCanaries);
  if (canaries.length > MAX_DIAGNOSTIC_CANARIES || (requireMatcher && !hasMatcher)) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  let totalBytes = 0;
  for (const canary of canaries) {
    if (
      typeof canary !== 'string' ||
      canary.length === 0 ||
      byteLength(canary) > MAX_DIAGNOSTIC_RECEIPT_TEXT_BYTES
    ) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    totalBytes += byteLength(canary);
    if (totalBytes > MAX_DIAGNOSTIC_RECEIPT_TEXT_BYTES) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
  }
  let tokenMatcher: PersistentSecretCanaries['tokenMatcher'] | undefined;
  if (hasMatcher) {
    const matcher = receiptDataRecord(bundle.tokenMatcher);
    if (typeof matcher.matches !== 'function') {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    const matches = matcher.matches as (value: Uint8Array) => boolean;
    const receiver = bundle.tokenMatcher;
    tokenMatcher = Object.freeze({
      matches: (value: Uint8Array): boolean => Reflect.apply(matches, receiver, [value]) as boolean,
    });
  }
  return Object.freeze({
    canaries: Object.freeze(canaries),
    tokenMatcher,
  });
}
export function snapshotDiagnosticCloseReceipt(value: unknown): DiagnosticCloseReceipt {
  if (value !== null && typeof value === 'object' && diagnosticReceiptSnapshots.has(value)) {
    return value as DiagnosticCloseReceipt;
  }
  const receipt = snapshotReceiptData(value, new WeakSet<object>(), 0);
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  diagnosticReceiptSnapshots.add(receipt);
  return receipt as DiagnosticCloseReceipt;
}
function snapshotDiagnosticCloseReceiptList(value: unknown): readonly DiagnosticCloseReceipt[] {
  const receipts = receiptDataArray(value);
  const snapshots: DiagnosticCloseReceipt[] = [];
  for (const receipt of receipts) {
    snapshots.push(snapshotDiagnosticCloseReceipt(receipt));
  }
  return Object.freeze(snapshots);
}
function snapshotCanaryPaths(value: unknown): readonly string[] {
  const paths = snapshotReceiptData(value, new WeakSet<object>(), 0);
  if (!Array.isArray(paths) || !paths.every((path) => typeof path === 'string')) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  return Object.freeze([...paths]);
}
function receiptDataArray(value: unknown): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    lengthDescriptor === undefined ||
    !Object.hasOwn(lengthDescriptor, 'value') ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > MAX_DIAGNOSTIC_RECEIPT_RECORDS ||
    Reflect.ownKeys(value).length !== lengthDescriptor.value + 1
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const output: unknown[] = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}
function receiptDataRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const prototype = Object.getPrototypeOf(value);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).length > MAX_DIAGNOSTIC_RECEIPT_SNAPSHOT_FIELDS) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const output: Record<string, unknown> = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    Object.defineProperty(output, key, {
      configurable: false,
      enumerable: true,
      value: descriptor.value,
      writable: false,
    });
  }
  return Object.freeze(output);
}
function snapshotReceiptData(value: unknown, ancestors: WeakSet<object>, depth: number): unknown {
  if (typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    depth > MAX_DIAGNOSTIC_RECEIPT_SNAPSHOT_DEPTH
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  if (ancestors.has(value)) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return Object.freeze(
        receiptDataArray(value).map((entry) => snapshotReceiptData(entry, ancestors, depth + 1)),
      );
    }
    const record = receiptDataRecord(value);
    const descriptors = Object.getOwnPropertyDescriptors(record);
    const output: Record<string, unknown> = Object.create(null);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!Object.hasOwn(descriptor, 'value')) {
        throw new DiagnosticPhaseError('secret-receipt');
      }
      Object.defineProperty(output, key, {
        configurable: false,
        enumerable: true,
        value: snapshotReceiptData(descriptor.value, ancestors, depth + 1),
        writable: false,
      });
    }
    return Object.freeze(output);
  } finally {
    ancestors.delete(value);
  }
}

function assertReceiptBounds(receipt: DiagnosticCloseReceipt): void {
  if (
    !isRecord(receipt) ||
    !hasOnlyKeys(
      receipt,
      receipt.browserState === undefined
        ? ['phase', 'records']
        : ['browserState', 'phase', 'records'],
    ) ||
    !isCloseReceiptPhase(receipt.phase) ||
    !Array.isArray(receipt.records)
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  if (receipt.records.length > MAX_DIAGNOSTIC_RECEIPT_RECORDS) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  let totalBytes = 0;
  for (const record of receipt.records) {
    if (!isRecord(record)) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    if (
      (record.kind === 'log' || record.kind === 'header') &&
      hasOnlyKeys(record, ['kind', 'text']) &&
      isBoundedText(record.text)
    ) {
      totalBytes += byteLength(record.text);
    } else if (
      record.kind === 'http-response' &&
      hasOnlyKeys(record, ['body', 'cacheControl', 'kind', 'path', 'transient']) &&
      typeof record.path === 'string' &&
      typeof record.cacheControl === 'string' &&
      typeof record.body === 'string' &&
      typeof record.transient === 'boolean' &&
      isBoundedText(record.path) &&
      isBoundedText(record.cacheControl) &&
      isBoundedText(record.body)
    ) {
      totalBytes +=
        byteLength(record.path) + byteLength(record.cacheControl) + byteLength(record.body);
    } else if (record.kind === 'runtime-cleanup' && validRuntimeCleanupRecord(record)) {
      continue;
    } else {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    if (totalBytes > MAX_DIAGNOSTIC_RECEIPT_TEXT_BYTES) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
  }
}

function assertBrowserState(receipt: DiagnosticCloseReceipt): void {
  if (receipt.phase !== 'browser-profile' && receipt.phase !== 'bootstrap-profile') {
    if (receipt.browserState !== undefined) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    return;
  }
  const state = receipt.browserState;
  if (
    !isRecord(state) ||
    !hasOnlyKeys(state, [
      'cacheStorageNames',
      'indexedDbNames',
      'localStorageKeys',
      'serviceWorkerRegistrations',
      'sessionStorageKeys',
    ])
  ) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  const collections = [
    state.localStorageKeys,
    state.sessionStorageKeys,
    state.indexedDbNames,
    state.cacheStorageNames,
    state.serviceWorkerRegistrations,
  ];
  for (const collection of collections) {
    if (!Array.isArray(collection) || collection.length !== 0) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
  }
}

function isExcludedTransientLoaderResponse(record: DiagnosticHttpReceiptRecord): boolean {
  return (
    record.transient === true &&
    record.path === CANONICAL_LOADER_PATH &&
    hasNoStore(record.cacheControl)
  );
}

function assertNoCanary(
  value: string,
  canaries: readonly string[],
  tokenMatcher: PersistentSecretCanaries['tokenMatcher'] | undefined,
): void {
  if (canaries.some((canary) => value.includes(canary))) {
    throw new DiagnosticPhaseError('secret-receipt');
  }
  if (tokenMatcher === undefined) {
    return;
  }

  let bytes: Uint8Array | undefined;
  try {
    bytes = encoder.encode(value);
    const matched = tokenMatcher.matches(bytes);
    if (matched !== true && matched !== false) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
    if (matched) {
      throw new DiagnosticPhaseError('secret-receipt');
    }
  } catch (error: unknown) {
    if (error instanceof DiagnosticPhaseError) {
      throw error;
    }
    throw new DiagnosticPhaseError('secret-receipt');
  } finally {
    bytes?.fill(0);
  }
}
function validRuntimeCleanupRecord(record: Record<string, unknown>): boolean {
  if (
    record.runtime === 'static' &&
    hasOnlyKeys(record, [
      'credentialCapabilityRevoked',
      'kind',
      'listenerClosed',
      'runtime',
      'tokenWiped',
    ])
  ) {
    return (
      record.kind === 'runtime-cleanup' &&
      record.listenerClosed === true &&
      record.credentialCapabilityRevoked === true &&
      record.tokenWiped === true
    );
  }
  if (
    record.runtime === 'managed-vite' &&
    hasOnlyKeys(record, [
      'cacheAuthorityClosed',
      'cacheWriterClosed',
      'credentialCapabilityRevoked',
      'kind',
      'processLeaseReleased',
      'runtime',
      'serverClosed',
      'signalListenersRemoved',
      'umaskRestored',
    ])
  ) {
    return (
      record.kind === 'runtime-cleanup' &&
      record.serverClosed === true &&
      record.cacheAuthorityClosed === true &&
      record.cacheWriterClosed === true &&
      record.credentialCapabilityRevoked === true &&
      record.signalListenersRemoved === true &&
      record.umaskRestored === true &&
      record.processLeaseReleased === true
    );
  }
  return false;
}

function hasOnlyKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isBoundedText(value: unknown): value is string {
  return typeof value === 'string' && byteLength(value) <= MAX_DIAGNOSTIC_RECEIPT_TEXT_BYTES;
}

function isCloseReceiptPhase(value: unknown): value is DiagnosticCloseReceiptPhase {
  return (
    value === 'browser-profile' ||
    value === 'bootstrap-profile' ||
    value === 'host' ||
    value === 'mcp-server' ||
    value === 'mcp-session'
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function byteLength(value: string): number {
  return encoder.encode(value).byteLength;
}

function formatFailures(failures: readonly RedactedDiagnosticFailure[]): string {
  const encoded = failures.map((failure) =>
    failure.status === undefined ? failure.phase : `${failure.phase}/${failure.status}`,
  );
  return `live diagnostics failed: ${encoded.join(', ')}`;
}
