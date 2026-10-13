import {
  VITE_CACHE_LIMITS,
  assertSafeViteCacheTree,
  assertViteCacheLimits,
  snapshotViteCacheSession,
  type CacheNativeSession,
  type CacheRuntimeFilesystemPort,
  type CacheTreeEntry,
  type CacheTreeScan,
  type CacheTreeWatcher,
  type ViteCacheLimits,
  type ViteCacheProvenance,
  type ViteCacheSession,
} from './cache.js';

export const VITE_CACHE_DEFAULT_POLL_INTERVAL_MS = 1_000;
export const VITE_CACHE_MAX_POLL_INTERVAL_MS = 5_000;
/** Bounds caller-controlled hash configuration before any collection allocation. */
export const VITE_CACHE_MAX_CANARY_HASHES = 1_000;

export type ViteCacheMonitorTrigger =
  'creation' | 'event' | 'poll' | 'shutdown' | 'failure' | 'recovery';
type ViteCacheBackgroundTrigger = Extract<ViteCacheMonitorTrigger, 'creation' | 'event' | 'poll'>;

interface PendingViteCacheMonitorScan {
  trigger: ViteCacheMonitorTrigger;
  background: boolean;
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (reason: unknown) => void;
}
interface ViteCacheWriterQuiescence {
  readonly quiesced: boolean;
  readonly failures: readonly ViteCacheCleanupOperation[];
}
interface ViteCacheAuthorityReleaseInspection {
  readonly tree: 'safe' | 'unsafe' | 'untrusted';
  readonly canary: 'clear' | 'detected' | 'untrusted';
}

/** A digest-only sample. Cache monitor APIs never accept token text. */
export interface CacheCanaryDigest {
  readonly algorithm: 'sha256';
  readonly digest: string;
}

/**
 * Canonical digest-only configuration consumed by the native scanner. Raw
 * tokens and JavaScript matcher callbacks never cross this boundary.
 */
export interface CacheCanaryConfiguration {
  readonly tokenHashes: readonly string[];
}

export interface CacheCanaryScanResult {
  readonly detected: boolean;
}

/**
 * A native, FD-bound content scanner. It must stream bytes through a hash,
 * perform no-follow traversal through the supplied live root capability, and
 * return only a boolean. Neither results nor monitor provenance may contain
 * token text.
 */
export interface CacheCanaryScannerPort {
  scanCacheCanaries(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly trigger: ViteCacheMonitorTrigger;
    readonly limits: ViteCacheLimits;
    readonly tokenHashes: readonly string[];
  }): Promise<CacheCanaryScanResult>;
}

export interface ViteCacheWriterControl {
  /** Synchronously latches failure before asynchronous containment begins. */
  abort(reason: ViteCacheMonitorReason): void;
  /** Resolves only after Vite can no longer issue cache writes. */
  terminate(reason: ViteCacheMonitorReason): Promise<void>;
}

export interface ViteCacheRecoveryPort {
  markCompensationRequired(input: {
    readonly provenance: ViteCacheProvenance;
    readonly trigger: ViteCacheMonitorTrigger;
    readonly reason: ViteCacheMonitorReason;
  }): Promise<void> | void;
}

export interface ViteCacheMonitorScheduler {
  setInterval(task: () => void, delayMs: number): unknown;
  clearInterval(handle: unknown): void;
}

export type ViteCacheMonitorReason = 'unsafe-tree' | 'token-canary-detected' | 'inspection-failed';

export type ViteCacheCleanupOperation =
  | 'abort-writer'
  | 'terminate-writer'
  | 'mark-compensation-required'
  | 'clear-poll-timer'
  | 'close-tree-watcher'
  | 'close-native-session';

export type ViteCacheMonitorState = 'new' | 'running' | 'violated' | 'stopped';

export class ViteCacheMonitorError extends Error {
  public readonly code = 'SCG_VITE_CACHE_MONITOR_VIOLATION';
  public readonly reason: ViteCacheMonitorReason;
  /** Generic operation names only; never paths, tokens, or native errors. */
  public readonly cleanupFailures: readonly ViteCacheCleanupOperation[];
  /** Whether durable compensation intent was recorded before this violation surfaced. */
  public readonly compensationRequired: boolean;
  /** Whether native-session closure completed; false retains native release authority. */
  public readonly nativeSessionReleased: boolean;

  public constructor(
    reason: ViteCacheMonitorReason,
    cleanupFailures: readonly ViteCacheCleanupOperation[] = [],
    compensationRequired = false,
    nativeSessionReleased = false,
  ) {
    super(`Vite cache monitor halted the managed writer: ${reason}`);
    this.name = 'ViteCacheMonitorError';
    this.reason = reason;
    this.cleanupFailures = Object.freeze([...cleanupFailures]);
    this.compensationRequired = compensationRequired;
    this.nativeSessionReleased = nativeSessionReleased;
  }
}

export interface ViteCacheMonitorOptions {
  readonly filesystem: CacheRuntimeFilesystemPort;
  readonly scanner: CacheCanaryScannerPort;
  readonly writer: ViteCacheWriterControl;
  readonly recovery: ViteCacheRecoveryPort;
  readonly session: ViteCacheSession;
  readonly canary: CacheCanaryConfiguration;
  readonly limits?: ViteCacheLimits;
  readonly pollIntervalMs?: number;
  readonly scheduler?: ViteCacheMonitorScheduler;
  /** Receives only generic reason codes and cleanup operation names. */
  readonly onBackgroundError?: (error: ViteCacheMonitorError) => void;
}

/**
 * Continuous active-process enforcement for the setup-owned cache. The native
 * filesystem port owns the root FD; this class retains its capability with the
 * watcher and timer. Standalone monitors close all three after writer
 * quiescence, while managed leases retain native-session closure authority.
 */
export class ViteCacheMonitor {
  readonly #filesystem: CacheRuntimeFilesystemPort;
  readonly #scanner: CacheCanaryScannerPort;
  readonly #writer: ViteCacheWriterControl;
  readonly #recovery: ViteCacheRecoveryPort;
  readonly #nativeSession: CacheNativeSession;
  readonly #provenance: ViteCacheProvenance;
  readonly #tokenHashes: readonly string[];
  readonly #limits: ViteCacheLimits;
  readonly #pollIntervalMs: number;
  readonly #scheduler: ViteCacheMonitorScheduler;
  readonly #onBackgroundError: ((error: ViteCacheMonitorError) => void) | undefined;
  #state: ViteCacheMonitorState = 'new';
  #watcher: CacheTreeWatcher | undefined;
  #watcherSetupCompletion: Promise<void> | undefined;
  #timer: unknown;
  #timerInstalled = false;
  #scanInFlight: Promise<void> | undefined;
  #pendingScan: PendingViteCacheMonitorScan | undefined;
  #terminalCleanup: Promise<readonly ViteCacheCleanupOperation[]> | undefined;
  #terminalInfrastructureDeferred = false;
  #infrastructureCleanup: Promise<readonly ViteCacheCleanupOperation[]> | undefined;
  #terminalTrigger: ViteCacheMonitorTrigger | undefined;
  #terminalReason: ViteCacheMonitorReason | undefined;
  #stopPromise: Promise<void> | undefined;
  #stopRequested = false;
  #startupCompletion: Promise<void> | undefined;
  #starting = false;
  #startupTrigger: ViteCacheBackgroundTrigger | undefined;
  #watcherFailureObserved = false;
  #compensationRequired = false;
  #compensationRecording: Promise<readonly ViteCacheCleanupOperation[]> | undefined;
  #terminalNotification: Promise<void> | undefined;
  #writerQuiesced = false;
  #nativeSessionClosed = false;
  #standaloneReleaseInspectionBlocked = false;
  #writerQuiescence: Promise<ViteCacheWriterQuiescence> | undefined;
  #synchronousWriterStopBarrierComplete = false;

  public constructor(options: ViteCacheMonitorOptions) {
    const session = snapshotViteCacheSession(options.session);
    assertViteCacheWriterControl(options.writer);
    this.#filesystem = options.filesystem;
    this.#scanner = options.scanner;
    this.#writer = options.writer;
    this.#recovery = options.recovery;
    this.#nativeSession = session.nativeSession;
    this.#provenance = session.provenance;
    this.#tokenHashes = normalizeTokenHashes(options.canary.tokenHashes);
    this.#limits = Object.freeze({ ...(options.limits ?? VITE_CACHE_LIMITS) });
    assertViteCacheLimits(this.#limits);
    this.#pollIntervalMs = options.pollIntervalMs ?? VITE_CACHE_DEFAULT_POLL_INTERVAL_MS;
    assertPollInterval(this.#pollIntervalMs);
    this.#scheduler = options.scheduler ?? globalScheduler;
    this.#onBackgroundError = options.onBackgroundError;
  }

  public get state(): ViteCacheMonitorState {
    return this.#state;
  }

  /** Installs the event trigger before checking creation, so no write window is missed. */
  public async start(): Promise<void> {
    if (this.#state !== 'new') {
      throw new Error('Vite cache monitor can only be started once');
    }
    this.#state = 'running';
    this.#starting = true;
    const startupCompletion = createCompletion();
    this.#startupCompletion = startupCompletion.promise;
    try {
      const watcherSetup = createCompletion();
      this.#watcherSetupCompletion = watcherSetup.promise;
      let watcher: CacheTreeWatcher | undefined;
      try {
        const installedWatcher = await this.#filesystem.watchCacheTree({
          session: this.#nativeSession,
          provenance: this.#provenance,
          onEvent: (event) => {
            this.#handleTrigger(event === 'created' ? 'creation' : 'event');
          },
          onFailure: () => {
            this.#handleWatcherFailure();
          },
        });
        watcher = installedWatcher;
        this.#watcher = installedWatcher;
      } finally {
        if (this.#watcherSetupCompletion === watcherSetup.promise) {
          this.#watcherSetupCompletion = undefined;
        }
        watcherSetup.resolve();
      }
      if (watcher === undefined) {
        throw new Error('Vite cache watcher setup failed');
      }
      if (this.#state !== 'running' || this.#stopRequested || this.#watcherFailureObserved) {
        const terminalCleanup = this.#beginTerminalCleanup(
          'failure',
          this.#terminalReason ?? 'inspection-failed',
        );
        const terminalFailures = await terminalCleanup;
        const cleanupFailures =
          this.#watcher === watcher && this.#writerQuiesced
            ? await this.#disposeInfrastructure()
            : Object.freeze([]);
        throw this.#monitorError(this.#terminalReason ?? 'inspection-failed', [
          ...terminalFailures,
          ...cleanupFailures,
        ]);
      }
      const timer = this.#scheduler.setInterval(() => {
        this.#handleTrigger('poll');
      }, this.#pollIntervalMs);
      this.#timer = timer;
      this.#timerInstalled = true;
      await this.#requestScan('creation');
      if (this.#state !== 'running' || this.#stopRequested) {
        const cleanupFailures = await this.#beginTerminalCleanup(
          'failure',
          this.#terminalReason ?? 'inspection-failed',
        );
        throw this.#monitorError(this.#terminalReason ?? 'inspection-failed', cleanupFailures);
      }
      const startupTrigger = this.#startupTrigger;
      this.#startupTrigger = undefined;
      this.#starting = false;
      if (startupTrigger !== undefined) {
        await this.#requestScan(startupTrigger);
      }
    } catch (error: unknown) {
      this.#starting = false;
      const terminalCleanup = this.#beginTerminalCleanup('creation', 'inspection-failed');
      const terminalFailures = await terminalCleanup;
      const cleanupFailures = await this.#completeTerminalInfrastructure(terminalCleanup, false);
      throw withCleanupFailures(error, [...terminalFailures, ...cleanupFailures]);
    } finally {
      this.#startupCompletion = undefined;
      startupCompletion.resolve();
    }
  }

  /** Quiesces the writer before suppressing events and performing the final scan. */
  public stop(): Promise<void> {
    if (this.#state === 'new') {
      return Promise.resolve();
    }
    const existing = this.#stopPromise;
    if (existing !== undefined) {
      return existing;
    }
    const stopping = this.#finishStop();
    this.#stopPromise = stopping;
    void stopping.catch(() => {
      if (this.#stopPromise === stopping) {
        this.#stopPromise = undefined;
      }
    });
    return stopping;
  }
  /**
   * Issues the current FD-bound release receipt immediately before every
   * managed native-session close. A prior clean shutdown scan is never a
   * release receipt. Returns a compensated semantic violation only after an
   * exact trusted release receipt; untrusted receipts reject and retain authority.
   */
  public async inspectBeforeAuthorityRelease(): Promise<ViteCacheMonitorError | undefined> {
    if (!this.#writerQuiesced || this.#nativeSessionClosed) {
      throw new Error('Vite cache authority cannot be released before writer quiescence');
    }
    await this.#drainActiveScans();
    const inspection = await this.#runPostQuiescenceFinalInspection('shutdown');
    await this.#drainActiveScans();
    const cleanupFailures =
      this.#terminalReason === undefined
        ? Object.freeze([])
        : await this.#recordCompensationRequired(this.#terminalTrigger ?? 'shutdown');
    const inspectionTrusted = inspection.tree !== 'untrusted' && inspection.canary !== 'untrusted';
    if (!inspectionTrusted) {
      throw this.#monitorError('inspection-failed', cleanupFailures);
    }
    if (
      cleanupFailures.length > 0 ||
      (this.#terminalReason !== undefined && !this.#compensationRequired)
    ) {
      throw this.#monitorError(this.#terminalReason ?? 'inspection-failed', cleanupFailures);
    }
    if (inspection.tree === 'unsafe' || inspection.canary === 'detected') {
      return this.#monitorError(
        inspection.tree === 'unsafe' ? 'unsafe-tree' : 'token-canary-detected',
      );
    }
    return undefined;
  }
  async #finishStop(): Promise<void> {
    const startupCompletion = this.#startupCompletion;
    if (startupCompletion !== undefined) {
      await startupCompletion;
    }

    const writerFailures: ViteCacheCleanupOperation[] = [];
    let writerStopped = true;
    if (this.#state === 'running') {
      writerStopped = await this.#establishWriterQuiescence('inspection-failed', writerFailures);
    }

    this.#stopRequested = true;
    await this.#drainActiveScans();

    const terminalReasonBeforeFinalInspection = this.#terminalReason;
    const finalInspectionWillRun =
      writerStopped && this.#writerQuiesced && this.#terminalCleanup === undefined;

    await this.#drainActiveScans();
    const terminalCleanup = this.#terminalCleanup;
    const cleanupFailures =
      terminalCleanup === undefined
        ? await this.#beginTerminalCleanup(
            'shutdown',
            writerStopped ? this.#terminalReason : 'inspection-failed',
            false,
            true,
          )
        : await this.#retryTerminalInfrastructure(terminalCleanup);
    const failures = [...writerFailures, ...cleanupFailures];
    const finalInspectionDetectedViolation =
      finalInspectionWillRun &&
      terminalReasonBeforeFinalInspection === undefined &&
      this.#terminalReason !== undefined;
    if (finalInspectionDetectedViolation) {
      throw this.#monitorError(this.#terminalReason ?? 'inspection-failed', failures);
    }
    if (this.#standaloneReleaseInspectionBlocked) {
      throw this.#monitorError('inspection-failed', failures);
    }
    if (failures.length > 0) {
      throw this.#monitorError('inspection-failed', failures);
    }
  }

  /** The managed runtime calls this before it begins compensation after a crash/failure. */
  public async inspectFailure(): Promise<void> {
    await this.#inspectExternal('failure');
  }

  /** The managed runtime calls this before it restores staged state during recovery. */
  public async inspectRecovery(): Promise<void> {
    await this.#inspectExternal('recovery');
  }

  async #inspectExternal(
    trigger: Extract<ViteCacheMonitorTrigger, 'failure' | 'recovery'>,
  ): Promise<void> {
    if (this.#state !== 'running' || this.#stopRequested) {
      throw new Error('Vite cache monitor is not running');
    }
    try {
      await this.#requestScan(trigger);
    } catch (error: unknown) {
      const terminalCleanup = this.#terminalCleanup;
      const cleanupFailures =
        terminalCleanup === undefined
          ? Object.freeze([])
          : await this.#completeTerminalInfrastructure(terminalCleanup, false);
      throw withCleanupFailures(error, cleanupFailures, this.#compensationRequired);
    }
  }

  #handleTrigger(trigger: ViteCacheBackgroundTrigger): void {
    if (this.#state !== 'running' || this.#stopRequested) {
      return;
    }
    if (this.#starting) {
      this.#startupTrigger ??= trigger;
      return;
    }
    this.#runInBackground(trigger);
  }

  #runInBackground(trigger: ViteCacheBackgroundTrigger): void {
    if (this.#state !== 'running' || this.#stopRequested) {
      return;
    }
    this.#scheduleBackgroundScan(trigger);
  }

  #notifyBackgroundError(error: ViteCacheMonitorError, trigger: ViteCacheMonitorTrigger): void {
    try {
      const observerResult = this.#onBackgroundError?.(error);
      void Promise.resolve(observerResult).catch(() => {
        this.#handleObserverFailure(trigger);
      });
    } catch {
      this.#handleObserverFailure(trigger);
    }
  }

  #handleObserverFailure(trigger: ViteCacheMonitorTrigger): void {
    void this.#beginTerminalCleanup(trigger, 'inspection-failed').catch(() => undefined);
  }
  #handleWatcherFailure(): void {
    if (this.#watcherFailureObserved || this.#state !== 'running' || this.#stopRequested) {
      return;
    }
    this.#watcherFailureObserved = true;
    void this.#beginTerminalCleanup('failure', 'inspection-failed').catch(() => undefined);
    this.#publishTerminalViolation('failure', 'inspection-failed');
  }

  #scheduleBackgroundScan(trigger: ViteCacheBackgroundTrigger): void {
    this.#scheduleScan(trigger, true);
  }

  #requestScan(trigger: ViteCacheMonitorTrigger): Promise<void> {
    if (this.#stopRequested && trigger !== 'shutdown') {
      return Promise.resolve();
    }
    return this.#scheduleScan(trigger, false);
  }

  #scheduleScan(trigger: ViteCacheMonitorTrigger, background: boolean): Promise<void> {
    if (this.#state !== 'running') {
      return Promise.resolve();
    }

    if (this.#scanInFlight === undefined) {
      const scan = this.#startScan(trigger);
      if (background) {
        this.#observeBackgroundScan(scan, trigger);
      }
      return scan;
    }

    let pending = this.#pendingScan;
    if (pending === undefined) {
      pending = createPendingViteCacheMonitorScan(trigger, background);
      this.#pendingScan = pending;
      void pending.promise.catch(() => undefined);
    } else {
      if (!isBackgroundTrigger(trigger)) {
        pending.trigger = trigger;
      }
      if (!background) {
        pending.background = false;
      }
    }
    return pending.promise;
  }

  #observeBackgroundScan(scan: Promise<void>, trigger: ViteCacheMonitorTrigger): void {
    void scan.catch((error: unknown) => {
      this.#publishTerminalViolation(trigger, toMonitorError(error).reason);
    });
  }

  #startScan(trigger: ViteCacheMonitorTrigger): Promise<void> {
    const scan = Promise.resolve().then(() => this.#inspect(trigger));
    this.#scanInFlight = scan;
    void scan
      .then(
        () => {
          this.#advanceScan(scan);
        },
        (error: unknown) => {
          this.#advanceScan(scan, error);
        },
      )
      .catch(() => undefined);
    return scan;
  }

  #advanceScan(completed: Promise<void>, failure?: unknown): void {
    if (this.#scanInFlight !== completed) {
      return;
    }
    this.#scanInFlight = undefined;

    const pending = this.#pendingScan;
    this.#pendingScan = undefined;
    if (pending === undefined) {
      return;
    }
    if (this.#state !== 'running' || this.#stopRequested) {
      void this.#rejectPendingTerminalScan(pending, failure);
      return;
    }
    const scan = this.#startScan(pending.trigger);
    if (pending.background) {
      this.#observeBackgroundScan(scan, pending.trigger);
    }
    void scan.then(pending.resolve, pending.reject).catch(() => undefined);
  }

  async #drainActiveScans(): Promise<void> {
    for (;;) {
      const active = this.#scanInFlight;
      if (active === undefined) {
        const pending = this.#pendingScan;
        this.#pendingScan = undefined;
        if (pending !== undefined) {
          pending.reject(this.#sanitizedTerminalScanError());
          continue;
        }
        return;
      }
      try {
        await active;
      } catch {
        // The primary scan failure remains attached to its caller or observer.
      }
      await Promise.resolve();
    }
  }
  async #rejectPendingTerminalScan(
    pending: PendingViteCacheMonitorScan,
    failure: unknown,
  ): Promise<void> {
    if (isSynchronousExternalTrigger(pending.trigger)) {
      const terminalCleanup = this.#terminalCleanup;
      if (terminalCleanup !== undefined) {
        await terminalCleanup;
      }
    }
    pending.reject(this.#sanitizedTerminalScanError(failure));
  }

  #sanitizedTerminalScanError(failure?: unknown): ViteCacheMonitorError {
    const monitorError = failure === undefined ? undefined : toMonitorError(failure);
    return this.#monitorError(
      monitorError?.reason ?? this.#terminalReason ?? 'inspection-failed',
      monitorError?.cleanupFailures ?? [],
    );
  }
  #publishTerminalViolation(
    trigger: ViteCacheMonitorTrigger,
    fallbackReason: ViteCacheMonitorReason,
  ): void {
    if (this.#terminalNotification !== undefined) {
      return;
    }
    const publication = (async (): Promise<void> => {
      const terminalCleanup = this.#terminalCleanup;
      const cleanupFailures = terminalCleanup === undefined ? [] : await terminalCleanup;
      await this.#drainActiveScans();
      const deferredCleanupFailures =
        terminalCleanup === undefined
          ? []
          : await this.#completeTerminalInfrastructure(terminalCleanup, false);
      this.#notifyBackgroundError(
        this.#monitorError(this.#terminalReason ?? fallbackReason, [
          ...cleanupFailures,
          ...deferredCleanupFailures,
        ]),
        trigger,
      );
    })();
    this.#terminalNotification = publication;
    void publication.catch(() => {
      this.#notifyBackgroundError(
        this.#monitorError(this.#terminalReason ?? fallbackReason),
        trigger,
      );
    });
  }

  async #inspect(trigger: ViteCacheMonitorTrigger): Promise<void> {
    try {
      const scan = await this.#filesystem.scanCacheTree({
        session: this.#nativeSession,
        provenance: this.#provenance,
        limits: this.#limits,
      });
      assertSafeViteCacheTree(this.#provenance, scan, this.#limits);
    } catch {
      throw this.#monitorError('unsafe-tree', await this.#contain(trigger, 'unsafe-tree'));
    }

    let detected: boolean;
    try {
      const result = await this.#scanner.scanCacheCanaries({
        session: this.#nativeSession,
        provenance: this.#provenance,
        trigger,
        limits: this.#limits,
        tokenHashes: this.#tokenHashes,
      });
      detected = readCanaryDetected(result);
    } catch {
      throw this.#monitorError(
        'inspection-failed',
        await this.#contain(trigger, 'inspection-failed'),
      );
    }
    if (detected) {
      throw this.#monitorError(
        'token-canary-detected',
        await this.#contain(trigger, 'token-canary-detected'),
      );
    }
  }
  #runPostQuiescenceFinalInspection(
    trigger: ViteCacheMonitorTrigger,
  ): Promise<ViteCacheAuthorityReleaseInspection> {
    return this.#inspectPostQuiescenceFinalState(trigger);
  }

  async #inspectPostQuiescenceFinalState(
    trigger: ViteCacheMonitorTrigger,
  ): Promise<ViteCacheAuthorityReleaseInspection> {
    let finalReason: ViteCacheMonitorReason | undefined;
    let tree: ViteCacheAuthorityReleaseInspection['tree'] = 'safe';
    try {
      const scan = await this.#filesystem.scanCacheTree({
        session: this.#nativeSession,
        provenance: this.#provenance,
        limits: this.#limits,
      });
      const exactScan = snapshotExactViteCacheTreeEnvelope(scan, this.#limits);
      if (exactScan === undefined) {
        tree = 'untrusted';
        finalReason = 'inspection-failed';
      } else {
        try {
          assertSafeViteCacheTree(this.#provenance, exactScan, this.#limits);
        } catch {
          tree = 'unsafe';
          finalReason = 'unsafe-tree';
        }
      }
    } catch {
      tree = 'untrusted';
      finalReason = 'inspection-failed';
    }

    let canary: ViteCacheAuthorityReleaseInspection['canary'] = 'clear';
    try {
      const result = await this.#scanner.scanCacheCanaries({
        session: this.#nativeSession,
        provenance: this.#provenance,
        trigger,
        limits: this.#limits,
        tokenHashes: this.#tokenHashes,
      });
      if (readCanaryDetected(result)) {
        canary = 'detected';
        finalReason = selectTerminalReason(finalReason, 'token-canary-detected');
      }
    } catch {
      canary = 'untrusted';
      finalReason = selectTerminalReason(finalReason, 'inspection-failed');
    }

    if (finalReason !== undefined) {
      this.#terminalReason = selectTerminalReason(this.#terminalReason, finalReason);
      this.#state = 'violated';
    }
    return Object.freeze({ tree, canary });
  }

  async #contain(
    trigger: ViteCacheMonitorTrigger,
    reason: ViteCacheMonitorReason,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    const terminalCleanup = this.#terminalCleanup;
    if (terminalCleanup !== undefined) {
      this.#terminalReason = selectTerminalReason(this.#terminalReason, reason);
      return Object.freeze([]);
    }
    return this.#beginTerminalCleanup(trigger, reason, true);
  }

  #beginTerminalCleanup(
    trigger: ViteCacheMonitorTrigger,
    reason?: ViteCacheMonitorReason,
    deferInfrastructure = false,
    writerAttempted = false,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    const existing = this.#terminalCleanup;
    if (existing !== undefined) {
      if (reason !== undefined) {
        this.#terminalReason = selectTerminalReason(this.#terminalReason, reason);
      }
      return existing;
    }

    if (reason === undefined) {
      if (this.#writerQuiesced && this.#state !== 'violated') {
        this.#state = 'stopped';
      }
    } else {
      this.#terminalReason = selectTerminalReason(this.#terminalReason, reason);
    }

    this.#terminalInfrastructureDeferred = deferInfrastructure;
    this.#terminalTrigger = trigger;
    let resolve!: (failures: readonly ViteCacheCleanupOperation[]) => void;
    const cleanup = new Promise<readonly ViteCacheCleanupOperation[]>((resolvePromise) => {
      resolve = resolvePromise;
    });
    this.#terminalCleanup = cleanup;
    void this.#runTerminalCleanup(trigger, reason, deferInfrastructure, writerAttempted).then(
      resolve,
    );
    if (reason !== undefined && this.#synchronousWriterStopBarrierComplete) {
      this.#state = 'violated';
    }
    return cleanup;
  }

  async #runTerminalCleanup(
    trigger: ViteCacheMonitorTrigger,
    reason: ViteCacheMonitorReason | undefined,
    deferInfrastructure: boolean,
    writerAttempted: boolean,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    const failures: ViteCacheCleanupOperation[] = [];
    if (reason === undefined) {
      if (!this.#writerQuiesced) {
        return Object.freeze(failures);
      }
      await this.#completePostQuiescenceTerminalRelease(trigger, failures);
      return Object.freeze(failures);
    }

    if (!writerAttempted) {
      await this.#establishWriterQuiescence(reason, failures);
    }
    if (this.#state === 'running') {
      this.#state = 'violated';
    }
    if (!this.#writerQuiesced) {
      failures.push(...(await this.#recordCompensationRequired(trigger)));
      return Object.freeze(failures);
    }
    if (deferInfrastructure) {
      return Object.freeze(failures);
    }

    await this.#completePostQuiescenceTerminalRelease(trigger, failures);
    return Object.freeze(failures);
  }

  #recordCompensationRequired(
    trigger: ViteCacheMonitorTrigger,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    const failures: ViteCacheCleanupOperation[] = [];
    if (this.#compensationRequired) {
      return Promise.resolve(Object.freeze(failures));
    }
    const reason = this.#terminalReason;
    if (reason === undefined) {
      return Promise.resolve(Object.freeze(failures));
    }
    const existing = this.#compensationRecording;
    if (existing !== undefined) {
      return existing;
    }

    const recording = (async (): Promise<readonly ViteCacheCleanupOperation[]> => {
      if (
        await this.#attempt(
          'mark-compensation-required',
          () =>
            this.#recovery.markCompensationRequired({
              provenance: this.#provenance,
              trigger,
              reason,
            }),
          failures,
        )
      ) {
        this.#compensationRequired = true;
      }
      return Object.freeze(failures);
    })();
    this.#compensationRecording = recording;
    void recording.then(
      () => {
        if (this.#compensationRecording === recording) {
          this.#compensationRecording = undefined;
        }
      },
      () => {
        if (this.#compensationRecording === recording) {
          this.#compensationRecording = undefined;
        }
      },
    );
    return recording;
  }

  #monitorError(
    reason: ViteCacheMonitorReason,
    cleanupFailures: readonly ViteCacheCleanupOperation[] = [],
  ): ViteCacheMonitorError {
    return new ViteCacheMonitorError(
      this.#terminalReason ?? reason,
      [...new Set(cleanupFailures)],
      this.#compensationRequired,
      this.#nativeSessionClosed,
    );
  }

  async #completePostQuiescenceTerminalRelease(
    trigger: ViteCacheMonitorTrigger,
    failures: ViteCacheCleanupOperation[],
  ): Promise<void> {
    if (this.#nativeSessionClosed && this.#infrastructureIsDisposed()) {
      this.#standaloneReleaseInspectionBlocked = false;
      return;
    }
    await this.#drainActiveScans();
    const inspection = await this.#runPostQuiescenceFinalInspection(trigger);
    await this.#drainActiveScans();
    failures.push(...(await this.#disposeInfrastructure()));
    const inspectionTrusted = inspection.tree !== 'untrusted' && inspection.canary !== 'untrusted';
    if (!managedViteCacheNativeSessionStates.has(this.#nativeSession)) {
      this.#standaloneReleaseInspectionBlocked = !inspectionTrusted;
    }
    if (this.#terminalReason !== undefined) {
      this.#state = 'violated';
      failures.push(...(await this.#recordCompensationRequired(trigger)));
      if (!this.#compensationRequired) {
        return;
      }
    } else {
      this.#state = 'stopped';
    }
    if (!inspectionTrusted || !this.#infrastructureIsDisposed()) {
      return;
    }
    failures.push(...(await this.#disposeStandaloneNativeSession()));
  }

  async #completeTerminalInfrastructure(
    terminalCleanup: Promise<readonly ViteCacheCleanupOperation[]>,
    retryWriter: boolean,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    await terminalCleanup;
    if (!retryWriter && !this.#terminalInfrastructureDeferred) {
      return Object.freeze([]);
    }

    const failures: ViteCacheCleanupOperation[] = [];
    if (!this.#writerQuiesced) {
      if (!retryWriter) {
        return Object.freeze(failures);
      }
      await this.#establishWriterQuiescence(this.#terminalReason ?? 'inspection-failed', failures);
    }
    if (!this.#writerQuiesced) {
      return Object.freeze(failures);
    }

    await this.#completePostQuiescenceTerminalRelease(this.#terminalTrigger ?? 'failure', failures);
    if (this.#infrastructureIsDisposed()) {
      this.#terminalInfrastructureDeferred = false;
    }
    return Object.freeze(failures);
  }

  #retryTerminalInfrastructure(
    terminalCleanup: Promise<readonly ViteCacheCleanupOperation[]>,
  ): Promise<readonly ViteCacheCleanupOperation[]> {
    return this.#completeTerminalInfrastructure(terminalCleanup, true);
  }

  async #establishWriterQuiescence(
    reason: ViteCacheMonitorReason,
    failures: ViteCacheCleanupOperation[],
  ): Promise<boolean> {
    if (this.#writerQuiesced) {
      this.#synchronousWriterStopBarrierComplete = true;
      return true;
    }

    const inFlight = this.#writerQuiescence;
    if (inFlight !== undefined) {
      const completed = await inFlight;
      failures.push(...completed.failures);
      return completed.quiesced;
    }

    let resolve!: (completed: ViteCacheWriterQuiescence) => void;
    const quiescence = new Promise<ViteCacheWriterQuiescence>((resolvePromise) => {
      resolve = resolvePromise;
    });
    this.#writerQuiescence = quiescence;
    const complete = async (): Promise<void> => {
      const attemptFailures: ViteCacheCleanupOperation[] = [];
      const aborted = this.#synchronousWriterStopBarrierComplete
        ? true
        : this.#attemptSynchronously(
            'abort-writer',
            () => this.#writer.abort(reason),
            attemptFailures,
          );
      if (aborted) {
        this.#synchronousWriterStopBarrierComplete = true;
      }
      const terminated = await this.#attempt(
        'terminate-writer',
        () => this.#writer.terminate(reason),
        attemptFailures,
      );
      if (terminated) {
        this.#writerQuiesced = true;
      }

      const completed = Object.freeze({
        quiesced: terminated,
        failures: Object.freeze([...attemptFailures]),
      });
      if (!terminated && this.#writerQuiescence === quiescence) {
        this.#writerQuiescence = undefined;
      }
      resolve(completed);
    };
    void complete().catch(() => {
      const completed = Object.freeze({
        quiesced: false,
        failures: Object.freeze(['terminate-writer'] as ViteCacheCleanupOperation[]),
      });
      if (this.#writerQuiescence === quiescence) {
        this.#writerQuiescence = undefined;
      }
      resolve(completed);
    });

    const completed = await quiescence;
    failures.push(...completed.failures);
    return completed.quiesced;
  }

  #attemptSynchronously(
    operation: ViteCacheCleanupOperation,
    action: () => unknown,
    failures: ViteCacheCleanupOperation[],
  ): boolean {
    try {
      const result = action();
      if (isThenable(result)) {
        failures.push(operation);
        void Promise.resolve(result).catch(() => undefined);
        return false;
      }
      return true;
    } catch {
      failures.push(operation);
      return false;
    }
  }

  async #attempt(
    operation: ViteCacheCleanupOperation,
    action: () => Promise<void> | void,
    failures: ViteCacheCleanupOperation[],
  ): Promise<boolean> {
    try {
      await action();
      return true;
    } catch {
      failures.push(operation);
      return false;
    }
  }

  #disposeInfrastructure(): Promise<readonly ViteCacheCleanupOperation[]> {
    if (!this.#writerQuiesced) {
      return Promise.resolve(Object.freeze([]));
    }

    const existing = this.#infrastructureCleanup;
    if (existing !== undefined) {
      return existing;
    }

    let resolve!: (failures: readonly ViteCacheCleanupOperation[]) => void;
    const cleanup = new Promise<readonly ViteCacheCleanupOperation[]>((resolvePromise) => {
      resolve = resolvePromise;
    });
    this.#infrastructureCleanup = cleanup;
    const dispose = async (): Promise<void> => {
      const watcherSetupCompletion = this.#watcherSetupCompletion;
      if (watcherSetupCompletion !== undefined) {
        await watcherSetupCompletion;
      }
      const failures: ViteCacheCleanupOperation[] = [];
      const timer = this.#timer;
      let pollTimerCleared = !this.#timerInstalled;
      if (this.#timerInstalled) {
        try {
          this.#scheduler.clearInterval(timer);
          this.#timer = undefined;
          this.#timerInstalled = false;
          pollTimerCleared = true;
        } catch {
          failures.push('clear-poll-timer');
        }
      }
      if (pollTimerCleared) {
        const watcher = this.#watcher;
        if (watcher !== undefined) {
          try {
            await watcher.close();
            if (this.#watcher === watcher) {
              this.#watcher = undefined;
            }
          } catch {
            failures.push('close-tree-watcher');
          }
        }
      }
      if (this.#infrastructureCleanup === cleanup) {
        this.#infrastructureCleanup = undefined;
      }
      resolve(Object.freeze(failures));
    };
    void dispose().catch(() => {
      if (this.#infrastructureCleanup === cleanup) {
        this.#infrastructureCleanup = undefined;
      }
      resolve(Object.freeze(['close-tree-watcher']));
    });
    return cleanup;
  }
  #infrastructureIsDisposed(): boolean {
    return !this.#timerInstalled && this.#watcher === undefined;
  }
  async #disposeStandaloneNativeSession(): Promise<readonly ViteCacheCleanupOperation[]> {
    if (this.#nativeSessionClosed || managedViteCacheNativeSessionStates.has(this.#nativeSession)) {
      return Object.freeze([]);
    }
    const failures: ViteCacheCleanupOperation[] = [];
    if (await this.#attempt('close-native-session', () => this.#closeNativeSession(), failures)) {
      this.#nativeSessionClosed = true;
    }
    return Object.freeze(failures);
  }

  async #closeNativeSession(): Promise<void> {
    await this.#filesystem.closeCacheSession({ session: this.#nativeSession });
  }
}
export type ManagedViteCacheAuthority = object;

type ManagedViteCacheAuthorityLifecycle =
  'new' | 'starting' | 'leased' | 'blocked' | 'closing' | 'closed';

interface ManagedViteCacheAuthorityState {
  readonly session: ViteCacheSession;
  readonly filesystem: CacheRuntimeFilesystemPort;
  readonly scanner: CacheCanaryScannerPort;
  readonly recovery: ViteCacheRecoveryPort;
  readonly limits: ViteCacheLimits;
  readonly pollIntervalMs: number;
  pendingRecoverySettlement: (() => Promise<void>) | undefined;
  releaseInspection: (() => Promise<ViteCacheMonitorError | undefined>) | undefined;
  noWriterCompensation: ViteCacheMonitorReason | undefined;
  lifecycle: ManagedViteCacheAuthorityLifecycle;
  nativeSessionClosed: boolean;
  nativeClosePromise: Promise<ViteCacheMonitorError | undefined> | undefined;
  failedStart:
    | {
        readonly monitor: ViteCacheMonitor;
        readonly completeRecovery: () => Promise<void>;
      }
    | undefined;
}
type ViteCacheRecoveryInput = Parameters<ViteCacheRecoveryPort['markCompensationRequired']>[0];

interface ManagedViteCacheRecoveryDeferral {
  readonly monitorRecovery: ViteCacheRecoveryPort;
  complete(): Promise<void>;
  compensationRequired(): boolean;
}

export interface CreateManagedViteCacheAuthorityInput {
  readonly session: ViteCacheSession;
  readonly filesystem: CacheRuntimeFilesystemPort;
  readonly scanner: CacheCanaryScannerPort;
  readonly recovery: ViteCacheRecoveryPort;
  readonly limits?: ViteCacheLimits;
  readonly pollIntervalMs?: number;
}

export interface StartManagedViteCacheAuthorityInput {
  readonly authority: ManagedViteCacheAuthority;
  readonly writer: ViteCacheWriterControl;
  /** Runtime-derived SHA-256 only; token text is never accepted here. */
  readonly canary: CacheCanaryDigest;
  readonly onBackgroundError: (error: ViteCacheMonitorError) => void;
}

export interface ManagedViteCacheLease {
  readonly cacheDir: string;
  readonly violation: Promise<ViteCacheMonitorError>;
  stop(): Promise<void>;
  close(): Promise<void>;
}

const issuedManagedViteCacheAuthorities = new WeakSet<object>();
const managedViteCacheAuthorityStates = new WeakMap<
  ManagedViteCacheAuthority,
  ManagedViteCacheAuthorityState
>();
const managedViteCacheNativeSessionStates = new WeakMap<
  CacheNativeSession,
  ManagedViteCacheAuthorityState
>();
const retiredManagedViteCacheNativeSessions = new WeakSet<CacheNativeSession>();
/**
 * This public, non-secret SHA-256 digest is used only to require a native
 * canary pass before closing an authority that never received writer credentials.
 */
const VITE_CACHE_NO_WRITER_RELEASE_CANARY_HASHES = Object.freeze([
  '0000000000000000000000000000000000000000000000000000000000000000',
]);

/**
 * Issues the sole managed authority for a live native session. The session must
 * already have been reopened and issued by `reopenViteCacheSession`; callers
 * cannot inject a monitor-shaped object into the managed Vite start surface.
 */
export function createManagedViteCacheAuthority(
  input: CreateManagedViteCacheAuthorityInput,
): ManagedViteCacheAuthority {
  const session = snapshotViteCacheSession(input.session);
  if (
    managedViteCacheNativeSessionStates.has(session.nativeSession) ||
    retiredManagedViteCacheNativeSessions.has(session.nativeSession)
  ) {
    throw managedAuthorityError();
  }
  const limits = Object.freeze({ ...(input.limits ?? VITE_CACHE_LIMITS) });
  assertViteCacheLimits(limits);
  const pollIntervalMs = input.pollIntervalMs ?? VITE_CACHE_DEFAULT_POLL_INTERVAL_MS;
  assertPollInterval(pollIntervalMs);
  assertManagedViteCacheAuthorityPorts(input);
  const authority = Object.freeze({}) as ManagedViteCacheAuthority;
  const state: ManagedViteCacheAuthorityState = {
    session,
    filesystem: input.filesystem,
    scanner: input.scanner,
    recovery: input.recovery,
    limits,
    pollIntervalMs,
    pendingRecoverySettlement: undefined,
    releaseInspection: undefined,
    noWriterCompensation: undefined,
    lifecycle: 'new',
    nativeSessionClosed: false,
    nativeClosePromise: undefined,
    failedStart: undefined,
  };
  issuedManagedViteCacheAuthorities.add(authority);
  managedViteCacheAuthorityStates.set(authority, state);
  managedViteCacheNativeSessionStates.set(session.nativeSession, state);
  return authority;
}
/** Confirms descriptor binding without revealing cache provenance to runtime callers. */
export function assertManagedViteCacheAuthorityInstallId(
  authority: ManagedViteCacheAuthority,
  installId: string,
): void {
  if (
    typeof installId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(installId) ||
    managedViteCacheAuthorityState(authority).session.provenance.installId !== installId
  ) {
    throw managedAuthorityError();
  }
}
/**
 * Releases an authority whose monitor never started through the no-writer
 * release inspection, which scans with a fixed public digest and never receives
 * a credential-derived canary. Active authorities stay lease-bound until native
 * closure and durable recovery settlement complete.
 */
export function closeManagedViteCacheAuthority(
  authority: ManagedViteCacheAuthority,
): Promise<void> {
  const state = managedViteCacheAuthorityState(authority);
  if (
    state.lifecycle === 'starting' ||
    state.lifecycle === 'leased' ||
    (state.lifecycle === 'closing' && state.pendingRecoverySettlement !== undefined)
  ) {
    throw managedAuthorityError();
  }
  if (state.lifecycle === 'blocked') {
    return retryBlockedManagedAuthorityClose(state);
  }
  return closeManagedViteCacheNativeSession(state).then(() => undefined);
}

/**
 * Starts the concrete monitor attached to a module-issued authority. The
 * runtime supplies the digest derived from its verified credential capability
 * immediately before startup; no public token-hash configuration is accepted.
 */
export async function startManagedViteCacheAuthority(
  input: StartManagedViteCacheAuthorityInput,
): Promise<ManagedViteCacheLease> {
  const authority = input.authority;
  const writer = input.writer;
  const canaryInput = input.canary;
  const onBackgroundError = input.onBackgroundError;
  const state = managedViteCacheAuthorityState(authority);
  if (state.lifecycle !== 'new') {
    throw managedAuthorityError();
  }
  if (!isViteCacheWriterControl(writer) || typeof onBackgroundError !== 'function') {
    throw managedAuthorityError();
  }

  const digest = normalizeCanaryDigest(canaryInput);
  const canary = Object.freeze([digest]);

  const violation = createMonitorViolation();
  const recoveryDeferral = createManagedViteCacheRecoveryDeferral(state.recovery);
  const monitor = new ViteCacheMonitor({
    filesystem: state.filesystem,
    scanner: state.scanner,
    writer,
    recovery: recoveryDeferral.monitorRecovery,
    session: state.session,
    canary: { tokenHashes: canary },
    limits: state.limits,
    pollIntervalMs: state.pollIntervalMs,
    onBackgroundError: (error) => {
      violation.resolve(error);
      onBackgroundError(error);
    },
  });
  state.failedStart = {
    monitor,
    completeRecovery: () => recoveryDeferral.complete(),
  };
  state.lifecycle = 'starting';
  state.releaseInspection = () => monitor.inspectBeforeAuthorityRelease();

  try {
    await monitor.start();
  } catch (error: unknown) {
    const monitorError = toMonitorError(error);
    const cleanupFailures = await closeFailedManagedAuthorityStart(
      monitor,
      state,
      recoveryDeferral.complete,
      monitorError.cleanupFailures,
    );
    throw new ViteCacheMonitorError(
      monitorError.reason,
      [...new Set([...monitorError.cleanupFailures, ...cleanupFailures])],
      monitorError.compensationRequired || recoveryDeferral.compensationRequired(),
    );
  }

  if (state.lifecycle !== 'starting') {
    const cleanupFailures = await closeFailedManagedAuthorityStart(
      monitor,
      state,
      recoveryDeferral.complete,
    );
    throw new ViteCacheMonitorError(
      'inspection-failed',
      cleanupFailures,
      recoveryDeferral.compensationRequired(),
    );
  }
  state.failedStart = undefined;
  state.pendingRecoverySettlement = () => recoveryDeferral.complete();
  state.lifecycle = 'leased';
  return createManagedViteCacheLease({
    monitor,
    beginAuthorityClose: () => {
      state.lifecycle = 'closing';
    },
    closeNativeSession: () => closeManagedViteCacheNativeSession(state),
    completeRecovery: () => recoveryDeferral.complete(),
    completeAuthorityClose: () => {
      state.pendingRecoverySettlement = undefined;
      state.lifecycle = 'closed';
    },
    deferAuthorityRecoverySettlement: () => {
      state.pendingRecoverySettlement = () => recoveryDeferral.complete();
      state.lifecycle = 'blocked';
    },
    compensationRequired: () => recoveryDeferral.compensationRequired(),
    cacheDir: state.session.provenance.root.canonicalPath,
    violation: violation.promise,
  });
}

function assertManagedViteCacheAuthorityPorts(input: CreateManagedViteCacheAuthorityInput): void {
  if (
    typeof input.filesystem !== 'object' ||
    input.filesystem === null ||
    typeof input.filesystem.scanCacheTree !== 'function' ||
    typeof input.filesystem.watchCacheTree !== 'function' ||
    typeof input.filesystem.closeCacheSession !== 'function' ||
    typeof input.scanner !== 'object' ||
    input.scanner === null ||
    typeof input.scanner.scanCacheCanaries !== 'function' ||
    typeof input.recovery !== 'object' ||
    input.recovery === null ||
    typeof input.recovery.markCompensationRequired !== 'function'
  ) {
    throw managedAuthorityError();
  }
}
function managedViteCacheAuthorityState(
  authority: ManagedViteCacheAuthority,
): ManagedViteCacheAuthorityState {
  if (
    typeof authority !== 'object' ||
    authority === null ||
    !issuedManagedViteCacheAuthorities.has(authority)
  ) {
    throw managedAuthorityError();
  }
  const state = managedViteCacheAuthorityStates.get(authority);
  if (state === undefined) {
    throw managedAuthorityError();
  }
  return state;
}
function closeManagedViteCacheNativeSession(
  state: ManagedViteCacheAuthorityState,
): Promise<ViteCacheMonitorError | undefined> {
  if (state.nativeSessionClosed) {
    return Promise.resolve(undefined);
  }
  const existing = state.nativeClosePromise;
  if (existing !== undefined) {
    return existing;
  }

  const settleLifecycle =
    state.lifecycle !== 'closing' && state.pendingRecoverySettlement === undefined;
  state.lifecycle = 'closing';
  const closing = (async (): Promise<ViteCacheMonitorError | undefined> => {
    let releaseViolation: ViteCacheMonitorError | undefined;
    try {
      releaseViolation = await admitManagedViteCacheAuthorityRelease(state);
    } catch (error: unknown) {
      blockNeverStartedManagedAuthorityRelease(state);
      throw toMonitorError(error);
    }
    try {
      await state.filesystem.closeCacheSession({ session: state.session.nativeSession });
      state.nativeSessionClosed = true;
      if (settleLifecycle) {
        state.lifecycle = 'closed';
      }
      retiredManagedViteCacheNativeSessions.add(state.session.nativeSession);
      if (managedViteCacheNativeSessionStates.get(state.session.nativeSession) === state) {
        managedViteCacheNativeSessionStates.delete(state.session.nativeSession);
      }
      return releaseViolation;
    } catch {
      blockNeverStartedManagedAuthorityRelease(state);
      if (releaseViolation !== undefined) {
        throw new ViteCacheMonitorError(
          releaseViolation.reason,
          ['close-native-session'],
          releaseViolation.compensationRequired,
        );
      }
      throw new ViteCacheMonitorError('inspection-failed', ['close-native-session']);
    }
  })();
  state.nativeClosePromise = closing;
  void closing
    .finally(() => {
      if (state.nativeClosePromise === closing) {
        state.nativeClosePromise = undefined;
      }
    })
    .catch(() => undefined);
  return closing;
}

async function admitManagedViteCacheAuthorityRelease(
  state: ManagedViteCacheAuthorityState,
): Promise<ViteCacheMonitorError | undefined> {
  const inspection = state.releaseInspection;
  if (inspection !== undefined) {
    return inspection();
  }
  await inspectNeverStartedManagedAuthorityRelease(state);
  return undefined;
}

async function inspectNeverStartedManagedAuthorityRelease(
  state: ManagedViteCacheAuthorityState,
): Promise<void> {
  let trusted = true;
  let reason: ViteCacheMonitorReason | undefined;
  try {
    const scan = await state.filesystem.scanCacheTree({
      session: state.session.nativeSession,
      provenance: state.session.provenance,
      limits: state.limits,
    });
    const exactScan = snapshotExactViteCacheTreeEnvelope(scan, state.limits);
    if (exactScan === undefined) {
      trusted = false;
      reason = 'inspection-failed';
    } else {
      try {
        assertSafeViteCacheTree(state.session.provenance, exactScan, state.limits);
      } catch {
        reason = 'unsafe-tree';
      }
    }
  } catch {
    trusted = false;
    reason = 'inspection-failed';
  }

  try {
    const result = await state.scanner.scanCacheCanaries({
      session: state.session.nativeSession,
      provenance: state.session.provenance,
      trigger: 'shutdown',
      limits: state.limits,
      tokenHashes: VITE_CACHE_NO_WRITER_RELEASE_CANARY_HASHES,
    });
    if (readCanaryDetected(result)) {
      reason = selectTerminalReason(reason, 'token-canary-detected');
    }
  } catch {
    trusted = false;
    reason = selectTerminalReason(reason, 'inspection-failed');
  }

  if (reason !== undefined) {
    state.noWriterCompensation = selectTerminalReason(state.noWriterCompensation, reason);
  }

  let compensationRequired = false;
  let compensationFailed = false;
  const compensationReason = state.noWriterCompensation;
  if (compensationReason !== undefined) {
    try {
      await state.recovery.markCompensationRequired({
        provenance: state.session.provenance,
        trigger: 'shutdown',
        reason: compensationReason,
      });
      compensationRequired = true;
      state.noWriterCompensation = undefined;
    } catch {
      compensationFailed = true;
    }
  }

  if (!trusted || compensationFailed) {
    throw new ViteCacheMonitorError(
      'inspection-failed',
      compensationFailed ? ['mark-compensation-required'] : [],
      compensationRequired,
    );
  }
}

function blockNeverStartedManagedAuthorityRelease(state: ManagedViteCacheAuthorityState): void {
  if (
    state.releaseInspection === undefined &&
    state.pendingRecoverySettlement === undefined &&
    !state.nativeSessionClosed
  ) {
    state.lifecycle = 'blocked';
  }
}

async function retryBlockedManagedAuthorityClose(
  state: ManagedViteCacheAuthorityState,
): Promise<void> {
  const failedStart = state.failedStart;
  if (failedStart !== undefined) {
    const failures = await closeFailedManagedAuthorityStart(
      failedStart.monitor,
      state,
      failedStart.completeRecovery,
    );
    if (failures.length > 0 || !state.nativeSessionClosed) {
      state.lifecycle = 'blocked';
      throw new ViteCacheMonitorError('inspection-failed', failures);
    }
    state.failedStart = undefined;
    state.lifecycle = 'closed';
    return;
  }

  const completeRecovery = state.pendingRecoverySettlement;
  if (completeRecovery === undefined && !state.nativeSessionClosed) {
    await closeManagedViteCacheNativeSession(state);
    return;
  }
  if (completeRecovery === undefined || !state.nativeSessionClosed) {
    throw managedAuthorityError();
  }
  try {
    await completeRecovery();
  } catch {
    throw new ViteCacheMonitorError('inspection-failed', ['mark-compensation-required']);
  }
  state.pendingRecoverySettlement = undefined;
  state.lifecycle = 'closed';
}
function createManagedViteCacheRecoveryDeferral(
  recovery: ViteCacheRecoveryPort,
): ManagedViteCacheRecoveryDeferral {
  let input: ViteCacheRecoveryInput | undefined;
  let intent: Promise<void> | undefined;
  let compensationRequired = false;

  const persistIntent = (): Promise<void> => {
    if (input === undefined) {
      return Promise.resolve();
    }
    const existing = intent;
    if (existing !== undefined) {
      return existing;
    }
    const attempt = Promise.resolve()
      .then(() => recovery.markCompensationRequired(input!))
      .then(() => {
        compensationRequired = true;
      });
    intent = attempt;
    void attempt.catch(() => {
      if (intent === attempt) {
        intent = undefined;
      }
    });
    return attempt;
  };
  const monitorRecovery = Object.freeze({
    markCompensationRequired(candidate: ViteCacheRecoveryInput): Promise<void> {
      if (
        input === undefined ||
        terminalReasonPrecedence(candidate.reason) > terminalReasonPrecedence(input.reason)
      ) {
        input = candidate;
      }
      return persistIntent();
    },
  });
  return Object.freeze({
    monitorRecovery,
    complete(): Promise<void> {
      return persistIntent();
    },
    compensationRequired(): boolean {
      return compensationRequired;
    },
  });
}

function createManagedViteCacheLease(input: {
  readonly monitor: ViteCacheMonitor;
  readonly beginAuthorityClose: () => void;
  readonly closeNativeSession: () => Promise<ViteCacheMonitorError | undefined>;
  readonly completeRecovery: () => Promise<void>;
  readonly completeAuthorityClose: () => void;
  readonly deferAuthorityRecoverySettlement: () => void;
  readonly compensationRequired: () => boolean;
  readonly cacheDir: string;
  readonly violation: Promise<ViteCacheMonitorError>;
}): ManagedViteCacheLease {
  let stopPromise: Promise<void> | undefined;
  let closePromise: Promise<void> | undefined;
  let retainedSemanticPrimary: ViteCacheMonitorError | undefined;
  let terminalOutcome: ViteCacheMonitorError | null | undefined;
  const replayTerminalOutcome = (): Promise<void> | undefined => {
    if (terminalOutcome === undefined) {
      return undefined;
    }
    return terminalOutcome === null ? Promise.resolve() : Promise.reject(terminalOutcome);
  };
  const stop = (): Promise<void> => {
    const terminal = replayTerminalOutcome();
    if (terminal !== undefined) {
      return terminal;
    }
    const existing = stopPromise;
    if (existing !== undefined) {
      return existing;
    }
    const stopping = input.monitor.stop();
    stopPromise = stopping;
    void stopping.catch(() => {
      if (stopPromise === stopping) {
        stopPromise = undefined;
      }
    });
    return stopping;
  };
  const close = (): Promise<void> => {
    const terminal = replayTerminalOutcome();
    if (terminal !== undefined) {
      return terminal;
    }
    const existing = closePromise;
    if (existing !== undefined) {
      return existing;
    }
    const closing = (async () => {
      input.beginAuthorityClose();
      const failures: ViteCacheCleanupOperation[] = [];
      let primary = retainedSemanticPrimary;
      try {
        await stop();
      } catch (error: unknown) {
        const stopError = toMonitorError(error);
        primary ??= stopError;
        failures.push(...stopError.cleanupFailures);
      }
      const authorityReleaseUnsafe =
        failures.includes('abort-writer') ||
        failures.includes('terminate-writer') ||
        failures.includes('close-tree-watcher') ||
        failures.includes('clear-poll-timer') ||
        failures.includes('mark-compensation-required') ||
        failures.includes('close-native-session');
      let nativeSessionReleased = false;
      let recoverySettled = false;
      if (!authorityReleaseUnsafe) {
        try {
          const releaseViolation = await input.closeNativeSession();
          nativeSessionReleased = true;
          primary ??= releaseViolation;
        } catch (error: unknown) {
          const closeError = toMonitorError(error);
          if (primary !== undefined && isSemanticViteCacheMonitorReason(primary.reason)) {
            retainedSemanticPrimary ??= primary;
          } else if (isSemanticViteCacheMonitorReason(closeError.reason)) {
            retainedSemanticPrimary ??= new ViteCacheMonitorError(
              closeError.reason,
              [],
              closeError.compensationRequired,
            );
          }
          primary ??= closeError;
          failures.push(...closeError.cleanupFailures);
        }
      }
      if (nativeSessionReleased) {
        try {
          await input.completeRecovery();
          input.completeAuthorityClose();
          recoverySettled = true;
        } catch {
          input.deferAuthorityRecoverySettlement();
          failures.push('mark-compensation-required');
        }
      }
      if (primary !== undefined || failures.length > 0) {
        const error = new ViteCacheMonitorError(
          primary?.reason ?? 'inspection-failed',
          [...new Set(failures)],
          primary?.compensationRequired || input.compensationRequired(),
          nativeSessionReleased,
        );
        if (nativeSessionReleased && recoverySettled) {
          terminalOutcome = error;
        }
        throw error;
      }
      if (nativeSessionReleased && recoverySettled) {
        terminalOutcome = null;
      }
    })();
    closePromise = closing;
    void closing
      .finally(() => {
        if (closePromise === closing) {
          closePromise = undefined;
        }
      })
      .catch(() => undefined);
    return closing;
  };
  return Object.freeze({
    cacheDir: input.cacheDir,
    violation: input.violation,
    stop,
    close,
  });
}

async function closeFailedManagedAuthorityStart(
  monitor: ViteCacheMonitor,
  state: ManagedViteCacheAuthorityState,
  completeRecovery: () => Promise<void>,
  initialCleanupFailures?: readonly ViteCacheCleanupOperation[],
): Promise<readonly ViteCacheCleanupOperation[]> {
  const failures: ViteCacheCleanupOperation[] = [];
  let stopped = false;
  const needsMonitorRetry =
    initialCleanupFailures === undefined ||
    initialCleanupFailures.some(
      (failure) => failure !== 'close-native-session' && failure !== 'mark-compensation-required',
    );
  if (needsMonitorRetry) {
    try {
      await monitor.stop();
      stopped = true;
    } catch (error: unknown) {
      failures.push(...toMonitorError(error).cleanupFailures);
    }
  } else {
    stopped = true;
  }

  const shouldCloseNativeSession =
    stopped &&
    !state.nativeSessionClosed &&
    initialCleanupFailures?.includes('close-native-session') !== true &&
    initialCleanupFailures?.includes('mark-compensation-required') !== true;
  if (shouldCloseNativeSession) {
    try {
      await closeManagedViteCacheNativeSession(state);
    } catch (error: unknown) {
      failures.push(...toMonitorError(error).cleanupFailures);
    }
  }
  if (state.nativeSessionClosed) {
    try {
      await completeRecovery();
    } catch {
      failures.push('mark-compensation-required');
    }
  }

  if (state.nativeSessionClosed && failures.length === 0) {
    state.failedStart = undefined;
    state.lifecycle = 'closed';
  } else {
    state.lifecycle = 'blocked';
  }
  return Object.freeze([...new Set(failures)]);
}

function createMonitorViolation(): {
  readonly promise: Promise<ViteCacheMonitorError>;
  readonly resolve: (error: ViteCacheMonitorError) => void;
} {
  let resolve!: (error: ViteCacheMonitorError) => void;
  const promise = new Promise<ViteCacheMonitorError>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function normalizeCanaryDigest(candidate: CacheCanaryDigest): string {
  if (typeof candidate !== 'object' || candidate === null || candidate.algorithm !== 'sha256') {
    throw managedAuthorityError();
  }
  return normalizeSha256(candidate.digest);
}

function managedAuthorityError(): Error {
  return new Error('Managed Vite cache authority is invalid.');
}

function createCompletion(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
function createPendingViteCacheMonitorScan(
  trigger: ViteCacheMonitorTrigger,
  background: boolean,
): PendingViteCacheMonitorScan {
  let resolve!: () => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { trigger, background, promise, resolve, reject };
}

function isBackgroundTrigger(
  trigger: ViteCacheMonitorTrigger,
): trigger is ViteCacheBackgroundTrigger {
  return trigger === 'creation' || trigger === 'event' || trigger === 'poll';
}

function isSynchronousExternalTrigger(
  trigger: ViteCacheMonitorTrigger,
): trigger is Extract<ViteCacheMonitorTrigger, 'failure' | 'recovery'> {
  return trigger === 'failure' || trigger === 'recovery';
}

function readCanaryDetected(result: unknown): boolean {
  if (
    result === null ||
    typeof result !== 'object' ||
    Object.getPrototypeOf(result) !== Object.prototype
  ) {
    throw new Error('Native canary inspection must return an exact detected boolean');
  }

  const keys = Reflect.ownKeys(result);
  if (keys.length !== 1 || keys[0] !== 'detected') {
    throw new Error('Native canary inspection must return an exact detected boolean');
  }

  const descriptor = Object.getOwnPropertyDescriptor(result, 'detected');
  if (
    descriptor === undefined ||
    !('value' in descriptor) ||
    typeof descriptor.value !== 'boolean'
  ) {
    throw new Error('Native canary inspection must return an exact detected boolean');
  }
  return descriptor.value;
}
function snapshotExactViteCacheTreeEnvelope(
  value: unknown,
  limits: ViteCacheLimits,
): CacheTreeScan | undefined {
  try {
    const scan = readExactViteCacheDataRecord(value, ['rootIdentity', 'entries']);
    if (scan === undefined) {
      return undefined;
    }
    const rootIdentity = snapshotExactViteCacheTreeIdentity(scan[0]);
    const entries = snapshotExactViteCacheTreeEntries(scan[1], limits);
    if (rootIdentity === undefined || entries === undefined) {
      return undefined;
    }
    return Object.freeze({ rootIdentity, entries });
  } catch {
    return undefined;
  }
}

function snapshotExactViteCacheTreeEntries(
  value: unknown,
  limits: ViteCacheLimits,
): readonly CacheTreeEntry[] | undefined {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return undefined;
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > limits.maxEntries
  ) {
    return undefined;
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== lengthDescriptor.value + 1 || keys[keys.length - 1] !== 'length') {
    return undefined;
  }

  const entries: CacheTreeEntry[] = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    if (keys[index] !== String(index)) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
      return undefined;
    }
    const entry = snapshotExactViteCacheTreeEntry(descriptor.value);
    if (entry === undefined) {
      return undefined;
    }
    entries.push(entry);
  }
  return Object.freeze(entries);
}

function snapshotExactViteCacheTreeEntry(value: unknown): CacheTreeEntry | undefined {
  const entry = readExactViteCacheDataRecord(value, [
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
  ]);
  if (entry === undefined) {
    return undefined;
  }
  const identity = snapshotExactViteCacheTreeIdentity(entry[0]);
  const parentIdentity = entry[1] === null ? null : snapshotExactViteCacheTreeIdentity(entry[1]);
  const owner = snapshotExactViteCacheTreeOwner(entry[3]);
  if (
    identity === undefined ||
    parentIdentity === undefined ||
    owner === undefined ||
    typeof entry[2] !== 'string' ||
    typeof entry[4] !== 'number' ||
    typeof entry[5] !== 'string' ||
    typeof entry[6] !== 'number' ||
    typeof entry[7] !== 'number' ||
    typeof entry[8] !== 'number' ||
    typeof entry[9] !== 'boolean'
  ) {
    return undefined;
  }
  return Object.freeze({
    identity,
    parentIdentity,
    device: entry[2],
    owner,
    mode: entry[4],
    kind: entry[5] as CacheTreeEntry['kind'],
    depth: entry[6],
    sizeBytes: entry[7],
    linkCount: entry[8],
    escaped: entry[9],
  });
}

function snapshotExactViteCacheTreeIdentity(
  value: unknown,
): CacheTreeScan['rootIdentity'] | undefined {
  const identity = readExactViteCacheDataRecord(value, ['device', 'inode']);
  if (
    identity === undefined ||
    typeof identity[0] !== 'string' ||
    typeof identity[1] !== 'string'
  ) {
    return undefined;
  }
  return Object.freeze({ device: identity[0], inode: identity[1] });
}

function snapshotExactViteCacheTreeOwner(
  value: unknown,
): Readonly<{ uid: number; gid: number }> | undefined {
  const owner = readExactViteCacheDataRecord(value, ['uid', 'gid']);
  if (owner === undefined || typeof owner[0] !== 'number' || typeof owner[1] !== 'number') {
    return undefined;
  }
  return Object.freeze({ uid: owner[0], gid: owner[1] });
}

function readExactViteCacheDataRecord(
  value: unknown,
  keys: readonly string[],
): readonly unknown[] | undefined {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    return undefined;
  }
  const actual = Reflect.ownKeys(value);
  const expected = new Set(keys);
  if (
    expected.size !== keys.length ||
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== 'string' || !expected.has(key))
  ) {
    return undefined;
  }
  const values: unknown[] = [];
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
      return undefined;
    }
    values.push(descriptor.value);
  }
  return values;
}

function normalizeTokenHashes(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values)) {
    throw new Error('Token canaries must be SHA-256 hashes, not raw tokens');
  }
  if (values.length === 0) {
    throw new Error('At least one token canary hash is required');
  }
  if (values.length > VITE_CACHE_MAX_CANARY_HASHES) {
    throw new Error('Too many token canary hashes');
  }
  for (let index = 0; index < values.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(values, index)) {
      throw new Error('Token canary hashes must be dense');
    }
  }

  const hashes: string[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < values.length; index += 1) {
    const hash = normalizeSha256(values[index]!);
    if (!seen.has(hash)) {
      seen.add(hash);
      hashes.push(hash);
    }
  }
  return Object.freeze(hashes);
}

function isViteCacheWriterControl(value: unknown): value is ViteCacheWriterControl {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Partial<ViteCacheWriterControl>).abort === 'function' &&
    typeof (value as Partial<ViteCacheWriterControl>).terminate === 'function'
  );
}

function assertViteCacheWriterControl(value: unknown): asserts value is ViteCacheWriterControl {
  if (!isViteCacheWriterControl(value)) {
    throw new Error('Vite cache writer control is invalid.');
  }
}
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

function selectTerminalReason(
  current: ViteCacheMonitorReason | undefined,
  candidate: ViteCacheMonitorReason,
): ViteCacheMonitorReason {
  if (current === undefined) {
    return candidate;
  }
  return terminalReasonPrecedence(candidate) > terminalReasonPrecedence(current)
    ? candidate
    : current;
}

/** Unsafe ownership evidence outranks canary evidence, which outranks a watcher failure. */
function terminalReasonPrecedence(reason: ViteCacheMonitorReason): number {
  switch (reason) {
    case 'unsafe-tree':
      return 3;
    case 'token-canary-detected':
      return 2;
    case 'inspection-failed':
      return 1;
  }
}
function isSemanticViteCacheMonitorReason(reason: ViteCacheMonitorReason): boolean {
  return reason === 'unsafe-tree' || reason === 'token-canary-detected';
}

function normalizeSha256(value: string): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error('Token canaries must be SHA-256 hashes, not raw tokens');
  }
  return value;
}

function assertPollInterval(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > VITE_CACHE_MAX_POLL_INTERVAL_MS) {
    throw new Error(
      `Vite cache polling must be between 1 and ${VITE_CACHE_MAX_POLL_INTERVAL_MS}ms`,
    );
  }
}

function toMonitorError(error: unknown): ViteCacheMonitorError {
  return error instanceof ViteCacheMonitorError
    ? error
    : new ViteCacheMonitorError('inspection-failed');
}
function withCleanupFailures(
  error: unknown,
  cleanupFailures: readonly ViteCacheCleanupOperation[],
  compensationRequired = false,
): ViteCacheMonitorError {
  const monitorError = toMonitorError(error);
  if (cleanupFailures.length === 0 && !compensationRequired) {
    return monitorError;
  }
  return new ViteCacheMonitorError(
    monitorError.reason,
    [...new Set([...monitorError.cleanupFailures, ...cleanupFailures])],
    monitorError.compensationRequired || compensationRequired,
    monitorError.nativeSessionReleased,
  );
}

const globalScheduler: ViteCacheMonitorScheduler = {
  setInterval(task, delayMs) {
    return globalThis.setInterval(task, delayMs);
  },
  clearInterval(handle) {
    globalThis.clearInterval(handle as ReturnType<typeof globalThis.setInterval>);
  },
};
