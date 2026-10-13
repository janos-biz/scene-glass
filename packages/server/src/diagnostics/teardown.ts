import { isProjectId } from '@scene-glass/contracts';
import { SceneGlassLogger, type SceneGlassTerminalOutcome } from '../observability/logger.js';

const MAX_TIMEOUT_MS = 2_147_483_647;

export const DIAGNOSTIC_RUN_TTL_MS = 60_000;

export type DiagnosticTeardownReason =
  'client-close' | 'expired' | 'revoked' | 'abort' | 'shutdown';

export interface DiagnosticTeardownEvidence {
  readonly activeRunCount: number;
  readonly activeProjectCount: number;
  readonly activeTimerCount: number;
  readonly shutDown: boolean;
}

export interface RegisterDiagnosticRunInput {
  readonly runId: string;
  readonly projectId: string;
  readonly expiresAt: number;
  readonly cleanup: (reason: DiagnosticTeardownReason) => void;
}

export interface DiagnosticsTeardownOptions {
  /** Host-owned structured logger for redacted run terminal outcomes. */
  readonly logger?: SceneGlassLogger;
  /** Injectable only to make expiry behavior deterministic in tests. */
  readonly now?: () => number;
}

interface ActiveDiagnosticRun {
  readonly runId: string;
  readonly projectId: string;
  readonly expiresAt: number;
  readonly cleanups: Set<(reason: DiagnosticTeardownReason) => void>;
  timer: ReturnType<typeof setTimeout> | undefined;
}

/**
 * Owns all diagnostic run lifetimes. Entries are removed from accounting before
 * cleanup callbacks run, so cleanup is idempotent even when a callback aborts
 * or throws.
 */
export class DiagnosticsTeardown {
  readonly #runs = new Map<string, ActiveDiagnosticRun>();
  readonly #projectCounts = new Map<string, number>();
  readonly #now: () => number;
  readonly #logger: SceneGlassLogger;
  #shutDown = false;

  public constructor(options: DiagnosticsTeardownOptions = {}) {
    this.#logger = options.logger ?? new SceneGlassLogger();
    this.#now = options.now ?? Date.now;
  }

  public get activeRunCount(): number {
    return this.#runs.size;
  }

  public get activeProjectCount(): number {
    return this.#projectCounts.size;
  }

  public get activeTimerCount(): number {
    let count = 0;
    for (const entry of this.#runs.values()) {
      if (entry.timer !== undefined) {
        count += 1;
      }
    }
    return count;
  }

  public get shutDown(): boolean {
    return this.#shutDown;
  }

  public activeRunCountForProject(projectId: string): number {
    return this.#projectCounts.get(projectId) ?? 0;
  }

  public evidence(): DiagnosticTeardownEvidence {
    return Object.freeze({
      activeRunCount: this.activeRunCount,
      activeProjectCount: this.activeProjectCount,
      activeTimerCount: this.activeTimerCount,
      shutDown: this.#shutDown,
    });
  }

  public isEmpty(): boolean {
    return this.#runs.size === 0 && this.#projectCounts.size === 0 && this.activeTimerCount === 0;
  }

  /** Useful for server-shutdown and integration-test zero-count assertions. */
  public assertEmpty(): void {
    if (!this.isEmpty()) {
      throw new Error('diagnostic teardown still has active runs');
    }
  }

  /**
   * Registers one issued capability and starts its server-owned expiry timer.
   * A shutdown teardown cannot be re-opened.
   */
  public register(input: RegisterDiagnosticRunInput): boolean {
    assertRunId(input.runId);
    assertProjectId(input.projectId);
    assertSafeTime(input.expiresAt, 'diagnostic expiry time');
    if (typeof input.cleanup !== 'function') {
      throw new TypeError('diagnostic cleanup must be a function');
    }
    if (this.#shutDown) {
      return false;
    }

    const now = this.readNow();
    if (input.expiresAt <= now) {
      return false;
    }
    if (this.#runs.has(input.runId)) {
      throw new TypeError('diagnostic run id is already active');
    }

    const entry: ActiveDiagnosticRun = {
      runId: input.runId,
      projectId: input.projectId,
      expiresAt: input.expiresAt,
      cleanups: new Set([input.cleanup]),
      timer: undefined,
    };
    this.#runs.set(entry.runId, entry);
    this.incrementProjectCount(entry.projectId);
    this.armExpiry(entry, input.expiresAt - now);
    return this.#runs.get(entry.runId) === entry;
  }

  /** Adds cleanup owned by a later phase, such as an initialized session. */
  public addCleanup(runId: string, cleanup: (reason: DiagnosticTeardownReason) => void): boolean {
    if (typeof cleanup !== 'function') {
      throw new TypeError('diagnostic cleanup must be a function');
    }
    const entry = this.#runs.get(runId);
    if (entry === undefined) {
      return false;
    }
    entry.cleanups.add(cleanup);
    return true;
  }

  public close(runId: string): boolean {
    return this.teardown(runId, 'client-close');
  }

  public expire(runId: string): boolean {
    return this.teardown(runId, 'expired');
  }

  public revoke(runId: string): boolean {
    return this.teardown(runId, 'revoked');
  }

  public abort(runId: string): boolean {
    return this.teardown(runId, 'abort');
  }

  /** Shutdown is final and drains every timer, map entry, and accounting slot. */
  public shutdown(): number {
    if (this.#shutDown) {
      return 0;
    }
    this.#shutDown = true;
    let closed = 0;
    for (const runId of [...this.#runs.keys()]) {
      if (this.teardown(runId, 'shutdown')) {
        closed += 1;
      }
    }
    return closed;
  }

  private teardown(
    runId: string,
    reason: DiagnosticTeardownReason,
    expiryClockFailed = false,
  ): boolean {
    if (typeof runId !== 'string' || runId.length === 0) {
      return false;
    }
    const entry = this.#runs.get(runId);
    if (entry === undefined) {
      return false;
    }

    this.#runs.delete(runId);
    this.decrementProjectCount(entry.projectId);
    if (entry.timer !== undefined) {
      clearTimeout(entry.timer);
      entry.timer = undefined;
    }
    const cleanupFailures: unknown[] = [];
    for (const cleanup of entry.cleanups) {
      try {
        cleanup(reason);
      } catch (error: unknown) {
        cleanupFailures.push(error);
      }
    }
    entry.cleanups.clear();

    if (expiryClockFailed) {
      this.#logger.emit(
        'diagnostics.rejected',
        { expiryClockFailureCount: 1 },
        { runId: entry.runId },
      );
    }
    if (cleanupFailures.length > 0) {
      this.#logger.emit(
        'cleanup.failed',
        { cleanupFailureCount: cleanupFailures.length },
        { runId: entry.runId },
      );
    }
    this.emitTerminal(
      entry.runId,
      cleanupFailures.length === 0 && !expiryClockFailed ? terminalOutcomeFor(reason) : 'failure',
    );
    return true;
  }

  private emitTerminal(runId: string, outcome: SceneGlassTerminalOutcome): void {
    this.#logger.terminal({ runId }, outcome);
  }

  private armExpiry(entry: ActiveDiagnosticRun, remaining: number): void {
    const schedule = (): void => {
      if (this.#runs.get(entry.runId) !== entry) {
        return;
      }

      let current: number;
      try {
        current = this.readNow();
      } catch {
        // A broken clock must not extend a diagnostic capability.
        this.teardown(entry.runId, 'expired', true);
        return;
      }
      const nextRemaining = entry.expiresAt - current;
      if (nextRemaining <= 0) {
        this.expire(entry.runId);
        return;
      }
      entry.timer = setTimeout(schedule, Math.min(nextRemaining, MAX_TIMEOUT_MS));
    };

    entry.timer = setTimeout(schedule, Math.min(remaining, MAX_TIMEOUT_MS));
  }

  private incrementProjectCount(projectId: string): void {
    this.#projectCounts.set(projectId, this.activeRunCountForProject(projectId) + 1);
  }

  private decrementProjectCount(projectId: string): void {
    const next = this.activeRunCountForProject(projectId) - 1;
    if (next <= 0) {
      this.#projectCounts.delete(projectId);
    } else {
      this.#projectCounts.set(projectId, next);
    }
  }

  private readNow(): number {
    const now = this.#now();
    assertSafeTime(now, 'diagnostic clock time');
    return now;
  }
}

function terminalOutcomeFor(reason: DiagnosticTeardownReason): SceneGlassTerminalOutcome {
  return reason === 'client-close' ? 'success' : 'cancelled';
}
function assertRunId(value: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new TypeError('diagnostic run id is invalid');
  }
}

function assertProjectId(value: string): void {
  if (!isProjectId(value)) {
    throw new TypeError('diagnostic project id is invalid');
  }
}

function assertSafeTime(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}
