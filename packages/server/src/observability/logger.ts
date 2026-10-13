import {
  hashProjectId,
  redactLogRecord,
  redactLogValue,
  type RedactedLogValue,
} from './redaction.js';

export const SCENE_GLASS_LOG_EVENTS = [
  'bind.ready',
  'bind.rejected',
  'config.accepted',
  'config.rejected',
  'origin.accepted',
  'origin.rejected',
  'origin.applied',
  'auth.accepted',
  'auth.rejected',
  'root.authorized',
  'root.changed',
  'root.rejected',
  'session.created',
  'session.expired',
  'session.rejected',
  'store.committed',
  'store.rejected',
  'store.indeterminate',
  'replay.hit',
  'replay.recorded',
  'replay.rejected',
  'diagnostics.started',
  'diagnostics.completed',
  'diagnostics.rejected',
  'cleanup.failed',
  'terminal.success',
  'terminal.failure',
  'terminal.cancelled',
] as const;

export type SceneGlassLogEvent = (typeof SCENE_GLASS_LOG_EVENTS)[number];
export type SceneGlassTerminalOutcome = 'success' | 'failure' | 'cancelled';
export type SceneGlassTerminalEvent = `terminal.${SceneGlassTerminalOutcome}`;

export interface SceneGlassLogScope {
  readonly requestId?: string;
  readonly runId?: string;
}

export interface SceneGlassLogRecord {
  readonly timestamp: string;
  readonly event: SceneGlassLogEvent;
  readonly scope?: Readonly<Record<string, string>>;
  readonly data?: RedactedLogValue;
}

export type SceneGlassLogSink = (record: SceneGlassLogRecord) => void;
export type SceneGlassLogData = Readonly<Record<string, unknown>>;

export interface SceneGlassLoggerOptions {
  /** A process-local sink; the logger never writes to console implicitly. */
  readonly sink?: SceneGlassLogSink;
  /** Injectable clock for deterministic callers and conformance tests. */
  readonly now?: () => Date;
}

const NOOP_SINK: SceneGlassLogSink = () => undefined;
const EVENT_NAMES = new Set<string>(SCENE_GLASS_LOG_EVENTS);
const MAX_TERMINAL_SCOPE_EVENTS = 1_024;

/**
 * Structured, secret-free operational logging. Request and diagnostic
 * lifecycles own terminal-event uniqueness; this sink retains only a bounded
 * recent assertion window and never rejects a terminal event.
 */
export class SceneGlassLogger {
  readonly #sink: SceneGlassLogSink;
  readonly #now: () => Date;
  readonly #terminalCounts = new Map<string, number>();
  readonly #terminalScopeEvents: string[][] = [];
  #sinkFailureCount = 0;

  constructor(options: SceneGlassLoggerOptions | SceneGlassLogSink = {}) {
    if (typeof options === 'function') {
      this.#sink = options;
      this.#now = () => new Date();
      return;
    }
    this.#sink = options.sink ?? NOOP_SINK;
    this.#now = options.now ?? (() => new Date());
  }

  emit(
    event: SceneGlassLogEvent,
    data?: SceneGlassLogData,
    scope?: SceneGlassLogScope,
  ): SceneGlassLogRecord {
    if (!EVENT_NAMES.has(event)) {
      throw new Error('Unknown Scene Glass log event');
    }

    const terminalScopeKeys = isTerminalEvent(event) ? scopeKeys(scope, true) : [];

    const timestamp = this.#now();
    const record = Object.freeze({
      timestamp: timestamp.toISOString(),
      event,
      ...(scope === undefined ? {} : { scope: redactScope(scope) }),
      ...(data === undefined ? {} : { data: redactLogRecord(data) }),
    });

    if (terminalScopeKeys.length > 0) {
      this.rememberTerminalScopes(terminalScopeKeys);
    }
    try {
      this.#sink(record);
    } catch {
      this.#sinkFailureCount = Math.min(Number.MAX_SAFE_INTEGER, this.#sinkFailureCount + 1);
    }
    return record;
  }

  public get sinkFailureCount(): number {
    return this.#sinkFailureCount;
  }

  terminal(
    scope: SceneGlassLogScope,
    outcome: SceneGlassTerminalOutcome,
    data?: SceneGlassLogData,
  ): SceneGlassLogRecord {
    return this.emit(`terminal.${outcome}`, data, scope);
  }

  /** Checks the bounded recent terminal-event assertion window for a scope. */
  public assertOneTerminalEvent(scope: SceneGlassLogScope): void {
    for (const key of scopeKeys(scope, true)) {
      if (this.#terminalCounts.get(key) !== 1) {
        throw new Error('Expected exactly one terminal log event');
      }
    }
  }

  private rememberTerminalScopes(keys: readonly string[]): void {
    this.#terminalScopeEvents.push([...keys]);
    for (const key of keys) {
      this.#terminalCounts.set(key, (this.#terminalCounts.get(key) ?? 0) + 1);
    }
    if (this.#terminalScopeEvents.length <= MAX_TERMINAL_SCOPE_EVENTS) {
      return;
    }

    const expired = this.#terminalScopeEvents.shift();
    if (expired === undefined) {
      return;
    }
    for (const key of expired) {
      const count = (this.#terminalCounts.get(key) ?? 0) - 1;
      if (count <= 0) {
        this.#terminalCounts.delete(key);
      } else {
        this.#terminalCounts.set(key, count);
      }
    }
  }

  /** Returns serialized output only after a defensive second redaction pass. */
  serialize(record: SceneGlassLogRecord): string {
    return JSON.stringify(redactLogValue(record));
  }
}

function isTerminalEvent(event: SceneGlassLogEvent): event is SceneGlassTerminalEvent {
  return event.startsWith('terminal.');
}

function scopeKeys(scope: SceneGlassLogScope | undefined, required: boolean): string[] {
  const keys: string[] = [];
  if (scope?.requestId !== undefined) {
    assertScopeIdentifier(scope.requestId);
    keys.push(hashLogIdentifier('request', scope.requestId));
  }
  if (scope?.runId !== undefined) {
    assertScopeIdentifier(scope.runId);
    keys.push(hashLogIdentifier('run', scope.runId));
  }
  if (required && keys.length === 0) {
    throw new Error('Terminal log events require a requestId or runId');
  }
  return keys;
}

function redactScope(scope: SceneGlassLogScope): Readonly<Record<string, string>> {
  const result: Record<string, string> = Object.create(null);
  if (scope.requestId !== undefined) {
    assertScopeIdentifier(scope.requestId);
    result.requestIdHash = hashLogIdentifier('request', scope.requestId);
  }
  if (scope.runId !== undefined) {
    assertScopeIdentifier(scope.runId);
    result.runIdHash = hashLogIdentifier('run', scope.runId);
  }
  return Object.freeze(result);
}

function assertScopeIdentifier(value: string): void {
  if (value.length === 0) {
    throw new Error('Log scope identifiers must be non-empty');
  }
}

function hashLogIdentifier(namespace: 'request' | 'run', value: string): string {
  const projectScoped = hashProjectId(`${namespace}\u0000${value}`);
  return `${namespace}_${projectScoped.slice('project_'.length)}`;
}
