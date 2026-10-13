export const DIAGNOSTIC_STEP_NAMES = [
  'test-token',
  'connection',
  'authentication',
  'round-trip',
] as const;

export type DiagnosticStepName = (typeof DIAGNOSTIC_STEP_NAMES)[number];
export type DiagnosticStepState = 'idle' | 'running' | 'passed' | 'failed' | 'cleaned';
export type DiagnosticRunState = DiagnosticStepState;

export interface DiagnosticConnection {
  readonly id: string;
}

export interface DiagnosticsTransport {
  issueProjectTestToken(input: { readonly projectId: string }): Promise<{ readonly token: string }>;
  initialize(input: {
    readonly projectId: string;
    readonly token: string;
  }): Promise<DiagnosticConnection>;
  sendInitializedNotification(input: { readonly connection: DiagnosticConnection }): Promise<void>;
  ping(input: { readonly connection: DiagnosticConnection }): Promise<void>;
  deleteClose(input: { readonly connection: DiagnosticConnection }): Promise<void>;
}

export interface DiagnosticsControllerOptions {
  readonly projectId: string;
  readonly transport: DiagnosticsTransport;
  readonly now?: () => number;
}

export interface DiagnosticStepSnapshot {
  readonly state: DiagnosticStepState;
  readonly durationMs: number;
}

export interface DiagnosticsFailure {
  readonly step: DiagnosticStepName | 'cleanup';
  readonly code: string;
  readonly message: string;
  readonly remediation: string;
}

export interface DiagnosticsSnapshot {
  readonly state: DiagnosticRunState;
  readonly durationMs: number;
  readonly steps: Readonly<Record<DiagnosticStepName, DiagnosticStepSnapshot>>;
  readonly cleanup: DiagnosticStepSnapshot;
  readonly failure: DiagnosticsFailure | null;
}

export interface DiagnosticsController {
  open(): void;
  run(): Promise<DiagnosticsSnapshot>;
  subscribe(listener: (snapshot: DiagnosticsSnapshot) => void): () => void;
  destroy(): void;
}

type MutableStepSnapshot = {
  state: DiagnosticStepState;
  durationMs: number;
};

type DiagnosticPhase = DiagnosticStepName | 'cleanup';

const FALLBACK_FAILURES: Readonly<Record<DiagnosticPhase, Omit<DiagnosticsFailure, 'step'>>> =
  Object.freeze({
    'test-token': {
      code: 'SCG_DIAGNOSTIC_TOKEN_FAILED',
      message: 'A diagnostic test token could not be issued.',
      remediation: 'Confirm the local server is running for this project, then try again.',
    },
    connection: {
      code: 'SCG_DIAGNOSTIC_CONNECTION_FAILED',
      message: 'The diagnostic connection could not be established.',
      remediation: 'Confirm Scene Glass is available on this page, then try again.',
    },
    authentication: {
      code: 'SCG_DIAGNOSTIC_AUTHENTICATION_FAILED',
      message: 'The diagnostic initialization was not accepted.',
      remediation: 'Reload the page to receive the current project capability, then try again.',
    },
    'round-trip': {
      code: 'SCG_DIAGNOSTIC_ROUND_TRIP_FAILED',
      message: 'The diagnostic ping did not complete.',
      remediation: 'Confirm the local server is running, then try again.',
    },
    cleanup: {
      code: 'SCG_DIAGNOSTIC_CLEANUP_FAILED',
      message: 'The diagnostic connection could not be closed.',
      remediation: 'Reload the page before starting another diagnostic.',
    },
  });

const STABLE_CODE = /^SCG_[A-Z0-9_]{1,80}$/;

export function createDiagnosticsController(
  options: DiagnosticsControllerOptions,
): DiagnosticsController {
  let projectId = options.projectId;
  let clock = options.now;
  let transport: DiagnosticsTransport | null = options.transport;
  let opened = false;
  let destroyed = false;
  let activeRun: Promise<DiagnosticsSnapshot> | null = null;
  let timer: ReturnType<typeof setInterval> | null = null;
  let startedAt: number | null = null;
  let elapsedMs = 0;
  let activePhase: DiagnosticPhase | null = null;
  let state: DiagnosticRunState = 'idle';
  let failure: DiagnosticsFailure | null = null;
  let cleanup: MutableStepSnapshot = { state: 'idle', durationMs: 0 };
  const steps: Record<DiagnosticStepName, MutableStepSnapshot> = {
    'test-token': { state: 'idle', durationMs: 0 },
    connection: { state: 'idle', durationMs: 0 },
    authentication: { state: 'idle', durationMs: 0 },
    'round-trip': { state: 'idle', durationMs: 0 },
  };
  const listeners = new Set<(snapshot: DiagnosticsSnapshot) => void>();
  let snapshot = freezeSnapshot(state, elapsedMs, steps, cleanup, failure);

  const publish = (): void => {
    snapshot = freezeSnapshot(state, readElapsed(), steps, cleanup, failure);
    if (destroyed) {
      return;
    }
    for (const listener of listeners) {
      try {
        listener(snapshot);
      } catch {
        // A diagnostic observer must not interrupt the host page or this run.
      }
    }
  };

  const setPhase = (phase: DiagnosticPhase, next: DiagnosticStepState): void => {
    const target = phase === 'cleanup' ? cleanup : steps[phase];
    target.state = next;
    target.durationMs = readElapsed();
    activePhase = next === 'running' ? phase : null;
    publish();
  };

  const startTimer = (): void => {
    if (timer !== null) {
      clearInterval(timer);
    }
    timer = setInterval(() => {
      if (destroyed || activePhase === null) {
        return;
      }
      const target = activePhase === 'cleanup' ? cleanup : steps[activePhase];
      target.durationMs = readElapsed();
      publish();
    }, 100);
  };

  const stopTimer = (): void => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };

  const resetRun = (): void => {
    elapsedMs = 0;
    startedAt = readClock(clock);
    activePhase = null;
    state = 'running';
    failure = null;
    cleanup = { state: 'idle', durationMs: 0 };
    for (const name of DIAGNOSTIC_STEP_NAMES) {
      steps[name] = { state: 'idle', durationMs: 0 };
    }
    startTimer();
    publish();
  };

  const run = async (): Promise<DiagnosticsSnapshot> => {
    const activeTransport = transport;
    if (!opened || destroyed || activeTransport === null) {
      return snapshot;
    }

    resetRun();
    let testToken = '';
    let connection: DiagnosticConnection | null = null;
    let runFailed = false;

    try {
      setPhase('test-token', 'running');
      testToken = (
        await activeTransport.issueProjectTestToken({
          projectId,
        })
      ).token;
      if (testToken.length === 0) {
        throw new Error('missing diagnostic token');
      }
      setPhase('test-token', 'passed');

      setPhase('connection', 'running');
      connection = await activeTransport.initialize({
        projectId,
        token: testToken,
      });
      testToken = '';
      setPhase('connection', 'passed');

      setPhase('authentication', 'running');
      await activeTransport.sendInitializedNotification({ connection });
      setPhase('authentication', 'passed');

      setPhase('round-trip', 'running');
      await activeTransport.ping({ connection });
      setPhase('round-trip', 'passed');
      state = 'passed';
      publish();
    } catch (error: unknown) {
      runFailed = true;
      const phase = activePhase ?? 'test-token';
      failure = redactedFailure(phase, error);
      setPhase(phase, 'failed');
    } finally {
      testToken = '';
      if (connection === null) {
        setPhase('cleanup', 'cleaned');
      } else {
        setPhase('cleanup', 'running');
        try {
          await activeTransport.deleteClose({ connection });
          setPhase('cleanup', 'cleaned');
        } catch (error: unknown) {
          runFailed = true;
          failure = redactedFailure('cleanup', error);
          setPhase('cleanup', 'failed');
        }
      }
      connection = null;
      activePhase = null;
      state = runFailed ? 'failed' : 'cleaned';
      stopTimer();
      publish();
    }

    return snapshot;
  };

  const controller: DiagnosticsController = {
    open(): void {
      if (!destroyed) {
        opened = true;
      }
    },
    run(): Promise<DiagnosticsSnapshot> {
      if (activeRun !== null) {
        return activeRun;
      }
      const pending = run();
      activeRun = pending;
      void pending.then(
        () => {
          if (activeRun === pending) {
            activeRun = null;
          }
        },
        () => {
          if (activeRun === pending) {
            activeRun = null;
          }
        },
      );
      return pending;
    },
    subscribe(listener: (next: DiagnosticsSnapshot) => void): () => void {
      if (destroyed) {
        return (): void => {};
      }
      listeners.add(listener);
      try {
        listener(snapshot);
      } catch {
        // A diagnostic observer must not interrupt the host page or this run.
      }
      let subscribed = true;
      return (): void => {
        if (subscribed) {
          subscribed = false;
          listeners.delete(listener);
        }
      };
    },
    destroy(): void {
      if (destroyed) {
        return;
      }
      destroyed = true;
      opened = false;
      stopTimer();
      listeners.clear();
      transport = null;
      activeRun = null;
      projectId = '';
      clock = undefined;
      startedAt = null;
      activePhase = null;
      failure = null;
      cleanup = { state: 'cleaned', durationMs: 0 };
      for (const name of DIAGNOSTIC_STEP_NAMES) {
        steps[name] = { state: 'cleaned', durationMs: 0 };
      }
      snapshot = freezeSnapshot('cleaned', 0, steps, cleanup, null);
    },
  };

  return controller;

  function readElapsed(): number {
    if (startedAt === null) {
      return elapsedMs;
    }
    const candidate = Math.max(0, Math.round(readClock(clock) - startedAt));
    elapsedMs = Math.max(elapsedMs, candidate);
    return elapsedMs;
  }
}

function freezeSnapshot(
  state: DiagnosticRunState,
  durationMs: number,
  steps: Readonly<Record<DiagnosticStepName, MutableStepSnapshot>>,
  cleanup: MutableStepSnapshot,
  failure: DiagnosticsFailure | null,
): DiagnosticsSnapshot {
  return Object.freeze({
    state,
    durationMs,
    steps: Object.freeze({
      'test-token': freezeStep(steps['test-token']),
      connection: freezeStep(steps.connection),
      authentication: freezeStep(steps.authentication),
      'round-trip': freezeStep(steps['round-trip']),
    }),
    cleanup: freezeStep(cleanup),
    failure: failure === null ? null : Object.freeze({ ...failure }),
  });
}

function freezeStep(step: MutableStepSnapshot): DiagnosticStepSnapshot {
  return Object.freeze({ state: step.state, durationMs: step.durationMs });
}

function readClock(now: (() => number) | undefined): number {
  try {
    const value = now === undefined ? performance.now() : now();
    return Number.isFinite(value) ? value : 0;
  } catch {
    return 0;
  }
}

function redactedFailure(phase: DiagnosticPhase, error: unknown): DiagnosticsFailure {
  const fallback = FALLBACK_FAILURES[phase];
  return Object.freeze({
    step: phase,
    code: stableErrorCode(error, fallback.code),
    message: fallback.message,
    remediation: fallback.remediation,
  });
}

function stableErrorCode(error: unknown, fallback: string): string {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return fallback;
  }
  const candidate = (error as { readonly code?: unknown }).code;
  return typeof candidate === 'string' && STABLE_CODE.test(candidate) ? candidate : fallback;
}
