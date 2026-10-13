export interface RenderSettlerOptions {
  readonly window?: Window;
  readonly document?: Document;
  readonly waitForHostReady?: boolean;
  readonly quietWindowMs?: number;
  readonly maximumWaitMs?: number;
}

export interface RenderSettledWaitOptions {
  readonly signal?: AbortSignal;
}

interface PendingRenderWait {
  readonly generation: number;
  readonly promise: Promise<boolean>;
  readonly resolve: (settled: boolean) => void;
  cleanup: () => void;
  closed: boolean;
}

/** 로더가 붙이는 식별자 속성. 호스트 렌더로 세지 않는다. */
const SCENE_GLASS_ID_ATTRIBUTE = 'data-scg-id';

function isSceneGlassIdMutation(record: MutationRecord): boolean {
  return record.type === 'attributes' && record.attributeName === SCENE_GLASS_ID_ATTRIBUTE;
}

const DEFAULT_QUIET_WINDOW_MS = 75;
const DEFAULT_MAXIMUM_WAIT_MS = 1_000;

/**
 * Latest-wins render settling for a single browser document. A host that
 * integrates the exposed notifyReady callback opts into explicit readiness;
 * other hosts use the bounded DOM quiet-window fallback.
 */
export class RenderSettler {
  private readonly window: Window;
  private readonly document: Document;
  private readonly waitForHostReady: boolean;
  private readonly quietWindowMs: number;
  private readonly maximumWaitMs: number;
  private active: PendingRenderWait | undefined;
  private latestGeneration = 0;
  private lastSettledGeneration = 0;
  private readyGeneration: number | undefined;
  private isTornDown = false;

  public constructor(options: RenderSettlerOptions = {}) {
    this.window = options.window ?? globalThis.window;
    this.document = options.document ?? this.window.document;
    this.waitForHostReady = options.waitForHostReady === true;
    this.quietWindowMs = validateDuration(
      options.quietWindowMs,
      DEFAULT_QUIET_WINDOW_MS,
      'quietWindowMs',
    );
    this.maximumWaitMs = validateDuration(
      options.maximumWaitMs,
      DEFAULT_MAXIMUM_WAIT_MS,
      'maximumWaitMs',
    );
  }

  /** A host may call this directly, or publish this bound callback as its API. */
  public readonly notifyReady = (generation = this.latestGeneration): void => {
    if (this.isTornDown || generation < this.latestGeneration) {
      return;
    }

    const active = this.active;
    if (this.waitForHostReady && active !== undefined && active.generation === generation) {
      this.finish(active, true);
      return;
    }

    this.readyGeneration = generation;
  };

  /**
   * Resolves true only when this generation remains current at the point it
   * settles. A false result is aborted, stale, or torn down and must not attach
   * page-specific client behavior.
   */
  public waitFor(generation: number, options: RenderSettledWaitOptions = {}): Promise<boolean> {
    assertGeneration(generation);
    if (this.isTornDown || options.signal?.aborted === true) {
      return Promise.resolve(false);
    }
    if (generation < this.latestGeneration) {
      return Promise.resolve(false);
    }
    if (generation === this.latestGeneration) {
      if (this.active !== undefined) {
        return waitForCaller(this.active.promise, options.signal);
      }
      if (this.lastSettledGeneration === generation) {
        return Promise.resolve(true);
      }
    } else {
      const active = this.active;
      this.latestGeneration = generation;
      this.lastSettledGeneration = 0;
      if (this.readyGeneration !== generation) {
        this.readyGeneration = undefined;
      }
      if (active !== undefined) {
        this.finish(active, false);
      }
    }

    if (this.waitForHostReady && this.readyGeneration === generation) {
      this.lastSettledGeneration = generation;
      return Promise.resolve(true);
    }

    let resolvePromise: (settled: boolean) => void = () => {};
    const promise = new Promise<boolean>((resolve) => {
      resolvePromise = resolve;
    });
    const pending: PendingRenderWait = {
      generation,
      promise,
      resolve: resolvePromise,
      cleanup: () => {},
      closed: false,
    };
    this.active = pending;
    const callerPromise = waitForCaller(promise, options.signal);

    if (this.waitForHostReady) {
      this.waitForHostSignal(pending);
    } else {
      this.waitForDomQuiet(pending);
    }
    return callerPromise;
  }

  public isCurrent(generation: number): boolean {
    return !this.isTornDown && generation === this.latestGeneration;
  }

  public teardown(): void {
    if (this.isTornDown) {
      return;
    }
    this.isTornDown = true;
    this.readyGeneration = undefined;
    if (this.active !== undefined) {
      this.finish(this.active, false);
    }
  }

  private waitForHostSignal(pending: PendingRenderWait): void {
    let maximumTimer: number | undefined;
    const cleanup = (): void => {
      if (maximumTimer !== undefined) {
        clearTimer(this.window, maximumTimer);
        maximumTimer = undefined;
      }
    };

    pending.cleanup = cleanup;

    let deadlineFired = false;
    const timer = scheduleTimer(
      this.window,
      () => {
        deadlineFired = true;
        maximumTimer = undefined;
        this.finish(pending, false);
      },
      this.maximumWaitMs,
    );
    if (timer === undefined) {
      this.finish(pending, false);
      return;
    }
    if (deadlineFired || pending.closed) {
      clearTimer(this.window, timer);
      return;
    }
    maximumTimer = timer;
  }

  private waitForDomQuiet(pending: PendingRenderWait): void {
    let observer: MutationObserver | undefined;
    let quietTimer: number | undefined;
    let maximumTimer: number | undefined;
    let firstFrame: number | undefined;
    let secondFrame: number | undefined;

    const clearQuietTimer = (): void => {
      if (quietTimer !== undefined) {
        clearTimer(this.window, quietTimer);
        quietTimer = undefined;
      }
    };
    const clearFrames = (): void => {
      if (firstFrame !== undefined) {
        cancelFrame(this.window, firstFrame);
        firstFrame = undefined;
      }
      if (secondFrame !== undefined) {
        cancelFrame(this.window, secondFrame);
        secondFrame = undefined;
      }
    };
    const cleanup = (): void => {
      clearQuietTimer();
      clearFrames();
      if (maximumTimer !== undefined) {
        clearTimer(this.window, maximumTimer);
        maximumTimer = undefined;
      }
      const activeObserver = observer;
      observer = undefined;
      try {
        activeObserver?.disconnect();
      } catch {
        // The terminal result must not be blocked by hostile observer implementations.
      }
    };
    const isActive = (): boolean =>
      !pending.closed &&
      !this.isTornDown &&
      this.active === pending &&
      pending.generation === this.latestGeneration;
    const scheduleSecondFrame = (): void => {
      let frameFired = false;
      const frame = requestFrame(this.window, () => {
        frameFired = true;
        secondFrame = undefined;
        if (isActive()) {
          this.finish(pending, true);
        }
      });
      if (frame === undefined) {
        return;
      }
      if (frameFired || !isActive()) {
        cancelFrame(this.window, frame);
        return;
      }
      secondFrame = frame;
    };
    const settleAfterFrames = (): void => {
      if (!isActive()) {
        return;
      }
      clearQuietTimer();
      if (firstFrame !== undefined || secondFrame !== undefined) {
        return;
      }

      let frameFired = false;
      const frame = requestFrame(this.window, () => {
        frameFired = true;
        firstFrame = undefined;
        if (isActive()) {
          scheduleSecondFrame();
        }
      });
      if (frame === undefined) {
        return;
      }
      if (frameFired || !isActive()) {
        cancelFrame(this.window, frame);
        return;
      }
      firstFrame = frame;
    };
    const scheduleQuietWindow = (): void => {
      if (!isActive()) {
        return;
      }
      clearQuietTimer();
      clearFrames();

      let timerFired = false;
      const timer = scheduleTimer(
        this.window,
        () => {
          timerFired = true;
          quietTimer = undefined;
          settleAfterFrames();
        },
        this.quietWindowMs,
      );
      if (timer === undefined) {
        return;
      }
      if (timerFired || !isActive()) {
        clearTimer(this.window, timer);
        return;
      }
      quietTimer = timer;
    };

    pending.cleanup = cleanup;

    let deadlineFired = false;
    const deadlineTimer = scheduleTimer(
      this.window,
      () => {
        deadlineFired = true;
        maximumTimer = undefined;
        this.finish(pending, false);
      },
      this.maximumWaitMs,
    );
    if (deadlineTimer === undefined) {
      this.finish(pending, false);
      return;
    }
    if (deadlineFired || pending.closed) {
      clearTimer(this.window, deadlineTimer);
      return;
    }
    maximumTimer = deadlineTimer;

    const MutationObserverConstructor =
      this.document.defaultView?.MutationObserver ?? globalThis.MutationObserver;
    if (typeof MutationObserverConstructor !== 'function') {
      this.finish(pending, false);
      return;
    }

    try {
      const nextObserver = new MutationObserverConstructor((records) => {
        // Scene Glass 가 스스로 찍는 식별자는 호스트의 렌더가 아니다. 이걸 세면 스탬프가
        // 정적 구간을 매번 다시 열어 `waitFor` 가 영영 풀리지 않는다.
        if (records.every(isSceneGlassIdMutation)) {
          return;
        }
        scheduleQuietWindow();
      });
      observer = nextObserver;
      nextObserver.observe(this.document, {
        attributes: true,
        characterData: true,
        childList: true,
        subtree: true,
      });
      scheduleQuietWindow();
    } catch {
      this.finish(pending, false);
    }
  }

  private finish(pending: PendingRenderWait, settled: boolean): void {
    if (pending.closed) {
      return;
    }
    pending.closed = true;
    pending.cleanup();
    if (this.active === pending) {
      this.active = undefined;
    }

    const isCurrent = settled && !this.isTornDown && pending.generation === this.latestGeneration;
    if (isCurrent) {
      this.lastSettledGeneration = pending.generation;
    }
    pending.resolve(isCurrent);
  }
}

export function createRenderSettler(options?: RenderSettlerOptions): RenderSettler {
  return new RenderSettler(options);
}

function assertGeneration(generation: number): void {
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new RangeError('generation must be a positive safe integer');
  }
}

function validateDuration(value: number | undefined, defaultValue: number, name: string): number {
  const duration = value ?? defaultValue;
  if (!Number.isFinite(duration) || duration < 0) {
    throw new RangeError(`${name} must be a non-negative finite number`);
  }
  return duration;
}

function listenForAbort(signal: AbortSignal | undefined, onAbort: () => void): () => void {
  if (signal === undefined) {
    return () => {};
  }
  signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}
function waitForCaller(
  promise: Promise<boolean>,
  signal: AbortSignal | undefined,
): Promise<boolean> {
  if (signal === undefined) {
    return promise;
  }
  if (signal.aborted) {
    return Promise.resolve(false);
  }

  return new Promise<boolean>((resolve) => {
    let complete = false;
    let removeAbortListener = (): void => {};
    const finish = (settled: boolean): void => {
      if (complete) {
        return;
      }
      complete = true;
      try {
        removeAbortListener();
      } catch {
        // A broken AbortSignal implementation must not block this caller's result.
      }
      resolve(settled);
    };

    removeAbortListener = listenForAbort(signal, () => finish(false));
    if (signal.aborted) {
      finish(false);
      return;
    }
    void promise.then(
      (settled) => finish(settled),
      () => finish(false),
    );
  });
}

function scheduleTimer(window: Window, callback: () => void, delay: number): number | undefined {
  const setTimeout = window.setTimeout;
  if (typeof setTimeout !== 'function') {
    return undefined;
  }
  try {
    return setTimeout.call(window, callback, delay);
  } catch {
    return undefined;
  }
}

function clearTimer(window: Window, timer: number): void {
  try {
    window.clearTimeout(timer);
  } catch {
    // The terminal result must not be blocked by hostile timer implementations.
  }
}

function requestFrame(window: Window, callback: FrameRequestCallback): number | undefined {
  const requestAnimationFrame = window.requestAnimationFrame;
  if (typeof requestAnimationFrame !== 'function') {
    return undefined;
  }
  try {
    return requestAnimationFrame.call(window, callback);
  } catch {
    return undefined;
  }
}

function cancelFrame(window: Window, frame: number): void {
  try {
    window.cancelAnimationFrame(frame);
  } catch {
    // The terminal result must not be blocked by hostile frame implementations.
  }
}
