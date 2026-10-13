import { afterEach, describe, expect, it, vi } from 'vitest';

import { RenderSettler } from '../../packages/browser-client/src/navigation/render-settled.js';

type FrameMode = 'available' | 'missing';

type FakeRenderEnvironment = {
  readonly document: Document;
  readonly window: Window;
  observerCount(): number;
  disconnectedObserverCount(): number;
  pendingFrameCount(): number;
  runNextFrame(): boolean;
};

type TrackedAbortSignal = {
  readonly signal: AbortSignal;
  abort(): void;
  listenerCount(): number;
};

function createRenderEnvironment(frameMode: FrameMode = 'available'): FakeRenderEnvironment {
  const frames = new Map<number, FrameRequestCallback>();
  let nextFrame = 1;
  let observerCount = 0;
  let disconnectedObserverCount = 0;

  class FakeMutationObserver {
    public constructor(callback: MutationCallback) {
      void callback;
      observerCount += 1;
    }

    public disconnect(): void {
      disconnectedObserverCount += 1;
    }

    public observe(target: Node, options: MutationObserverInit): void {
      void target;
      void options;
    }
  }

  const document = {
    defaultView: {
      MutationObserver: FakeMutationObserver,
    },
  } as unknown as Document;
  const window = {
    document,
    setTimeout(callback: () => void, delay = 0): number {
      return globalThis.setTimeout(callback, delay) as unknown as number;
    },
    clearTimeout(timer: number): void {
      globalThis.clearTimeout(timer);
    },
    cancelAnimationFrame(frame: number): void {
      frames.delete(frame);
    },
    ...(frameMode === 'available'
      ? {
          requestAnimationFrame(callback: FrameRequestCallback): number {
            const frame = nextFrame;
            nextFrame += 1;
            frames.set(frame, callback);
            return frame;
          },
        }
      : {}),
  } as unknown as Window;

  return {
    document,
    window,
    observerCount: () => observerCount,
    disconnectedObserverCount: () => disconnectedObserverCount,
    pendingFrameCount: () => frames.size,
    runNextFrame: (): boolean => {
      const nextFrameEntry = frames.entries().next().value as
        [number, FrameRequestCallback] | undefined;
      if (nextFrameEntry === undefined) {
        return false;
      }
      const [frame, callback] = nextFrameEntry;
      frames.delete(frame);
      callback(0);
      return true;
    },
  };
}

function createTrackedAbortSignal(): TrackedAbortSignal {
  let aborted = false;
  const listeners = new Set<EventListener>();
  const signal = {
    get aborted(): boolean {
      return aborted;
    },
    addEventListener(type: string, listener: EventListener | null): void {
      if (type === 'abort' && listener !== null) {
        listeners.add(listener);
      }
    },
    removeEventListener(type: string, listener: EventListener | null): void {
      if (type === 'abort' && listener !== null) {
        listeners.delete(listener);
      }
    },
  } as unknown as AbortSignal;

  return {
    signal,
    abort(): void {
      if (aborted) {
        return;
      }
      aborted = true;
      for (const listener of [...listeners]) {
        listener(new Event('abort'));
      }
    },
    listenerCount: () => listeners.size,
  };
}

describe('render settling contract', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('cancels a later same-generation waiter without cancelling its peer', async () => {
    vi.useFakeTimers();
    const environment = createRenderEnvironment();
    const first = createTrackedAbortSignal();
    const later = createTrackedAbortSignal();
    const settler = new RenderSettler({
      window: environment.window,
      document: environment.document,
      quietWindowMs: 5,
      maximumWaitMs: 20,
    });

    const firstWait = settler.waitFor(1, { signal: first.signal });
    const laterWait = settler.waitFor(1, { signal: later.signal });
    later.abort();

    await expect(laterWait).resolves.toBe(false);
    expect(later.listenerCount()).toBe(0);
    expect(first.listenerCount()).toBe(1);
    expect(environment.observerCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(5);
    expect(environment.runNextFrame()).toBe(true);
    expect(environment.runNextFrame()).toBe(true);

    await expect(firstWait).resolves.toBe(true);
    expect(first.listenerCount()).toBe(0);
    expect(environment.disconnectedObserverCount()).toBe(1);
    expect(environment.pendingFrameCount()).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancels the initiating waiter without cancelling a later same-generation waiter', async () => {
    vi.useFakeTimers();
    const environment = createRenderEnvironment();
    const first = createTrackedAbortSignal();
    const later = createTrackedAbortSignal();
    const settler = new RenderSettler({
      window: environment.window,
      document: environment.document,
      quietWindowMs: 5,
      maximumWaitMs: 20,
    });

    const firstWait = settler.waitFor(1, { signal: first.signal });
    const laterWait = settler.waitFor(1, { signal: later.signal });
    first.abort();

    await expect(firstWait).resolves.toBe(false);
    expect(first.listenerCount()).toBe(0);
    expect(later.listenerCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(5);
    expect(environment.runNextFrame()).toBe(true);
    expect(environment.runNextFrame()).toBe(true);

    await expect(laterWait).resolves.toBe(true);
    expect(later.listenerCount()).toBe(0);
    expect(environment.disconnectedObserverCount()).toBe(1);
    expect(environment.pendingFrameCount()).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('fails closed at the deadline when hidden-page frames are unavailable', async () => {
    vi.useFakeTimers();
    const environment = createRenderEnvironment('missing');
    const settler = new RenderSettler({
      window: environment.window,
      document: environment.document,
      quietWindowMs: 5,
      maximumWaitMs: 20,
    });

    const wait = settler.waitFor(1);
    await vi.advanceTimersByTimeAsync(19);
    expect(environment.disconnectedObserverCount()).toBe(0);

    await vi.advanceTimersByTimeAsync(1);

    await expect(wait).resolves.toBe(false);
    expect(environment.disconnectedObserverCount()).toBe(1);
    expect(environment.pendingFrameCount()).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('fails closed at the deadline while an available frame remains queued', async () => {
    vi.useFakeTimers();
    const environment = createRenderEnvironment();
    const settler = new RenderSettler({
      window: environment.window,
      document: environment.document,
      quietWindowMs: 5,
      maximumWaitMs: 20,
    });

    const wait = settler.waitFor(1);
    await vi.advanceTimersByTimeAsync(5);
    expect(environment.observerCount()).toBe(1);
    expect(environment.pendingFrameCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(14);
    expect(environment.disconnectedObserverCount()).toBe(0);
    expect(environment.pendingFrameCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(1);

    await expect(wait).resolves.toBe(false);
    expect(environment.disconnectedObserverCount()).toBe(1);
    expect(environment.pendingFrameCount()).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});
