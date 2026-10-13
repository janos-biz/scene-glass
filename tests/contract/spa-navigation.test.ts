import { describe, expect, it } from 'vitest';

import { createSpaNavigationAdapter } from '../../packages/browser-client/src/navigation/spa.js';

type HistoryMethod = History['pushState'];
type SetFailure = (next: HistoryMethod) => unknown | undefined;

type NavigationEventName = 'hashchange' | 'popstate';

interface FakeWindow {
  readonly history: History;
  readonly originalPushState: HistoryMethod;
  readonly originalReplaceState: HistoryMethod;
  readonly window: Window;
  dispatch(eventName: NavigationEventName): void;
  listenerCount(eventName: NavigationEventName): number;
  setPushStateFailure(failure: SetFailure | undefined): void;
  setReplaceStateFailure(failure: SetFailure | undefined): void;
}

function createFakeWindow(
  options: { readonly inheritedHistoryMethods?: boolean } = {},
): FakeWindow {
  const originalPushState: HistoryMethod = function (this: History): void {};
  const originalReplaceState: History['replaceState'] = function (this: History): void {};
  let pushState = originalPushState;
  let replaceState = originalReplaceState;
  let pushStateFailure: SetFailure | undefined;
  let replaceStateFailure: SetFailure | undefined;
  const eventListeners = new Map<string, Set<EventListenerOrEventListenerObject>>();
  const history = (
    options.inheritedHistoryMethods
      ? Object.create({
          pushState: originalPushState,
          replaceState: originalReplaceState,
        })
      : {}
  ) as History;

  if (!options.inheritedHistoryMethods) {
    Object.defineProperties(history, {
      pushState: {
        configurable: true,
        get: (): HistoryMethod => pushState,
        set(next: HistoryMethod): void {
          const failure = pushStateFailure?.(next);
          if (failure !== undefined) {
            throw failure;
          }
          pushState = next;
        },
      },
      replaceState: {
        configurable: true,
        get: (): History['replaceState'] => replaceState,
        set(next: History['replaceState']): void {
          const failure = replaceStateFailure?.(next);
          if (failure !== undefined) {
            throw failure;
          }
          replaceState = next;
        },
      },
    });
  }

  return {
    history,
    originalPushState,
    originalReplaceState,
    window: {
      history,
      addEventListener(type: string, listener: EventListenerOrEventListenerObject | null): void {
        if (listener === null) {
          return;
        }
        const listeners = eventListeners.get(type) ?? new Set<EventListenerOrEventListenerObject>();
        listeners.add(listener);
        eventListeners.set(type, listeners);
      },
      removeEventListener(type: string, listener: EventListenerOrEventListenerObject | null): void {
        if (listener === null) {
          return;
        }
        eventListeners.get(type)?.delete(listener);
      },
    } as unknown as Window,
    dispatch(eventName: NavigationEventName): void {
      for (const listener of eventListeners.get(eventName) ?? []) {
        if (typeof listener === 'function') {
          listener({ type: eventName } as Event);
        } else {
          listener.handleEvent({ type: eventName } as Event);
        }
      }
    },
    listenerCount(eventName: NavigationEventName): number {
      return eventListeners.get(eventName)?.size ?? 0;
    },
    setPushStateFailure(failure: SetFailure | undefined): void {
      pushStateFailure = failure;
    },
    setReplaceStateFailure(failure: SetFailure | undefined): void {
      replaceStateFailure = failure;
    },
  };
}

function captureFailure(action: () => void): unknown {
  try {
    action();
  } catch (error: unknown) {
    return error;
  }
  throw new Error('Expected the action to throw');
}

describe('SPA navigation History patch recovery', () => {
  it('retains partial patch ownership, reports rollback failure, and retries without stacking', () => {
    const fakeWindow = createFakeWindow();
    const startupFailure = new Error('replaceState install failed');
    const rollbackFailure = new Error('pushState restoration failed');
    let rejectReplaceInstall = true;
    let rejectPushRestore = true;
    fakeWindow.setReplaceStateFailure((next) =>
      rejectReplaceInstall && next !== fakeWindow.originalReplaceState ? startupFailure : undefined,
    );
    fakeWindow.setPushStateFailure((next) =>
      rejectPushRestore && next === fakeWindow.originalPushState ? rollbackFailure : undefined,
    );

    const events: string[] = [];
    const adapter = createSpaNavigationAdapter({
      window: fakeWindow.window,
      observeHashChanges: true,
    });
    const failure = captureFailure(() => adapter.start((event) => events.push(event.kind)));

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors).toEqual([startupFailure, rollbackFailure]);
    expect(fakeWindow.history.pushState).not.toBe(fakeWindow.originalPushState);
    expect(fakeWindow.history.replaceState).toBe(fakeWindow.originalReplaceState);

    rejectReplaceInstall = false;
    rejectPushRestore = false;
    adapter.start((event) => events.push(event.kind));
    expect(fakeWindow.listenerCount('popstate')).toBe(1);
    expect(fakeWindow.listenerCount('hashchange')).toBe(1);
    fakeWindow.history.pushState({}, '', '/recovered');
    fakeWindow.dispatch('popstate');
    fakeWindow.dispatch('hashchange');

    expect(events).toEqual(['bootstrap', 'pushstate', 'popstate', 'hashchange']);
    adapter.teardown();
    expect(fakeWindow.listenerCount('popstate')).toBe(0);
    expect(fakeWindow.listenerCount('hashchange')).toBe(0);
    expect(fakeWindow.history.pushState).toBe(fakeWindow.originalPushState);
    expect(fakeWindow.history.replaceState).toBe(fakeWindow.originalReplaceState);
  });

  it('surfaces teardown restoration failures and recovers the retained patch on retry', () => {
    const fakeWindow = createFakeWindow();
    const teardownFailure = new Error('pushState teardown restoration failed');
    let rejectPushRestore = false;
    fakeWindow.setPushStateFailure((next) =>
      rejectPushRestore && next === fakeWindow.originalPushState ? teardownFailure : undefined,
    );

    const adapter = createSpaNavigationAdapter({ window: fakeWindow.window });
    adapter.start(() => {});
    const retainedWrapper = fakeWindow.history.pushState;
    rejectPushRestore = true;

    expect(captureFailure(() => adapter.teardown())).toBe(teardownFailure);
    expect(fakeWindow.history.pushState).toBe(retainedWrapper);
    expect(fakeWindow.history.replaceState).toBe(fakeWindow.originalReplaceState);

    rejectPushRestore = false;
    adapter.start(() => {});
    expect(fakeWindow.history.pushState).not.toBe(retainedWrapper);
    adapter.teardown();
    expect(fakeWindow.history.pushState).toBe(fakeWindow.originalPushState);
    expect(fakeWindow.history.replaceState).toBe(fakeWindow.originalReplaceState);
  });

  it('leaves externally replaced host History methods untouched during teardown', () => {
    const fakeWindow = createFakeWindow();
    const adapter = createSpaNavigationAdapter({ window: fakeWindow.window });
    adapter.start(() => {});

    let hostPushStateCalls = 0;
    let hostReplaceStateCalls = 0;
    const hostPushState: HistoryMethod = function (
      this: History,
      ...args: Parameters<HistoryMethod>
    ): void {
      hostPushStateCalls += 1;
      Reflect.apply(fakeWindow.originalPushState, this, args);
    };
    const hostReplaceState: History['replaceState'] = function (
      this: History,
      ...args: Parameters<History['replaceState']>
    ): void {
      hostReplaceStateCalls += 1;
      Reflect.apply(fakeWindow.originalReplaceState, this, args);
    };
    fakeWindow.history.pushState = hostPushState;
    fakeWindow.history.replaceState = hostReplaceState;

    adapter.teardown();

    expect(fakeWindow.history.pushState).toBe(hostPushState);
    expect(fakeWindow.history.replaceState).toBe(hostReplaceState);
    fakeWindow.history.pushState({}, '', '/host-push');
    fakeWindow.history.replaceState({}, '', '/host-replace');
    expect(hostPushStateCalls).toBe(1);
    expect(hostReplaceStateCalls).toBe(1);
  });
  it('removes temporary own History shadows after teardown for inherited methods', () => {
    const fakeWindow = createFakeWindow({ inheritedHistoryMethods: true });
    const adapter = createSpaNavigationAdapter({ window: fakeWindow.window });

    expect(Object.hasOwn(fakeWindow.history, 'pushState')).toBe(false);
    expect(Object.hasOwn(fakeWindow.history, 'replaceState')).toBe(false);

    adapter.start(() => {});

    expect(Object.hasOwn(fakeWindow.history, 'pushState')).toBe(true);
    expect(Object.hasOwn(fakeWindow.history, 'replaceState')).toBe(true);

    adapter.teardown();

    expect(Object.hasOwn(fakeWindow.history, 'pushState')).toBe(false);
    expect(Object.hasOwn(fakeWindow.history, 'replaceState')).toBe(false);
    expect(fakeWindow.history.pushState).toBe(fakeWindow.originalPushState);
    expect(fakeWindow.history.replaceState).toBe(fakeWindow.originalReplaceState);
  });

  it('preserves host wrappers that replace inherited History methods', () => {
    const fakeWindow = createFakeWindow({ inheritedHistoryMethods: true });
    const adapter = createSpaNavigationAdapter({ window: fakeWindow.window });
    adapter.start(() => {});

    const hostPushState: HistoryMethod = function (): void {};
    const hostReplaceState: History['replaceState'] = function (): void {};
    fakeWindow.history.pushState = hostPushState;
    fakeWindow.history.replaceState = hostReplaceState;

    adapter.teardown();

    expect(Object.hasOwn(fakeWindow.history, 'pushState')).toBe(true);
    expect(Object.hasOwn(fakeWindow.history, 'replaceState')).toBe(true);
    expect(fakeWindow.history.pushState).toBe(hostPushState);
    expect(fakeWindow.history.replaceState).toBe(hostReplaceState);
  });
});
