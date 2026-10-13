export type NavigationEventKind =
  'bootstrap' | 'pageshow' | 'pushstate' | 'replacestate' | 'popstate' | 'hashchange';

export interface NavigationEvent {
  readonly generation: number;
  readonly kind: NavigationEventKind;
}

export type NavigationListener = (event: NavigationEvent) => void;

/**
 * A browser navigation source. Calling start or teardown more than once is a
 * no-op. A stopped adapter may be started again with a new listener.
 */
export interface NavigationAdapter {
  start(listener: NavigationListener): void;
  teardown(): void;
}

export interface NavigationEmitter {
  readonly isStarted: boolean;
  start(listener: NavigationListener): boolean;
  teardown(): boolean;
  emit(kind: NavigationEventKind): void;
}

/**
 * Keeps generations monotonic across an adapter's stop/start lifecycle and
 * prevents client failures from propagating into the host's navigation APIs.
 */
export function createNavigationEmitter(): NavigationEmitter {
  let isStarted = false;
  let generation = 0;
  let listener: NavigationListener | undefined;

  return {
    get isStarted(): boolean {
      return isStarted;
    },
    start(nextListener: NavigationListener): boolean {
      if (isStarted) {
        return false;
      }
      isStarted = true;
      listener = nextListener;
      return true;
    },
    teardown(): boolean {
      if (!isStarted) {
        return false;
      }
      isStarted = false;
      listener = undefined;
      return true;
    },
    emit(kind: NavigationEventKind): void {
      if (!isStarted || listener === undefined) {
        return;
      }

      const event = Object.freeze({
        generation: (generation += 1),
        kind,
      });
      try {
        listener(event);
      } catch {
        // Scene Glass failures must not affect host navigation.
      }
    },
  };
}
