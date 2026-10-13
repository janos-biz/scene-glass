import {
  createNavigationEmitter,
  type NavigationAdapter,
  type NavigationEventKind,
  type NavigationListener,
} from './adapter.js';

export interface SpaNavigationAdapterOptions {
  readonly window?: Window;
  readonly observeHashChanges?: boolean;
}

interface HistoryPatchRegistry {
  readonly adapters: Set<SpaNavigationAdapter>;
  readonly originalPushState: History['pushState'];
  readonly originalReplaceState: History['replaceState'];
  readonly hadOwnPushState: boolean;
  readonly hadOwnReplaceState: boolean;
  readonly originalPushStateDescriptor: PropertyDescriptor | undefined;
  readonly originalReplaceStateDescriptor: PropertyDescriptor | undefined;
  readonly pushStateWrapper: History['pushState'];
  readonly replaceStateWrapper: History['replaceState'];
}

const historyPatchRegistries = new WeakMap<Window, HistoryPatchRegistry>();

/**
 * Observes History API navigations without coupling the client to a framework.
 * Multiple adapters for the same window share one reversible History patch.
 */
export class SpaNavigationAdapter implements NavigationAdapter {
  private readonly emitter = createNavigationEmitter();
  private readonly window: Window;
  private readonly observeHashChanges: boolean;

  public constructor(options: SpaNavigationAdapterOptions = {}) {
    this.window = options.window ?? globalThis.window;
    this.observeHashChanges = options.observeHashChanges === true;
  }

  public start(listener: NavigationListener): void {
    if (!this.emitter.start(listener)) {
      return;
    }

    try {
      this.window.addEventListener('popstate', this.onPopState);
      if (this.observeHashChanges) {
        this.window.addEventListener('hashchange', this.onHashChange);
      }
      acquireHistoryPatch(this.window, this);
      this.emitter.emit('bootstrap');
    } catch (error: unknown) {
      const rollbackErrors: unknown[] = [];
      try {
        this.window.removeEventListener('popstate', this.onPopState);
      } catch (rollbackError: unknown) {
        rollbackErrors.push(rollbackError);
      }
      if (this.observeHashChanges) {
        try {
          this.window.removeEventListener('hashchange', this.onHashChange);
        } catch (rollbackError: unknown) {
          rollbackErrors.push(rollbackError);
        }
      }
      try {
        releaseHistoryPatch(this.window, this);
      } catch (rollbackError: unknown) {
        rollbackErrors.push(rollbackError);
      }
      this.emitter.teardown();
      throwWithRollbackErrors(error, rollbackErrors, 'SPA navigation startup rollback failed');
    }
  }

  public teardown(): void {
    if (!this.emitter.teardown()) {
      return;
    }

    const cleanupErrors: unknown[] = [];
    try {
      this.window.removeEventListener('popstate', this.onPopState);
    } catch (cleanupError: unknown) {
      cleanupErrors.push(cleanupError);
    }
    if (this.observeHashChanges) {
      try {
        this.window.removeEventListener('hashchange', this.onHashChange);
      } catch (cleanupError: unknown) {
        cleanupErrors.push(cleanupError);
      }
    }
    try {
      releaseHistoryPatch(this.window, this);
    } catch (cleanupError: unknown) {
      cleanupErrors.push(cleanupError);
    }
    throwIfCleanupErrors(cleanupErrors, 'SPA navigation teardown failed');
  }

  public emitHistoryNavigation(kind: 'pushstate' | 'replacestate'): void {
    this.emitter.emit(kind);
  }

  private readonly onPopState = (): void => {
    this.emitter.emit('popstate');
  };

  private readonly onHashChange = (): void => {
    this.emitter.emit('hashchange');
  };
}

export function createSpaNavigationAdapter(
  options?: SpaNavigationAdapterOptions,
): SpaNavigationAdapter {
  return new SpaNavigationAdapter(options);
}

function acquireHistoryPatch(window: Window, adapter: SpaNavigationAdapter): void {
  let registry = historyPatchRegistries.get(window);
  if (registry !== undefined && registry.adapters.size === 0) {
    restoreHistoryPatch(window, registry);
    registry = historyPatchRegistries.get(window);
  }

  if (registry === undefined) {
    registry = createHistoryPatch(window);
    historyPatchRegistries.set(window, registry);
    try {
      installHistoryPatch(window, registry);
    } catch (error: unknown) {
      const rollbackErrors: unknown[] = [];
      try {
        restoreHistoryPatch(window, registry);
      } catch (rollbackError: unknown) {
        rollbackErrors.push(rollbackError);
      }
      throwWithRollbackErrors(error, rollbackErrors, 'History patch startup rollback failed');
    }
  }

  registry.adapters.add(adapter);
}

function releaseHistoryPatch(window: Window, adapter: SpaNavigationAdapter): void {
  const registry = historyPatchRegistries.get(window);
  if (registry === undefined || !registry.adapters.delete(adapter)) {
    return;
  }
  if (registry.adapters.size !== 0) {
    return;
  }

  restoreHistoryPatch(window, registry);
}

function createHistoryPatch(window: Window): HistoryPatchRegistry {
  const history = window.history;
  const originalPushStateDescriptor = Object.getOwnPropertyDescriptor(history, 'pushState');
  const originalReplaceStateDescriptor = Object.getOwnPropertyDescriptor(history, 'replaceState');
  const registry: HistoryPatchRegistry = {
    adapters: new Set(),
    originalPushState: history.pushState,
    originalReplaceState: history.replaceState,
    hadOwnPushState: originalPushStateDescriptor !== undefined,
    hadOwnReplaceState: originalReplaceStateDescriptor !== undefined,
    originalPushStateDescriptor,
    originalReplaceStateDescriptor,
    pushStateWrapper: function (this: History, ...args: Parameters<History['pushState']>): void {
      Reflect.apply(registry.originalPushState, this, args);
      emitHistoryNavigation(registry, 'pushstate');
    },
    replaceStateWrapper: function (
      this: History,
      ...args: Parameters<History['replaceState']>
    ): void {
      Reflect.apply(registry.originalReplaceState, this, args);
      emitHistoryNavigation(registry, 'replacestate');
    },
  };
  return registry;
}

function installHistoryPatch(window: Window, registry: HistoryPatchRegistry): void {
  const history = window.history;
  history.pushState = registry.pushStateWrapper;
  if (history.pushState !== registry.pushStateWrapper) {
    throw new Error('History pushState patch was not installed');
  }
  history.replaceState = registry.replaceStateWrapper;
  if (history.replaceState !== registry.replaceStateWrapper) {
    throw new Error('History replaceState patch was not installed');
  }
}

function restoreHistoryPatch(window: Window, registry: HistoryPatchRegistry): void {
  const history = window.history;
  const pushStateRecovery = restoreHistoryMethod(
    () => history.pushState,
    () =>
      restoreHistoryProperty(
        history,
        'pushState',
        () => {
          history.pushState = registry.originalPushState;
        },
        registry.hadOwnPushState,
        registry.originalPushStateDescriptor,
      ),
    registry.pushStateWrapper,
  );
  const replaceStateRecovery = restoreHistoryMethod(
    () => history.replaceState,
    () =>
      restoreHistoryProperty(
        history,
        'replaceState',
        () => {
          history.replaceState = registry.originalReplaceState;
        },
        registry.hadOwnReplaceState,
        registry.originalReplaceStateDescriptor,
      ),
    registry.replaceStateWrapper,
  );

  if (
    pushStateRecovery.resolved &&
    replaceStateRecovery.resolved &&
    historyPatchRegistries.get(window) === registry
  ) {
    historyPatchRegistries.delete(window);
  }

  throwIfCleanupErrors(
    [...pushStateRecovery.errors, ...replaceStateRecovery.errors],
    'History patch restoration failed',
  );
}
function restoreHistoryProperty(
  history: History,
  property: 'pushState' | 'replaceState',
  restoreOriginalValue: () => void,
  hadOwnProperty: boolean,
  originalDescriptor: PropertyDescriptor | undefined,
): void {
  if (!hadOwnProperty) {
    if (!Reflect.deleteProperty(history, property)) {
      throw new Error(`History ${property} patch could not be removed`);
    }
    return;
  }

  if (originalDescriptor === undefined) {
    throw new Error(`History ${property} original descriptor is missing`);
  }

  restoreOriginalValue();
  Object.defineProperty(history, property, originalDescriptor);
}

function restoreHistoryMethod(
  getCurrent: () => History['pushState'],
  restore: () => void,
  wrapper: History['pushState'],
): { readonly errors: readonly unknown[]; readonly resolved: boolean } {
  const errors: unknown[] = [];
  let current: History['pushState'];
  try {
    current = getCurrent();
  } catch (error: unknown) {
    return { errors: [error], resolved: false };
  }

  if (current !== wrapper) {
    return { errors, resolved: true };
  }

  try {
    restore();
  } catch (error: unknown) {
    errors.push(error);
  }

  try {
    if (getCurrent() !== wrapper) {
      return { errors, resolved: true };
    }
  } catch (error: unknown) {
    errors.push(error);
    return { errors, resolved: false };
  }

  if (errors.length === 0) {
    errors.push(new Error('History patch wrapper remains installed after restoration'));
  }
  return { errors, resolved: false };
}

function throwWithRollbackErrors(
  startupError: unknown,
  rollbackErrors: readonly unknown[],
  message: string,
): never {
  if (rollbackErrors.length === 0) {
    throw startupError;
  }
  throw new AggregateError([startupError, ...rollbackErrors], message);
}

function throwIfCleanupErrors(errors: readonly unknown[], message: string): void {
  if (errors.length === 0) {
    return;
  }
  if (errors.length === 1) {
    throw errors[0];
  }
  throw new AggregateError(errors, message);
}

function emitHistoryNavigation(
  registry: HistoryPatchRegistry,
  kind: Extract<NavigationEventKind, 'pushstate' | 'replacestate'>,
): void {
  for (const adapter of [...registry.adapters]) {
    adapter.emitHistoryNavigation(kind);
  }
}
