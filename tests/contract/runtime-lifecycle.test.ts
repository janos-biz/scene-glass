import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  BrowserPageIdentityOptions,
  PageIdentityResolverContext,
} from '../../packages/browser-client/src/identity/resolver.js';

const fixture = vi.hoisted(() => ({
  clientState: 'booting',
  cleanupCalls: [] as string[],
  controllerCreateInputs: [] as unknown[],
  controllerLoadFailure: null as Error | null,
  controllerPage: null as { readonly pageId: string } | null,
  diagnosticTransport: null as unknown,
  diagnosticControllerCreates: 0,
  diagnosticPanelCreates: 0,
  diagnosticPanelCreationFailure: null as Error | null,
  diagnosticPanelOpenCalls: 0,
  identityDeferred: null as Deferred<{ readonly pageId: string }> | null,
  identityFailure: null as Error | null,
  identityResolverInputs: [] as IdentityResolverInput[],
  initializationDeferred: null as Deferred<void> | null,
  locatorCaptureDeferred: null as Deferred<void> | null,
  locatorCaptureDeferreds: [] as Deferred<void>[],
  manualErrorCodes: [] as string[],
  manualErrorFailure: null as Error | null,
  mcpClients: [] as FakeMcpClient[],
  mcpCloseFailure: null as Error | null,
  mcpCloseDeferred: null as Deferred<void> | null,
  mcpInitializationAbortError: null as Error | null,
  mutationObserverAvailable: true,
  mutationObserverDisconnectFailure: null as Error | null,
  mutationObserverObserveCalls: 0,
  mutationObserverObserveFailure: null as Error | null,
  navigationListener: null as (() => void) | null,
  navigationStartCalls: 0,
  openDiagnosticsFailure: null as Error | null,
  overlayRetry: null as (() => Promise<void>) | null,
  overlaySetStateFailure: null as Error | null,
  overlayStates: [] as unknown[],
  reentrantDestroy: null as (() => Promise<void>) | null,
  reentrantDestroyOwner: null as string | null,
  reentrantDestroyTask: null as Promise<void> | null,
  reentrantDiagnostics: null as (() => Promise<void>) | null,
  reentrantDiagnosticsOwner: null as string | null,
  reentrantDiagnosticsTask: null as Promise<void> | null,
  selectorOnSelect: null as ((selection: unknown) => void) | null,
  selectorOnUnsupportedSelect: null as ((selection: unknown) => void) | null,
  selectorReviewing: false,
  selectorStopCalls: 0,
  selectorStopFailure: null as Error | null,
  settlerWaits: [] as Array<{ readonly generation: number; readonly deferred: Deferred<boolean> }>,
  throwOwners: new Set<string>(),
}));

type Deferred<T> = {
  readonly promise: Promise<T>;
  reject(reason: unknown): void;
  resolve(value: T): void;
};
type IdentityResolverInput = Pick<BrowserPageIdentityOptions, 'location' | 'override' | 'policy'>;

type FakeMcpClient = {
  closeCalls: number;
  disposeCalls: number;
};

type DiagnosticTransport = {
  deleteClose(): Promise<void>;
  initialize(input: {
    readonly projectId: string;
    readonly token: string;
  }): Promise<{ readonly id: string }>;
};

function createDeferred<T>(): Deferred<T> {
  let resolvePromise: ((value: T) => void) | undefined;
  let rejectPromise: ((reason: unknown) => void) | undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    reject(reason: unknown): void {
      rejectPromise?.(reason);
    },
    resolve(value: T): void {
      resolvePromise?.(value);
    },
  };
}

function recordCleanup(owner: string): void {
  fixture.cleanupCalls.push(owner);
  if (fixture.reentrantDestroyOwner === owner && fixture.reentrantDestroy !== null) {
    fixture.reentrantDestroyTask = fixture.reentrantDestroy();
  }
  if (fixture.reentrantDiagnosticsOwner === owner && fixture.reentrantDiagnostics !== null) {
    fixture.reentrantDiagnosticsTask = fixture.reentrantDiagnostics();
  }
  if (fixture.throwOwners.has(owner)) {
    throw new Error(`${owner} cleanup failed`);
  }
}

vi.mock('../../packages/browser-client/src/annotation/controller.js', () => ({
  AnnotationController: class {
    public destroy(): void {
      recordCleanup('controller');
    }

    public getState(): Record<string, unknown> {
      return {
        annotations: [],
        bindings: [],
        generation: 0,
        ...(fixture.controllerPage === null ? {} : { page: fixture.controllerPage, revision: 0 }),
      };
    }

    public setManualError(_message: string, code: string): void {
      fixture.manualErrorCodes.push(code);
      const failure = fixture.manualErrorFailure;
      if (failure !== null) {
        fixture.manualErrorFailure = null;
        throw failure;
      }
    }

    public setPage(page: { readonly pageId: string }): void {
      fixture.controllerPage = page;
    }

    public async load(): Promise<{ readonly status: 'applied' }> {
      if (fixture.controllerLoadFailure !== null) {
        throw fixture.controllerLoadFailure;
      }
      return { status: 'applied' };
    }

    public async create(input: unknown): Promise<{ readonly status: 'applied' }> {
      fixture.controllerCreateInputs.push(input);
      return { status: 'applied' };
    }
  },
}));

vi.mock('../../packages/browser-client/src/annotation/selector.js', () => ({
  createElementSelector: (options: {
    readonly onSelect?: (selection: unknown) => void;
    readonly onUnsupportedSelect?: (selection: unknown) => void;
  }): {
    readonly isReviewing: boolean;
    destroy(): void;
    start(): void;
    stop(): void;
  } => {
    fixture.selectorOnSelect = options.onSelect ?? null;
    fixture.selectorOnUnsupportedSelect = options.onUnsupportedSelect ?? null;
    return {
      get isReviewing(): boolean {
        return fixture.selectorReviewing;
      },
      destroy(): void {
        recordCleanup('selector');
      },
      start(): void {
        fixture.selectorReviewing = true;
      },
      stop(): void {
        fixture.selectorReviewing = false;
        fixture.selectorStopCalls += 1;
        const failure = fixture.selectorStopFailure;
        if (failure !== null) {
          fixture.selectorStopFailure = null;
          throw failure;
        }
      },
    };
  },
  isSceneGlassOwnedElement(): boolean {
    return false;
  },
}));

vi.mock('../../packages/browser-client/src/identity/resolver.js', () => ({
  async resolvePageIdentity(input: IdentityResolverInput): Promise<{ readonly pageId: string }> {
    fixture.identityResolverInputs.push(input);
    const deferred = fixture.identityDeferred;
    if (deferred !== null) {
      return deferred.promise;
    }
    if (fixture.identityFailure !== null) {
      throw fixture.identityFailure;
    }
    return { pageId: input.override ?? 'page' };
  },
}));

vi.mock('../../packages/browser-client/src/client.js', () => ({
  SceneGlassClient: class {
    private readonly onDiagnostics: ((capability: unknown) => Promise<void> | void) | undefined;
    private readonly onStateChange: ((state: string) => void) | undefined;

    public constructor(options: {
      readonly onStateChange?: (state: string) => void;
      readonly openDiagnosticsPanel?: (capability: unknown) => Promise<void> | void;
    }) {
      this.onDiagnostics = options.openDiagnosticsPanel;
      this.onStateChange = options.onStateChange;
    }

    public get state(): string {
      return fixture.clientState;
    }

    public async start(): Promise<void> {
      fixture.clientState = 'ready';
      this.onStateChange?.('ready');
    }

    public async retry(): Promise<void> {
      fixture.clientState = 'ready';
      this.onStateChange?.('ready');
    }

    public async openDiagnostics(): Promise<void> {
      if (fixture.openDiagnosticsFailure !== null) {
        throw fixture.openDiagnosticsFailure;
      }
      await this.onDiagnostics?.({
        endpoint: 'http://127.0.0.1:4175/mcp/v1/projects/project/diagnostic-runs/run-1',
        expiresAt: 1,
        runId: 'run-1',
        token: 'diagnostic-token',
      });
    }

    public async destroy(): Promise<void> {
      recordCleanup('client');
    }
  },
}));

vi.mock('../../packages/browser-client/src/diagnostics/controller.js', () => ({
  createDiagnosticsController: (options: {
    readonly transport: unknown;
  }): {
    destroy(): void;
    open(): void;
  } => {
    fixture.diagnosticControllerCreates += 1;
    fixture.diagnosticTransport = options.transport;
    return {
      destroy(): void {
        recordCleanup('diagnostics-controller');
      },
      open(): void {},
    };
  },
}));

vi.mock('../../packages/browser-client/src/diagnostics/panel.js', () => ({
  createDiagnosticsPanel: (): {
    destroy(): void;
    open(): void;
  } => {
    const failure = fixture.diagnosticPanelCreationFailure;
    if (failure !== null) {
      throw failure;
    }
    fixture.diagnosticPanelCreates += 1;
    return {
      destroy(): void {
        recordCleanup('diagnostics-panel');
      },
      open(): void {
        fixture.diagnosticPanelOpenCalls += 1;
      },
    };
  },
}));

vi.mock('../../packages/browser-client/src/mcp-client.js', () => ({
  McpClient: class {
    public closeCalls = 0;
    public disposeCalls = 0;
    private closeTask: Promise<void> | null = null;
    private initializationTask: Promise<void> | null = null;

    public constructor() {
      fixture.mcpClients.push(this);
    }

    public close(): Promise<void> {
      if (this.closeTask !== null) {
        return this.closeTask;
      }
      this.closeCalls += 1;
      const initializationTask = this.initializationTask;
      if (initializationTask !== null) {
        fixture.initializationDeferred?.reject(
          fixture.mcpInitializationAbortError ?? new Error('MCP session was superseded'),
        );
      }
      const task = (async (): Promise<void> => {
        if (initializationTask !== null) {
          await initializationTask.catch(() => undefined);
        }
        const deferred = fixture.mcpCloseDeferred;
        if (deferred !== null) {
          await deferred.promise;
        }
        if (fixture.mcpCloseFailure !== null) {
          throw fixture.mcpCloseFailure;
        }
      })();
      this.closeTask = task;
      return task;
    }

    public dispose(): void {
      this.disposeCalls += 1;
    }

    public initializeSession(): Promise<void> {
      const deferred = fixture.initializationDeferred;
      const task = deferred === null ? Promise.resolve() : deferred.promise;
      this.initializationTask = task;
      return task;
    }

    public async ping(): Promise<void> {}

    public async sendInitializedNotification(): Promise<void> {}
  },
}));
vi.mock('../../packages/browser-client/src/annotation/locator.js', () => ({
  captureElementLocator: async (): Promise<Record<never, never>> => {
    const deferred = fixture.locatorCaptureDeferreds.shift() ?? fixture.locatorCaptureDeferred;
    if (deferred !== null) {
      await deferred.promise;
    }
    return Object.freeze({});
  },
}));

vi.mock('../../packages/browser-client/src/navigation/document.js', () => ({
  createDocumentNavigationAdapter: (): {
    start(listener: () => void): void;
    teardown(): void;
  } => ({
    start(listener: () => void): void {
      fixture.navigationStartCalls += 1;
      fixture.navigationListener = listener;
      recordCleanup('navigation-start');
    },
    teardown(): void {
      recordCleanup('navigation');
    },
  }),
}));

vi.mock('../../packages/browser-client/src/navigation/render-settled.js', () => ({
  createRenderSettler: (): {
    isCurrent(): boolean;
    teardown(): void;
    waitFor(generation: number): Promise<boolean>;
  } => ({
    isCurrent(): boolean {
      return true;
    },
    teardown(): void {
      recordCleanup('settler');
    },
    waitFor(generation: number): Promise<boolean> {
      const deferred = createDeferred<boolean>();
      fixture.settlerWaits.push({ deferred, generation });
      return deferred.promise;
    },
  }),
}));

vi.mock('../../packages/browser-client/src/ui/overlay.js', () => ({
  createSceneGlassOverlay: (options: {
    readonly onRetry: () => Promise<void>;
  }): {
    destroy(): void;
    open(): void;
    setState(state: unknown): void;
  } => {
    fixture.overlayRetry = options.onRetry;
    return {
      destroy(): void {
        recordCleanup('overlay');
      },
      open(): void {},
      setState(state: unknown): void {
        const failure = fixture.overlaySetStateFailure;
        if (failure !== null) {
          fixture.overlaySetStateFailure = null;
          throw failure;
        }
        fixture.overlayStates.push(state);
      },
    };
  },
}));

import {
  SceneGlassRuntime,
  type SceneGlassRuntimeOptions,
} from '../../packages/browser-client/src/runtime.js';

function resetFixture(): void {
  fixture.clientState = 'booting';
  fixture.cleanupCalls = [];
  fixture.controllerCreateInputs = [];
  fixture.controllerLoadFailure = null;
  fixture.controllerPage = null;
  fixture.diagnosticTransport = null;
  fixture.diagnosticControllerCreates = 0;
  fixture.diagnosticPanelCreates = 0;
  fixture.diagnosticPanelCreationFailure = null;
  fixture.diagnosticPanelOpenCalls = 0;
  fixture.identityDeferred = null;
  fixture.identityFailure = null;
  fixture.identityResolverInputs = [];
  fixture.initializationDeferred = null;
  fixture.locatorCaptureDeferred = null;
  fixture.locatorCaptureDeferreds = [];
  fixture.manualErrorCodes = [];
  fixture.manualErrorFailure = null;
  fixture.mcpClients = [];
  fixture.mcpCloseFailure = null;
  fixture.mcpCloseDeferred = null;
  fixture.mcpInitializationAbortError = null;
  fixture.mutationObserverAvailable = true;
  fixture.mutationObserverDisconnectFailure = null;
  fixture.mutationObserverObserveCalls = 0;
  fixture.mutationObserverObserveFailure = null;
  fixture.navigationListener = null;
  fixture.navigationStartCalls = 0;
  fixture.openDiagnosticsFailure = null;
  fixture.overlayRetry = null;
  fixture.overlaySetStateFailure = null;
  fixture.overlayStates = [];
  fixture.reentrantDestroy = null;
  fixture.reentrantDestroyOwner = null;
  fixture.reentrantDestroyTask = null;
  fixture.reentrantDiagnostics = null;
  fixture.reentrantDiagnosticsOwner = null;
  fixture.reentrantDiagnosticsTask = null;
  fixture.selectorOnSelect = null;
  fixture.selectorOnUnsupportedSelect = null;
  fixture.selectorReviewing = false;
  fixture.selectorStopCalls = 0;
  fixture.selectorStopFailure = null;
  fixture.settlerWaits = [];
  fixture.throwOwners.clear();
}

function mutationObserverConstructor(): typeof MutationObserver | undefined {
  if (!fixture.mutationObserverAvailable) {
    return undefined;
  }

  return class {
    public disconnect(): void {
      if (fixture.mutationObserverDisconnectFailure !== null) {
        throw fixture.mutationObserverDisconnectFailure;
      }
    }

    public observe(): void {
      fixture.mutationObserverObserveCalls += 1;
      if (fixture.mutationObserverObserveFailure !== null) {
        throw fixture.mutationObserverObserveFailure;
      }
    }
  } as unknown as typeof MutationObserver;
}

function createRuntime(
  options: {
    readonly location?: string;
    readonly pageIdentity?: SceneGlassRuntimeOptions['pageIdentity'];
  } = {},
): SceneGlassRuntime {
  return new SceneGlassRuntime({
    crypto: {
      getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        return array;
      },
    },
    diagnosticEndpoint: 'http://127.0.0.1:4175/mcp/v1/projects/project/diagnostic-runs',
    document: {
      defaultView: { MutationObserver: mutationObserverConstructor() } as unknown as Window,
      documentElement: {},
    } as unknown as Document,
    endpoint: 'http://127.0.0.1:4175/mcp/v1/projects/project',
    navigation: 'document',
    projectId: 'project',
    token: 'runtime-token',
    window: {
      clearTimeout(): void {},
      location: new URL(options.location ?? 'http://example.test/current') as unknown as Location,
    } as unknown as Window,
    ...(options.pageIdentity === undefined ? {} : { pageIdentity: options.pageIdentity }),
  });
}

function diagnosticTransport(): DiagnosticTransport {
  return fixture.diagnosticTransport as DiagnosticTransport;
}

async function flushAsyncWork(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}
/** 흔들기 한 번 분량의 포인터 표본을 런타임 처리기에 그대로 흘려보낸다. */
function feedShake(target: { onShakeMove(event: PointerEvent): void }): void {
  const sample = (x: number, at: number): PointerEvent =>
    ({ clientX: x, clientY: 0, timeStamp: at }) as unknown as PointerEvent;
  let position = 0;
  let at = 0;
  target.onShakeMove(sample(0, 0));
  for (let leg = 0; leg < 6; leg += 1) {
    position += leg % 2 === 0 ? 80 : -80;
    at += 60;
    target.onShakeMove(sample(position, at));
  }
}

function countErrorIdentity(
  root: unknown,
  expected: unknown,
  visited: Set<object> = new Set<object>(),
): number {
  const occurrences = root === expected ? 1 : 0;
  if (
    typeof root !== 'object' ||
    root === null ||
    visited.has(root) ||
    !(root instanceof AggregateError)
  ) {
    return occurrences;
  }
  visited.add(root);
  return (
    occurrences +
    root.errors.reduce((count, error) => count + countErrorIdentity(error, expected, visited), 0)
  );
}

beforeEach(resetFixture);
afterEach(() => vi.unstubAllGlobals());

describe('runtime lifecycle contract', () => {
  it('publishes an active settlement failure and retries with a fresh generation without restarting navigation', async () => {
    const runtime = createRuntime();
    await runtime.start();

    expect(fixture.navigationStartCalls).toBe(1);
    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1]);

    fixture.settlerWaits[0]?.deferred.resolve(false);
    await flushAsyncWork();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_RENDER_SETTLEMENT_FAILED', kind: 'error' },
    });

    await fixture.overlayRetry?.();

    expect(fixture.navigationStartCalls).toBe(1);
    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1, 2]);
    await runtime.destroy();
  });

  it('keeps page-load rejections from stale generations silent', async () => {
    const runtime = createRuntime();
    await runtime.start();

    fixture.navigationListener?.();
    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1, 2]);

    fixture.settlerWaits[0]?.deferred.reject(new Error('stale settlement failure'));
    await flushAsyncWork();

    expect(fixture.overlayStates).not.toContainEqual(
      expect.objectContaining({
        status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
      }),
    );
    await runtime.destroy();
  });
  it('surfaces current settler rejections with retained cause and retry', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const settlerFailure = new Error('settler rejected');

    fixture.settlerWaits[0]?.deferred.reject(settlerFailure);
    await flushAsyncWork();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
    });
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown };
      }
    ).navigationFailure;
    expect(navigationFailure.cause).toBe(settlerFailure);

    await fixture.overlayRetry?.();

    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1, 2]);
    await runtime.destroy();
  });

  it('surfaces current controller loading rejections with retained cause and retry', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const controllerFailure = new Error('controller load rejected');
    fixture.controllerLoadFailure = controllerFailure;

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
    });
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown };
      }
    ).navigationFailure;
    expect(navigationFailure.cause).toBe(controllerFailure);

    await fixture.overlayRetry?.();

    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1, 2]);
    await runtime.destroy();
  });

  it('surfaces current annotation render rejections with retained cause and retry', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const renderFailure = new Error('annotation render rejected');
    fixture.overlaySetStateFailure = renderFailure;

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
    });
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown };
      }
    ).navigationFailure;
    expect(navigationFailure.cause).toBe(renderFailure);

    await fixture.overlayRetry?.();

    expect(fixture.settlerWaits.map(({ generation }) => generation)).toEqual([1, 2]);
    await runtime.destroy();
  });
  it('retains the current page-identity failure behind its stable UI code', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const identityFailure = new Error('identity resolution failed');
    fixture.identityFailure = identityFailure;

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_PAGE_IDENTITY', kind: 'error' },
    });
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown; readonly code: string };
      }
    ).navigationFailure;
    expect(navigationFailure.code).toBe('SCG_PAGE_IDENTITY');
    expect(navigationFailure.cause).toBe(identityFailure);
    await runtime.destroy();
  });
  it('retains page-identity publication failures without relabeling the identity failure', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const identityFailure = new Error('identity resolution failed');
    const manualPublicationFailure = new Error('manual error publication failed');
    const overlayPublicationFailure = new Error('overlay publication failed');
    fixture.identityFailure = identityFailure;
    fixture.manualErrorFailure = manualPublicationFailure;
    fixture.overlaySetStateFailure = overlayPublicationFailure;

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.manualErrorCodes).toEqual(['SCG_PAGE_IDENTITY']);
    expect(fixture.overlaySetStateFailure).toBeNull();
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & {
          readonly cause?: unknown;
          readonly cleanupErrors?: readonly unknown[];
          readonly code: string;
        };
      }
    ).navigationFailure;
    expect(navigationFailure.code).toBe('SCG_PAGE_IDENTITY');
    expect(navigationFailure.code).not.toBe('SCG_NAVIGATION_UNAVAILABLE');
    expect(navigationFailure.cause).toBe(identityFailure);
    expect(navigationFailure.cleanupErrors).toEqual([
      manualPublicationFailure,
      overlayPublicationFailure,
    ]);
    expect(navigationFailure.cleanupErrors).not.toContain(identityFailure);
    expect(fixture.overlayStates).not.toContainEqual(
      expect.objectContaining({
        status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
      }),
    );
    await runtime.destroy();
  });

  it('keeps a stale page-identity failure from replacing the current generation state', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const identity = createDeferred<{ readonly pageId: string }>();
    fixture.identityDeferred = identity;

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();
    fixture.navigationListener?.();
    identity.reject(new Error('stale identity failure'));
    await flushAsyncWork();

    expect(
      (runtime as unknown as { readonly navigationFailure: unknown }).navigationFailure,
    ).toBeNull();
    expect(fixture.overlayStates).not.toContainEqual(
      expect.objectContaining({
        status: { code: 'SCG_PAGE_IDENTITY', kind: 'error' },
      }),
    );
    await runtime.destroy();
  });
  it('passes a frozen pathname-only snapshot with no implicit page-identity authority', async () => {
    const runtime = createRuntime({
      location: 'http://example.test/current?filter=open#annotation-1',
    });
    await runtime.start();

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    const input = fixture.identityResolverInputs[0];
    expect(input).toEqual({
      location: {
        pathname: '/current',
        search: '?filter=open',
        hash: '#annotation-1',
      },
    });
    expect(Object.isFrozen(input?.location)).toBe(true);
    expect(input).not.toHaveProperty('override');
    expect(input).not.toHaveProperty('policy');
    await runtime.destroy();
  });
  it('passes a snapshotted static override and explicit query/hash policy to core resolution', async () => {
    const authority = {
      override: '/router/current',
      policy: { includeQuery: true, includeHash: true },
    };
    const runtime = createRuntime({
      location: 'http://example.test/current?filter=open#annotation-1',
      pageIdentity: authority,
    });
    authority.override = '/router/changed';
    authority.policy.includeQuery = false;
    authority.policy.includeHash = false;
    await runtime.start();

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    const input = fixture.identityResolverInputs[0];
    expect(input).toEqual({
      location: {
        pathname: '/current',
        search: '?filter=open',
        hash: '#annotation-1',
      },
      override: '/router/current',
      policy: { includeQuery: true, includeHash: true },
    });
    expect(Object.isFrozen(input?.policy)).toBe(true);
    await runtime.destroy();
  });
  it('gives async resolvers distinct frozen location snapshots for each navigation generation', async () => {
    const firstOverride = createDeferred<string | undefined>();
    const secondOverride = createDeferred<string | undefined>();
    const contexts: PageIdentityResolverContext[] = [];
    const runtime = createRuntime({
      location: 'http://example.test/current?view=first#first',
      pageIdentity: {
        override: (context) => {
          contexts.push(context);
          return context.navigationGeneration === 1
            ? firstOverride.promise
            : secondOverride.promise;
        },
      },
    });
    await runtime.start();

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    const runtimeWindow = (runtime as unknown as { readonly window: { readonly location: URL } })
      .window;
    runtimeWindow.location.href = 'http://example.test/next?view=second#second';
    fixture.navigationListener?.();
    fixture.settlerWaits[1]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(contexts).toEqual([
      {
        location: { pathname: '/current', search: '?view=first', hash: '#first' },
        navigationGeneration: 1,
      },
      {
        location: { pathname: '/next', search: '?view=second', hash: '#second' },
        navigationGeneration: 2,
      },
    ]);
    expect(Object.isFrozen(contexts[0])).toBe(true);
    expect(Object.isFrozen(contexts[0]?.location)).toBe(true);
    expect(Object.isFrozen(contexts[1])).toBe(true);
    expect(Object.isFrozen(contexts[1]?.location)).toBe(true);
    expect(contexts[0]?.location).not.toBe(contexts[1]?.location);

    secondOverride.resolve('/router/next');
    await flushAsyncWork();
    firstOverride.resolve('/router/current');
    await flushAsyncWork();
    await runtime.destroy();
  });
  it('keeps stale async page-identity overrides from publishing an older page', async () => {
    const staleOverride = createDeferred<string | undefined>();
    const runtime = createRuntime({
      pageIdentity: {
        override: ({ navigationGeneration }) =>
          navigationGeneration === 1 ? staleOverride.promise : '/router/newer',
      },
    });
    await runtime.start();

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();
    fixture.navigationListener?.();
    fixture.settlerWaits[1]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.identityResolverInputs).toEqual([
      {
        location: { pathname: '/current', search: '', hash: '' },
        override: '/router/newer',
      },
    ]);
    staleOverride.resolve('/router/older');
    await flushAsyncWork();

    expect(fixture.identityResolverInputs).toEqual([
      {
        location: { pathname: '/current', search: '', hash: '' },
        override: '/router/newer',
      },
    ]);
    expect(fixture.controllerPage).toEqual({ pageId: '/router/newer' });
    await runtime.destroy();
  });
  it('surfaces active page-identity resolver callback rejection through SCG_PAGE_IDENTITY', async () => {
    const callbackFailure = new Error('page identity callback failed');
    const runtime = createRuntime({
      pageIdentity: {
        override: async () => {
          throw callbackFailure;
        },
      },
    });
    await runtime.start();

    fixture.settlerWaits[0]?.deferred.resolve(true);
    await flushAsyncWork();

    expect(fixture.identityResolverInputs).toEqual([]);
    expect(fixture.manualErrorCodes).toEqual(['SCG_PAGE_IDENTITY']);
    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_PAGE_IDENTITY', kind: 'error' },
    });
    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown; readonly code: string };
      }
    ).navigationFailure;
    expect(navigationFailure.code).toBe('SCG_PAGE_IDENTITY');
    expect(navigationFailure.cause).toBe(callbackFailure);
    await runtime.destroy();
  });
  it('surfaces unavailable MutationObserver installation and retries after it is restored', async () => {
    fixture.mutationObserverAvailable = false;
    vi.stubGlobal('MutationObserver', undefined);
    const runtime = createRuntime();

    await runtime.start();

    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_MUTATION_OBSERVER_UNAVAILABLE', kind: 'error' },
    });
    expect(
      (runtime as unknown as { readonly navigationFailure: unknown }).navigationFailure,
    ).toMatchObject({ code: 'SCG_MUTATION_OBSERVER_UNAVAILABLE' });

    fixture.mutationObserverAvailable = true;
    Object.assign((runtime as unknown as { document: Document }).document, {
      defaultView: { MutationObserver: mutationObserverConstructor() } as unknown as Window,
    });
    await fixture.overlayRetry?.();

    expect(fixture.navigationStartCalls).toBe(2);
    expect(
      (runtime as unknown as { readonly navigationFailure: unknown }).navigationFailure,
    ).toBeNull();
    await runtime.destroy();
  });

  it('retains the MutationObserver installation cause in recoverable navigation state', async () => {
    const observerFailure = new Error('observer installation failed');
    fixture.mutationObserverObserveFailure = observerFailure;
    const runtime = createRuntime();

    await runtime.start();

    const navigationFailure = (
      runtime as unknown as {
        readonly navigationFailure: Error & { readonly cause?: unknown };
      }
    ).navigationFailure;
    expect(navigationFailure).toMatchObject({ code: 'SCG_MUTATION_OBSERVER_UNAVAILABLE' });
    expect(navigationFailure.cause).toBe(observerFailure);
    await runtime.destroy();
  });
  it('preserves startup and rollback failures while retry reinstalls a disconnected observer', async () => {
    const startupFailure = new Error('selection cleanup failed during startup');
    const observerRollbackFailure = new Error('observer disconnect failed during rollback');
    fixture.selectorStopFailure = startupFailure;
    fixture.mutationObserverDisconnectFailure = observerRollbackFailure;
    fixture.throwOwners.add('navigation');
    const runtime = createRuntime();

    await runtime.start();

    const internals = runtime as unknown as {
      readonly mutationObserver: MutationObserver | null;
      readonly navigationFailure: Error & {
        readonly cause?: unknown;
        readonly cleanupErrors?: readonly unknown[];
      };
    };
    expect(internals.mutationObserver).toBeNull();
    expect(internals.navigationFailure).toMatchObject({
      code: 'SCG_NAVIGATION_UNAVAILABLE',
    });
    expect(internals.navigationFailure.cause).toBe(startupFailure);
    expect(internals.navigationFailure.cleanupErrors).toEqual([
      new Error('navigation cleanup failed'),
      observerRollbackFailure,
    ]);
    expect(fixture.overlayStates.at(-1)).toMatchObject({
      capabilities: { canRetry: true },
      status: { code: 'SCG_NAVIGATION_UNAVAILABLE', kind: 'error' },
    });

    fixture.mutationObserverDisconnectFailure = null;
    fixture.throwOwners.clear();
    await fixture.overlayRetry?.();

    expect(fixture.navigationStartCalls).toBe(2);
    expect(fixture.mutationObserverObserveCalls).toBe(2);
    await runtime.destroy();
  });

  it('propagates public diagnostics failures', async () => {
    const runtime = createRuntime();
    await runtime.start();
    const failure = new Error('diagnostics unavailable');
    fixture.openDiagnosticsFailure = failure;

    await expect(runtime.getApi().openDiagnostics()).rejects.toBe(failure);
    await runtime.destroy();
  });
  it('serializes concurrent diagnostics opens so only the current owner publishes a panel', async () => {
    const runtime = createRuntime();
    await runtime.start();

    const first = runtime.getApi().openDiagnostics();
    const firstFailure = first.catch((error: unknown) => error);
    const second = runtime.getApi().openDiagnostics();

    await expect(second).resolves.toBeUndefined();
    await expect(firstFailure).resolves.toMatchObject({
      code: 'SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE',
    });
    expect(fixture.diagnosticControllerCreates).toBe(1);
    expect(fixture.diagnosticPanelCreates).toBe(1);
    expect(fixture.diagnosticPanelOpenCalls).toBe(1);

    await runtime.destroy();
  });
  it('serializes a diagnostic open re-entered from panel teardown', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();

    fixture.reentrantDiagnosticsOwner = 'diagnostics-panel';
    fixture.reentrantDiagnostics = () => runtime.getApi().openDiagnostics();
    const replacement = runtime.getApi().openDiagnostics();
    const replacementFailure = replacement.catch((error: unknown) => error);
    await flushAsyncWork();

    const reentrant = fixture.reentrantDiagnosticsTask;
    if (reentrant === null) {
      throw new Error('diagnostic teardown did not re-enter openDiagnostics');
    }
    await expect(replacementFailure).resolves.toMatchObject({
      code: 'SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE',
    });
    await expect(reentrant).resolves.toBeUndefined();
    expect(fixture.diagnosticControllerCreates).toBe(2);
    expect(fixture.diagnosticPanelCreates).toBe(2);
    fixture.reentrantDiagnostics = null;
    fixture.reentrantDiagnosticsOwner = null;
    await runtime.destroy();
  });

  it('publishes destroy ownership before synchronous teardown re-entry', async () => {
    const runtime = createRuntime();
    await runtime.start();
    fixture.reentrantDestroyOwner = 'navigation';
    fixture.reentrantDestroy = () => runtime.destroy();
    fixture.throwOwners.add('navigation');

    const destroy = runtime.destroy();
    await flushAsyncWork();

    expect(fixture.reentrantDestroyTask).toBe(destroy);
    await expect(destroy).rejects.toBeInstanceOf(AggregateError);
    await expect(fixture.reentrantDestroyTask).rejects.toBeInstanceOf(AggregateError);
  });
  it('waits for an in-flight replacement before destroy and never publishes it', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();
    const transport = diagnosticTransport();
    await transport.initialize({ projectId: 'project', token: 'diagnostic-token' });

    const closeDeferred = createDeferred<void>();
    fixture.mcpCloseDeferred = closeDeferred;
    const replacement = runtime.getApi().openDiagnostics();
    const replacementFailure = replacement.catch((error: unknown) => error);
    await flushAsyncWork();

    let destroyFinished = false;
    const destroy = runtime
      .getApi()
      .destroy()
      .then(() => {
        destroyFinished = true;
      });
    await flushAsyncWork();
    expect(destroyFinished).toBe(false);

    closeDeferred.resolve();
    await destroy;
    await expect(replacementFailure).resolves.toMatchObject({
      code: 'SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE',
    });
    expect(fixture.diagnosticControllerCreates).toBe(1);
    expect(fixture.diagnosticPanelCreates).toBe(1);
    expect(fixture.mcpClients[0]?.closeCalls).toBe(1);
    expect(fixture.mcpClients[0]?.disposeCalls).toBe(1);
  });
  it('drains an in-flight replacement teardown failure into destroy exactly once', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as { readonly diagnostics: unknown };
    await runtime.start();
    await runtime.getApi().openDiagnostics();
    const transport = diagnosticTransport();
    await transport.initialize({ projectId: 'project', token: 'diagnostic-token' });

    const closeDeferred = createDeferred<void>();
    const teardownFailure = new Error('replacement diagnostic teardown failed');
    fixture.mcpCloseDeferred = closeDeferred;
    const replacement = runtime.getApi().openDiagnostics();
    const replacementFailure = replacement.catch((error: unknown) => error);
    await flushAsyncWork();
    expect(internals.diagnostics).toBeNull();

    const destroyFailure = runtime
      .getApi()
      .destroy()
      .catch((error: unknown) => error);
    fixture.mcpCloseFailure = teardownFailure;
    closeDeferred.resolve();

    const failure = await destroyFailure;
    const predecessor = await replacementFailure;
    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors).toHaveLength(1);
    expect((failure as AggregateError).errors[0]).toBe(predecessor);
    expect(countErrorIdentity(failure, teardownFailure)).toBe(1);
    expect(fixture.mcpClients[0]?.closeCalls).toBe(1);
    expect(fixture.mcpClients[0]?.disposeCalls).toBe(1);
  });
  it('preserves a diagnostics construction failure with every local cleanup failure', async () => {
    const runtime = createRuntime();
    await runtime.start();
    fixture.cleanupCalls.length = 0;
    const primaryFailure = new Error('diagnostics panel construction failed');
    fixture.diagnosticPanelCreationFailure = primaryFailure;
    fixture.throwOwners.add('diagnostics-controller');

    const failure = await runtime
      .getApi()
      .openDiagnostics()
      .catch((error: unknown) => error);

    expect(failure).toBe(primaryFailure);
    const cleanupErrors = (
      failure as Error & {
        readonly cleanupErrors?: readonly unknown[];
      }
    ).cleanupErrors;
    expect(cleanupErrors).toHaveLength(1);
    expect(cleanupErrors?.[0]).toBeInstanceOf(AggregateError);
    expect((cleanupErrors?.[0] as AggregateError).errors).toEqual([
      expect.objectContaining({ message: 'diagnostics-controller cleanup failed' }),
    ]);
    expect(fixture.cleanupCalls).toEqual(['diagnostics-controller']);

    await runtime.destroy();
  });

  it.each([
    ['unmounts during locator capture', false, false],
    ['cannot be found in host DOM order', true, false],
  ])('does not persist a target that %s', async (_scenario, mountedAtCapture, inDomOrder) => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      document: Document;
      navigationStarted: boolean;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
      selectedTarget: unknown;
    };
    let mounted = true;
    const element = {
      closest(): null {
        return null;
      },
      getAttribute(): null {
        return null;
      },
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'selected target',
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(): boolean {
          return mounted;
        },
      },
      querySelectorAll(): readonly Element[] {
        return inDomOrder ? [element] : [];
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';

    const capture = createDeferred<void>();
    fixture.clientState = 'ready';
    fixture.locatorCaptureDeferred = capture;
    fixture.selectorOnSelect?.({ element, status: 'selected' });
    mounted = Boolean(mountedAtCapture);
    capture.resolve();
    await flushAsyncWork();

    expect(internals.selectedTarget).toBeNull();
    expect(fixture.manualErrorCodes).toEqual(['SCG_SELECTION_CAPTURE_FAILED']);
    expect(fixture.selectorStopCalls).toBeGreaterThan(0);
    await runtime.destroy();
  });
  it('keeps a selection publication failure observable without relabeling it as capture failure', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      captureTask: Promise<void> | null;
      document: Document;
      navigationStarted: boolean;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
    };
    const element = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'selected target',
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(candidate: Element): boolean {
          return candidate === element;
        },
      },
      querySelectorAll(): readonly Element[] {
        return [element];
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';
    fixture.clientState = 'ready';
    const publicationFailure = new Error('selector publication failed');
    fixture.selectorStopFailure = publicationFailure;

    fixture.selectorOnSelect?.({ element, status: 'selected' });
    await flushAsyncWork();

    const captureTask = internals.captureTask;
    if (captureTask === null) {
      throw new Error('selection publication failure was cleared');
    }
    await expect(captureTask).rejects.toBe(publicationFailure);
    expect(fixture.manualErrorCodes).toEqual([]);
    await runtime.destroy();
  });
  it('retains capture publication cleanup failures on the stable capture error', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      captureTask: Promise<void> | null;
      document: Document;
      navigationStarted: boolean;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
    };
    const element = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(): boolean {
          return false;
        },
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';
    fixture.clientState = 'ready';
    const publicationFailure = new Error('selection failure publication failed');
    fixture.selectorStopFailure = publicationFailure;

    fixture.selectorOnSelect?.({ element, status: 'selected' });
    await flushAsyncWork();

    const captureTask = internals.captureTask;
    if (captureTask === null) {
      throw new Error('capture failure was cleared');
    }
    await expect(captureTask).rejects.toMatchObject({
      cleanupErrors: [publicationFailure],
      code: 'SCG_SELECTION_CAPTURE_FAILED',
    });
    expect(fixture.manualErrorCodes).toEqual(['SCG_SELECTION_CAPTURE_FAILED']);
    await runtime.destroy();
  });
  it('keeps a later selected capture when an older locator capture completes out of order and rejects a memo bound to the older capture', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      captureTask: Promise<void> | null;
      createMemo(input: { readonly memo: string }): Promise<void>;
      crypto: Pick<Crypto, 'getRandomValues'>;
      document: Document;
      navigationStarted: boolean;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
      selectedTarget: { readonly surroundingText: string } | null;
    };
    const first = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'first selection',
    } as unknown as Element;
    const second = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'second selection',
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(candidate: Element): boolean {
          return candidate === first || candidate === second;
        },
      },
      querySelectorAll(): readonly Element[] {
        return [first, second];
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';
    internals.crypto = {
      getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        if (array instanceof Uint8Array) {
          array[6] = 0x40;
          array[8] = 0x80;
        }
        return array;
      },
    };
    fixture.clientState = 'ready';
    fixture.controllerPage = { pageId: 'page' };
    const firstCapture = createDeferred<void>();
    const secondCapture = createDeferred<void>();
    fixture.locatorCaptureDeferreds = [firstCapture, secondCapture];

    fixture.selectorOnSelect?.({ element: first, status: 'selected' });
    const memoForFirstCapture = internals.createMemo({ memo: 'memo for first selection' });
    fixture.selectorOnSelect?.({ element: second, status: 'selected' });
    secondCapture.resolve();
    await flushAsyncWork();

    expect(internals.selectedTarget).toMatchObject({ surroundingText: 'second selection' });
    const selectorStopsAfterSecondCapture = fixture.selectorStopCalls;

    firstCapture.resolve();
    await flushAsyncWork();

    expect(internals.selectedTarget).toMatchObject({ surroundingText: 'second selection' });
    expect(internals.captureTask).toBeNull();
    expect(fixture.selectorStopCalls).toBe(selectorStopsAfterSecondCapture);
    expect(fixture.manualErrorCodes).toEqual([]);
    await expect(memoForFirstCapture).rejects.toMatchObject({ code: 'SCG_SELECTION_REQUIRED' });
    expect(fixture.controllerCreateInputs).toEqual([]);
    await internals.createMemo({ memo: 'memo for second selection' });
    expect(fixture.controllerCreateInputs).toMatchObject([{ surroundingText: 'second selection' }]);
    expect(internals.selectedTarget).toBeNull();
    await runtime.destroy();
  });
  it('ignores the shake gesture while a picked element waits for its memo and honours it once the memo is saved', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      createMemo(input: { readonly memo: string }): Promise<void>;
      crypto: Pick<Crypto, 'getRandomValues'>;
      document: Document;
      navigationStarted: boolean;
      onShakeMove(event: PointerEvent): void;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
      selectedTarget: unknown;
    };
    const element = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'picked element',
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(candidate: Element): boolean {
          return candidate === element;
        },
      },
      querySelectorAll(): readonly Element[] {
        return [element];
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';
    internals.crypto = {
      getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        if (array instanceof Uint8Array) {
          array[6] = 0x40;
          array[8] = 0x80;
        }
        return array;
      },
    };
    fixture.clientState = 'ready';
    fixture.controllerPage = { pageId: 'page' };

    fixture.selectorOnSelect?.({ element, status: 'selected' });
    await flushAsyncWork();

    expect(internals.selectedTarget).not.toBeNull();
    expect(fixture.selectorReviewing).toBe(false);

    feedShake(internals);
    await flushAsyncWork();

    // 작성 중인 대상을 제스처가 지우지 않는다 — 다시 켜면 선택 세대가 올라가 저장할 것이 없어진다.
    expect(fixture.selectorReviewing).toBe(false);
    expect(internals.selectedTarget).not.toBeNull();

    await internals.createMemo({ memo: 'memo for the picked element' });
    expect(internals.selectedTarget).toBeNull();

    // 대상이 풀리면 같은 제스처가 다시 선택을 켠다.
    feedShake(internals);
    await flushAsyncWork();

    expect(fixture.selectorReviewing).toBe(true);
    await runtime.destroy();
  });
  it('invalidates a selected capture when a later unsupported callback arrives', async () => {
    const runtime = createRuntime();
    const internals = runtime as unknown as {
      captureTask: Promise<void> | null;
      createMemo(input: { readonly memo: string }): Promise<void>;
      document: Document;
      navigationStarted: boolean;
      pageReadyNavigationGeneration: number | null;
      readyControllerGeneration: number | null;
      readyPageId: string | null;
      selectedTarget: unknown;
    };
    const element = {
      getRootNode(): Document {
        return internals.document;
      },
      ownerDocument: internals.document,
      textContent: 'selected before unsupported',
    } as unknown as Element;
    Object.assign(internals.document, {
      documentElement: {
        contains(candidate: Element): boolean {
          return candidate === element;
        },
      },
      querySelectorAll(): readonly Element[] {
        return [element];
      },
    });
    internals.navigationStarted = true;
    internals.pageReadyNavigationGeneration = 0;
    internals.readyControllerGeneration = 0;
    internals.readyPageId = 'page';
    fixture.clientState = 'ready';
    fixture.controllerPage = { pageId: 'page' };
    fixture.selectorReviewing = true;
    const capture = createDeferred<void>();
    fixture.locatorCaptureDeferreds = [capture];

    fixture.selectorOnSelect?.({ element, status: 'selected' });
    fixture.selectorOnUnsupportedSelect?.({ reason: 'not-element', status: 'unsupported' });
    const selectorStopsBeforeStaleCapture = fixture.selectorStopCalls;
    expect(internals.selectedTarget).toBeNull();
    expect(internals.captureTask).toBeNull();
    expect(fixture.overlayStates.at(-1)).toMatchObject({
      status: { code: 'SCG_SELECTION_UNSUPPORTED_NOT_ELEMENT', kind: 'error' },
    });

    capture.reject(new Error('stale selection capture failed'));
    await flushAsyncWork();

    expect(internals.selectedTarget).toBeNull();
    expect(fixture.selectorStopCalls).toBe(selectorStopsBeforeStaleCapture);
    expect(fixture.manualErrorCodes).toEqual([]);
    await expect(internals.createMemo({ memo: 'stale memo' })).rejects.toMatchObject({
      code: 'SCG_SELECTION_REQUIRED',
    });
    await runtime.destroy();
  });
  it('propagates diagnostic close failures through the public destroy promise', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();
    const transport = diagnosticTransport();
    await transport.initialize({ projectId: 'project', token: 'diagnostic-token' });
    const closeFailure = new Error('diagnostic close failed');
    fixture.mcpCloseFailure = closeFailure;

    await expect(runtime.getApi().destroy()).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(AggregateError);
      const runtimeCleanup = error as AggregateError;
      expect(runtimeCleanup.errors).toHaveLength(1);
      expect(runtimeCleanup.errors[0]).toBeInstanceOf(AggregateError);
      const diagnosticCleanup = runtimeCleanup.errors[0] as AggregateError;
      expect(diagnosticCleanup.errors).toHaveLength(1);
      expect(diagnosticCleanup.errors[0]).toBeInstanceOf(AggregateError);
      expect((diagnosticCleanup.errors[0] as AggregateError).errors).toEqual([closeFailure]);
      return true;
    });
    expect(fixture.mcpClients[0]?.disposeCalls).toBe(1);
  });

  it('preserves every runtime and diagnostics teardown failure in deterministic order', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();

    fixture.throwOwners = new Set([
      'client',
      'controller',
      'diagnostics-controller',
      'diagnostics-panel',
      'navigation',
      'overlay',
      'selector',
      'settler',
    ]);

    let failure: unknown;
    try {
      await runtime.destroy();
    } catch (error: unknown) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    const aggregate = failure as AggregateError;
    expect(aggregate.message).toBe('Scene Glass runtime cleanup failed');
    expect(aggregate.errors).toHaveLength(7);
    expect(aggregate.errors.map((error) => (error as Error).message)).toEqual([
      'navigation cleanup failed',
      'settler cleanup failed',
      'selector cleanup failed',
      'overlay cleanup failed',
      'Scene Glass diagnostics cleanup failed',
      'controller cleanup failed',
      'client cleanup failed',
    ]);
    expect(aggregate.errors[4]).toBeInstanceOf(AggregateError);
    expect(
      (aggregate.errors[4] as AggregateError).errors.map((error) => (error as Error).message),
    ).toEqual(['diagnostics-panel cleanup failed', 'diagnostics-controller cleanup failed']);
    expect(fixture.cleanupCalls).toEqual([
      'navigation-start',
      'navigation',
      'settler',
      'selector',
      'overlay',
      'diagnostics-panel',
      'diagnostics-controller',
      'controller',
      'client',
    ]);
    await expect(runtime.destroy()).rejects.toBeInstanceOf(AggregateError);
  });

  it('rejects a second diagnostic initialize while the first owns initialization', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();
    const transport = diagnosticTransport();
    const deferred = createDeferred<void>();
    fixture.initializationDeferred = deferred;

    const first = transport.initialize({ projectId: 'project', token: 'diagnostic-token' });
    await expect(
      transport.initialize({ projectId: 'project', token: 'diagnostic-token' }),
    ).rejects.toMatchObject({ code: 'SCG_DIAGNOSTIC_CAPABILITY_UNAVAILABLE' });

    deferred.resolve();
    await expect(first).resolves.toEqual({ id: 'run-1' });
    await runtime.destroy();
  });

  it('closes and disposes a deferred diagnostic initialization superseded by destroy or deleteClose', async () => {
    for (const cleanup of [
      async (runtime: SceneGlassRuntime): Promise<void> => {
        await runtime.destroy();
      },
      async (_runtime: SceneGlassRuntime, transport: DiagnosticTransport): Promise<void> => {
        await transport.deleteClose();
      },
    ]) {
      resetFixture();
      const runtime = createRuntime();
      await runtime.start();
      await runtime.getApi().openDiagnostics();
      const transport = diagnosticTransport();
      const deferred = createDeferred<void>();
      fixture.initializationDeferred = deferred;

      const initialization = transport.initialize({
        projectId: 'project',
        token: 'diagnostic-token',
      });
      const initializationFailure = initialization.catch((error: unknown) => error);
      const cleanupTask = cleanup(runtime, transport);
      await flushAsyncWork();
      await cleanupTask;

      await expect(initializationFailure).resolves.toMatchObject({
        code: 'SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE',
      });
      await flushAsyncWork();
      expect(fixture.mcpClients).toHaveLength(1);
      expect(fixture.mcpClients[0]?.closeCalls).toBe(1);
      expect(fixture.mcpClients[0]?.disposeCalls).toBe(1);
    }
  });

  it('classifies an abort-faithful diagnostic initialization supersession with cause and DELETE cleanup error', async () => {
    const runtime = createRuntime();
    await runtime.start();
    await runtime.getApi().openDiagnostics();
    const transport = diagnosticTransport();
    const deferred = createDeferred<void>();
    const supersession = new Error('MCP session was superseded');
    fixture.initializationDeferred = deferred;
    fixture.mcpInitializationAbortError = supersession;
    const closeFailure = new Error('diagnostic close failed');
    fixture.mcpCloseFailure = closeFailure;

    const initialization = transport.initialize({
      projectId: 'project',
      token: 'diagnostic-token',
    });
    const initializationFailure = initialization.catch((error: unknown) => error);
    const closeTask = transport.deleteClose();
    await flushAsyncWork();

    const cleanupFailure = await closeTask.catch((error: unknown) => error);
    expect(cleanupFailure).toBeInstanceOf(AggregateError);
    expect((cleanupFailure as AggregateError).errors).toEqual([closeFailure]);
    await expect(initializationFailure).resolves.toSatisfy((error: unknown) => {
      expect(error).toMatchObject({
        code: 'SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE',
        cleanupErrors: [closeFailure],
      });
      expect((error as Error & { readonly cause?: unknown }).cause).toBe(supersession);
      return true;
    });
    expect(fixture.mcpClients).toHaveLength(1);
    expect(fixture.mcpClients[0]?.closeCalls).toBe(1);
    expect(fixture.mcpClients[0]?.disposeCalls).toBe(1);
    await expect(runtime.destroy()).rejects.toBeInstanceOf(AggregateError);
  });
});
