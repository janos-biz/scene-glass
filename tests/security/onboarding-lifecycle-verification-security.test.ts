import { formatWithOptions, inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  CANONICAL_LOADER_PATH,
  LiveDiagnosticError,
  assertNoPersistentSecret,
  runBootstrapSmoke,
  type BrowserDiagnosticCloseReceipt,
  type BootstrapSmokeProfileHandle,
  type DiagnosticCloseReceipt,
  type DiagnosticExecutionContext,
} from '../../packages/onboarding/src/lifecycle/verification.js';

const TOKEN_CANARY = 'token-canary-7Gx';
const PATH_CANARY = '/private/scene-glass/authority';
const BOOTSTRAP_SMOKE_TOKEN_CANARY = 'token-canary-bootstrap-smoke-7Gx';
const BOOTSTRAP_SMOKE_PATH_CANARY = '/private/scene-glass/bootstrap-smoke';
const BOOTSTRAP_CLEANUP_TOKEN_CANARY = 'token-canary-bootstrap-cleanup-7Gx';
const BOOTSTRAP_CLEANUP_PATH_CANARY = '/private/scene-glass/bootstrap-cleanup';
const BOOTSTRAP_SMOKE_CANARIES = Object.freeze([
  BOOTSTRAP_SMOKE_TOKEN_CANARY,
  BOOTSTRAP_SMOKE_PATH_CANARY,
]);
const BOOTSTRAP_CLEANUP_CANARIES = Object.freeze([
  BOOTSTRAP_CLEANUP_TOKEN_CANARY,
  BOOTSTRAP_CLEANUP_PATH_CANARY,
]);

describe('onboarding lifecycle verification security', () => {
  it('excludes only a transient, canonical no-store loader response body from canary scanning', () => {
    expect(() =>
      assertNoPersistentSecret({
        canaries: canaries(),
        receipts: [
          {
            phase: 'host',
            records: [
              {
                body: `loader source ${TOKEN_CANARY}`,
                cacheControl: 'no-store, private, max-age=0',
                kind: 'http-response',
                path: CANONICAL_LOADER_PATH,
                transient: true,
              },
            ],
          },
        ],
      }),
    ).not.toThrow();

    for (const record of [
      {
        body: TOKEN_CANARY,
        cacheControl: 'no-store',
        kind: 'http-response' as const,
        path: '/other-loader.js',
        transient: true,
      },
      {
        body: TOKEN_CANARY,
        cacheControl: 'max-age=0',
        kind: 'http-response' as const,
        path: CANONICAL_LOADER_PATH,
        transient: true,
      },
      {
        body: TOKEN_CANARY,
        cacheControl: 'no-store',
        kind: 'http-response' as const,
        path: CANONICAL_LOADER_PATH,
        transient: false,
      },
    ]) {
      const failure = secretReceiptFailure(() =>
        assertNoPersistentSecret({
          canaries: canaries(),
          receipts: [{ phase: 'host', records: [record] }],
        }),
      );
      expect(failure.message).toBe('secret-receipt');
      assertErrorGraphRedacted(failure, [TOKEN_CANARY, PATH_CANARY]);
    }
  });

  it('rejects token and path canaries in all retained close-record fields without echoing them', () => {
    const receipts: DiagnosticCloseReceipt[] = [
      { phase: 'host', records: [{ kind: 'log', text: `diagnostic ${TOKEN_CANARY}` }] },
      { phase: 'mcp-server', records: [{ kind: 'header', text: `path=${PATH_CANARY}` }] },
      {
        phase: 'mcp-session',
        records: [
          {
            body: 'safe',
            cacheControl: `no-store; ${PATH_CANARY}`,
            kind: 'http-response',
            path: CANONICAL_LOADER_PATH,
            transient: true,
          },
        ],
      },
    ];

    for (const receipt of receipts) {
      const failure = secretReceiptFailure(() =>
        assertNoPersistentSecret({ canaries: canaries(), receipts: [receipt] }),
      );
      expect(failure.message).toBe('secret-receipt');
      assertErrorGraphRedacted(failure, [TOKEN_CANARY, PATH_CANARY]);
    }
  });

  it.each([
    'localStorageKeys',
    'sessionStorageKeys',
    'indexedDbNames',
    'cacheStorageNames',
    'serviceWorkerRegistrations',
  ] as const)('rejects browser %s persistence even when it contains no known canary', (field) => {
    const state = emptyBrowserState();
    state[field].push('unexpected-store');

    const failure = secretReceiptFailure(() =>
      assertNoPersistentSecret({
        canaries: canaries(),
        receipts: [{ browserState: state, phase: 'browser-profile', records: [] }],
      }),
    );
    expect(failure.message).toBe('secret-receipt');
    assertErrorGraphRedacted(failure, [TOKEN_CANARY, PATH_CANARY]);
  });

  it('requires browser profile receipts to attest every browser store is absent', () => {
    const failure = secretReceiptFailure(() =>
      assertNoPersistentSecret({
        canaries: canaries(),
        receipts: [{ phase: 'browser-profile', records: [] }],
      }),
    );
    expect(failure.message).toBe('secret-receipt');
    assertErrorGraphRedacted(failure, [TOKEN_CANARY, PATH_CANARY]);
  });

  it.each([
    ['public property', () => Object.assign(new Error('safe'), { retained: TOKEN_CANARY })],
    ['nested value', () => Object.assign(new Error('safe'), { retained: { nested: PATH_CANARY } })],
    [
      'non-enumerable property',
      () => Object.defineProperty(new Error('safe'), 'retained', { value: TOKEN_CANARY }),
    ],
    [
      'accessor property',
      () => Object.defineProperty(new Error('safe'), 'retained', { get: () => TOKEN_CANARY }),
    ],
    [
      'symbol property',
      () => Object.defineProperty(new Error('safe'), Symbol('retained'), { value: PATH_CANARY }),
    ],
    [
      'cause',
      () => Object.defineProperty(new Error('safe'), 'cause', { value: new Error(TOKEN_CANARY) }),
    ],
    [
      'stack',
      () => {
        const error = new Error('safe');
        error.stack = PATH_CANARY;
        return error;
      },
    ],
    ['string surface', () => Object.assign(new Error('safe'), { toString: () => TOKEN_CANARY })],
    [
      'inspect surface',
      () => Object.defineProperty(new Error('safe'), inspect.custom, { value: () => PATH_CANARY }),
    ],
    [
      'format surface',
      () => {
        let inspections = 0;
        return Object.defineProperty(new Error('safe'), inspect.custom, {
          value: () => {
            inspections += 1;
            return inspections === 1 ? 'safe' : TOKEN_CANARY;
          },
        });
      },
    ],
    [
      'prototype property',
      () => {
        const error = new Error('safe');
        Object.setPrototypeOf(error, { retained: TOKEN_CANARY });
        return error;
      },
    ],
    [
      'Map entry hidden by custom inspection',
      () => {
        const retained = new Map([['safe', PATH_CANARY]]);
        Object.defineProperty(retained, inspect.custom, { value: () => 'safe' });
        return Object.assign(new Error('safe'), { retained });
      },
    ],
    [
      'Set entry hidden by custom inspection',
      () => {
        const retained = new Set([TOKEN_CANARY]);
        Object.defineProperty(retained, inspect.custom, { value: () => 'safe' });
        return Object.assign(new Error('safe'), { retained });
      },
    ],
  ] as const)('fails closed when a %s retains a canary', (_surface, createError) => {
    const failure = errorGraphFailure(() =>
      assertErrorGraphRedacted(createError(), [TOKEN_CANARY, PATH_CANARY]),
    );
    expect(failure.message).toBe('diagnostic error retained sensitive data');
  });

  it('completes empty workers-enabled smoke and closes the profile', async () => {
    const calls: string[] = [];
    let closeCount = 0;

    await expect(
      runBootstrapSmoke({
        context: context(),
        persistentSecretCanaries: canaries(),
        port: {
          async startEmptyWorkersEnabledProfile() {
            calls.push('profile-start');
            return {
              empty: true,
              persistent: false,
              workersEnabled: true,
              async close() {
                closeCount += 1;
                calls.push('profile-close');
                return browserReceipt('bootstrap-profile');
              },
              async smoke() {
                calls.push('smoke');
              },
            };
          },
        },
      }),
    ).resolves.toEqual({ persistent: false, workersEnabled: true });

    expect(calls).toEqual(['profile-start', 'smoke', 'profile-close']);
    expect(closeCount).toBe(1);
  });

  it('redacts bootstrap cleanup failures while still removing the profile', async () => {
    let closeCount = 0;
    const error = await failureOf(
      runBootstrapSmoke({
        context: context(),
        persistentSecretCanaries: Object.freeze({
          pathCanaries: [] as const,
        }),
        port: {
          async startEmptyWorkersEnabledProfile() {
            return {
              empty: true,
              persistent: false,
              workersEnabled: true,
              async close() {
                closeCount += 1;
                throw faultError(BOOTSTRAP_CLEANUP_CANARIES);
              },
              async smoke() {
                throw faultError(BOOTSTRAP_SMOKE_CANARIES);
              },
            };
          },
        },
      }),
    );

    expect(error.failures).toEqual([
      { phase: 'bootstrap-smoke' },
      { phase: 'bootstrap-profile-close' },
    ]);
    expect(error.message).toBe('live diagnostics failed: bootstrap-smoke, bootstrap-profile-close');
    assertErrorGraphRedacted(error, [...BOOTSTRAP_SMOKE_CANARIES, ...BOOTSTRAP_CLEANUP_CANARIES]);
    expect(closeCount).toBe(1);
  });
  it('redacts a deferred canary-bearing cleanup convergence rejection without mutating the caller failure', async () => {
    const aborter = new AbortController();
    const diagnosticContext = context(aborter.signal);
    const profileStarted = createDeferred<void>();
    const lateProfile = createDeferred<BootstrapSmokeProfileHandle>();
    const closeContexts: DiagnosticExecutionContext[] = [];
    let closeCount = 0;
    const diagnostic = runBootstrapSmoke({
      context: diagnosticContext,
      persistentSecretCanaries: canaries(),
      port: {
        async startEmptyWorkersEnabledProfile() {
          profileStarted.resolve(undefined);
          return lateProfile.promise;
        },
      },
    });

    await awaitBounded(profileStarted.promise, 'deferred bootstrap profile startup');
    aborter.abort();

    const error = await failureOf(
      awaitBounded(diagnostic, 'caller-facing deferred bootstrap smoke failure'),
    );
    const terminalFailures = error.failures;
    const terminalMessage = error.message;
    expect(error.failures).toStrictEqual([{ phase: 'aborted' }]);
    expect(error.message).toBe('live diagnostics failed: aborted');
    expect(Object.isFrozen(error.failures)).toBe(true);
    expect(Object.isFrozen(error.failures[0])).toBe(true);
    assertErrorGraphRedacted(error, [TOKEN_CANARY, PATH_CANARY]);
    expect(closeCount).toBe(0);

    const cleanupConvergence = error.cleanupConvergence;
    if (cleanupConvergence === undefined) {
      throw new Error('deferred bootstrap cleanup convergence was unavailable');
    }
    let convergenceSettled = false;
    void cleanupConvergence.then(
      () => {
        convergenceSettled = true;
      },
      () => {
        convergenceSettled = true;
      },
    );
    await Promise.resolve();
    expect(convergenceSettled).toBe(false);

    const injectedCleanupFailure = faultError([TOKEN_CANARY, PATH_CANARY]);
    lateProfile.resolve({
      empty: true,
      persistent: false,
      workersEnabled: true,
      async close(cleanupContext) {
        closeContexts.push(cleanupContext);
        closeCount += 1;
        if (closeCount !== 1) {
          throw new Error('deferred bootstrap profile close invoked more than once');
        }
        throw injectedCleanupFailure;
      },
      async smoke() {},
    });

    const lateCleanupFailure = await expectDeferredCleanupConvergenceRejection(
      cleanupConvergence,
      'secret-receipt',
    );
    expect(lateCleanupFailure).not.toBe(injectedCleanupFailure);
    assertErrorGraphRedacted(lateCleanupFailure, [TOKEN_CANARY, PATH_CANARY]);
    expect(closeCount).toBe(1);
    expect(closeContexts).toHaveLength(1);
    const [cleanupContext] = closeContexts;
    if (cleanupContext === undefined) {
      throw new Error('deferred bootstrap cleanup context was unavailable');
    }
    expect(Object.isFrozen(cleanupContext)).toBe(true);
    expect(cleanupContext.deadline).toBe(diagnosticContext.deadline);
    expect(cleanupContext.signal).not.toBe(diagnosticContext.signal);
    expect(cleanupContext.signal.aborted).toBe(false);
    expect(error.failures).toBe(terminalFailures);
    expect(error.failures).toStrictEqual([{ phase: 'aborted' }]);
    expect(error.message).toBe(terminalMessage);
    assertErrorGraphRedacted(error, [TOKEN_CANARY, PATH_CANARY]);
  });
});

function canaries(): {
  readonly pathCanaries: readonly string[];
  readonly tokenMatcher: { matches(value: Uint8Array): boolean };
} {
  const token = new TextEncoder().encode(TOKEN_CANARY);
  return {
    pathCanaries: [PATH_CANARY],
    tokenMatcher: {
      matches(value) {
        return containsBytes(value, token);
      },
    },
  };
}

function containsBytes(value: Uint8Array, candidate: Uint8Array): boolean {
  for (let offset = 0; offset <= value.length - candidate.length; offset += 1) {
    let matched = true;
    for (let index = 0; index < candidate.length; index += 1) {
      if (value[offset + index] !== candidate[index]) {
        matched = false;
        break;
      }
    }
    if (matched) return true;
  }
  return false;
}

function context(signal: AbortSignal = new AbortController().signal): DiagnosticExecutionContext {
  return { deadline: Date.now() + 10_000, signal };
}

function emptyBrowserState(): {
  cacheStorageNames: string[];
  indexedDbNames: string[];
  localStorageKeys: string[];
  serviceWorkerRegistrations: string[];
  sessionStorageKeys: string[];
} {
  return {
    cacheStorageNames: [],
    indexedDbNames: [],
    localStorageKeys: [],
    serviceWorkerRegistrations: [],
    sessionStorageKeys: [],
  };
}

function browserReceipt(
  phase: BrowserDiagnosticCloseReceipt['phase'],
): BrowserDiagnosticCloseReceipt {
  return { browserState: emptyBrowserState(), phase, records: [] };
}

function secretReceiptFailure(action: () => void): Error {
  try {
    action();
  } catch (error: unknown) {
    if (error instanceof Error) {
      return error;
    }
    throw error;
  }
  throw new Error('secret receipt unexpectedly passed');
}

async function failureOf(promise: Promise<unknown>): Promise<LiveDiagnosticError> {
  try {
    await promise;
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(LiveDiagnosticError);
    return error as LiveDiagnosticError;
  }
  throw new Error('bootstrap smoke unexpectedly succeeded');
}

interface ProductDiagnosticPhaseError extends Error {
  readonly phase: 'secret-receipt';
}
async function expectDeferredCleanupConvergenceRejection(
  cleanupConvergence: Promise<void>,
  expectedPhase: ProductDiagnosticPhaseError['phase'],
): Promise<ProductDiagnosticPhaseError> {
  const timeoutSentinel = Symbol('deferred cleanup convergence timeout');
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const settled = await (() => {
    const timeoutResult = new Promise<typeof timeoutSentinel>((resolve) => {
      timeout = setTimeout(() => {
        resolve(timeoutSentinel);
      }, 2_000);
    });
    return Promise.race([
      cleanupConvergence.then(
        () => ({ state: 'fulfilled' as const }),
        (reason: unknown) => ({ reason, state: 'rejected' as const }),
      ),
      timeoutResult,
    ]);
  })().finally(() => {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  });

  if (settled === timeoutSentinel) {
    throw new Error('deferred cleanup convergence did not settle within the bounded test interval');
  }
  expect(settled.state).toBe('rejected');
  if (settled.state !== 'rejected') {
    throw new Error('deferred cleanup convergence unexpectedly fulfilled');
  }

  const rejection = settled.reason;
  expect(rejection).toBeInstanceOf(Error);
  if (!(rejection instanceof Error)) {
    throw new Error('deferred cleanup convergence rejected without a product error');
  }
  expect(rejection.constructor.name).toBe('DiagnosticPhaseError');
  expect(rejection.name).toBe('DiagnosticPhaseError');
  expect(rejection.message).toBe(expectedPhase);
  expect((rejection as Error & { readonly phase?: unknown }).phase).toBe(expectedPhase);
  return rejection as ProductDiagnosticPhaseError;
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
}

function createDeferred<T>(): Deferred<T> {
  let resolvePromise: ((value: T | PromiseLike<T>) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  if (resolvePromise === undefined) {
    throw new Error('deferred promise did not expose its resolver');
  }
  const resolve = resolvePromise;
  return Object.freeze({
    promise,
    resolve(value: T): void {
      resolve(value);
    },
  });
}

async function awaitBounded<T>(operation: Promise<T>, description: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutFailure = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`${description} did not settle within the bounded test interval`));
    }, 2_000);
  });
  try {
    return await Promise.race([operation, timeoutFailure]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}
function faultError(canaries: readonly string[]): Error {
  const [token, path] = canaries;
  if (token === undefined || path === undefined) {
    throw new Error('fault canaries are required');
  }

  const error = new Error('diagnostic fault');
  Object.defineProperty(error, 'cause', {
    value: new Error(`diagnostic cause ${path}`),
  });
  Object.defineProperty(error, 'retained', {
    value: Object.freeze({
      nested: Object.freeze({
        bytes: new TextEncoder().encode(`${path}:${token}`),
        path,
        token,
      }),
    }),
  });
  Object.defineProperty(error, Symbol(`diagnostic ${token}`), {
    value: Object.freeze({ path, token }),
  });
  Object.defineProperty(error, inspect.custom, {
    value: () => `diagnostic fault ${path}`,
  });
  Object.defineProperty(error, 'toString', {
    value: () => `diagnostic fault ${token}`,
  });
  Object.defineProperty(error, 'publicCanary', { enumerable: true, value: token });
  error.stack = `${error.stack ?? error.name}\n${path}`;
  return error;
}

const ERROR_GRAPH_NODE_LIMIT = 128;
const ERROR_GRAPH_DEPTH_LIMIT = 8;
const ERROR_GRAPH_PROPERTY_LIMIT = 64;
const ERROR_GRAPH_TEXT_LIMIT = 131_072;
const ERROR_GRAPH_BYTE_LIMIT = 131_072;
const ERROR_GRAPH_INSPECT_OPTIONS = Object.freeze({
  breakLength: 120,
  compact: true,
  customInspect: true,
  depth: ERROR_GRAPH_DEPTH_LIMIT,
  getters: false,
  maxArrayLength: ERROR_GRAPH_PROPERTY_LIMIT,
  maxStringLength: ERROR_GRAPH_TEXT_LIMIT,
  showHidden: true,
  sorted: true,
});
const ERROR_GRAPH_TRUSTED_PROTOTYPES = new Set<object>([
  Array.prototype,
  ArrayBuffer.prototype,
  DataView.prototype,
  Error.prototype,
  Function.prototype,
  Map.prototype,
  Object.prototype,
  Set.prototype,
  Uint8Array.prototype,
]);

interface ErrorGraphEntry {
  readonly depth: number;
  readonly value: unknown;
}

function assertErrorGraphRedacted(error: unknown, canaries: readonly string[]): void {
  if (canaries.length > ERROR_GRAPH_PROPERTY_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  const tokenBytes = canaries.map((canary) => {
    if (canary.length > ERROR_GRAPH_TEXT_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }
    return new TextEncoder().encode(canary);
  });
  const queue: ErrorGraphEntry[] = [{ depth: 0, value: error }];
  const seen = new WeakSet<object>();

  for (let offset = 0; offset < queue.length; offset += 1) {
    const entry = queue[offset];
    if (entry === undefined) {
      throwSensitiveErrorGraphFailure();
    }
    assertErrorGraphValue(entry.value, canaries, tokenBytes);

    if (!isErrorGraphObject(entry.value)) {
      continue;
    }
    if (seen.has(entry.value)) {
      continue;
    }
    if (entry.depth >= ERROR_GRAPH_DEPTH_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }
    seen.add(entry.value);
    let prototype: object | null;
    try {
      prototype = Object.getPrototypeOf(entry.value);
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    if (prototype !== null && !ERROR_GRAPH_TRUSTED_PROTOTYPES.has(prototype)) {
      enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: prototype });
    }
    enqueueErrorGraphCollectionEntries(entry.value, entry.depth, queue);

    assertErrorGraphSurface(() => String(entry.value), canaries, tokenBytes);
    assertErrorGraphSurface(
      () => inspect(entry.value, ERROR_GRAPH_INSPECT_OPTIONS),
      canaries,
      tokenBytes,
    );
    assertErrorGraphSurface(
      () => formatWithOptions(ERROR_GRAPH_INSPECT_OPTIONS, '%o', entry.value),
      canaries,
      tokenBytes,
    );
    assertErrorGraphSurface(
      () => formatWithOptions(ERROR_GRAPH_INSPECT_OPTIONS, '%O', entry.value),
      canaries,
      tokenBytes,
    );

    let keys: readonly PropertyKey[];
    try {
      keys = Reflect.ownKeys(entry.value);
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    if (keys.length > ERROR_GRAPH_PROPERTY_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }

    for (const key of keys) {
      if (typeof key === 'string') {
        assertErrorGraphText(key, canaries, tokenBytes);
      } else {
        assertErrorGraphSurface(() => String(key), canaries, tokenBytes);
      }

      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(entry.value, key);
      } catch {
        throwSensitiveErrorGraphFailure();
      }
      if (descriptor === undefined) {
        throwSensitiveErrorGraphFailure();
      }
      if ('value' in descriptor) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.value });
      }
      if (descriptor.get !== undefined) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.get });
        let getterValue: unknown;
        try {
          getterValue = Reflect.get(entry.value, key);
        } catch {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: getterValue });
      }
      if (descriptor.set !== undefined) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.set });
      }
    }
  }
}

function enqueueErrorGraphValue(queue: ErrorGraphEntry[], entry: ErrorGraphEntry): void {
  if (queue.length >= ERROR_GRAPH_NODE_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  queue.push(entry);
}
function enqueueErrorGraphCollectionEntries(
  value: object,
  depth: number,
  queue: ErrorGraphEntry[],
): void {
  if (value instanceof Map) {
    let entries = 0;
    try {
      for (const [key, item] of Map.prototype.entries.call(value)) {
        entries += 1;
        if (entries > ERROR_GRAPH_PROPERTY_LIMIT) {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: key });
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: item });
      }
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    return;
  }
  if (value instanceof Set) {
    let entries = 0;
    try {
      for (const item of Set.prototype.values.call(value)) {
        entries += 1;
        if (entries > ERROR_GRAPH_PROPERTY_LIMIT) {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: item });
      }
    } catch {
      throwSensitiveErrorGraphFailure();
    }
  }
}

function isErrorGraphObject(value: unknown): value is object {
  return (typeof value === 'object' && value !== null) || typeof value === 'function';
}

function assertErrorGraphValue(
  value: unknown,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  if (typeof value === 'string') {
    assertErrorGraphText(value, canaries, tokenBytes);
    return;
  }
  if (typeof value === 'symbol') {
    assertErrorGraphSurface(() => String(value), canaries, tokenBytes);
    return;
  }
  if (value instanceof Uint8Array) {
    assertErrorGraphBytes(value, tokenBytes);
    return;
  }
  if (ArrayBuffer.isView(value)) {
    assertErrorGraphBytes(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
      tokenBytes,
    );
    return;
  }
  if (value instanceof ArrayBuffer) {
    assertErrorGraphBytes(new Uint8Array(value), tokenBytes);
  }
}

function assertErrorGraphSurface(
  render: () => string,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  try {
    assertErrorGraphText(render(), canaries, tokenBytes);
  } catch {
    throwSensitiveErrorGraphFailure();
  }
}

function assertErrorGraphText(
  value: string,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  if (value.length > ERROR_GRAPH_TEXT_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  for (const canary of canaries) {
    if (value.includes(canary)) {
      throwSensitiveErrorGraphFailure();
    }
  }
  assertErrorGraphBytes(new TextEncoder().encode(value), tokenBytes);
}

function assertErrorGraphBytes(value: Uint8Array, canaries: readonly Uint8Array[]): void {
  if (value.byteLength > ERROR_GRAPH_BYTE_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  for (const canary of canaries) {
    if (containsBytes(value, canary)) {
      throwSensitiveErrorGraphFailure();
    }
  }
}

function errorGraphFailure(action: () => void): Error {
  try {
    action();
  } catch (error: unknown) {
    if (error instanceof Error) {
      return error;
    }
    throw error;
  }
  throw new Error('error graph oracle unexpectedly passed');
}

function throwSensitiveErrorGraphFailure(): never {
  throw new Error('diagnostic error retained sensitive data');
}
