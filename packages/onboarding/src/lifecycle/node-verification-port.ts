import { assertSecureReadNativeAvailable } from '../native.js';
import type { DescriptorProjectSet } from '../types.js';
import type { FinalizedHostIntegrationPlan } from './host-plan.js';
import {
  runBootstrapSmoke,
  runLiveDiagnostics,
  CANONICAL_LOADER_PATH,
  MAX_DIAGNOSTIC_HEADER_BYTES,
  MAX_DIAGNOSTIC_HEADERS,
  MAX_DIAGNOSTIC_RESPONSE_BYTES,
  type BootstrapSmokePort,
  type BrowserDiagnosticCloseReceipt,
  type BrowserDiagnosticProfileHandle,
  type DiagnosticCloseReceipt,
  type DiagnosticExecutionContext,
  type DiagnosticHttpResponse,
  type FinalizedVerificationAuthority,
  type LiveDiagnosticBrowserPort,
  type LiveDiagnosticHostPort,
  type LiveDiagnosticMcpPort,
  type LoopbackMcpRuntimeHandle,
  type McpSessionTransportHandle,
  type McpServerHandle,
  type SelectedHostKind,
  type SelectedHostRuntimeHandle,
} from './verification.js';

const MAX_HTTP_RESPONSE_BYTES = MAX_DIAGNOSTIC_RESPONSE_BYTES;
const MAX_HTTP_RESPONSE_CHUNKS = 1_024;

const authorityStates = new WeakMap<
  FinalizedVerificationAuthority,
  NodeVerificationAuthorityState
>();

declare const nodeVerificationAuthorityBrand: unique symbol;

/**
 * Opaque authority used only by the production lifecycle and verification
 * adapters. It is intentionally not serializable and never contains token
 * bytes.
 */
export interface NodeVerificationAuthority extends FinalizedVerificationAuthority {
  readonly [nodeVerificationAuthorityBrand]: 'scene-glass-node-verification-authority';
}

export interface NodeVerificationAuthorityInput {
  readonly finalizedHost: FinalizedHostIntegrationPlan;
  readonly configuredProjects: DescriptorProjectSet;
  readonly projectRoot: string;
}

interface NodeVerificationAuthorityState {
  readonly finalizedHost: FinalizedHostIntegrationPlan;
  readonly configuredProjects: DescriptorProjectSet;
  readonly projectRoot: string;
}

export interface NodeMcpRuntime {
  readonly server: McpServerHandle;
  readonly session: McpSessionTransportHandle;
}

/**
 * Opaque mutable-byte token oracle supplied by the lifecycle engine. Its
 * implementation owns raw, encoded, and digest canaries and destroys them in
 * the engine adapter's all-exits cleanup.
 */
export interface OpaqueSecretPersistenceMatcher {
  matches(value: Uint8Array): boolean;
  destroy(): void;
}

export type NodeBrowserProfile = BrowserDiagnosticProfileHandle;

export interface NodeBootstrapProfile {
  readonly empty: true;
  readonly workersEnabled: true;
  readonly persistent: false;
  smoke(context: DiagnosticExecutionContext): Promise<void>;
  close(context: DiagnosticExecutionContext): Promise<BrowserDiagnosticCloseReceipt>;
}

/**
 * Verification dependencies are explicit because browser and MCP process
 * ownership belongs to the executable that selects their launch policy. No
 * synthetic success implementation is provided.
 */
export interface NodeLifecycleVerificationPortOptions {
  readonly fetch?: typeof fetch;
  /**
   * Loopback port of the lifecycle MCP server that serves the canonical
   * loader script (`/scene-glass-loader.js`). The host runtimes (static and
   * managed Vite) only inject the loader URL into HTML; the loader bytes are
   * served cross-origin by the MCP server, so the diagnostic loader phase
   * must verify the descriptor loader URL against this authority and fetch
   * from it (the MCP server is started in the `mcp-start` phase, before the
   * `loader` phase performs the fetch).
   */
  readonly loaderPort: number;
  readonly startBrowserProfile: (
    context: DiagnosticExecutionContext,
  ) => Promise<NodeBrowserProfile>;
  readonly startBootstrapProfile: (
    context: DiagnosticExecutionContext,
  ) => Promise<NodeBootstrapProfile>;
  readonly startLoopbackMcp: (
    input: Readonly<{
      readonly authority: NodeVerificationAuthority;
      readonly host: SelectedHostRuntimeHandle;
      readonly context: DiagnosticExecutionContext;
    }>,
  ) => Promise<NodeMcpRuntime>;
}

export interface NodeLifecycleVerificationPorts {
  readonly host: LiveDiagnosticHostPort;
  readonly mcp: LiveDiagnosticMcpPort;
  readonly browser: LiveDiagnosticBrowserPort;
  readonly bootstrap: BootstrapSmokePort;
  runNativeSelfTest(): Promise<void>;
  runBootstrapSmoke(context: DiagnosticExecutionContext): Promise<void>;
  runLiveDiagnostics(
    input: Readonly<{
      readonly authority: NodeVerificationAuthority;
      readonly selectedHost: SelectedHostKind;
      readonly context: DiagnosticExecutionContext;
      readonly tokenMatcher: OpaqueSecretPersistenceMatcher;
      readonly pathCanaries: readonly string[];
    }>,
  ): Promise<void>;
}

export function createNodeFinalizedVerificationAuthority(
  input: NodeVerificationAuthorityInput,
): NodeVerificationAuthority {
  const authority = Object.freeze({}) as unknown as NodeVerificationAuthority;
  authorityStates.set(authority, Object.freeze({ ...input }));
  return authority;
}

/** Throws rather than returning partial authority facts. */
export function nodeVerificationAuthorityState(
  authority: FinalizedVerificationAuthority,
): Readonly<NodeVerificationAuthorityState> {
  const state = authorityStates.get(authority);
  if (state === undefined) {
    throw new Error('verification authority is not owned by the Node lifecycle adapter');
  }
  return state;
}

export function createNodeLifecycleVerificationPorts(
  options: NodeLifecycleVerificationPortOptions,
): NodeLifecycleVerificationPorts {
  const fetchImplementation = options.fetch ?? globalThis.fetch;
  if (typeof fetchImplementation !== 'function') {
    throw new Error('Node verification requires a fetch implementation');
  }

  const host: LiveDiagnosticHostPort = {
    async start(input) {
      if (input.selectedHost !== 'static') {
        throw new Error('verification host selection is invalid');
      }
      const state = nodeVerificationAuthorityState(input.authority);
      return loopbackLoaderHostHandle(
        fetchImplementation,
        state.finalizedHost.descriptor.loaderUrl,
        options.loaderPort,
      );
    },
  };

  const mcp: LiveDiagnosticMcpPort = {
    async startLoopback(input): Promise<LoopbackMcpRuntimeHandle> {
      const authority = input.authority as NodeVerificationAuthority;
      nodeVerificationAuthorityState(authority);
      const runtime = await options.startLoopbackMcp({
        authority,
        host: input.host,
        context: input.context,
      });
      return Object.freeze({ server: runtime.server, session: runtime.session });
    },
  };

  const browser: LiveDiagnosticBrowserPort = {
    async startProfile(context): Promise<BrowserDiagnosticProfileHandle> {
      return options.startBrowserProfile(context);
    },
  };

  const bootstrap: BootstrapSmokePort = {
    async startEmptyWorkersEnabledProfile(context) {
      return options.startBootstrapProfile(context);
    },
  };

  return Object.freeze({
    host,
    mcp,
    browser,
    bootstrap,
    async runNativeSelfTest(): Promise<void> {
      assertSecureReadNativeAvailable();
    },
    async runBootstrapSmoke(context: DiagnosticExecutionContext): Promise<void> {
      await withAbortingDeadline(context, (boundedContext) =>
        runBootstrapSmoke({
          context: boundedContext,
          persistentSecretCanaries: Object.freeze({
            pathCanaries: Object.freeze([]) as readonly [],
          }),
          port: bootstrap,
        }),
      );
    },
    async runLiveDiagnostics(
      input: Parameters<NodeLifecycleVerificationPorts['runLiveDiagnostics']>[0],
    ): Promise<void> {
      const persistentSecretCanaries = Object.freeze({
        pathCanaries: input.pathCanaries,
        tokenMatcher: input.tokenMatcher,
      });
      await withAbortingDeadline(input.context, (boundedContext) =>
        runLiveDiagnostics({
          authority: input.authority,
          browser,
          context: boundedContext,
          host,
          mcp,
          persistentSecretCanaries,
          selectedHost: input.selectedHost,
        }),
      );
    },
  });
}

function loopbackLoaderHostHandle(
  fetchImplementation: typeof fetch,
  loaderUrl: string,
  loaderPort: number,
): SelectedHostRuntimeHandle {
  const boundLoaderUrl = bindRuntimeLoaderUrl(loaderUrl, '127.0.0.1', loaderPort);
  return Object.freeze({
    kind: 'static' as const,
    foreground: true as const,
    persistent: false as const,
    async load(
      path: Parameters<SelectedHostRuntimeHandle['load']>[0],
      context: Parameters<SelectedHostRuntimeHandle['load']>[1],
    ): Promise<DiagnosticHttpResponse> {
      assertActive(context);
      assertBoundLoaderUrl(path);
      const response = await awaitContext(
        context,
        fetchImplementation(boundLoaderUrl, { signal: context.signal }),
        discardLateResponse,
      );
      return responseSnapshot(response, context);
    },
    async close(): Promise<DiagnosticCloseReceipt> {
      return Object.freeze({
        phase: 'host' as const,
        records: Object.freeze([
          Object.freeze({
            kind: 'runtime-cleanup' as const,
            runtime: 'static' as const,
            listenerClosed: true as const,
            credentialCapabilityRevoked: true as const,
            tokenWiped: true as const,
          }),
        ]),
      });
    },
  });
}

function bindRuntimeLoaderUrl(loaderUrl: string, host: unknown, port: unknown): string {
  if (
    host !== '127.0.0.1' ||
    typeof port !== 'number' ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    loaderUrl !== `http://127.0.0.1:${port}${CANONICAL_LOADER_PATH}`
  ) {
    throw new Error('verification runtime endpoint is not the canonical loopback authority');
  }
  return loaderUrl;
}

function assertBoundLoaderUrl(path: string): void {
  if (path !== CANONICAL_LOADER_PATH) {
    throw new Error('verification loader path is not canonical');
  }
}

async function responseSnapshot(
  response: Response,
  context: DiagnosticExecutionContext,
): Promise<DiagnosticHttpResponse> {
  let body: Uint8Array | undefined;
  let completed = false;
  try {
    assertActive(context);
    const headers = boundedResponseHeaders(response.headers);
    body = await readBoundedResponseBody(response, context);
    assertActive(context);
    const snapshot = Object.freeze({
      status: response.status,
      headers,
      body,
    });
    body = undefined;
    completed = true;
    return snapshot;
  } finally {
    if (!completed) {
      body?.fill(0);
      cancelResponseBody(response.body);
    }
  }
}
function boundedResponseHeaders(headers: Headers): Readonly<Record<string, string | undefined>> {
  const snapshot: Record<string, string | undefined> = Object.create(null);
  let count = 0;
  for (const [key, value] of headers.entries()) {
    count += 1;
    if (
      count > MAX_DIAGNOSTIC_HEADERS ||
      !isBoundedDiagnosticHeader(key) ||
      !isBoundedDiagnosticHeader(value) ||
      Object.prototype.hasOwnProperty.call(snapshot, key)
    ) {
      throw new Error('verification response headers are invalid');
    }
    snapshot[key] = value;
  }
  return Object.freeze(snapshot);
}
function isBoundedDiagnosticHeader(value: string): boolean {
  let bytes = 0;
  for (let index = 0; index < value.length;) {
    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      return false;
    }
    bytes += codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
    if (bytes > MAX_DIAGNOSTIC_HEADER_BYTES) {
      return false;
    }
    index += codePoint > 0xffff ? 2 : 1;
  }
  return true;
}

async function readBoundedResponseBody(
  response: Response,
  context: DiagnosticExecutionContext,
): Promise<Uint8Array> {
  const contentLength = response.headers.get('content-length');
  if (
    contentLength !== null &&
    /^(?:0|[1-9][0-9]*)$/u.test(contentLength) &&
    Number(contentLength) > MAX_HTTP_RESPONSE_BYTES
  ) {
    cancelResponseBody(response.body);
    throw new Error('verification response exceeds its byte limit');
  }

  const stream = response.body;
  if (stream === null) {
    return new Uint8Array(0);
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let complete = false;
  let releaseFailed = false;
  let body: Uint8Array | undefined;
  let byteLength = 0;
  let currentChunk: Uint8Array | undefined;

  try {
    for (;;) {
      assertActive(context);
      const chunk = await awaitContext(context, reader.read(), wipeLateStreamChunk);
      if (!chunk.done && chunk.value instanceof Uint8Array) {
        currentChunk = chunk.value;
      }
      assertActive(context);
      if (chunk.done) {
        break;
      }
      if (!(chunk.value instanceof Uint8Array)) {
        throw new Error('verification response body is invalid');
      }
      if (chunk.value.byteLength > MAX_HTTP_RESPONSE_BYTES - byteLength) {
        chunk.value.fill(0);
        throw new Error('verification response exceeds its byte limit');
      }
      if (chunks.length >= MAX_HTTP_RESPONSE_CHUNKS) {
        chunk.value.fill(0);
        throw new Error('verification response has too many chunks');
      }
      byteLength += chunk.value.byteLength;
      chunks.push(chunk.value);
      currentChunk = undefined;
    }

    body = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    complete = true;
  } finally {
    currentChunk?.fill(0);
    for (const chunk of chunks) {
      chunk.fill(0);
    }
    if (!complete) {
      body?.fill(0);
      cancelResponseBody(stream, reader);
    } else {
      try {
        reader.releaseLock();
      } catch {
        body?.fill(0);
        releaseFailed = true;
      }
    }
  }
  if (releaseFailed || body === undefined) {
    throw new Error('verification response body could not release its reader');
  }
  return body;
}

function cancelResponseBody(
  stream: ReadableStream<Uint8Array> | null,
  reader: ReadableStreamDefaultReader<Uint8Array> | undefined = undefined,
): void {
  try {
    const cancellation = reader?.cancel() ?? stream?.cancel();
    void cancellation?.catch(() => undefined);
  } catch {
    // Cancellation is best-effort after the bounded read has already failed.
  } finally {
    try {
      reader?.releaseLock();
    } catch {
      // The stream may already have released its reader during cancellation.
    }
  }
}

async function withAbortingDeadline<T>(
  context: DiagnosticExecutionContext,
  operation: (context: DiagnosticExecutionContext) => Promise<T>,
): Promise<T> {
  assertActive(context);
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  let timer: ReturnType<typeof setTimeout> | undefined;
  context.signal.addEventListener('abort', abort, { once: true });
  try {
    timer = setTimeout(abort, Math.max(0, context.deadline - Date.now()));
    return await operation(
      Object.freeze({ deadline: context.deadline, signal: controller.signal }),
    );
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    context.signal.removeEventListener('abort', abort);
    controller.abort();
  }
}

async function awaitContext<T>(
  context: DiagnosticExecutionContext,
  operation: Promise<T>,
  adoptLateFulfillment: ((value: T) => void) | undefined = undefined,
): Promise<T> {
  let completed = false;
  const observed = operation.then(
    (value) => {
      if (completed) {
        try {
          adoptLateFulfillment?.(value);
        } catch {
          // Late cleanup must not create an unhandled rejection.
        }
      }
      return value;
    },
    (error: unknown) => {
      throw error;
    },
  );
  void observed.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  try {
    assertActive(context);
    const abort = new Promise<never>((_resolve, reject) => {
      const interrupted = (): void => {
        reject(new Error('verification context is no longer active'));
      };
      context.signal.addEventListener('abort', interrupted, { once: true });
      removeAbortListener = () => context.signal.removeEventListener('abort', interrupted);
      timer = setTimeout(interrupted, Math.max(0, context.deadline - Date.now()));
    });
    return await Promise.race([observed, abort]);
  } finally {
    completed = true;
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    removeAbortListener?.();
  }
}

function discardLateResponse(response: Response): void {
  cancelResponseBody(response.body);
}

function wipeLateStreamChunk(result: ReadableStreamReadResult<Uint8Array>): void {
  if (!result.done && result.value instanceof Uint8Array) {
    result.value.fill(0);
  }
}

function assertActive(context: DiagnosticExecutionContext): void {
  if (context.signal.aborted || Date.now() >= context.deadline) {
    throw new Error('verification context is no longer active');
  }
}
