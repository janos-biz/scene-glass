import { Buffer } from 'node:buffer';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { isAbsolute, join, normalize } from 'node:path';
import {
  verifyCredentialAuthorities,
  withSelectedCredential,
  type VerifiedCredentialAuthorities,
} from '../credential-authority.js';
import { snapshotTrustedStaticRuntimeAuthority } from '../descriptors.js';
import {
  revokeCredentialReadCapability,
  secureReadBeneath,
  type CredentialReadCapability,
} from '../native.js';
import type { DescriptorProjectSet, FileIdentity, StaticHostDescriptorV1 } from '../types.js';
import {
  staticInternalServerError,
  staticMethodNotAllowed,
  staticMimeType,
  staticNotFound,
  writeStaticResponse,
  writeStaticSocketResponse,
  type StaticHttpResponse,
} from './http.js';
import type { DiagnosticCloseReceipt } from '../lifecycle/verification.js';

const CREDENTIAL_MAX_BYTES = 8 * 1024;
const HTML_MAX_BYTES = 8 * 1024 * 1024;
const ASSET_MAX_BYTES = 16 * 1024 * 1024;
const DRAIN_TIMEOUT_MS = 2_000;
const MAX_CONCURRENT_HANDLERS = 32;
const MAX_CONCURRENT_CONNECTIONS = 64;
const SOCKET_TIMEOUT_MS = 5_000;
const HEADER_TIMEOUT_MS = 5_000;
const REQUEST_TIMEOUT_MS = 5_000;
const RETAINED_CLEANUP_RETRY_MS = 100;
const MAX_RETAINED_CLEANUP_OWNERS = 32;
const MAX_RETAINED_CLEANUP_ATTEMPTS = 2;
const MARKER = '<!-- scene-glass:static-loader:v1 -->';
const HTML_CONTENT_TYPE = 'text/html; charset=utf-8';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

const retainedCleanupOwners = new Set<RetainedCleanupOwner>();
let retainedCleanupFatal = false;

export interface StartStaticRuntimeOptions {
  readonly descriptor: unknown;
  readonly configuredProjects: DescriptorProjectSet;
  readonly projectRoot: string;
  readonly signal?: AbortSignal;
}

export interface StaticRuntime {
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly projectId: string;
  stop(): Promise<void>;
  /** Runtime-produced cleanup evidence for lifecycle diagnostics. */
  closeWithReceipt(): Promise<DiagnosticCloseReceipt>;
}

interface RuntimeState {
  readonly descriptor: StaticHostDescriptorV1;
  readonly publicRoot: string;
  readonly publicRootIdentity: FileIdentity;
  readonly ownerUid: number;
  readonly deniedIdentities: readonly FileIdentity[];
  credentialCapability: CredentialReadCapability | undefined;
  token: Buffer | undefined;
  boundPort: number | undefined;
  accepting: boolean;
  readonly handlerTasks: Set<Promise<void>>;
  readonly drainWaiters: Set<() => void>;
}
interface RetainedCleanupOwner {
  readonly state: RuntimeState;
  cleanupAttempts: number;
  reportedFailure: boolean;
  running: boolean;
  scheduled: boolean;
  terminal: boolean;
}

interface HtmlRoute {
  readonly kind: 'html';
}

interface ReadinessRoute {
  readonly kind: 'readiness';
}

interface AssetRoute {
  readonly kind: 'asset';
  readonly relativePath: string;
}

type Route = HtmlRoute | ReadinessRoute | AssetRoute;
interface TemplateInjectionPoint {
  readonly markerIndex: number;
  readonly afterMarker: number;
  readonly headIndex: number;
}

export async function startStaticRuntime(
  options: StartStaticRuntimeOptions,
): Promise<StaticRuntime> {
  throwIfAborted(options.signal);
  if (retainedCleanupFatal) {
    throw new Error('static runtime credential cleanup entered a fatal state');
  }

  const projectRoot = options.projectRoot;
  const authority = snapshotTrustedStaticRuntimeAuthority(
    options.descriptor,
    options.configuredProjects,
  );
  if (projectRoot !== authority.canonicalRoot) {
    throw new Error('static runtime project root is not authorized');
  }

  const descriptor = authority.descriptor;
  const state: RuntimeState = {
    descriptor,
    publicRoot: publicRootPath(authority.canonicalRoot),
    publicRootIdentity: authority.publicRootIdentity,
    ownerUid: ownerUid(),
    deniedIdentities: authority.deniedCredentialIdentities,
    credentialCapability: undefined,
    token: undefined,
    boundPort: undefined,
    accepting: true,
    handlerTasks: new Set<Promise<void>>(),
    drainWaiters: new Set<() => void>(),
  };
  let server: Server | undefined;

  try {
    const verified = await settleStartupRead(
      () => verifyCredentialAuthoritySet(descriptor, state.ownerUid),
      options.signal,
      (lateVerified) => {
        state.credentialCapability = lateVerified.capability;
        retainLateCleanupOwner(state);
      },
    );
    state.credentialCapability = verified.capability;
    throwIfAborted(options.signal);

    state.token = await settleStartupRead(
      () => readSelectedToken(verified, descriptor),
      options.signal,
      (lateToken) => {
        lateToken.fill(0);
      },
    );
    revokeCredentialCapability(state);
    throwIfAborted(options.signal);

    await settleStartupRead(() => verifyTemplateBeforeListen(state), options.signal);
    throwIfAborted(options.signal);
    server = createStaticServer(state);
    state.boundPort = await listen(server, descriptor.port, descriptor.host, options.signal);
    throwIfAborted(options.signal);
    return createRuntime(server, state, options.signal);
  } catch (primaryError: unknown) {
    try {
      await cleanupRuntime(server, state);
    } catch (cleanupError: unknown) {
      retainFailedStartupCleanupOwner(state);
      throw combineRuntimeFailures(primaryError, cleanupError);
    }
    throw primaryError;
  }
}

function createStaticServer(state: RuntimeState): Server {
  const dispatchRequest = (request: IncomingMessage, response: ServerResponse): void => {
    if (!hasHandlerCapacity(state)) {
      rejectOverCapacity(response, request.method);
      return;
    }
    trackHandler(handleRequest(request, response, state), state);
  };
  const server = createServer({ requireHostHeader: false }, dispatchRequest);
  server.maxConnections = MAX_CONCURRENT_CONNECTIONS;
  server.timeout = SOCKET_TIMEOUT_MS;
  server.headersTimeout = HEADER_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = SOCKET_TIMEOUT_MS;
  server.on('timeout', (socket) => {
    socket.destroy();
  });
  server.on('checkContinue', dispatchRequest);
  server.on('checkExpectation', dispatchRequest);
  server.on('connect', (request, socket, head) => {
    if (!hasHandlerCapacity(state)) {
      head.fill(0);
      socket.destroy();
      return;
    }
    trackHandler(handleConnect(request, socket, head, state), state);
  });
  server.on('clientError', (_error, socket) => {
    socket.destroy();
  });
  return server;
}

function hasHandlerCapacity(state: RuntimeState): boolean {
  return state.handlerTasks.size < MAX_CONCURRENT_HANDLERS;
}

function rejectOverCapacity(response: ServerResponse, method: string | undefined): void {
  response.sendDate = false;
  try {
    writeStaticResponse(response, method, staticInternalServerError());
  } catch {
    response.destroy();
  }
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  state: RuntimeState,
): Promise<void> {
  response.sendDate = false;
  try {
    let result: StaticHttpResponse;
    if (!hasExpectedHost(request, state) || !state.accepting) {
      result = staticNotFound();
    } else if (request.method !== 'GET' && request.method !== 'HEAD') {
      result = staticMethodNotAllowed();
    } else {
      const route = routeFor(request.url, state.descriptor);
      if (route === undefined) {
        result = staticNotFound();
      } else {
        try {
          result = await responseForRoute(route, state);
        } catch (error: unknown) {
          if (isExpectedReadDenial(error)) {
            result = staticNotFound();
          } else {
            reportUnexpectedRequestFault();
            result = staticInternalServerError();
          }
        }
      }
    }
    await sendSafely(response, request.method, result);
  } finally {
    if (!response.writableEnded) {
      response.destroy();
    }
  }
}

async function handleConnect(
  request: IncomingMessage,
  socket: Duplex,
  head: Buffer,
  state: RuntimeState,
): Promise<void> {
  try {
    const result =
      hasExpectedHost(request, state) && state.accepting
        ? staticMethodNotAllowed()
        : staticNotFound();
    await sendSocketSafely(socket, result);
  } finally {
    head.fill(0);
    if (!socket.writableEnded && !socket.destroyed) {
      socket.destroy();
    }
  }
}

async function responseForRoute(route: Route, state: RuntimeState): Promise<StaticHttpResponse> {
  if (route.kind === 'readiness') {
    return {
      statusCode: 200,
      body: Buffer.from(
        `{"ready":true,"projectId":${JSON.stringify(state.descriptor.projectId)}}\n`,
        'utf8',
      ),
      contentType: JSON_CONTENT_TYPE,
    };
  }

  const read = await secureReadBeneath({
    root: state.publicRoot,
    expectedRoot: state.publicRootIdentity,
    relativePath: route.kind === 'html' ? 'index.html' : route.relativePath,
    deniedIdentities: state.deniedIdentities,
    maxBytes: route.kind === 'html' ? HTML_MAX_BYTES : ASSET_MAX_BYTES,
  });
  const bytes = read.bytes;
  if (!state.accepting) {
    bytes.fill(0);
    return staticNotFound();
  }

  if (route.kind === 'html') {
    try {
      if (state.token === undefined) {
        throw new Error('static runtime token has been cleared');
      }
      return {
        statusCode: 200,
        body: renderTemplate(bytes, state.descriptor, state.token),
        contentType: HTML_CONTENT_TYPE,
      };
    } finally {
      bytes.fill(0);
    }
  }

  try {
    return {
      statusCode: 200,
      body: bytes,
      contentType: staticMimeType(route.relativePath),
    };
  } catch (error: unknown) {
    bytes.fill(0);
    throw error;
  }
}
async function verifyTemplateBeforeListen(state: RuntimeState): Promise<void> {
  const read = await secureReadBeneath({
    root: state.publicRoot,
    expectedRoot: state.publicRootIdentity,
    relativePath: 'index.html',
    deniedIdentities: state.deniedIdentities,
    maxBytes: HTML_MAX_BYTES,
  });

  try {
    validateTemplate(read.bytes);
  } finally {
    read.bytes.fill(0);
  }
}

function routeFor(url: string | undefined, descriptor: StaticHostDescriptorV1): Route | undefined {
  if (url === undefined || !url.startsWith('/') || url.includes('?') || url.includes('#')) {
    return undefined;
  }

  let pathname: string;
  try {
    pathname = decodeURIComponent(url);
  } catch {
    return undefined;
  }

  if (
    pathname.includes('%') ||
    pathname.includes('\u0000') ||
    pathname.includes('\\') ||
    pathname.includes('?') ||
    pathname.includes('#') ||
    !pathname.startsWith('/') ||
    pathname.startsWith('//')
  ) {
    return undefined;
  }

  if (pathname === '/' || pathname === '/index.html') {
    return { kind: 'html' };
  }
  if (pathname === descriptor.readinessPath) {
    return { kind: 'readiness' };
  }

  const relativePath = pathname.slice(1);
  if (
    relativePath.length === 0 ||
    relativePath.endsWith('/') ||
    relativePath.toLowerCase().endsWith('.html')
  ) {
    return undefined;
  }

  const segments = relativePath.split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    return undefined;
  }

  return { kind: 'asset', relativePath };
}

function renderTemplate(
  template: Buffer,
  descriptor: StaticHostDescriptorV1,
  token: Buffer,
): Buffer {
  const injection = validateTemplate(template);
  const newline = template.subarray(injection.afterMarker, injection.headIndex);
  const script = Buffer.concat([
    Buffer.from('<script async src="', 'utf8'),
    Buffer.from(escapeHtmlAttribute(descriptor.loaderUrl), 'utf8'),
    Buffer.from('" data-scg-project="', 'utf8'),
    Buffer.from(escapeHtmlAttribute(descriptor.projectId), 'utf8'),
    Buffer.from('" data-scg-token="', 'utf8'),
    token,
    Buffer.from('" data-scg-navigation="document"></script>', 'utf8'),
    newline,
  ]);
  try {
    return Buffer.concat([
      template.subarray(0, injection.markerIndex),
      script,
      template.subarray(injection.headIndex),
    ]);
  } finally {
    script.fill(0);
  }
}

function validateTemplate(template: Buffer): TemplateInjectionPoint {
  const marker = Buffer.from(MARKER, 'ascii');
  const closingHead = Buffer.from('</head>', 'ascii');
  try {
    const markerIndex = template.indexOf(marker);
    if (
      markerIndex === -1 ||
      template.indexOf(marker, markerIndex + marker.length) !== -1 ||
      (markerIndex !== 0 && template[markerIndex - 1] !== 0x0a)
    ) {
      throw new Error('static HTML loader marker is ambiguous');
    }

    const afterMarker = markerIndex + marker.length;
    const newlineLength =
      template[afterMarker] === 0x0d && template[afterMarker + 1] === 0x0a
        ? 2
        : template[afterMarker] === 0x0a
          ? 1
          : 0;
    if (newlineLength === 0) {
      throw new Error('static HTML loader marker must be a standalone line');
    }

    const headLineStart = afterMarker + newlineLength;
    let headIndex = headLineStart;
    while (template[headIndex] === 0x20 || template[headIndex] === 0x09) {
      headIndex += 1;
    }
    if (
      indexOfAsciiIgnoreCase(template, closingHead, 0) !== headIndex ||
      indexOfAsciiIgnoreCase(template, closingHead, headIndex + closingHead.length) !== -1
    ) {
      throw new Error('static HTML must contain one closing head tag after the marker line');
    }

    return { markerIndex, afterMarker, headIndex };
  } finally {
    marker.fill(0);
    closingHead.fill(0);
  }
}

function escapeHtmlAttribute(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function equalsAsciiIgnoreCase(source: Uint8Array, offset: number, expected: Uint8Array): boolean {
  if (offset + expected.length > source.length) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    const actual = source[offset + index];
    if (actual === undefined || asciiLowercase(actual) !== expected[index]) {
      return false;
    }
  }
  return true;
}

function indexOfAsciiIgnoreCase(source: Uint8Array, expected: Uint8Array, from: number): number {
  for (let index = from; index + expected.length <= source.length; index += 1) {
    if (equalsAsciiIgnoreCase(source, index, expected)) {
      return index;
    }
  }
  return -1;
}

function asciiLowercase(value: number): number {
  return value >= 0x41 && value <= 0x5a ? value + 0x20 : value;
}

async function verifyCredentialAuthoritySet(
  descriptor: StaticHostDescriptorV1,
  expectedOwnerUid: number,
): Promise<VerifiedCredentialAuthorities> {
  return verifyCredentialAuthorities({
    authorities: descriptor.credentialAuthorities,
    selectedProjectId: descriptor.credentialProjectId,
    expectedOwnerUid,
    maxBytes: CREDENTIAL_MAX_BYTES,
  });
}

async function readSelectedToken(
  verified: VerifiedCredentialAuthorities,
  descriptor: StaticHostDescriptorV1,
): Promise<Buffer> {
  return withSelectedCredential(verified, (bytes) =>
    parseCredentialToken(
      bytes,
      descriptor.credentialKey,
      descriptor.credentialProjectId,
      descriptor.loaderUrl,
    ),
  );
}
function parseCredentialToken(
  bytes: Buffer,
  expectedKey: string,
  projectId: string,
  loaderUrl: string,
): Buffer {
  const prefix = Buffer.from(
    `VITE_SCENE_GLASS_LOADER_URL=${loaderUrl}\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=`,
    'utf8',
  );
  const suffix = Buffer.from(`\n${expectedKey}=`, 'utf8');
  if (bytes.byteLength !== prefix.byteLength + 43 + suffix.byteLength + 43 + 1) {
    throw new Error('credential source is not the canonical Vite envelope');
  }
  const firstTokenStart = prefix.byteLength;
  const secondTokenStart = firstTokenStart + 43 + suffix.byteLength;
  if (
    bytes.at(-1) !== 0x0a ||
    !bytes.subarray(0, prefix.byteLength).equals(prefix) ||
    !bytes.subarray(firstTokenStart + 43, firstTokenStart + 43 + suffix.byteLength).equals(suffix)
  ) {
    throw new Error('credential source is not the canonical Vite envelope');
  }
  const token = Buffer.from(bytes.subarray(firstTokenStart, firstTokenStart + 43));
  try {
    if (
      !isCanonicalOpaqueTokenBytes(token) ||
      !token.equals(bytes.subarray(secondTokenStart, secondTokenStart + 43))
    ) {
      throw new Error('credential source tokens are not canonical and equal');
    }
    return token;
  } catch (error) {
    token.fill(0);
    throw error;
  }
}

function isCanonicalOpaqueTokenBytes(value: Uint8Array): boolean {
  const remainder = value.length % 4;
  if (remainder === 1) {
    return false;
  }

  let finalSextet = 0;
  for (const byte of value) {
    const sextet = base64urlSextet(byte);
    if (sextet === -1) {
      return false;
    }
    finalSextet = sextet;
  }

  const decodedByteLength =
    Math.floor(value.length / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
  if (decodedByteLength < 32) {
    return false;
  }
  if (remainder === 2) {
    return (finalSextet & 0b1111) === 0;
  }
  if (remainder === 3) {
    return (finalSextet & 0b11) === 0;
  }
  return true;
}

function base64urlSextet(byte: number): number {
  if (byte >= 0x41 && byte <= 0x5a) {
    return byte - 0x41;
  }
  if (byte >= 0x61 && byte <= 0x7a) {
    return byte - 0x61 + 26;
  }
  if (byte >= 0x30 && byte <= 0x39) {
    return byte - 0x30 + 52;
  }
  if (byte === 0x2d) {
    return 62;
  }
  if (byte === 0x5f) {
    return 63;
  }
  return -1;
}
function wipeToken(state: RuntimeState): void {
  const token = state.token;
  state.token = undefined;
  token?.fill(0);
}
function revokeCredentialCapability(state: RuntimeState): void {
  const capability = state.credentialCapability;
  if (capability === undefined) {
    return;
  }
  revokeCredentialReadCapability(capability);
  state.credentialCapability = undefined;
}

function send(
  response: ServerResponse,
  method: string | undefined,
  result: StaticHttpResponse,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = result.body;
    let completed = false;
    const zeroize = (): void => {
      if (!completed) {
        completed = true;
        body.fill(0);
        resolve();
      }
    };
    response.once('finish', zeroize);
    response.once('close', zeroize);
    if (response.destroyed || response.writableEnded) {
      zeroize();
      return;
    }
    try {
      writeStaticResponse(response, method, result);
    } catch (error: unknown) {
      if (!completed) {
        completed = true;
        body.fill(0);
      }
      reject(error);
    }
  });
}
async function sendSafely(
  response: ServerResponse,
  method: string | undefined,
  result: StaticHttpResponse,
): Promise<void> {
  try {
    await send(response, method, result);
  } catch {
    reportUnexpectedRequestFault();
    response.destroy();
  }
}

async function sendSocketSafely(socket: Duplex, result: StaticHttpResponse): Promise<void> {
  try {
    await writeStaticSocketResponse(socket, result);
  } catch {
    reportUnexpectedRequestFault();
    socket.destroy();
  }
}

function hasExpectedHost(request: IncomingMessage, state: RuntimeState): boolean {
  const port = state.boundPort;
  if (port === undefined) {
    return false;
  }

  let authority: string | undefined;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() !== 'host') {
      continue;
    }
    const value = request.rawHeaders[index + 1];
    if (authority !== undefined || value === undefined) {
      return false;
    }
    authority = value;
  }

  return (
    authority !== undefined &&
    authority === request.headers.host &&
    isExpectedLoopbackAuthority(authority, state.descriptor.host, port)
  );
}

function isExpectedLoopbackAuthority(
  authority: string,
  expectedHost: string,
  expectedPort: number,
): boolean {
  const separator = authority.lastIndexOf(':');
  if (separator <= 0 || authority.indexOf(':') !== separator) {
    return false;
  }

  const host = authority.slice(0, separator);
  const portText = authority.slice(separator + 1);
  if (!/^[1-9][0-9]*$/.test(portText)) {
    return false;
  }

  const port = Number(portText);
  return (
    Number.isSafeInteger(port) &&
    port <= 65_535 &&
    host === expectedHost &&
    port === expectedPort &&
    authority === `${expectedHost}:${expectedPort}`
  );
}

function isExpectedReadDenial(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }

  try {
    const code = (error as { readonly code?: unknown }).code;
    return (
      code === 'SCG_NATIVE_PATH_DENIED' ||
      code === 'SCG_NATIVE_IDENTITY_MISMATCH' ||
      code === 'SCG_NATIVE_READ_LIMIT'
    );
  } catch {
    return false;
  }
}

function reportUnexpectedRequestFault(): void {
  process.emitWarning('Unexpected static runtime request failure.', {
    code: 'SCG_STATIC_RUNTIME_UNEXPECTED',
    type: 'SceneGlassStaticRuntimeError',
  });
}
function retainLateCleanupOwner(state: RuntimeState): void {
  retainCleanupOwner(state, true);
}

function retainFailedStartupCleanupOwner(state: RuntimeState): void {
  retainCleanupOwner(state, false);
}

function retainCleanupOwner(state: RuntimeState, immediate: boolean): void {
  if (state.credentialCapability === undefined) {
    return;
  }
  if (retainedCleanupFatal || retainedCleanupOwners.size >= MAX_RETAINED_CLEANUP_OWNERS) {
    revokeCapabilityAtCleanupCapacity(state);
    return;
  }

  const owner: RetainedCleanupOwner = {
    state,
    cleanupAttempts: 0,
    reportedFailure: false,
    running: false,
    scheduled: false,
    terminal: false,
  };
  retainedCleanupOwners.add(owner);
  scheduleRetainedCleanup(owner, immediate);
}

function revokeCapabilityAtCleanupCapacity(state: RuntimeState): void {
  for (let attempt = 1; attempt <= MAX_RETAINED_CLEANUP_ATTEMPTS; attempt += 1) {
    try {
      revokeCredentialCapability(state);
      wipeToken(state);
      return;
    } catch {
      // Keep the capability in state until a retry succeeds or fail-stop exits.
    }
  }

  retainedCleanupFatal = true;
  try {
    reportRetainedCleanupFailure('revokeCredentialReadCapability', MAX_RETAINED_CLEANUP_ATTEMPTS);
  } finally {
    process.exitCode = 1;
    process.exit(1);
  }
}

function scheduleRetainedCleanup(owner: RetainedCleanupOwner, immediate: boolean): void {
  if (!retainedCleanupOwners.has(owner) || owner.running || owner.scheduled || owner.terminal) {
    return;
  }
  owner.scheduled = true;
  const run = (): void => {
    owner.scheduled = false;
    void cleanupRetainedOwner(owner);
  };
  if (immediate) {
    queueMicrotask(run);
    return;
  }
  setTimeout(run, RETAINED_CLEANUP_RETRY_MS);
}

async function cleanupRetainedOwner(owner: RetainedCleanupOwner): Promise<void> {
  if (!retainedCleanupOwners.has(owner) || owner.running || owner.terminal) {
    return;
  }
  owner.running = true;
  let cleanupFailed = false;
  try {
    await cleanupRuntime(undefined, owner.state);
  } catch {
    cleanupFailed = true;
    owner.cleanupAttempts += 1;
  } finally {
    owner.running = false;
  }

  if (!cleanupFailed) {
    retainedCleanupOwners.delete(owner);
    return;
  }
  if (owner.cleanupAttempts >= MAX_RETAINED_CLEANUP_ATTEMPTS) {
    owner.terminal = true;
    if (!owner.reportedFailure) {
      owner.reportedFailure = true;
      reportRetainedCleanupFailure('revokeCredentialReadCapability', owner.cleanupAttempts);
    }
    return;
  }
  scheduleRetainedCleanup(owner, false);
}
function reportRetainedCleanupFailure(operation: string, attempt: number): void {
  process.emitWarning('Static runtime credential capability cleanup failed.', {
    code: 'SCG_STATIC_RUNTIME_CREDENTIAL_CLEANUP_FAILED',
    type: 'SceneGlassStaticRuntimeCleanupError',
    detail: `operation=${operation} attempt=${attempt}`,
  });
}

function trackHandler(task: Promise<void>, state: RuntimeState): void {
  state.handlerTasks.add(task);
  const release = (): void => {
    state.handlerTasks.delete(task);
    if (state.handlerTasks.size === 0) {
      for (const resolve of state.drainWaiters) {
        resolve();
      }
      state.drainWaiters.clear();
    }
  };
  void task.then(release, () => {
    release();
    reportUnexpectedRequestFault();
  });
}

function createRuntime(
  server: Server,
  state: RuntimeState,
  signal: AbortSignal | undefined,
): StaticRuntime {
  const port = state.boundPort;
  if (port === undefined) {
    throw new Error('static runtime has no bound port');
  }

  let stopping: Promise<void> | undefined;
  let abortListener: (() => void) | undefined;
  const stop = (): Promise<void> => {
    if (stopping === undefined) {
      stopping = cleanupRuntime(server, state).finally(() => {
        if (signal !== undefined && abortListener !== undefined) {
          signal.removeEventListener('abort', abortListener);
        }
      });
    }
    return stopping;
  };
  const closeWithReceipt = async (): Promise<DiagnosticCloseReceipt> => {
    await stop();
    return staticRuntimeCloseReceipt();
  };

  if (signal !== undefined) {
    abortListener = () => {
      void stop().catch(reportUnexpectedRequestFault);
    };
    signal.addEventListener('abort', abortListener, { once: true });
    if (signal.aborted) {
      abortListener();
    }
  }

  return Object.freeze({
    host: state.descriptor.host,
    port,
    projectId: state.descriptor.projectId,
    stop,
    closeWithReceipt,
  });
}

function staticRuntimeCloseReceipt(): DiagnosticCloseReceipt {
  return Object.freeze({
    phase: 'host',
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
}
async function cleanupRuntime(server: Server | undefined, state: RuntimeState): Promise<void> {
  state.accepting = false;
  const failures: unknown[] = [];

  if (server !== undefined) {
    try {
      await stopServer(server, state);
    } catch (error: unknown) {
      failures.push(error);
    }
  }
  try {
    revokeCredentialCapability(state);
  } catch (error: unknown) {
    failures.push(error);
  }
  try {
    wipeToken(state);
  } catch (error: unknown) {
    failures.push(error);
  }

  throwCleanupFailures(failures);
}

async function stopServer(server: Server, state: RuntimeState): Promise<void> {
  state.accepting = false;
  const failures: unknown[] = [];
  try {
    server.closeIdleConnections();
  } catch (error: unknown) {
    failures.push(error);
  }

  const closed = closeServer(server);
  void closed.catch(() => undefined);
  const forceClose = (): void => {
    try {
      server.closeAllConnections();
    } catch (error: unknown) {
      failures.push(error);
    }
  };

  const initiallyDrained = await waitForHandlerDrainWithin(state);
  if (!initiallyDrained) {
    forceClose();
  }

  let closeSettlement = await settleWithin(closed);
  if (!closeSettlement.settled) {
    forceClose();
    closeSettlement = await settleWithin(closed);
  }
  if (!closeSettlement.settled) {
    failures.push(new Error('static runtime listener did not close during shutdown'));
  } else if (closeSettlement.error !== undefined) {
    failures.push(closeSettlement.error);
  }

  let handlersDrained = initiallyDrained || (await waitForHandlerDrainWithin(state));
  if (!handlersDrained) {
    forceClose();
    handlersDrained = await waitForHandlerDrainWithin(state);
  }
  if (!handlersDrained) {
    failures.push(new Error('static runtime request handlers did not settle during shutdown'));
  }

  throwCleanupFailures(failures);
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (
        error === undefined ||
        (error as NodeJS.ErrnoException).code === 'ERR_SERVER_NOT_RUNNING'
      ) {
        resolve();
        return;
      }
      reject(error);
    });
  });
}

interface TaskSettlement {
  readonly settled: boolean;
  readonly error: unknown | undefined;
}

async function settleWithin(task: Promise<void>): Promise<TaskSettlement> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      task.then(
        () => ({ settled: true, error: undefined }),
        (error: unknown) => ({ settled: true, error }),
      ),
      new Promise<TaskSettlement>((resolve) => {
        timer = setTimeout(() => resolve({ settled: false, error: undefined }), DRAIN_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

function waitForHandlerDrainWithin(state: RuntimeState): Promise<boolean> {
  if (state.handlerTasks.size === 0) {
    return Promise.resolve(true);
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (drained: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      state.drainWaiters.delete(onDrained);
      resolve(drained);
    };
    const onDrained = (): void => finish(true);
    state.drainWaiters.add(onDrained);
    const timer = setTimeout(() => finish(false), DRAIN_TIMEOUT_MS);
  });
}

function throwCleanupFailures(failures: readonly unknown[]): void {
  if (failures.length === 1) {
    throw failures[0];
  }
  if (failures.length > 1) {
    throw new AggregateError(failures, 'static runtime cleanup failed');
  }
}

function combineRuntimeFailures(primaryError: unknown, cleanupError: unknown): AggregateError {
  return new AggregateError(
    [primaryError, cleanupError],
    'static runtime failed and cleanup also failed',
  );
}

function listen(
  server: Server,
  port: number,
  host: string,
  signal: AbortSignal | undefined,
): Promise<number> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      server.off('error', onError);
      server.off('listening', onListening);
      signal?.removeEventListener('abort', onAbort);
    };
    const fail = (error: unknown): void => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(error);
      }
    };
    const onError = (error: Error): void => fail(error);
    const onListening = (): void => {
      if (settled) {
        return;
      }
      const address = server.address();
      if (address === null || typeof address === 'string' || address.address !== host) {
        fail(new Error('static runtime listener did not bind the expected loopback address'));
        return;
      }
      settled = true;
      cleanup();
      resolve(address.port);
    };
    const onAbort = (): void => fail(abortError());

    if (signal?.aborted) {
      fail(abortError());
      return;
    }

    server.once('error', onError);
    server.once('listening', onListening);
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      server.listen({ host, port, exclusive: true });
    } catch (error: unknown) {
      fail(error);
    }
  });
}

function publicRootPath(projectRoot: string): string {
  if (
    !isAbsolute(projectRoot) ||
    projectRoot.includes('\u0000') ||
    normalize(projectRoot) !== projectRoot ||
    projectRoot === '/'
  ) {
    throw new Error('static project root must be a canonical absolute path');
  }
  return join(projectRoot, 'public');
}

function ownerUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new Error('static runtime requires a POSIX owner identity');
  }
  const uid = process.geteuid();
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error('static runtime could not determine the invoking user');
  }
  return uid;
}

function settleStartupRead<T>(
  operation: () => T | PromiseLike<T>,
  signal: AbortSignal | undefined,
  onLateValue?: (value: T) => void,
): Promise<T> {
  if (signal?.aborted) {
    return Promise.reject(abortError());
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let aborted = false;
    const cleanup = (): void => {
      signal?.removeEventListener('abort', onAbort);
    };
    const fail = (error: unknown): void => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(error);
      }
    };
    const onAbort = (): void => {
      aborted = true;
      fail(abortError());
    };

    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }

    const task = new Promise<T>((resolveTask) => {
      resolveTask(operation());
    });
    void task.then(
      (value) => {
        if (settled) {
          if (aborted) {
            try {
              onLateValue?.(value);
            } catch {
              reportUnexpectedRequestFault();
            }
          }
          return;
        }
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(error);
        }
      },
    );
  });
}
function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw abortError();
  }
}

function abortError(): Error {
  const error = new Error('static runtime start was aborted');
  error.name = 'AbortError';
  return error;
}
