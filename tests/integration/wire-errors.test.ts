import { access, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify, { type FastifyReply } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSceneGlassAppForTest,
  type ProjectRootProbe,
} from '../../packages/server/src/app.js';
import type { ProjectRootProbeResult } from '../../packages/server/src/platform/probe.js';
import {
  mcpRoute,
  type McpBearerVerifier,
  type McpDispatcher as HttpMcpDispatcher,
  type McpRouteOptions,
  type McpSessionGateway,
} from '../../packages/server/src/http/mcp-route.js';
import { SessionManager } from '../../packages/server/src/mcp/session-manager.js';
import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';
import {
  ConfigProjectRegistry,
  type ProjectRegistry,
} from '../../packages/server/src/registry/config-project-registry.js';

const ALPHA_ORIGIN = 'http://127.0.0.1:43101';
const BETA_ORIGIN = 'http://127.0.0.1:43102';
const ALPHA_TOKEN = Buffer.alloc(32, 0x11).toString('base64url');
const BETA_TOKEN = Buffer.alloc(32, 0x22).toString('base64url');
const INVALID_TOKEN = Buffer.alloc(32, 0x33).toString('base64url');
const HTTP_BODY_BYTES = 256;
const activeHarnesses: Harness[] = [];

interface Harness {
  readonly app: Awaited<ReturnType<typeof createSceneGlassAppForTest>>;
  readonly alphaRoot: string;
  readonly baseUrl: string;
  readonly betaRoot: string;
  readonly configPath: string;
  readonly rootProbeCalls: ReadonlyMap<string, number>;
}
interface RouteServerOptions {
  readonly diagnosticRunStore?: McpRouteOptions['diagnosticRunStore'];
  readonly logger?: SceneGlassLogger;
  readonly now?: () => number;
  readonly onRequest?: (reply: FastifyReply) => void;
  readonly requestTimeoutMs?: number;
  readonly sessions?: McpSessionGateway;
  readonly verifier?: McpBearerVerifier;
}

afterEach(async () => {
  await Promise.all(
    activeHarnesses.splice(0).map(async (harness) => {
      await harness.app.close();
      await Promise.all([
        rm(harness.alphaRoot, { force: true, recursive: true }),
        rm(harness.betaRoot, { force: true, recursive: true }),
      ]);
    }),
  );
});

describe('MCP HTTP wire errors', () => {
  it('serves an unauthenticated exact-origin preflight with only requested CORS fields', async () => {
    const harness = await startHarness();
    const baselineProbeCalls = new Map(harness.rootProbeCalls);

    const response = await request(harness, 'OPTIONS', 'alpha', {
      headers: {
        Origin: ALPHA_ORIGIN,
        'Access-Control-Request-Method': 'POST',
      },
    });

    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');
    expect(response.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(response.headers.get('access-control-allow-methods')).toBe('POST');
    expect(response.headers.get('vary')).toBe('Origin');
    expect(response.headers.get('access-control-allow-headers')).toBeNull();
    expect(response.headers.get('access-control-expose-headers')).toBeNull();
    expect(response.headers.get('www-authenticate')).toBeNull();
    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });
  it('does not invoke later auth, session, dispatcher, or root-handle dependencies on early requests', async () => {
    const harness = await startHarness();
    const registry = await ConfigProjectRegistry.load(harness.configPath, wireEnvironment());
    const manager = new SessionManager();
    const calls = {
      dispatcher: 0,
      initialize: 0,
      lookup: 0,
      rootHandle: 0,
      verifier: 0,
    };
    const countedRegistry: ProjectRegistry = {
      getOriginPolicy: (projectId) => registry.getOriginPolicy(projectId),
      resolveAuthorizedProject: (auth) => {
        calls.rootHandle += 1;
        return registry.resolveAuthorizedProject(auth);
      },
    };
    const sessions: McpSessionGateway = {
      initialize: (input) => {
        calls.initialize += 1;
        return manager.initialize(input);
      },
      commit: (input) => manager.commit(input),
      lookup: (input) => {
        calls.lookup += 1;
        return manager.lookup(input);
      },
      abort: (sessionId) => manager.abort(sessionId),
      close: (sessionId) => manager.close(sessionId),
    };
    const verifier: McpBearerVerifier = {
      verify: (input) => {
        calls.verifier += 1;
        return registry.normalTokenVerifier.verify(input);
      },
    };
    const dispatcher: HttpMcpDispatcher = {
      dispatch: async () => {
        calls.dispatcher += 1;
        return undefined;
      },
    };
    const server = Fastify({ logger: false });
    await server.register(mcpRoute, {
      dispatcher,
      maxBodyBytes: registry.effectiveLimits.global.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry: countedRegistry,
      sessions,
      verifier,
    });
    await server.listen({ host: '127.0.0.1', port: 0 });

    try {
      const address = server.server.address();
      if (
        address === null ||
        typeof address === 'string' ||
        address.address !== '127.0.0.1' ||
        address.port <= 0
      ) {
        throw new Error('instrumented server did not bind an ephemeral literal loopback port');
      }
      const baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}/mcp/v1/projects/alpha`;

      const preflight = await fetch(baseUrl, {
        headers: {
          'Access-Control-Request-Method': 'POST',
          Origin: ALPHA_ORIGIN,
        },
        method: 'OPTIONS',
      });
      expect(preflight.status).toBe(204);
      expect(calls).toEqual({
        dispatcher: 0,
        initialize: 0,
        lookup: 0,
        rootHandle: 0,
        verifier: 0,
      });

      const originDenied = await fetch(baseUrl, {
        body: JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'initialize' }),
        headers: authenticatedHeaders(ALPHA_TOKEN, 'null'),
        method: 'POST',
      });
      expect(originDenied.status).toBe(403);
      expect(calls).toEqual({
        dispatcher: 0,
        initialize: 0,
        lookup: 0,
        rootHandle: 0,
        verifier: 0,
      });

      const unauthenticated = await fetch(baseUrl, {
        body: '{',
        headers: { 'content-type': 'application/json', Origin: ALPHA_ORIGIN },
        method: 'POST',
      });
      expect(unauthenticated.status).toBe(401);
      expect(calls).toEqual({
        dispatcher: 0,
        initialize: 0,
        lookup: 0,
        rootHandle: 0,
        verifier: 1,
      });
      await expectNoStoreRoots(harness);
    } finally {
      manager.shutdown();
      await server.close();
    }
  });

  it.each([
    ['null', 'null'],
    ['suffix', 'http://attacker.127.0.0.1:43101'],
    ['wrong port', 'http://127.0.0.1:43103'],
  ])('rejects a %s Origin without CORS or a response body', async (_name, origin) => {
    const harness = await startHarness();
    const baselineProbeCalls = new Map(harness.rootProbeCalls);

    const response = await request(harness, 'OPTIONS', 'alpha', {
      headers: {
        Origin: origin,
        'Access-Control-Request-Method': 'POST',
      },
    });

    expect(response.status).toBe(403);
    expect((await response.arrayBuffer()).byteLength).toBe(0);
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(response.headers.get('access-control-allow-methods')).toBeNull();
    expect(response.headers.get('vary')).toBeNull();
    expect(response.headers.get('content-type')).toBeNull();
    const actual = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, origin, {
      id: 'denied-origin',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    expect(actual.status).toBe(403);
    expect(await actual.text()).toBe('');
    expect(actual.headers.get('access-control-allow-origin')).toBeNull();
    expect(actual.headers.get('content-type')).toBeNull();
    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });

  it('authenticates before inspecting an invalid or oversized POST body', async () => {
    const harness = await startHarness();
    const baselineProbeCalls = new Map(harness.rootProbeCalls);

    const malformed = await request(harness, 'POST', 'alpha', {
      body: '{',
      headers: {
        'content-type': 'application/json',
        Origin: ALPHA_ORIGIN,
      },
    });
    await expectProblem(malformed, 401, 'SCG_AUTH_INVALID', ALPHA_ORIGIN);

    const oversized = await request(harness, 'POST', 'alpha', {
      body: 'x'.repeat(HTTP_BODY_BYTES + 1),
      headers: {
        'content-type': 'application/json',
        Origin: ALPHA_ORIGIN,
      },
    });
    await expectProblem(oversized, 401, 'SCG_AUTH_INVALID', ALPHA_ORIGIN);

    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });

  it('serializes media, length, JSON, and JSON-RPC failures on the approved wire', async () => {
    const harness = await startHarness();

    const unsupportedMedia = await request(harness, 'POST', 'alpha', {
      body: '{}',
      headers: authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN, {
        'content-type': 'text/plain',
      }),
    });
    await expectProblem(unsupportedMedia, 415, 'SCG_MEDIA_TYPE_INVALID', ALPHA_ORIGIN);

    const oversized = await request(harness, 'POST', 'alpha', {
      body: 'x'.repeat(HTTP_BODY_BYTES + 1),
      headers: authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN),
    });
    await expectProblem(oversized, 413, 'SCG_BODY_TOO_LARGE', ALPHA_ORIGIN);

    const invalidJson = await request(harness, 'POST', 'alpha', {
      body: '{',
      headers: authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN),
    });
    await expectProblem(invalidJson, 400, 'SCG_JSON_INVALID', ALPHA_ORIGIN);

    const invalidRpc = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 'wrong-version',
      jsonrpc: '1.0',
      method: 'initialize',
    });
    expect(invalidRpc.status).toBe(200);
    expect(invalidRpc.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(await invalidRpc.json()).toEqual({
      error: {
        code: -32600,
        message: 'Invalid Request',
      },
      id: null,
      jsonrpc: '2.0',
    });

    const invalidParams = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 41,
      jsonrpc: '2.0',
      method: 'initialize',
      params: { protocolVersion: 42 },
    });
    await expectProblem(invalidParams, 400, 'SCG_MCP_PROTOCOL_VERSION', ALPHA_ORIGIN);
    expect(invalidParams.headers.get('mcp-session-id')).toBeNull();
  });

  it('fails closed negotiation and releases a failed initialize reservation before quota reuse', async () => {
    const harness = await startHarness();

    const unsupportedVersion = await request(harness, 'POST', 'alpha', {
      body: JSON.stringify({
        id: 'unsupported-version',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      }),
      headers: authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN, {
        'mcp-protocol-version': '2024-11-05',
      }),
    });
    await expectProblem(unsupportedVersion, 400, 'SCG_MCP_PROTOCOL_VERSION', ALPHA_ORIGIN);

    const unsupportedAccept = await request(harness, 'POST', 'alpha', {
      body: JSON.stringify({
        id: 'unsupported-accept',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      }),
      headers: authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN, { Accept: 'text/plain' }),
    });
    await expectProblem(unsupportedAccept, 406, 'SCG_MCP_ACCEPT_INVALID', ALPHA_ORIGIN);

    const failedHandshake = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 'bad-client-info',
      jsonrpc: '2.0',
      method: 'initialize',
      params: {
        capabilities: {},
        clientInfo: { name: 42, version: '1.0.0' },
        protocolVersion: '2025-11-25',
      },
    });
    expect(failedHandshake.status).toBe(200);
    expect(failedHandshake.headers.get('mcp-session-id')).toBeNull();
    expect(await failedHandshake.json()).toMatchObject({
      error: { code: -32602 },
      id: 'bad-client-info',
      jsonrpc: '2.0',
    });

    const reusedQuota = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 'quota-reused',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    expect(reusedQuota.status).toBe(200);
    expect(reusedQuota.headers.get('mcp-session-id')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('keeps initialize reservations unaddressable and releases them when response writing fails', async () => {
    const harness = await startHarness();
    const manager = new SessionManager();
    let addressableBeforeCommit: boolean | undefined;
    let failInitializeResponseWrite = false;
    const sessions: McpSessionGateway = {
      abort: (sessionId) => manager.abort(sessionId),
      close: (sessionId, signal) => manager.close(sessionId, signal),
      commit: (input) => manager.commit(input),
      initialize: (input) => {
        const initialized = manager.initialize(input);
        if (initialized.ok) {
          addressableBeforeCommit = manager.lookup({
            auth: input.auth,
            method: 'POST',
            sessionId: initialized.session.id,
          }).ok;
        }
        return initialized;
      },
      lookup: (input) => manager.lookup(input),
    };
    const server = await startRouteServer(
      harness,
      {
        dispatch(input) {
          failInitializeResponseWrite = true;
          return {
            id: input.message.id,
            jsonrpc: '2.0',
            result: {
              capabilities: {},
              protocolVersion: '2025-11-25',
              serverInfo: { name: 'test', version: '1.0.0' },
            },
          };
        },
      },
      {
        onRequest: (reply) => {
          const send = reply.send.bind(reply);
          reply.send = (payload?: unknown) => {
            if (failInitializeResponseWrite) {
              failInitializeResponseWrite = false;
              throw new Error('forced initialize response write failure');
            }
            return send(payload);
          };
        },
        sessions,
      },
    );

    try {
      const response = await routeJson(server.baseUrl, {
        id: 'write-failure',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(response, 500, 'SCG_HTTP_INTERNAL', ALPHA_ORIGIN);
      expect(response.headers.get('mcp-session-id')).toBeNull();
      expect(addressableBeforeCommit).toBe(false);
      expect(manager.activeSessionCount).toBe(0);
    } finally {
      manager.shutdown();
      await server.server.close();
    }
  });
  it('rejects malformed dispatcher output and notification output without committing a new session', async () => {
    const harness = await startHarness();
    const server = await startRouteServer(harness, {
      dispatch(input) {
        if (input.message.method === 'initialize') {
          return {
            id: input.message.id,
            jsonrpc: '2.0',
            result: {
              capabilities: {},
              protocolVersion: '2025-11-25',
              serverInfo: { name: 'test', version: '1.0.0' },
            },
          };
        }
        if (input.message.id === undefined) {
          return { id: 'unexpected', jsonrpc: '2.0', result: {} };
        }
        return { id: input.message.id, jsonrpc: '1.0', result: {} };
      },
    });

    try {
      const initialized = await routeJson(server.baseUrl, {
        id: 'strict-init',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      const sessionId = initialized.headers.get('mcp-session-id');
      expect(initialized.status).toBe(200);
      expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const malformed = await routeJson(
        server.baseUrl,
        { id: 'malformed-output', jsonrpc: '2.0', method: 'ping', params: {} },
        sessionId!,
      );
      await expectProblem(malformed, 500, 'SCG_MCP_RESPONSE_INVALID', ALPHA_ORIGIN);

      const notification = await routeJson(
        server.baseUrl,
        { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
        sessionId!,
      );
      await expectProblem(notification, 500, 'SCG_MCP_RESPONSE_INVALID', ALPHA_ORIGIN);
    } finally {
      await server.server.close();
    }
  });

  it('aborts a session created after the request deadline and keeps verifier failures distinct', async () => {
    const harness = await startHarness();
    const manager = new SessionManager();
    let releaseInitialize!: () => void;
    const delayedInitialize = new Promise<void>((resolve) => {
      releaseInitialize = resolve;
    });
    const sessions: McpSessionGateway = {
      abort: (sessionId) => manager.abort(sessionId),
      close: (sessionId, signal) => manager.close(sessionId, signal),
      commit: (input) => manager.commit(input),
      initialize: async (input) => {
        await delayedInitialize;
        const { signal, ...withoutSignal } = input;
        void signal;
        return manager.initialize(withoutSignal);
      },
      lookup: (input) => manager.lookup(input),
    };
    const server = await startRouteServer(
      harness,
      {
        dispatch(input) {
          return {
            id: input.message.id,
            jsonrpc: '2.0',
            result: {
              capabilities: {},
              protocolVersion: '2025-11-25',
              serverInfo: { name: 'test', version: '1.0.0' },
            },
          };
        },
      },
      { requestTimeoutMs: 10, sessions },
    );

    try {
      const timed = routeJson(server.baseUrl, {
        id: 'late-initialize',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(await timed, 503, 'SCG_REQUEST_TIMEOUT', ALPHA_ORIGIN);
      releaseInitialize();
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      expect(manager.activeSessionCount).toBe(0);
    } finally {
      manager.shutdown();
      await server.server.close();
    }

    const verifierFailure = await startRouteServer(
      harness,
      { dispatch: () => undefined },
      {
        verifier: {
          verify: () => {
            throw new Error('verifier unavailable');
          },
        },
      },
    );
    try {
      const response = await routeJson(verifierFailure.baseUrl, {
        id: 'verifier-failure',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(response, 500, 'SCG_AUTH_VERIFIER_FAILED', ALPHA_ORIGIN);
    } finally {
      await verifierFailure.server.close();
    }
    const diagnosticCalls: string[] = [];
    const diagnosticRunStore: NonNullable<McpRouteOptions['diagnosticRunStore']> = {
      abort: () => {
        diagnosticCalls.push('abort');
        throw new Error('unexpected diagnostic abort');
      },
      authenticate: () => {
        diagnosticCalls.push('authenticate');
        throw new Error('diagnostic store unavailable');
      },
      authorizeMethod: () => {
        diagnosticCalls.push('authorizeMethod');
        throw new Error('unexpected diagnostic authorization');
      },
      close: () => {
        diagnosticCalls.push('close');
        throw new Error('unexpected diagnostic close');
      },
      consumeInitialize: () => {
        diagnosticCalls.push('consumeInitialize');
        throw new Error('unexpected diagnostic initialize consumption');
      },
      recognizesCredential: () => {
        diagnosticCalls.push('recognizesCredential');
        throw new Error('unexpected diagnostic credential recognition');
      },
    };
    const diagnosticFailure = await startRouteServer(
      harness,
      { dispatch: () => undefined },
      {
        diagnosticRunStore,
        verifier: {
          verify: () => ({ code: 'SCG_AUTH_INVALID', ok: false, status: 401 }),
        },
      },
    );
    try {
      const response = await routeJson(diagnosticFailure.baseUrl, {
        id: 'diagnostic-store-failure',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(response, 500, 'SCG_DIAGNOSTIC_STORE_FAILED', ALPHA_ORIGIN);
      expect(diagnosticCalls).toEqual(['authenticate']);
    } finally {
      await diagnosticFailure.server.close();
    }
  });
  it('fails closed with terminal evidence when the diagnostic clock is invalid', async () => {
    const harness = await startHarness();
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
    let dispatchCalls = 0;
    const server = await startRouteServer(
      harness,
      {
        dispatch: () => {
          dispatchCalls += 1;
          return undefined;
        },
      },
      {
        logger,
        now: () => Number.NaN,
      },
    );

    try {
      const response = await routeJson(server.baseUrl, {
        id: 'invalid-diagnostic-clock',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(response, 500, 'SCG_HTTP_INTERNAL', ALPHA_ORIGIN);
      expect(dispatchCalls).toBe(0);
      const terminal = records.filter((record) => record.event.startsWith('terminal.'));
      expect(terminal).toEqual([
        expect.objectContaining({
          data: { stage: 'handler-error' },
          event: 'terminal.failure',
          scope: { requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/) },
        }),
      ]);
      expect(JSON.stringify(terminal)).not.toContain(ALPHA_TOKEN);
      expect(JSON.stringify(terminal)).not.toContain(ALPHA_ORIGIN);
    } finally {
      await server.server.close();
    }
  });
  it('applies exact allowed-origin CORS to 401 and 403 responses only', async () => {
    const harness = await startHarness();

    const unauthorized = await jsonRequest(harness, 'alpha', INVALID_TOKEN, ALPHA_ORIGIN, {
      id: 'wrong-token',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    await expectProblem(unauthorized, 401, 'SCG_AUTH_INVALID', ALPHA_ORIGIN);
    expect(unauthorized.headers.get('www-authenticate')).toBe('Bearer');

    const forbidden = await jsonRequest(harness, 'beta', ALPHA_TOKEN, BETA_ORIGIN, {
      id: 'wrong-project',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    await expectProblem(forbidden, 403, 'SCG_PROJECT_FORBIDDEN', BETA_ORIGIN);
    expect(forbidden.headers.get('www-authenticate')).toBeNull();

    const originDenied = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, 'null', {
      id: 'origin-denied',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    expect(originDenied.status).toBe(403);
    expect(await originDenied.text()).toBe('');
    expect(originDenied.headers.get('access-control-allow-origin')).toBeNull();
    expect(originDenied.headers.get('content-type')).toBeNull();
  });
});

async function startHarness(): Promise<Harness> {
  const alphaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-wire-alpha-')));
  const betaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-wire-beta-')));
  const configPath = join(alphaRoot, 'scene-glass.config.json');
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      globalLimits: { httpBodyBytes: HTTP_BODY_BYTES, normalSessionsGlobal: 1 },
      projects: [
        {
          allowedOrigins: [ALPHA_ORIGIN],
          projectId: 'alpha',
          root: alphaRoot,
          tokenEnv: 'SCG_WIRE_ALPHA_TOKEN',
        },
        {
          allowedOrigins: [BETA_ORIGIN],
          projectId: 'beta',
          root: betaRoot,
          tokenEnv: 'SCG_WIRE_BETA_TOKEN',
        },
      ],
    }),
  );

  const rootProbeCalls = new Map<string, number>();
  const projectRootProbe: ProjectRootProbe = async (root) => {
    rootProbeCalls.set(root, (rootProbeCalls.get(root) ?? 0) + 1);
    return supportedRoot(root);
  };
  const app = await createSceneGlassAppForTest({
    configPath,
    environment: wireEnvironment(),
    projectRootProbe,
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (
    address === null ||
    typeof address === 'string' ||
    address.address !== '127.0.0.1' ||
    address.port <= 0
  ) {
    await app.close();
    await Promise.all([
      rm(alphaRoot, { force: true, recursive: true }),
      rm(betaRoot, { force: true, recursive: true }),
    ]);
    throw new Error('test server did not bind an ephemeral literal loopback port');
  }

  const harness: Harness = {
    alphaRoot,
    app,
    baseUrl: `http://127.0.0.1:${(address as AddressInfo).port}`,
    betaRoot,
    configPath,
    rootProbeCalls,
  };
  activeHarnesses.push(harness);
  return harness;
}

function wireEnvironment(): Record<string, string> {
  return {
    SCG_WIRE_ALPHA_TOKEN: ALPHA_TOKEN,
    SCG_WIRE_BETA_TOKEN: BETA_TOKEN,
  };
}

function supportedRoot(root: string): ProjectRootProbeResult {
  return {
    authority: 'macos-authoritative',
    code: null,
    facts: {
      device: 1,
      fileSystemType: 1,
      identityStableAtProbe: true,
      inode: 1,
      realPath: root,
    },
    failStopReason: null,
    platform: 'darwin',
    supported: true,
  };
}

async function startRouteServer(
  harness: Harness,
  dispatcher: HttpMcpDispatcher,
  options: RouteServerOptions = {},
): Promise<{ readonly baseUrl: string; readonly server: ReturnType<typeof Fastify> }> {
  const registry = await ConfigProjectRegistry.load(harness.configPath, wireEnvironment());
  const sessions = options.sessions ?? new SessionManager();
  const server = Fastify({ logger: false });
  if (options.onRequest !== undefined) {
    server.addHook('onRequest', (_request, reply, done) => {
      options.onRequest?.(reply);
      done();
    });
  }
  if (sessions instanceof SessionManager) {
    server.addHook('onClose', () => {
      sessions.shutdown();
    });
  }
  await server.register(mcpRoute, {
    dispatcher,
    ...(options.diagnosticRunStore === undefined
      ? {}
      : { diagnosticRunStore: options.diagnosticRunStore }),
    logger: options.logger ?? new SceneGlassLogger(),
    maxBodyBytes: registry.effectiveLimits.global.httpBodyBytes,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.requestTimeoutMs === undefined
      ? {}
      : { requestTimeoutMs: options.requestTimeoutMs }),
    registry,
    sessions,
    verifier: options.verifier ?? registry.normalTokenVerifier,
  });
  await server.listen({ host: '127.0.0.1', port: 0 });
  const address = server.server.address();
  if (
    address === null ||
    typeof address === 'string' ||
    address.address !== '127.0.0.1' ||
    address.port <= 0
  ) {
    await server.close();
    throw new Error('custom MCP server did not bind an ephemeral literal loopback port');
  }
  return { baseUrl: `http://127.0.0.1:${(address as AddressInfo).port}`, server };
}

function routeJson(baseUrl: string, body: unknown, sessionId?: string): Promise<Response> {
  return fetch(`${baseUrl}/mcp/v1/projects/alpha`, {
    body: JSON.stringify(body),
    headers: {
      ...authenticatedHeaders(ALPHA_TOKEN, ALPHA_ORIGIN),
      ...(sessionId === undefined ? {} : { 'mcp-session-id': sessionId }),
    },
    method: 'POST',
  });
}
function request(
  harness: Harness,
  method: 'OPTIONS' | 'POST',
  projectId: 'alpha' | 'beta',
  init: Omit<RequestInit, 'method'> = {},
): Promise<Response> {
  return fetch(`${harness.baseUrl}/mcp/v1/projects/${projectId}`, { ...init, method });
}

function jsonRequest(
  harness: Harness,
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  body: unknown,
): Promise<Response> {
  return request(harness, 'POST', projectId, {
    body: JSON.stringify(body),
    headers: authenticatedHeaders(token, origin),
  });
}

function authenticatedHeaders(
  token: string,
  origin: string,
  additional: Record<string, string> = {},
): Record<string, string> {
  return {
    Accept: 'application/json, text/event-stream',
    Authorization: `Bearer ${token}`,
    Origin: origin,
    'content-type': 'application/json',
    'mcp-protocol-version': '2025-11-25',
    ...additional,
  };
}

function initializeParams(): Record<string, unknown> {
  return {
    capabilities: {},
    clientInfo: { name: 'wire-errors', version: '1.0.0' },
    protocolVersion: '2025-11-25',
  };
}

async function expectProblem(
  response: Response,
  status: number,
  code: string,
  origin: string,
): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.get('access-control-allow-origin')).toBe(origin);
  expect(response.headers.get('vary')).toBe('Origin');
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('content-type')).toContain('application/problem+json');
  expect(await response.json()).toMatchObject({ code, status });
}

async function expectNoStoreRoots(harness: Harness): Promise<void> {
  await Promise.all(
    [harness.alphaRoot, harness.betaRoot].map((root) =>
      expect(access(join(root, '.scg'))).rejects.toMatchObject({ code: 'ENOENT' }),
    ),
  );
}
