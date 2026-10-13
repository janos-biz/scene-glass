import { access, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { connect, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSceneGlassAppForTest,
  type ProjectRootProbe,
} from '../../packages/server/src/app.js';
import type { LimitValues } from '@scene-glass/contracts';
import { createMcpDispatcher } from '../../packages/server/src/mcp/dispatcher.js';
import {
  mcpRoute,
  type McpDispatcher as HttpMcpDispatcher,
  type McpScopeAuthorizer,
} from '../../packages/server/src/http/mcp-route.js';
import { SessionManager } from '../../packages/server/src/mcp/session-manager.js';
import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';
import type { ProjectRootProbeResult } from '../../packages/server/src/platform/probe.js';
import {
  ConfigProjectRegistry,
  type ProjectRegistry,
} from '../../packages/server/src/registry/config-project-registry.js';

const ALPHA_ORIGIN = 'http://127.0.0.1:43301';
const ALPHA_SECONDARY_ORIGIN = 'http://127.0.0.1:43302';
const BETA_ORIGIN = 'http://127.0.0.1:43303';
const ALPHA_TOKEN = Buffer.alloc(32, 0x41).toString('base64url');
const BETA_TOKEN = Buffer.alloc(32, 0x42).toString('base64url');
const activeHarnesses: Harness[] = [];

interface Clock {
  now: number;
}

interface Harness {
  readonly alphaRoot: string;
  readonly app: Awaited<ReturnType<typeof createSceneGlassAppForTest>>;
  readonly baseUrl: string;
  readonly betaRoot: string;
  readonly configPath: string;
  readonly rootProbeCalls: ReadonlyMap<string, number>;
}

interface InitializedSession {
  readonly sessionId: string;
}
interface McpRouteServer {
  readonly baseUrl: string;
  readonly port: number;
  readonly server: FastifyInstance;
}

interface McpRouteServerOptions {
  readonly limits?: Partial<
    Pick<
      LimitValues,
      'concurrentRequestsGlobal' | 'concurrentRequestsPerProject' | 'requestTimeoutMs'
    >
  >;
  readonly onClientClose?: () => void;
  readonly onRequest?: (reply: FastifyReply) => void;
  readonly scopeAuthorizer?: McpScopeAuthorizer;
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

describe('MCP session transport', () => {
  it('binds POST, GET, and DELETE to the server-generated session and closes it on DELETE', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const session = await initialize(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, 'main');

    const initialized = await postJson(
      harness,
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      {
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {},
      },
      session.sessionId,
    );
    expect(initialized.status).toBe(202);

    const ping = await postJson(
      harness,
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      { id: 'ping', jsonrpc: '2.0', method: 'ping', params: {} },
      session.sessionId,
    );
    expect(ping.status).toBe(200);
    expect(await ping.json()).toEqual({ id: 'ping', jsonrpc: '2.0', result: {} });

    const get = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    await expectProblem(get, 405, 'SCG_MCP_GET_UNSUPPORTED', ALPHA_ORIGIN);

    const closed = await sessionRequest(
      harness,
      'DELETE',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    expect(closed.status).toBe(204);
    expect(await closed.text()).toBe('');
    expect(closed.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(closed.headers.get('cache-control')).toBe('no-store');

    const reused = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    await expectProblem(reused, 404, 'SCG_SESSION_NOT_FOUND', ALPHA_ORIGIN);
  });

  it('rejects client-provided session fixation and closes a mismatched-origin session', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const fixedId = 'A'.repeat(43);

    const fixation = await postJson(
      harness,
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      {
        id: 'fixed',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      },
      fixedId,
    );
    await expectProblem(fixation, 404, 'SCG_SESSION_NOT_FOUND', ALPHA_ORIGIN);
    expect(fixation.headers.get('mcp-session-id')).toBeNull();

    const session = await initialize(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, 'mismatch');
    const mismatch = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_SECONDARY_ORIGIN,
      session.sessionId,
    );
    await expectProblem(mismatch, 403, 'SCG_SESSION_CONTEXT_MISMATCH', ALPHA_SECONDARY_ORIGIN);

    const afterMismatch = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    await expectProblem(afterMismatch, 404, 'SCG_SESSION_NOT_FOUND', ALPHA_ORIGIN);
  });

  it('expires sessions before dispatch and isolates the two configured tokens and roots', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const baselineProbeCalls = new Map(harness.rootProbeCalls);
    const session = await initialize(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, 'expiry');

    clock.now = 61_000;
    const expired = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    await expectProblem(expired, 401, 'SCG_SESSION_EXPIRED', ALPHA_ORIGIN);
    expect(expired.headers.get('www-authenticate')).toBe('Bearer');

    const expiredReuse = await sessionRequest(
      harness,
      'GET',
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      session.sessionId,
    );
    await expectProblem(expiredReuse, 404, 'SCG_SESSION_NOT_FOUND', ALPHA_ORIGIN);

    const alphaOnBeta = await postJson(harness, 'beta', ALPHA_TOKEN, BETA_ORIGIN, {
      id: 'alpha-on-beta',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    await expectProblem(alphaOnBeta, 403, 'SCG_PROJECT_FORBIDDEN', BETA_ORIGIN);

    const betaOnAlpha = await postJson(harness, 'alpha', BETA_TOKEN, ALPHA_ORIGIN, {
      id: 'beta-on-alpha',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });
    await expectProblem(betaOnAlpha, 403, 'SCG_PROJECT_FORBIDDEN', ALPHA_ORIGIN);

    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });

  it('returns the shutdown contract after the host drains its session manager', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const registry = await ConfigProjectRegistry.load(harness.configPath, environment());
    const sessions = new SessionManager({ now: () => clock.now });
    const jsonRpc = createMcpDispatcher({ scope: 'normal' });
    const dispatcher: HttpMcpDispatcher = {
      dispatch: (input) => jsonRpc.dispatch(input.message, { signal: input.signal }),
    };
    const server = Fastify({ logger: false });
    await server.register(mcpRoute, {
      dispatcher,
      maxBodyBytes: registry.effectiveLimits.global.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry,
      sessions,
      verifier: registry.normalTokenVerifier,
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
        throw new Error('shutdown server did not bind an ephemeral literal loopback port');
      }
      const baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
      const initialized = await postJsonAt(baseUrl, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
        id: 'before-shutdown',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      expect(initialized.status).toBe(200);
      expect(sessions.activeSessionCount).toBe(1);
      expect(sessions.shutdown()).toBe(1);
      expect(sessions.activeSessionCount).toBe(0);

      const afterShutdown = await postJsonAt(baseUrl, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
        id: 'after-shutdown',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      await expectProblem(afterShutdown, 503, 'SCG_SESSION_SHUTDOWN', ALPHA_ORIGIN);
    } finally {
      sessions.shutdown();
      await server.close();
    }
  });
  it('preserves rejected DELETE sessions and closes once only after admitted authorization', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const registry = await ConfigProjectRegistry.load(harness.configPath, environment());
    const sessions = new SessionManager({ now: () => clock.now });
    const logger = new SceneGlassLogger();
    const jsonRpc = createMcpDispatcher({ scope: 'normal' });
    let allowDelete = false;
    let closeCalls = 0;
    let releaseHeldDispatch!: () => void;
    let markDispatchStarted!: () => void;
    const dispatchStarted = new Promise<void>((resolve) => {
      markDispatchStarted = resolve;
    });
    const dispatcher: HttpMcpDispatcher = {
      dispatch(input) {
        if (input.message.method === 'hold') {
          markDispatchStarted();
          return new Promise((resolve) => {
            releaseHeldDispatch = () =>
              resolve({ id: input.message.id, jsonrpc: '2.0', result: {} });
          });
        }
        return jsonRpc.dispatch(input.message, { signal: input.signal });
      },
    };
    const server = await startMcpRouteServer(registry, sessions, dispatcher, logger, {
      limits: { concurrentRequestsGlobal: 1, concurrentRequestsPerProject: 1 },
      scopeAuthorizer: {
        allows: ({ operation }) => operation !== 'delete' || allowDelete,
      },
      onClientClose: () => {
        closeCalls += 1;
      },
    });

    try {
      const initialized = await postJsonAt(server.baseUrl, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
        id: 'delete-order',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      const sessionId = initialized.headers.get('mcp-session-id');
      expect(initialized.status).toBe(200);
      expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const denied = await sessionRequestAt(
        server.baseUrl,
        'DELETE',
        'alpha',
        ALPHA_TOKEN,
        ALPHA_ORIGIN,
        sessionId!,
      );
      await expectProblem(denied, 403, 'SCG_SCOPE_FORBIDDEN', ALPHA_ORIGIN);
      expect(closeCalls).toBe(0);
      expect(sessions.activeSessionCount).toBe(1);

      allowDelete = true;
      const held = postJsonAt(
        server.baseUrl,
        'alpha',
        ALPHA_TOKEN,
        ALPHA_ORIGIN,
        { id: 'hold-delete', jsonrpc: '2.0', method: 'hold', params: {} },
        sessionId!,
      );
      await dispatchStarted;

      const saturated = await sessionRequestAt(
        server.baseUrl,
        'DELETE',
        'alpha',
        ALPHA_TOKEN,
        ALPHA_ORIGIN,
        sessionId!,
      );
      await expectProblem(saturated, 429, 'SCG_REQUEST_LIMIT_GLOBAL', ALPHA_ORIGIN);
      expect(closeCalls).toBe(0);
      expect(sessions.activeSessionCount).toBe(1);

      releaseHeldDispatch();
      expect((await held).status).toBe(200);

      const closed = await sessionRequestAt(
        server.baseUrl,
        'DELETE',
        'alpha',
        ALPHA_TOKEN,
        ALPHA_ORIGIN,
        sessionId!,
      );
      expect(closed.status).toBe(204);
      expect(closeCalls).toBe(1);
      expect(sessions.activeSessionCount).toBe(0);
    } finally {
      sessions.shutdown();
      await server.server.close();
    }
  });

  it('preserves terminal evidence when the timeout response write fails', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const registry = await ConfigProjectRegistry.load(harness.configPath, environment());
    const sessions = new SessionManager({ now: () => clock.now });
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
    const jsonRpc = createMcpDispatcher({ scope: 'normal' });
    let releaseDispatch!: () => void;
    let markAborted!: () => void;
    let failTimeoutResponseWrite = false;
    const aborted = new Promise<void>((resolve) => {
      markAborted = resolve;
    });
    const dispatcher: HttpMcpDispatcher = {
      dispatch(input) {
        if (input.message.method !== 'deadline-hold') {
          return jsonRpc.dispatch(input.message, { signal: input.signal });
        }
        failTimeoutResponseWrite = true;
        return new Promise((resolve) => {
          releaseDispatch = () =>
            resolve({ id: input.message.id, jsonrpc: '2.0', result: { late: true } });
          input.signal.addEventListener('abort', markAborted, { once: true });
        });
      },
    };
    const server = await startMcpRouteServer(registry, sessions, dispatcher, logger, {
      limits: { requestTimeoutMs: 10 },
      onRequest: (reply) => {
        const send = reply.send.bind(reply);
        reply.send = (payload?: unknown) => {
          if (failTimeoutResponseWrite) {
            failTimeoutResponseWrite = false;
            throw new Error('forced timeout response write failure');
          }
          return send(payload);
        };
      },
    });

    try {
      const initialized = await postJsonAt(server.baseUrl, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
        id: 'deadline-init',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      const sessionId = initialized.headers.get('mcp-session-id');
      expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const logStart = records.length;
      const timed = postJsonAt(
        server.baseUrl,
        'alpha',
        ALPHA_TOKEN,
        ALPHA_ORIGIN,
        { id: 'deadline-hold', jsonrpc: '2.0', method: 'deadline-hold', params: {} },
        sessionId!,
      );

      await aborted;
      expect(sessions.activeSessionCount).toBe(1);
      releaseDispatch();
      await expectProblem(await timed, 503, 'SCG_REQUEST_TIMEOUT', ALPHA_ORIGIN);

      const terminal = records
        .slice(logStart)
        .filter((record) => record.event.startsWith('terminal.'));
      expect(terminal).toHaveLength(1);
      expect(terminal[0]).toMatchObject({
        data: { stage: 'request-timeout' },
        event: 'terminal.failure',
        scope: { requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/) },
      });
      const writeFailure = records
        .slice(logStart)
        .filter((record) => record.event === 'cleanup.failed');
      expect(writeFailure).toEqual([
        expect.objectContaining({
          data: { resource: 'timeout-response' },
          scope: { requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/) },
        }),
      ]);
      expect(JSON.stringify(writeFailure)).not.toContain(ALPHA_TOKEN);
      expect(JSON.stringify(writeFailure)).not.toContain(ALPHA_ORIGIN);
      expect(JSON.stringify(terminal)).not.toContain(ALPHA_TOKEN);
      expect(JSON.stringify(terminal)).not.toContain(ALPHA_ORIGIN);
    } finally {
      sessions.shutdown();
      await server.server.close();
    }
  });

  it('tears down an authenticated session when the client socket disconnects', async () => {
    const clock = { now: 1_000 };
    const harness = await startHarness(clock);
    const registry = await ConfigProjectRegistry.load(harness.configPath, environment());
    const sessions = new SessionManager({ now: () => clock.now });
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
    const jsonRpc = createMcpDispatcher({ scope: 'normal' });
    let markDispatched!: () => void;
    let markAborted!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      markDispatched = resolve;
    });
    const aborted = new Promise<void>((resolve) => {
      markAborted = resolve;
    });
    const dispatcher: HttpMcpDispatcher = {
      dispatch(input) {
        if (input.message.method !== 'socket-hold') {
          return jsonRpc.dispatch(input.message, { signal: input.signal });
        }
        markDispatched();
        return new Promise((resolve) => {
          input.signal.addEventListener(
            'abort',
            () => {
              markAborted();
              resolve({ id: input.message.id, jsonrpc: '2.0', result: {} });
            },
            { once: true },
          );
        });
      },
    };
    const server = await startMcpRouteServer(registry, sessions, dispatcher, logger);

    try {
      const initialized = await postJsonAt(server.baseUrl, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
        id: 'socket-init',
        jsonrpc: '2.0',
        method: 'initialize',
        params: initializeParams(),
      });
      const sessionId = initialized.headers.get('mcp-session-id');
      expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const socket = connect(server.port, '127.0.0.1');
      socket.on('error', () => undefined);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });
      const body = JSON.stringify({
        id: 'socket-hold',
        jsonrpc: '2.0',
        method: 'socket-hold',
        params: {},
      });
      socket.write(
        [
          'POST /mcp/v1/projects/alpha HTTP/1.1',
          'Host: 127.0.0.1',
          `Authorization: Bearer ${ALPHA_TOKEN}`,
          `Origin: ${ALPHA_ORIGIN}`,
          'content-type: application/json',
          `mcp-session-id: ${sessionId!}`,
          `content-length: ${Buffer.byteLength(body)}`,
          '',
          body,
        ].join('\r\n'),
      );
      await dispatched;
      const logStart = records.length;
      socket.destroy();
      await aborted;
      await Promise.resolve();

      expect(sessions.activeSessionCount).toBe(0);
      const terminal = records
        .slice(logStart)
        .filter((record) => record.event.startsWith('terminal.'));
      expect(terminal).toHaveLength(1);
      expect(terminal[0]).toMatchObject({
        data: { stage: 'disconnect' },
        event: 'terminal.cancelled',
      });
    } finally {
      sessions.shutdown();
      await server.server.close();
    }
  });
});

async function startHarness(clock: Clock): Promise<Harness> {
  const alphaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-session-alpha-')));
  const betaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-session-beta-')));
  const configPath = join(alphaRoot, 'scene-glass.config.json');
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      globalLimits: {
        sessionIdleMs: 60_000,
        sessionMaxAgeMs: 60_000,
      },
      projects: [
        {
          allowedOrigins: [ALPHA_ORIGIN, ALPHA_SECONDARY_ORIGIN],
          projectId: 'alpha',
          root: alphaRoot,
          tokenEnv: 'SCG_SESSION_ALPHA_TOKEN',
        },
        {
          allowedOrigins: [BETA_ORIGIN],
          projectId: 'beta',
          root: betaRoot,
          tokenEnv: 'SCG_SESSION_BETA_TOKEN',
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
    environment: environment(),
    now: () => clock.now,
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
async function startMcpRouteServer(
  registry: ConfigProjectRegistry,
  sessions: SessionManager,
  dispatcher: HttpMcpDispatcher,
  logger: SceneGlassLogger,
  options: McpRouteServerOptions = {},
): Promise<McpRouteServer> {
  const limitOverrides = options.limits;
  const routeRegistry: ProjectRegistry =
    limitOverrides === undefined
      ? registry
      : {
          getOriginPolicy: (projectId) => registry.getOriginPolicy(projectId),
          resolveAuthorizedProject: (auth) => {
            const project = registry.resolveAuthorizedProject(auth);
            if (project === undefined) {
              return undefined;
            }
            const effectiveLimits: LimitValues = {
              ...project.effectiveLimits,
              ...limitOverrides,
            };
            return Object.freeze({
              ...project,
              effectiveLimits: Object.freeze(effectiveLimits),
            });
          },
        };
  const server = Fastify({ logger: false });
  if (options.onRequest !== undefined) {
    server.addHook('onRequest', (_request, reply, done) => {
      options.onRequest?.(reply);
      done();
    });
  }
  await server.register(mcpRoute, {
    dispatcher,
    logger,
    maxBodyBytes: registry.effectiveLimits.global.httpBodyBytes,
    registry: routeRegistry,
    ...(options.scopeAuthorizer === undefined ? {} : { scopeAuthorizer: options.scopeAuthorizer }),
    sessions: {
      abort: (sessionId) => sessions.abort(sessionId),
      close: (sessionId) => {
        const result = sessions.close(sessionId);
        if (result.tornDown) {
          options.onClientClose?.();
        }
        return result;
      },
      initialize: (input) => sessions.initialize(input),
      commit: (input) => sessions.commit(input),
      lookup: (input) => sessions.lookup(input),
    },
    verifier: registry.normalTokenVerifier,
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
    throw new Error('MCP test server did not bind an ephemeral literal loopback port');
  }
  const port = (address as AddressInfo).port;
  return { baseUrl: `http://127.0.0.1:${port}`, port, server };
}

function environment(): Record<string, string> {
  return {
    SCG_SESSION_ALPHA_TOKEN: ALPHA_TOKEN,
    SCG_SESSION_BETA_TOKEN: BETA_TOKEN,
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

async function initialize(
  harness: Harness,
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  id: string,
): Promise<InitializedSession> {
  const response = await postJson(harness, projectId, token, origin, {
    id,
    jsonrpc: '2.0',
    method: 'initialize',
    params: initializeParams(),
  });
  expect(response.status).toBe(200);
  const sessionId = response.headers.get('mcp-session-id');
  expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return { sessionId: sessionId! };
}

function postJson(
  harness: Harness,
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  body: unknown,
  sessionId?: string,
): Promise<Response> {
  return postJsonAt(harness.baseUrl, projectId, token, origin, body, sessionId);
}

function postJsonAt(
  baseUrl: string,
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  body: unknown,
  sessionId?: string,
): Promise<Response> {
  return fetch(`${baseUrl}/mcp/v1/projects/${projectId}`, {
    body: JSON.stringify(body),
    headers: {
      Authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(sessionId === undefined ? {} : { 'mcp-session-id': sessionId }),
      Origin: origin,
    },
    method: 'POST',
  });
}

function sessionRequest(
  harness: Harness,
  method: 'DELETE' | 'GET',
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  sessionId: string,
): Promise<Response> {
  return sessionRequestAt(harness.baseUrl, method, projectId, token, origin, sessionId);
}

function sessionRequestAt(
  baseUrl: string,
  method: 'DELETE' | 'GET',
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  sessionId: string,
): Promise<Response> {
  return fetch(`${baseUrl}/mcp/v1/projects/${projectId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'mcp-session-id': sessionId,
      Origin: origin,
    },
    method,
  });
}

function initializeParams(): Record<string, unknown> {
  return {
    capabilities: {},
    clientInfo: { name: 'session-test', version: '1.0.0' },
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
