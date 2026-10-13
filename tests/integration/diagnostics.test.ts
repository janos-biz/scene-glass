import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { InjectPayload, Response as LightMyRequestResponse } from 'light-my-request';
import { BUILT_IN_LIMITS, parsePageFileV1, type PageFileV1 } from '@scene-glass/contracts';
import { createSceneGlassAppForTest, SerialProjectLock } from '../../packages/server/src/app.js';
import type { AuthContext } from '../../packages/server/src/auth/auth-context.js';
import {
  SCENE_GLASS_AUDIENCE,
  createCredentialSubject,
} from '../../packages/server/src/auth/credential-subject.js';
import {
  LocalTokenVerifier,
  createLocalTokenCredential,
} from '../../packages/server/src/auth/local-token-verifier.js';
import {
  createDiagnosticsLifecycle,
  DiagnosticsTeardown,
} from '../../packages/server/src/diagnostics/index.js';
import { MCP_PROTOCOL_VERSION, McpRpcError } from '../../packages/server/src/mcp/dispatcher.js';
import { createPromptExportTool } from '../../packages/server/src/mcp/export-tool.js';
import { SessionManager } from '../../packages/server/src/mcp/session-manager.js';
import type { ProjectLock } from '../../packages/server/src/mcp/annotation-tools.js';
import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import type { AnnotationStore } from '../../packages/server/src/storage/scg-annotation-store.js';
import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';

const ALPHA_ORIGIN = 'https://alpha.diagnostics.test';
const BETA_ORIGIN = 'https://beta.diagnostics.test';
const ALPHA_PROJECT = 'alpha';
const BETA_PROJECT = 'beta';
const NORMAL_TOKEN = opaqueToken(1);
const BETA_TOKEN = opaqueToken(2);
const temporaryServers = new Set<RunningServer>();
const ADMISSION_GATE_WATCHDOG_MS = 100;

afterEach(async () => {
  await Promise.all([...temporaryServers].map((server) => stopServer(server)));
});

describe('diagnostic runs over the loopback MCP authority', () => {
  it('issues one project- and Origin-bound, 60-second raw capability with no cacheable representation', async () => {
    const now = 1_700_000_000_000;
    const server = await startServer({ now: () => now });
    await prepopulateScgTree(server.alphaRoot);
    const before = await scgTreeSnapshot(server.alphaRoot);

    const issuedResponse = await issueDiagnostic(server, {
      origin: ALPHA_ORIGIN,
      token: NORMAL_TOKEN,
    });
    const issued = await expectIssuedRun(issuedResponse, server, ALPHA_ORIGIN);

    expect(Buffer.from(issued.token, 'base64url')).toHaveLength(32);
    expect(issued.token).not.toBe(NORMAL_TOKEN);
    expect(issued.expiresAt).toBe(new Date(now + 60_000).toISOString());

    const noListing = await fetch(
      `${server.endpoint}/mcp/v1/projects/${ALPHA_PROJECT}/diagnostic-runs/${encodeURIComponent(issued.runId)}`,
      {
        headers: {
          authorization: `Bearer ${NORMAL_TOKEN}`,
          origin: ALPHA_ORIGIN,
        },
      },
    );
    expect(noListing.status).toBe(404);
    expect(await noListing.text()).not.toContain(issued.token);

    const after = await scgTreeSnapshot(server.alphaRoot);
    expect(after).toEqual(before);
  });

  it('rejects non-exact and unconfigured Origins, wrong project, wrong normal token, and a 31-byte bearer before any store path', async () => {
    const server = await startServer();
    await Promise.all([prepopulateScgTree(server.alphaRoot), prepopulateScgTree(server.betaRoot)]);
    const [alphaBefore, betaBefore] = await Promise.all([
      scgTreeSnapshot(server.alphaRoot),
      scgTreeSnapshot(server.betaRoot),
    ]);

    for (const origin of ['https://attacker.diagnostics.test', `${ALPHA_ORIGIN}/`]) {
      const wrongOrigin = await issueDiagnostic(server, {
        origin,
        token: NORMAL_TOKEN,
      });
      expect(wrongOrigin.status).toBe(403);
      expect(wrongOrigin.headers.get('access-control-allow-origin')).toBeNull();
      expect(wrongOrigin.headers.get('cache-control')).toBeNull();
      expect(await wrongOrigin.text()).toBe('');
    }

    await expectProblem(
      await issueDiagnostic(server, {
        origin: BETA_ORIGIN,
        projectId: BETA_PROJECT,
        token: NORMAL_TOKEN,
      }),
      BETA_ORIGIN,
      403,
      'SCG_PROJECT_FORBIDDEN',
    );

    await expectProblem(
      await issueDiagnostic(server, {
        origin: ALPHA_ORIGIN,
        token: opaqueToken(3),
      }),
      ALPHA_ORIGIN,
      401,
      'SCG_AUTH_INVALID',
    );

    const lowerBoundToken = opaqueToken(4, 31);
    expect(Buffer.from(lowerBoundToken, 'base64url')).toHaveLength(31);
    await expectProblem(
      await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: lowerBoundToken,
        message: initializeMessage(1),
      }),
      ALPHA_ORIGIN,
      401,
      'SCG_AUTH_INVALID',
    );

    expect(await scgTreeSnapshot(server.alphaRoot)).toEqual(alphaBefore);
    expect(await scgTreeSnapshot(server.betaRoot)).toEqual(betaBefore);
  });

  it('permits only the diagnostic initialize lifecycle and rejects tools before storage or the normal dispatcher', async () => {
    const server = await startServer();
    await prepopulateScgTree(server.alphaRoot);
    const before = await scgTreeSnapshot(server.alphaRoot);
    const issued = await issueAndRead(server);

    for (const message of [
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
      },
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'annotations.list', arguments: {} },
      },
      {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'prompt.export', arguments: {} },
      },
    ]) {
      await expectProblem(
        await postMcp(server, {
          origin: ALPHA_ORIGIN,
          token: issued.token,
          message,
        }),
        ALPHA_ORIGIN,
        403,
        'SCG_DIAGNOSTIC_METHOD_FORBIDDEN',
      );
    }

    const initialized = await postMcp(server, {
      origin: ALPHA_ORIGIN,
      token: issued.token,
      message: initializeMessage(4),
    });
    expect(initialized.status).toBe(200);
    expectNoStore(initialized);
    const sessionId = initialized.headers.get('mcp-session-id');
    if (sessionId === null) {
      throw new Error('diagnostic initialize response omitted mcp-session-id');
    }
    expect(sessionId).toMatch(/^diagnostic-session-[A-Za-z0-9_-]{22}$/);
    expect(initialized.headers.get('access-control-expose-headers')).toBe('mcp-session-id');
    expect(await initialized.json()).toEqual({
      jsonrpc: '2.0',
      id: 4,
      result: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        serverInfo: { name: 'scene-glass', version: '0.1.0' },
      },
    });
    await expectProblem(
      await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: issued.token,
        message: initializeMessage(5),
      }),
      ALPHA_ORIGIN,
      401,
      'SCG_DIAGNOSTIC_REUSED',
    );

    await expectProblem(
      await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: issued.token,
        sessionId,
        message: initializeMessage(5),
      }),
      ALPHA_ORIGIN,
      403,
      'SCG_DIAGNOSTIC_METHOD_FORBIDDEN',
    );

    const initializedNotification = await postMcp(server, {
      origin: ALPHA_ORIGIN,
      token: issued.token,
      sessionId,
      message: {
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {},
      },
    });
    expect(initializedNotification.status).toBe(202);
    expectNoStore(initializedNotification);
    expect(await initializedNotification.text()).toBe('');

    const ping = await postMcp(server, {
      origin: ALPHA_ORIGIN,
      token: issued.token,
      sessionId,
      message: { jsonrpc: '2.0', id: 6, method: 'ping', params: {} },
    });
    expect(ping.status).toBe(200);
    expectNoStore(ping);
    expect(await ping.json()).toEqual({
      jsonrpc: '2.0',
      id: 6,
      result: {},
    });

    const closed = await deleteMcpSession(server, {
      origin: ALPHA_ORIGIN,
      token: issued.token,
      sessionId,
    });
    expect(closed.status).toBe(204);
    expectNoStore(closed);
    expect(await closed.text()).toBe('');

    await expectProblem(
      await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: issued.token,
        sessionId,
        message: { jsonrpc: '2.0', id: 7, method: 'ping', params: {} },
      }),
      ALPHA_ORIGIN,
      401,
      'SCG_DIAGNOSTIC_INVALID',
    );

    expect(await scgTreeSnapshot(server.alphaRoot)).toEqual(before);
  });
  it('treats diagnostic session entropy faults as internal failures without consuming credentials', async () => {
    const random = vi.spyOn(globalThis.crypto, 'getRandomValues');
    try {
      const throwingServer = await startServer();
      const throwingIssued = await issueAndRead(throwingServer);
      random.mockImplementationOnce(() => {
        throw new Error('diagnostic session entropy unavailable');
      });
      await expectProblem(
        await postMcp(throwingServer, {
          origin: ALPHA_ORIGIN,
          token: throwingIssued.token,
          message: initializeMessage(1),
        }),
        ALPHA_ORIGIN,
        500,
        'SCG_DIAGNOSTIC_STORE_FAILED',
      );
      await initializeAndClose(throwingServer, throwingIssued);

      const wrongLengthServer = await startServer();
      const wrongLengthIssued = await issueAndRead(wrongLengthServer);
      random.mockImplementationOnce(
        (() => new Uint8Array(15)) as typeof globalThis.crypto.getRandomValues,
      );
      await expectProblem(
        await postMcp(wrongLengthServer, {
          origin: ALPHA_ORIGIN,
          token: wrongLengthIssued.token,
          message: initializeMessage(1),
        }),
        ALPHA_ORIGIN,
        500,
        'SCG_DIAGNOSTIC_STORE_FAILED',
      );
      await initializeAndClose(wrongLengthServer, wrongLengthIssued);

      const duplicateServer = await startServer({
        alphaActiveRuns: 2,
        globalActiveRuns: 2,
      });
      random.mockClear();
      random.mockImplementation((value) => {
        (value as Uint8Array).fill(0);
        return value;
      });
      const first = await issueAndRead(duplicateServer);
      const firstInitialized = await postMcp(duplicateServer, {
        origin: ALPHA_ORIGIN,
        token: first.token,
        message: initializeMessage(1),
      });
      expect(firstInitialized.status).toBe(200);
      const firstSessionId = firstInitialized.headers.get('mcp-session-id');
      if (firstSessionId === null) {
        throw new Error('first duplicate-session fixture omitted mcp-session-id');
      }

      const duplicate = await issueAndRead(duplicateServer);
      await expectProblem(
        await postMcp(duplicateServer, {
          origin: ALPHA_ORIGIN,
          token: duplicate.token,
          message: initializeMessage(2),
        }),
        ALPHA_ORIGIN,
        500,
        'SCG_DIAGNOSTIC_STORE_FAILED',
      );
      expect(random).toHaveBeenCalledTimes(9);

      const firstPing = await postMcp(duplicateServer, {
        origin: ALPHA_ORIGIN,
        token: first.token,
        sessionId: firstSessionId,
        message: { jsonrpc: '2.0', id: 3, method: 'ping', params: {} },
      });
      expect(firstPing.status).toBe(200);

      random.mockRestore();
      await initializeAndClose(duplicateServer, duplicate);
      const closed = await deleteMcpSession(duplicateServer, {
        origin: ALPHA_ORIGIN,
        token: first.token,
        sessionId: firstSessionId,
      });
      expect(closed.status).toBe(204);
    } finally {
      random.mockRestore();
    }
  });

  it('releases expired runs on the injected 60-second boundary before admitting the next run', async () => {
    let now = 1_700_000_000_000;
    const server = await startServer({
      now: () => now,
      alphaActiveRuns: 1,
      globalActiveRuns: 1,
    });
    const issued = await issueAndRead(server);

    now += 60_000;
    await expectProblem(
      await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: issued.token,
        message: initializeMessage(1),
      }),
      ALPHA_ORIGIN,
      401,
      'SCG_DIAGNOSTIC_EXPIRED',
    );

    const replacement = await expectIssuedRun(
      await issueDiagnostic(server, { origin: ALPHA_ORIGIN, token: NORMAL_TOKEN }),
      server,
      ALPHA_ORIGIN,
    );
    expect(replacement.expiresAt).toBe(new Date(now + 60_000).toISOString());
  });

  it('enforces project and global active-run caps, then the rolling per-project issuance rate', async () => {
    expect.hasAssertions();
    const projectCap = await startServer({
      alphaActiveRuns: 1,
      globalActiveRuns: 2,
      alphaRate: 5,
    });
    await issueAndRead(projectCap);
    await expectProblem(
      await issueDiagnostic(projectCap, { origin: ALPHA_ORIGIN, token: NORMAL_TOKEN }),
      ALPHA_ORIGIN,
      429,
      'SCG_DIAGNOSTIC_LIMIT_PROJECT',
    );

    const globalCap = await startServer({
      alphaActiveRuns: 2,
      betaActiveRuns: 2,
      globalActiveRuns: 1,
      alphaRate: 5,
      betaRate: 5,
    });
    await issueAndRead(globalCap);
    await expectProblem(
      await issueDiagnostic(globalCap, {
        origin: BETA_ORIGIN,
        projectId: BETA_PROJECT,
        token: BETA_TOKEN,
      }),
      BETA_ORIGIN,
      429,
      'SCG_DIAGNOSTIC_LIMIT_GLOBAL',
    );

    const rateCap = await startServer({
      alphaActiveRuns: 2,
      globalActiveRuns: 2,
      alphaRate: 2,
    });
    await initializeAndClose(rateCap, await issueAndRead(rateCap));
    await initializeAndClose(rateCap, await issueAndRead(rateCap));
    await expectProblem(
      await issueDiagnostic(rateCap, { origin: ALPHA_ORIGIN, token: NORMAL_TOKEN }),
      ALPHA_ORIGIN,
      429,
      'SCG_DIAGNOSTIC_RATE_LIMIT',
    );
  });
  it('shares request admission with diagnostics and releases rejected capacity', async () => {
    const projectLimited = await startServer({
      alphaActiveRuns: 2,
      alphaConcurrentRequests: 1,
      globalActiveRuns: 2,
      globalConcurrentRequests: 2,
    });
    const projectRun = await issueAndRead(projectLimited);
    const projectPendingRequests: Promise<unknown>[] = [];
    const projectInitializeEntered = deferred<void>();
    const projectInitializeRelease = deferred<void>();
    const originalInitialize = SessionManager.prototype.initialize;
    const projectInitialize = vi
      .spyOn(SessionManager.prototype, 'initialize')
      .mockImplementationOnce(async function (
        this: SessionManager,
        input: Parameters<typeof originalInitialize>[0],
      ) {
        projectInitializeEntered.resolve();
        await projectInitializeRelease.promise;
        return originalInitialize.call(this, input);
      } as unknown as typeof originalInitialize);
    try {
      const heldNormalRequest = injectDiagnosticPost(projectLimited, {
        message: initializeMessage(100),
        origin: ALPHA_ORIGIN,
        token: NORMAL_TOKEN,
      });
      projectPendingRequests.push(heldNormalRequest);
      await awaitHeldRequestEntry(
        projectInitializeEntered.promise,
        heldNormalRequest,
        'project diagnostic admission holder',
      );

      const projectRejected = await injectDiagnosticPost(projectLimited, {
        accept: 'text/plain',
        message: initializeMessage(1),
        origin: ALPHA_ORIGIN,
        token: projectRun.token,
      });
      expect(projectRejected.statusCode).toBe(429);
      expect(projectRejected.headers['access-control-allow-origin']).toBe(ALPHA_ORIGIN);
      expect(projectRejected.headers['cache-control']).toBe('no-store');
      expect(projectRejected.json()).toEqual({
        code: 'SCG_REQUEST_LIMIT_PROJECT',
        status: 429,
        title: 'Too Many Requests',
        type: 'urn:scene-glass:problem:scg_request_limit_project',
      });

      projectInitializeRelease.resolve();
      expect((await heldNormalRequest).statusCode).toBe(200);
      const projectReallocated = await injectDiagnosticPost(projectLimited, {
        message: initializeMessage(2),
        origin: ALPHA_ORIGIN,
        token: projectRun.token,
      });
      expect(projectReallocated.statusCode).toBe(200);
    } finally {
      projectInitializeRelease.resolve();
      await settlePendingRequests(projectPendingRequests);
      projectInitialize.mockRestore();
    }

    const globallyLimited = await startServer({
      alphaActiveRuns: 2,
      alphaConcurrentRequests: 2,
      betaActiveRuns: 2,
      betaConcurrentRequests: 2,
      globalActiveRuns: 4,
      globalConcurrentRequests: 1,
    });
    const globalRun = await expectIssuedRun(
      await issueDiagnostic(globallyLimited, {
        origin: BETA_ORIGIN,
        projectId: BETA_PROJECT,
        token: BETA_TOKEN,
      }),
      globallyLimited,
      BETA_ORIGIN,
      BETA_PROJECT,
    );
    const globalPendingRequests: Promise<unknown>[] = [];
    const globalInitializeEntered = deferred<void>();
    const globalInitializeRelease = deferred<void>();
    const globalInitialize = vi
      .spyOn(SessionManager.prototype, 'initialize')
      .mockImplementationOnce(async function (
        this: SessionManager,
        input: Parameters<typeof originalInitialize>[0],
      ) {
        globalInitializeEntered.resolve();
        await globalInitializeRelease.promise;
        return originalInitialize.call(this, input);
      } as unknown as typeof originalInitialize);
    try {
      const heldNormalRequest = injectDiagnosticPost(globallyLimited, {
        message: initializeMessage(200),
        origin: ALPHA_ORIGIN,
        token: NORMAL_TOKEN,
      });
      globalPendingRequests.push(heldNormalRequest);
      await awaitHeldRequestEntry(
        globalInitializeEntered.promise,
        heldNormalRequest,
        'global diagnostic admission holder',
      );

      const globalRejected = await injectDiagnosticPost(globallyLimited, {
        accept: 'text/plain',
        message: initializeMessage(1),
        origin: BETA_ORIGIN,
        projectId: BETA_PROJECT,
        token: globalRun.token,
      });
      expect(globalRejected.statusCode).toBe(429);
      expect(globalRejected.headers['access-control-allow-origin']).toBe(BETA_ORIGIN);
      expect(globalRejected.headers['cache-control']).toBe('no-store');
      expect(globalRejected.json()).toEqual({
        code: 'SCG_REQUEST_LIMIT_GLOBAL',
        status: 429,
        title: 'Too Many Requests',
        type: 'urn:scene-glass:problem:scg_request_limit_global',
      });

      globalInitializeRelease.resolve();
      expect((await heldNormalRequest).statusCode).toBe(200);
      const globalReallocated = await injectDiagnosticPost(globallyLimited, {
        message: initializeMessage(2),
        origin: BETA_ORIGIN,
        projectId: BETA_PROJECT,
        token: globalRun.token,
      });
      expect(globalReallocated.statusCode).toBe(200);
    } finally {
      globalInitializeRelease.resolve();
      await settlePendingRequests(globalPendingRequests);
      globalInitialize.mockRestore();
    }
  });
  it('acquires diagnostic POST admission before negotiation and body parsing, then applies it to GET', async () => {
    const server = await startServer({
      alphaActiveRuns: 2,
      alphaConcurrentRequests: 1,
      globalActiveRuns: 2,
      globalConcurrentRequests: 2,
    });
    const run = await issueAndRead(server);
    const pendingRequests: Promise<unknown>[] = [];

    const negotiationFailure = await injectDiagnosticPost(server, {
      accept: 'text/plain',
      message: initializeMessage(1),
      origin: ALPHA_ORIGIN,
      token: run.token,
    });
    expect(negotiationFailure.statusCode).toBe(406);
    expect(negotiationFailure.json()).toMatchObject({ code: 'SCG_MCP_ACCEPT_INVALID' });

    const mediaFailure = await injectDiagnosticPost(server, {
      contentType: 'text/plain',
      message: initializeMessage(1),
      origin: ALPHA_ORIGIN,
      token: run.token,
    });
    expect(mediaFailure.statusCode).toBe(415);
    expect(mediaFailure.json()).toMatchObject({ code: 'SCG_MEDIA_TYPE_INVALID' });

    const parserFailure = await injectDiagnosticPost(server, {
      message: '{"jsonrpc":',
      origin: ALPHA_ORIGIN,
      token: run.token,
    });
    expect(parserFailure.statusCode).toBe(400);
    expect(parserFailure.json()).toMatchObject({ code: 'SCG_JSON_INVALID' });

    const protocolFailure = await injectDiagnosticPost(server, {
      message: { jsonrpc: '2.0' },
      origin: ALPHA_ORIGIN,
      token: run.token,
    });
    expect(protocolFailure.statusCode).toBe(200);
    expect(protocolFailure.json()).toMatchObject({
      error: { code: -32600 },
      id: null,
      jsonrpc: '2.0',
    });

    const reallocated = await injectDiagnosticPost(server, {
      message: initializeMessage(299),
      origin: ALPHA_ORIGIN,
      token: NORMAL_TOKEN,
    });
    expect(reallocated.statusCode).toBe(200);

    const initializeEntered = deferred<void>();
    const initializeRelease = deferred<void>();
    const originalInitialize = SessionManager.prototype.initialize;
    const initialize = vi
      .spyOn(SessionManager.prototype, 'initialize')
      .mockImplementationOnce(async function (
        this: SessionManager,
        input: Parameters<typeof originalInitialize>[0],
      ) {
        initializeEntered.resolve();
        await initializeRelease.promise;
        return originalInitialize.call(this, input);
      } as unknown as typeof originalInitialize);
    try {
      const heldNormalRequest = injectDiagnosticPost(server, {
        message: initializeMessage(300),
        origin: ALPHA_ORIGIN,
        token: NORMAL_TOKEN,
      });
      pendingRequests.push(heldNormalRequest);
      await awaitHeldRequestEntry(
        initializeEntered.promise,
        heldNormalRequest,
        'diagnostic post admission holder',
      );

      const negotiationRejected = await injectDiagnosticPost(server, {
        accept: 'text/plain',
        message: initializeMessage(1),
        origin: ALPHA_ORIGIN,
        token: run.token,
      });
      expect(negotiationRejected.statusCode).toBe(429);
      expect(negotiationRejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      const mediaRejected = await injectDiagnosticPost(server, {
        contentType: 'text/plain',
        message: initializeMessage(1),
        origin: ALPHA_ORIGIN,
        token: run.token,
      });
      expect(mediaRejected.statusCode).toBe(429);
      expect(mediaRejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      const parserRejected = await injectDiagnosticPost(server, {
        message: '{"jsonrpc":',
        origin: ALPHA_ORIGIN,
        token: run.token,
      });
      expect(parserRejected.statusCode).toBe(429);
      expect(parserRejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      const malformedGetRejected = await server.app.inject({
        method: 'GET',
        url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
        headers: {
          accept: 'text/plain',
          authorization: `Bearer ${run.token}`,
          'mcp-protocol-version': MCP_PROTOCOL_VERSION,
          origin: ALPHA_ORIGIN,
        },
      });
      expect(malformedGetRejected.statusCode).toBe(429);
      expect(malformedGetRejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      const rejected = await server.app.inject({
        method: 'GET',
        url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
        headers: {
          authorization: `Bearer ${run.token}`,
          'mcp-protocol-version': MCP_PROTOCOL_VERSION,
          origin: ALPHA_ORIGIN,
        },
      });
      expect(rejected.statusCode).toBe(429);
      expect(rejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      initializeRelease.resolve();
      expect((await heldNormalRequest).statusCode).toBe(200);
    } finally {
      initializeRelease.resolve();
      await settlePendingRequests(pendingRequests);
      initialize.mockRestore();
    }

    const unsupported = await server.app.inject({
      method: 'GET',
      url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
      headers: {
        authorization: `Bearer ${run.token}`,
        'mcp-protocol-version': MCP_PROTOCOL_VERSION,
        origin: ALPHA_ORIGIN,
      },
    });
    expect(unsupported.statusCode).toBe(405);
    expect(unsupported.json()).toMatchObject({ code: 'SCG_MCP_GET_UNSUPPORTED' });

    const accepted = await injectDiagnosticPost(server, {
      message: initializeMessage(1),
      origin: ALPHA_ORIGIN,
      token: run.token,
    });
    expect(accepted.statusCode).toBe(200);
  });

  it('applies post-auth admission to diagnostic DELETE and releases it after close', async () => {
    const server = await startServer({
      alphaActiveRuns: 2,
      alphaConcurrentRequests: 1,
      globalActiveRuns: 2,
      globalConcurrentRequests: 2,
    });
    const closeRun = await issueAndRead(server);
    const pendingRequests: Promise<unknown>[] = [];
    const initialized = await injectDiagnosticPost(server, {
      message: initializeMessage(1),
      origin: ALPHA_ORIGIN,
      token: closeRun.token,
    });
    expect(initialized.statusCode).toBe(200);
    const sessionId = initialized.headers['mcp-session-id'];
    if (sessionId === undefined) {
      throw new Error('diagnostic close fixture omitted mcp-session-id');
    }

    const initializeEntered = deferred<void>();
    const initializeRelease = deferred<void>();
    const originalInitialize = SessionManager.prototype.initialize;
    const initialize = vi
      .spyOn(SessionManager.prototype, 'initialize')
      .mockImplementationOnce(async function (
        this: SessionManager,
        input: Parameters<typeof originalInitialize>[0],
      ) {
        initializeEntered.resolve();
        await initializeRelease.promise;
        return originalInitialize.call(this, input);
      } as unknown as typeof originalInitialize);
    try {
      const heldNormalRequest = injectDiagnosticPost(server, {
        message: initializeMessage(301),
        origin: ALPHA_ORIGIN,
        token: NORMAL_TOKEN,
      });
      pendingRequests.push(heldNormalRequest);
      await awaitHeldRequestEntry(
        initializeEntered.promise,
        heldNormalRequest,
        'diagnostic delete admission holder',
      );

      const malformedDeleteRejected = await server.app.inject({
        method: 'DELETE',
        url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
        headers: {
          accept: 'text/plain',
          authorization: `Bearer ${closeRun.token}`,
          'mcp-protocol-version': MCP_PROTOCOL_VERSION,
          'mcp-session-id': sessionId,
          origin: ALPHA_ORIGIN,
        },
      });
      expect(malformedDeleteRejected.statusCode).toBe(429);
      expect(malformedDeleteRejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      const rejected = await server.app.inject({
        method: 'DELETE',
        url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
        headers: {
          authorization: `Bearer ${closeRun.token}`,
          'mcp-protocol-version': MCP_PROTOCOL_VERSION,
          'mcp-session-id': sessionId,
          origin: ALPHA_ORIGIN,
        },
      });
      expect(rejected.statusCode).toBe(429);
      expect(rejected.json()).toMatchObject({ code: 'SCG_REQUEST_LIMIT_PROJECT' });

      initializeRelease.resolve();
      expect((await heldNormalRequest).statusCode).toBe(200);
    } finally {
      initializeRelease.resolve();
      await settlePendingRequests(pendingRequests);
      initialize.mockRestore();
    }

    const closed = await server.app.inject({
      method: 'DELETE',
      url: `/mcp/v1/projects/${ALPHA_PROJECT}`,
      headers: {
        authorization: `Bearer ${closeRun.token}`,
        'mcp-protocol-version': MCP_PROTOCOL_VERSION,
        'mcp-session-id': sessionId,
        origin: ALPHA_ORIGIN,
      },
    });
    expect(closed.statusCode).toBe(204);

    const nextRun = await issueAndRead(server);
    const nextInitialized = await injectDiagnosticPost(server, {
      message: initializeMessage(2),
      origin: ALPHA_ORIGIN,
      token: nextRun.token,
    });
    expect(nextInitialized.statusCode).toBe(200);
  });
});

describe('diagnostic lifecycle cleanup', () => {
  it('drains real issuer and run-store state with one redacted terminal event per teardown', () => {
    let now = 1_700_000_000_000;
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
    const lifecycle = createDiagnosticsLifecycle({ logger, now: () => now });
    const auth = verifiedNormalAuth(NORMAL_TOKEN, ALPHA_ORIGIN);
    const limits = {
      diagnosticActiveRunsPerProject: 2,
      diagnosticActiveRunsGlobal: 2,
      diagnosticRunsPerProjectPerMinute: 5,
    };

    const revoked = issueFromLifecycle(lifecycle, auth, limits);
    const revokedSession = consumeFromLifecycle(lifecycle, revoked);
    expect(
      lifecycle.runStore.consumeInitialize({
        token: revoked.token,
        projectId: ALPHA_PROJECT,
        origin: ALPHA_ORIGIN,
        audience: 'diagnostics',
        method: 'initialize',
      }),
    ).toMatchObject({ ok: false, status: 401, code: 'SCG_DIAGNOSTIC_REUSED' });
    expect(lifecycle.runStore.activeSessionCount).toBe(1);
    expect(lifecycle.issuer.revoke(revoked.runId)).toBe(true);
    expect(lifecycle.issuer.isEmpty()).toBe(true);
    expect(lifecycle.runStore.isEmpty()).toBe(true);
    expect(
      lifecycle.runStore.authorizeMethod({
        token: revoked.token,
        projectId: ALPHA_PROJECT,
        origin: ALPHA_ORIGIN,
        audience: 'diagnostics',
        sessionId: revokedSession.id,
        method: 'ping',
      }),
    ).toMatchObject({ ok: false, status: 401, code: 'SCG_DIAGNOSTIC_INVALID' });

    const closable = issueFromLifecycle(lifecycle, auth, limits);
    const closableSession = consumeFromLifecycle(lifecycle, closable);
    expect(
      lifecycle.runStore.close({
        token: closable.token,
        projectId: ALPHA_PROJECT,
        origin: ALPHA_ORIGIN,
        audience: 'diagnostics',
        sessionId: closableSession.id,
      }),
    ).toMatchObject({ ok: true });
    expect(lifecycle.teardown.close(closable.runId)).toBe(false);
    expect(lifecycle.issuer.isEmpty()).toBe(true);
    expect(lifecycle.runStore.isEmpty()).toBe(true);

    const expired = issueFromLifecycle(lifecycle, auth, limits);
    now += 60_000;
    expect(
      lifecycle.runStore.consumeInitialize({
        token: expired.token,
        projectId: ALPHA_PROJECT,
        origin: ALPHA_ORIGIN,
        audience: 'diagnostics',
        method: 'initialize',
      }),
    ).toMatchObject({ ok: false, status: 401, code: 'SCG_DIAGNOSTIC_EXPIRED' });
    expect(lifecycle.issuer.isEmpty()).toBe(true);
    expect(lifecycle.runStore.isEmpty()).toBe(true);
    const aborted = issueFromLifecycle(lifecycle, auth, limits);
    const abortedSession = consumeFromLifecycle(lifecycle, aborted);
    expect(lifecycle.runStore.abort(abortedSession.id)).toBe(true);
    expect(lifecycle.runStore.abort(abortedSession.id)).toBe(false);
    expect(lifecycle.issuer.isEmpty()).toBe(true);
    expect(lifecycle.runStore.isEmpty()).toBe(true);

    const shutdown = issueFromLifecycle(lifecycle, auth, limits);
    expect(lifecycle.shutdown()).toBe(1);
    expect(lifecycle.issuer.isEmpty()).toBe(true);
    expect(lifecycle.runStore.isEmpty()).toBe(true);
    expect(
      lifecycle.issuer.authenticate({
        token: shutdown.token,
        projectId: ALPHA_PROJECT,
        origin: ALPHA_ORIGIN,
        audience: 'diagnostics',
      }),
    ).toMatchObject({ ok: false, status: 503, code: 'SCG_DIAGNOSTIC_SHUTDOWN' });
    const terminalRunIds = [
      revoked.runId,
      closable.runId,
      expired.runId,
      aborted.runId,
      shutdown.runId,
    ];
    const terminalEvents = records.filter((record) => record.event.startsWith('terminal.'));
    expect(terminalEvents.map((record) => record.event)).toEqual([
      'terminal.cancelled',
      'terminal.success',
      'terminal.cancelled',
      'terminal.cancelled',
      'terminal.cancelled',
    ]);
    expect(terminalEvents).toHaveLength(terminalRunIds.length);
    for (const runId of terminalRunIds) {
      logger.assertOneTerminalEvent({ runId });
    }
    for (const record of terminalEvents) {
      expect(record.scope).toEqual({ runIdHash: expect.any(String) });
      expect(record.data).toBeUndefined();
    }
    const serializedTerminalEvents = JSON.stringify(terminalEvents);
    const forbiddenValues = [
      NORMAL_TOKEN,
      ALPHA_ORIGIN,
      ...terminalRunIds,
      revoked.token,
      closable.token,
      expired.token,
      aborted.token,
      shutdown.token,
      revokedSession.id,
      closableSession.id,
      abortedSession.id,
    ];
    for (const value of forbiddenValues) {
      expect(serializedTerminalEvents).not.toContain(value);
    }
  });
  it('expires initialized runs from the timer without a follow-up request', async () => {
    vi.useFakeTimers();
    try {
      let now = 1_700_000_000_000;
      const records: SceneGlassLogRecord[] = [];
      const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
      const lifecycle = createDiagnosticsLifecycle({ logger, now: () => now });
      const issued = issueFromLifecycle(lifecycle, verifiedNormalAuth(NORMAL_TOKEN, ALPHA_ORIGIN), {
        diagnosticActiveRunsPerProject: 1,
        diagnosticActiveRunsGlobal: 1,
        diagnosticRunsPerProjectPerMinute: 1,
      });
      consumeFromLifecycle(lifecycle, issued);
      const cleanupReasons: string[] = [];
      expect(
        lifecycle.teardown.addCleanup(issued.runId, (reason) => cleanupReasons.push(reason)),
      ).toBe(true);

      now += 60_000;
      await vi.advanceTimersByTimeAsync(60_000);

      expect(lifecycle.teardown.isEmpty()).toBe(true);
      expect(lifecycle.runStore.isEmpty()).toBe(true);
      expect(lifecycle.issuer.isEmpty()).toBe(true);
      expect(cleanupReasons).toEqual(['expired']);
      const terminalEvents = records.filter((record) => record.event.startsWith('terminal.'));
      expect(terminalEvents).toHaveLength(1);
      expect(terminalEvents[0]).toMatchObject({
        event: 'terminal.cancelled',
        scope: { runIdHash: expect.any(String) },
      });
      logger.assertOneTerminalEvent({ runId: issued.runId });
      expect(lifecycle.shutdown()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
  it('fails closed with redacted evidence when the expiry clock throws or becomes invalid', async () => {
    vi.useFakeTimers();
    try {
      const clockFailureSecret = opaqueToken(10);
      for (const [clockKind, brokenClock] of [
        [
          'throwing',
          (): number => {
            throw new Error(`diagnostic clock failure: ${clockFailureSecret}`);
          },
        ],
        ['invalid', (): number => Number.NaN],
      ] as const) {
        const initialNow = 1_700_000_000_000;
        const runId = `diagnostic-broken-clock-${clockKind}`;
        const records: SceneGlassLogRecord[] = [];
        const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
        let clockReads = 0;
        const teardown = new DiagnosticsTeardown({
          logger,
          now: (): number => {
            clockReads += 1;
            return clockReads === 1 ? initialNow : brokenClock();
          },
        });
        const cleanupReasons: string[] = [];

        expect(
          teardown.register({
            runId,
            projectId: ALPHA_PROJECT,
            expiresAt: initialNow + 1,
            cleanup: (reason) => cleanupReasons.push(reason),
          }),
        ).toBe(true);

        await vi.advanceTimersByTimeAsync(1);

        expect(cleanupReasons).toEqual(['expired']);
        expect(teardown.isEmpty()).toBe(true);
        expect(records.map((record) => record.event)).toEqual([
          'diagnostics.rejected',
          'terminal.failure',
        ]);
        expect(records).toMatchObject([
          {
            event: 'diagnostics.rejected',
            data: { expiryClockFailureCount: 1 },
            scope: { runIdHash: expect.any(String) },
          },
          {
            event: 'terminal.failure',
            scope: { runIdHash: expect.any(String) },
          },
        ]);
        expect(records[1]?.data).toBeUndefined();
        logger.assertOneTerminalEvent({ runId });
        const serializedRecords = JSON.stringify(records);
        expect(serializedRecords).not.toContain(runId);
        expect(serializedRecords).not.toContain(clockFailureSecret);
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('records redacted cleanup failure evidence before the terminal failure', () => {
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({ sink: (record) => records.push(record) });
    const teardown = new DiagnosticsTeardown({ logger, now: () => 1_700_000_000_000 });
    const runId = 'diagnostic-cleanup-failure';
    const sessionId = 'diagnostic-session-AAAAAAAAAAAAAAAAAAAAAA';
    const cleanupOrder: string[] = [];
    const reentrantResults: boolean[] = [];
    expect(
      teardown.register({
        runId,
        projectId: ALPHA_PROJECT,
        expiresAt: 1_700_000_060_000,
        cleanup: (reason) => {
          cleanupOrder.push(`first:${reason}`);
          reentrantResults.push(teardown.close(runId));
          throw new Error(`token: ${opaqueToken(9)} origin: ${ALPHA_ORIGIN} session: ${sessionId}`);
        },
      }),
    ).toBe(true);
    expect(
      teardown.addCleanup(runId, (reason) => {
        cleanupOrder.push(`second:${reason}`);
      }),
    ).toBe(true);

    expect(teardown.close(runId)).toBe(true);
    expect(cleanupOrder).toEqual(['first:client-close', 'second:client-close']);
    expect(reentrantResults).toEqual([false]);
    expect(teardown.isEmpty()).toBe(true);
    expect(records.map((record) => record.event)).toEqual(['cleanup.failed', 'terminal.failure']);
    expect(records[0]).toMatchObject({
      event: 'cleanup.failed',
      data: { cleanupFailureCount: 1 },
      scope: { runIdHash: expect.any(String) },
    });
    expect(records[1]).toMatchObject({
      event: 'terminal.failure',
      scope: { runIdHash: expect.any(String) },
    });
    expect(records[1]?.data).toBeUndefined();
    logger.assertOneTerminalEvent({ runId });
    const serializedRecords = JSON.stringify(records);
    for (const value of [opaqueToken(9), ALPHA_ORIGIN, sessionId, runId]) {
      expect(serializedRecords).not.toContain(value);
    }
  });

  it('counts logger sink failures after completing diagnostic cleanup', () => {
    for (const failingEvent of ['cleanup.failed', 'terminal.failure'] as const) {
      const events: string[] = [];
      const logger = new SceneGlassLogger({
        sink: (record) => {
          events.push(record.event);
          if (record.event === failingEvent) {
            throw new Error(`${failingEvent} sink failure`);
          }
        },
      });
      const teardown = new DiagnosticsTeardown({ logger, now: () => 1_700_000_000_000 });
      const cleanupOrder: string[] = [];
      const runId = `diagnostic-logger-${failingEvent.replace('.', '-')}`;
      expect(
        teardown.register({
          runId,
          projectId: ALPHA_PROJECT,
          expiresAt: 1_700_000_060_000,
          cleanup: (reason) => {
            cleanupOrder.push(`first:${reason}`);
            throw new Error('cleanup failed');
          },
        }),
      ).toBe(true);
      expect(
        teardown.addCleanup(runId, (reason) => {
          cleanupOrder.push(`second:${reason}`);
        }),
      ).toBe(true);

      expect(teardown.close(runId)).toBe(true);
      expect(cleanupOrder).toEqual(['first:client-close', 'second:client-close']);
      expect(events).toEqual(['cleanup.failed', 'terminal.failure']);
      expect(teardown.isEmpty()).toBe(true);
      expect(logger.sinkFailureCount).toBe(1);
      logger.assertOneTerminalEvent({ runId });
    }
  });
});
describe('app lifecycle ownership', () => {
  it('does not retain an initialization request signal in a cached normal-session dispatcher', async () => {
    const server = await startServer();
    const initialized = await postMcp(server, {
      origin: ALPHA_ORIGIN,
      token: NORMAL_TOKEN,
      message: initializeMessage(1),
    });
    expect(initialized.status).toBe(200);
    const sessionId = initialized.headers.get('mcp-session-id');
    if (sessionId === null) {
      throw new Error('normal initialize response omitted mcp-session-id');
    }

    const notification = await postMcp(server, {
      origin: ALPHA_ORIGIN,
      token: NORMAL_TOKEN,
      sessionId,
      message: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    });
    expect(notification.status).toBe(202);

    for (const id of [2, 3]) {
      const ping = await postMcp(server, {
        origin: ALPHA_ORIGIN,
        token: NORMAL_TOKEN,
        sessionId,
        message: { jsonrpc: '2.0', id, method: 'ping', params: {} },
      });
      expect(ping.status).toBe(200);
      expect(await ping.json()).toEqual({ jsonrpc: '2.0', id, result: {} });
    }

    await stopServer(server);
  });

  it('uses the supplied logger as the single application sink', async () => {
    const events: string[] = [];
    const server = await startServer({
      logger: new SceneGlassLogger({ sink: (record) => events.push(record.event) }),
    });

    expect(events).toEqual(['config.accepted']);
    await stopServer(server);
  });

  it('validates DELETE before its idempotent client-close teardown', () => {
    const sessions = new SessionManager({ now: () => 1_700_000_000_000 });
    const initialized = sessions.initialize({
      auth: verifiedNormalAuth(NORMAL_TOKEN, ALPHA_ORIGIN),
      normalSessionsGlobal: 2,
      normalSessionsPerProject: 2,
      sessionIdleMs: 60_000,
      sessionMaxAgeMs: 60_000,
    });
    if (!initialized.ok) {
      throw new Error(`session initialization failed: ${initialized.code}`);
    }
    expect(
      sessions.commit({
        auth: verifiedNormalAuth(NORMAL_TOKEN, ALPHA_ORIGIN),
        sessionId: initialized.session.id,
      }),
    ).toMatchObject({ ok: true, session: initialized.session });

    expect(
      sessions.lookup({
        auth: verifiedNormalAuth(NORMAL_TOKEN, ALPHA_ORIGIN),
        method: 'DELETE',
        sessionId: initialized.session.id,
      }),
    ).toMatchObject({ ok: true, session: initialized.session });
    expect(sessions.activeSessionCount).toBe(1);
    expect(sessions.close(initialized.session.id)).toEqual({
      tornDown: true,
      reason: 'client-close',
    });
    expect(sessions.close(initialized.session.id)).toEqual({
      tornDown: false,
      reason: 'client-close',
    });
    expect(sessions.isEmpty()).toBe(true);
  });

  it('removes queued aborted lock waiters with their exact reason and releases later work once', async () => {
    const lock = new SerialProjectLock();
    const firstSignal = new AbortController();
    const queuedSignal = new AbortController();
    const laterSignal = new AbortController();
    const active = deferred<void>();
    const order: string[] = [];

    const first = lock.runExclusive(firstSignal.signal, async () => {
      order.push('first');
      await active.promise;
      return 'first';
    });
    await Promise.resolve();

    const queued = lock.runExclusive(queuedSignal.signal, async () => {
      order.push('queued');
      return 'queued';
    });
    const later = lock.runExclusive(laterSignal.signal, async () => {
      order.push('later');
      return 'later';
    });
    const abortReason = new Error('queued request aborted');
    queuedSignal.abort(abortReason);

    await expect(queued).rejects.toBe(abortReason);
    active.resolve();
    await expect(first).resolves.toBe('first');
    await expect(later).resolves.toBe('later');
    expect(order).toEqual(['first', 'later']);

    const alreadyAborted = new AbortController();
    const alreadyAbortedReason = new Error('already aborted');
    alreadyAborted.abort(alreadyAbortedReason);
    await expect(
      lock.runExclusive(alreadyAborted.signal, async () => {
        order.push('already-aborted');
        return 'already-aborted';
      }),
    ).rejects.toBe(alreadyAbortedReason);
    expect(order).toEqual(['first', 'later']);
  });

  it('uses one disposable child signal for export lock and storage work', async () => {
    vi.useFakeTimers();
    try {
      const parent = new AbortController();
      const lockSignals: AbortSignal[] = [];
      const listSignals: AbortSignal[] = [];
      const tool = createPromptExportTool({
        project: promptExportProject(),
        exportTimeoutMs: 10,
        projectLock: recordingProjectLock(lockSignals),
        store: exportStore((signal) => {
          listSignals.push(signal);
          return emptyPageFiles();
        }),
      });

      await expect(
        tool.execute({ mode: 'project' }, { signal: parent.signal }),
      ).resolves.toMatchObject({
        mode: 'project',
      });
      expect(lockSignals).toHaveLength(1);
      expect(listSignals).toHaveLength(1);
      const [lockSignal] = lockSignals;
      if (lockSignal === undefined) {
        throw new Error('Expected export lock to receive one child signal');
      }
      expect(lockSignal).toBe(listSignals[0]);
      expect(lockSignal).not.toBe(parent.signal);
      expect(lockSignal.aborted).toBe(false);

      parent.abort(new Error('completed request must not retain resources'));
      await vi.advanceTimersByTimeAsync(10);
      expect(lockSignal.aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('propagates parent aborts and export-only deadlines through the child signal', async () => {
    vi.useFakeTimers();
    try {
      const parent = new AbortController();
      const parentReason = new Error('request cancelled');
      const parentSignals: AbortSignal[] = [];
      const parentTool = createPromptExportTool({
        project: promptExportProject(),
        exportTimeoutMs: 10,
        projectLock: recordingProjectLock(parentSignals),
        store: exportStore(waitForAbort),
      });
      const parentExecution = parentTool.execute({ mode: 'project' }, { signal: parent.signal });
      const parentRejected = parentExecution.then(
        () => Object.freeze({ rejected: false as const }),
        (error: unknown) => Object.freeze({ rejected: true as const, error }),
      );
      await Promise.resolve();
      await Promise.resolve();
      parent.abort(parentReason);
      expect(await parentRejected).toEqual({ rejected: true, error: parentReason });
      expect(parentSignals[0]).not.toBe(parent.signal);

      const deadlineParent = new AbortController();
      const deadlineSignals: AbortSignal[] = [];
      const deadlineTool = createPromptExportTool({
        project: promptExportProject(),
        exportTimeoutMs: 10,
        projectLock: recordingProjectLock(deadlineSignals),
        store: exportStore(waitForAbort),
      });
      const deadlineExecution = deadlineTool.execute(
        { mode: 'project' },
        { signal: deadlineParent.signal },
      );
      const deadlineRejected = deadlineExecution.then(
        () => Object.freeze({ rejected: false as const }),
        (error: unknown) => Object.freeze({ rejected: true as const, error }),
      );
      await Promise.resolve();
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(10);
      expect(await deadlineRejected).toMatchObject({
        rejected: true,
        error: { code: 'SCG_EXPORT_TIMEOUT' },
      });
      expect(deadlineSignals).toHaveLength(1);
      const [deadlineSignal] = deadlineSignals;
      if (deadlineSignal === undefined) {
        throw new Error('Expected export deadline to abort its child signal');
      }
      expect(deadlineSignal.reason).toBeInstanceOf(McpRpcError);
      expect((deadlineSignal.reason as McpRpcError).code).toBe('SCG_EXPORT_TIMEOUT');
      expect(deadlineParent.signal.aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
  it('enforces the export deadline during synchronous markdown rendering', async () => {
    let clockReads = 0;
    const now = vi.spyOn(performance, 'now').mockImplementation(() => {
      clockReads += 1;
      return clockReads >= 6 ? 11 : 0;
    });
    try {
      const parent = new AbortController();
      const childSignals: AbortSignal[] = [];
      const tool = createPromptExportTool({
        project: promptExportProject(),
        exportTimeoutMs: 10,
        projectLock: recordingProjectLock(childSignals),
        store: exportStore(() => emptyPageFiles()),
      });

      await expect(
        tool.execute({ mode: 'project' }, { signal: parent.signal }),
      ).rejects.toMatchObject({
        code: 'SCG_EXPORT_TIMEOUT',
      });
      expect(childSignals).toHaveLength(1);
      expect(childSignals[0]?.aborted).toBe(true);
      expect((childSignals[0]?.reason as McpRpcError).code).toBe('SCG_EXPORT_TIMEOUT');
      expect(parent.signal.aborted).toBe(false);
    } finally {
      now.mockRestore();
    }
  });
  it('enforces the export deadline while enumerating immediately available pages', async () => {
    let clock = 0;
    let consumedPages = 0;
    const now = vi.spyOn(performance, 'now').mockImplementation(() => clock++);
    try {
      const parent = new AbortController();
      const childSignals: AbortSignal[] = [];
      const tool = createPromptExportTool({
        project: promptExportProject(),
        exportTimeoutMs: 5,
        projectLock: recordingProjectLock(childSignals),
        store: exportStore(async function* () {
          for (let index = 1; index <= 3; index += 1) {
            consumedPages += 1;
            yield minimalExportPage(index);
          }
        }),
      });

      await expect(
        tool.execute({ mode: 'project' }, { signal: parent.signal }),
      ).rejects.toMatchObject({
        code: 'SCG_EXPORT_TIMEOUT',
      });
      expect(consumedPages).toBe(2);
      expect(childSignals[0]?.aborted).toBe(true);
      expect(parent.signal.aborted).toBe(false);
    } finally {
      now.mockRestore();
    }
  });
});

interface RunningServer {
  readonly app: Awaited<ReturnType<typeof createSceneGlassAppForTest>>;
  readonly alphaRoot: string;
  readonly betaRoot: string;
  readonly endpoint: string;
  readonly workspace: string;
}

interface StartServerOptions {
  readonly alphaActiveRuns?: number;
  readonly alphaConcurrentRequests?: number;
  readonly alphaRate?: number;
  readonly betaActiveRuns?: number;
  readonly betaConcurrentRequests?: number;
  readonly betaRate?: number;
  readonly globalActiveRuns?: number;
  readonly globalConcurrentRequests?: number;
  readonly logger?: SceneGlassLogger;
  readonly now?: () => number;
}

interface DiagnosticIssueInput {
  readonly origin: string;
  readonly projectId?: string;
  readonly token: string;
}

interface IssuedRun {
  readonly endpoint: string;
  readonly expiresAt: string;
  readonly runId: string;
  readonly token: string;
}

async function startServer(options: StartServerOptions = {}): Promise<RunningServer> {
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-diagnostics-')));
  try {
    const alphaRoot = join(workspace, 'alpha');
    const betaRoot = join(workspace, 'beta');
    await Promise.all([mkdir(alphaRoot), mkdir(betaRoot)]);
    const [canonicalAlphaRoot, canonicalBetaRoot] = await Promise.all([
      realpath(alphaRoot),
      realpath(betaRoot),
    ]);
    const configPath = join(workspace, 'scene-glass.json');
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        globalLimits: {
          diagnosticActiveRunsGlobal: options.globalActiveRuns ?? 16,
          ...(options.globalConcurrentRequests === undefined
            ? {}
            : { concurrentRequestsGlobal: options.globalConcurrentRequests }),
        },
        projects: [
          {
            projectId: ALPHA_PROJECT,
            root: canonicalAlphaRoot,
            allowedOrigins: [ALPHA_ORIGIN],
            tokenEnv: 'SCG_ALPHA_TOKEN',
            limits: {
              diagnosticActiveRunsPerProject: options.alphaActiveRuns ?? 4,
              diagnosticRunsPerProjectPerMinute: options.alphaRate ?? 5,
              ...(options.alphaConcurrentRequests === undefined
                ? {}
                : { concurrentRequestsPerProject: options.alphaConcurrentRequests }),
            },
          },
          {
            projectId: BETA_PROJECT,
            root: canonicalBetaRoot,
            allowedOrigins: [BETA_ORIGIN],
            tokenEnv: 'SCG_BETA_TOKEN',
            limits: {
              diagnosticActiveRunsPerProject: options.betaActiveRuns ?? 4,
              diagnosticRunsPerProjectPerMinute: options.betaRate ?? 5,
              ...(options.betaConcurrentRequests === undefined
                ? {}
                : { concurrentRequestsPerProject: options.betaConcurrentRequests }),
            },
          },
        ],
      }),
    );
    const app = await createSceneGlassAppForTest({
      configPath,
      environment: {
        SCG_ALPHA_TOKEN: NORMAL_TOKEN,
        SCG_BETA_TOKEN: BETA_TOKEN,
      },
      ...(options.logger === undefined ? {} : { logger: options.logger }),
      ...(options.now === undefined ? {} : { now: options.now }),
      projectRootProbe: async (root) => ({
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
        facts: {
          realPath: root,
          device: 1,
          inode: 1,
          fileSystemType: 1,
          identityStableAtProbe: true,
        },
      }),
    });
    const endpoint = new URL(await app.listen({ host: '127.0.0.1', port: 0 })).origin;
    const server = {
      app,
      alphaRoot: canonicalAlphaRoot,
      betaRoot: canonicalBetaRoot,
      endpoint,
      workspace,
    };
    temporaryServers.add(server);
    return server;
  } catch (error: unknown) {
    await rm(workspace, { force: true, recursive: true });
    throw error;
  }
}

async function stopServer(server: RunningServer): Promise<void> {
  if (!temporaryServers.delete(server)) {
    return;
  }
  await server.app.close();
  await rm(server.workspace, { force: true, recursive: true });
}

async function issueDiagnostic(
  server: RunningServer,
  input: DiagnosticIssueInput,
): Promise<Response> {
  return fetch(
    `${server.endpoint}/mcp/v1/projects/${input.projectId ?? ALPHA_PROJECT}/diagnostic-runs`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${input.token}`,
        'content-type': 'application/json',
        origin: input.origin,
      },
      body: JSON.stringify({ schemaVersion: 1 }),
    },
  );
}

async function issueAndRead(server: RunningServer): Promise<IssuedRun> {
  return expectIssuedRun(
    await issueDiagnostic(server, { origin: ALPHA_ORIGIN, token: NORMAL_TOKEN }),
    server,
    ALPHA_ORIGIN,
  );
}

async function expectIssuedRun(
  response: Response,
  server: RunningServer,
  origin: string,
  projectId = ALPHA_PROJECT,
): Promise<IssuedRun> {
  expect(response.status).toBe(201);
  expect(response.headers.get('content-type')).toContain('application/json');
  expectNoStore(response);
  expect(response.headers.get('access-control-allow-origin')).toBe(origin);
  expect(response.headers.get('vary')).toBe('Origin');

  const body = await response.json();
  expect(body).toMatchObject({
    endpoint: `${server.endpoint}/mcp/v1/projects/${projectId}`,
  });
  expect(Object.keys(body as Record<string, unknown>).sort()).toEqual([
    'endpoint',
    'expiresAt',
    'runId',
    'token',
  ]);
  const candidate = body as Partial<IssuedRun>;
  if (
    typeof candidate.endpoint !== 'string' ||
    typeof candidate.expiresAt !== 'string' ||
    typeof candidate.runId !== 'string' ||
    typeof candidate.token !== 'string'
  ) {
    throw new TypeError('diagnostic issue response has an invalid wire shape');
  }
  return {
    endpoint: candidate.endpoint,
    expiresAt: candidate.expiresAt,
    runId: candidate.runId,
    token: candidate.token,
  };
}

async function postMcp(
  server: RunningServer,
  input: {
    readonly message: unknown;
    readonly origin: string;
    readonly projectId?: string;
    readonly sessionId?: string;
    readonly token: string;
  },
): Promise<Response> {
  return fetch(`${server.endpoint}/mcp/v1/projects/${input.projectId ?? ALPHA_PROJECT}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${input.token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      origin: input.origin,
      ...(input.sessionId === undefined ? {} : { 'mcp-session-id': input.sessionId }),
    },
    body: JSON.stringify(input.message),
  });
}
function injectDiagnosticPost(
  server: RunningServer,
  input: {
    readonly accept?: string;
    readonly contentType?: string;
    readonly message: InjectPayload;
    readonly origin: string;
    readonly projectId?: string;
    readonly token: string;
  },
): Promise<LightMyRequestResponse> {
  return server.app.inject({
    method: 'POST',
    url: `/mcp/v1/projects/${input.projectId ?? ALPHA_PROJECT}`,
    headers: {
      authorization: `Bearer ${input.token}`,
      'content-type': input.contentType ?? 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      origin: input.origin,
      ...(input.accept === undefined ? {} : { accept: input.accept }),
    },
    payload: input.message,
  });
}

async function deleteMcpSession(
  server: RunningServer,
  input: {
    readonly origin: string;
    readonly sessionId: string;
    readonly token: string;
  },
): Promise<Response> {
  return fetch(`${server.endpoint}/mcp/v1/projects/${ALPHA_PROJECT}`, {
    method: 'DELETE',
    headers: {
      authorization: `Bearer ${input.token}`,
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      origin: input.origin,
      'mcp-session-id': input.sessionId,
    },
  });
}

async function initializeAndClose(server: RunningServer, issued: IssuedRun): Promise<void> {
  const initialized = await postMcp(server, {
    origin: ALPHA_ORIGIN,
    token: issued.token,
    message: initializeMessage(1),
  });
  expect(initialized.status).toBe(200);
  const sessionId = initialized.headers.get('mcp-session-id');
  if (sessionId === null) {
    throw new Error('diagnostic initialize response omitted mcp-session-id');
  }
  expect(sessionId).toMatch(/^diagnostic-session-[A-Za-z0-9_-]{22}$/);

  const closed = await deleteMcpSession(server, {
    origin: ALPHA_ORIGIN,
    token: issued.token,
    sessionId,
  });
  expect(closed.status).toBe(204);
}

function initializeMessage(id: number): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'diagnostics-integration', version: '1.0.0' },
    },
  };
}

async function expectProblem(
  response: Response,
  origin: string,
  status: 401 | 403 | 429 | 500,
  code: string,
): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.get('content-type')).toContain('application/problem+json');
  expectNoStore(response);
  expect(response.headers.get('access-control-allow-origin')).toBe(origin);
  expect(response.headers.get('www-authenticate')).toBe(status === 401 ? 'Bearer' : null);
  expect(await response.json()).toEqual({
    type: `urn:scene-glass:problem:${code.toLowerCase()}`,
    title:
      status === 401
        ? 'Unauthorized'
        : status === 403
          ? 'Forbidden'
          : status === 429
            ? 'Too Many Requests'
            : 'Internal Server Error',
    status,
    code,
  });
}

function expectNoStore(response: Response): void {
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('etag')).toBeNull();
  expect(response.headers.get('last-modified')).toBeNull();
}

async function prepopulateScgTree(root: string): Promise<void> {
  const annotations = join(root, '.scg', 'annotations');
  await mkdir(annotations, { recursive: true });
  await Promise.all([
    writeFile(join(root, '.scg', 'project.json'), '{"schemaVersion":1}\n'),
    writeFile(join(annotations, 'seed.json'), '{"seed":"diagnostics"}\n'),
  ]);
}

async function scgTreeSnapshot(root: string): Promise<readonly string[]> {
  const scgRoot = join(root, '.scg');
  const entries: string[] = [];

  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolutePath = join(directory, entry.name);
      const name = relative(scgRoot, absolutePath);
      if (entry.isDirectory()) {
        entries.push(`directory:${name}`);
        await visit(absolutePath);
      } else if (entry.isFile()) {
        const digest = createHash('sha256')
          .update(await readFile(absolutePath))
          .digest('hex');
        entries.push(`file:${name}:${digest}`);
      } else {
        entries.push(`other:${name}`);
      }
    }
  }

  await visit(scgRoot);
  return Object.freeze(entries.sort());
}

function promptExportProject(): AuthorizedProject {
  return Object.freeze({
    projectId: ALPHA_PROJECT,
    effectiveLimits: BUILT_IN_LIMITS,
  });
}

function recordingProjectLock(signals: AbortSignal[]): ProjectLock {
  return {
    runExclusive: async <T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> => {
      signals.push(signal);
      return operation();
    },
  };
}

function exportStore(
  listPages: (signal: AbortSignal) => AsyncIterable<PageFileV1>,
): AnnotationStore {
  return {
    readPage: async () => {
      throw new Error('prompt export must not read pages');
    },
    listPages: (_project, signal) => listPages(signal),
    commitPage: async () => {
      throw new Error('prompt export must not commit pages');
    },
  };
}

async function* emptyPageFiles(): AsyncGenerator<PageFileV1> {}

function minimalExportPage(index: number): PageFileV1 {
  const route = `/deadline-${index}`;
  return parsePageFileV1({
    schemaVersion: 1,
    page: {
      policyVersion: 1,
      route,
      canonicalIdentity: route,
      pageId: `p_${index.toString(16).padStart(64, '0')}`,
    },
    revision: 0,
    annotations: [],
    replayWindow: [],
  });
}

async function* waitForAbort(signal: AbortSignal): AsyncGenerator<PageFileV1> {
  await new Promise<void>((_resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    signal.addEventListener(
      'abort',
      () => {
        reject(signal.reason);
      },
      { once: true },
    );
  });
  signal.throwIfAborted();
  yield* emptyPageFiles();
}

function deferred<T>(): { readonly promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
async function awaitHeldRequestEntry(
  entered: Promise<unknown>,
  heldRequest: Promise<unknown>,
  label: string,
): Promise<void> {
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      entered.then(
        () => 'entered' as const,
        () => 'entry-failed' as const,
      ),
      heldRequest.then(
        () => 'request-completed' as const,
        () => 'request-failed' as const,
      ),
      new Promise<'watchdog'>((resolve) => {
        watchdog = setTimeout(() => resolve('watchdog'), ADMISSION_GATE_WATCHDOG_MS);
      }),
    ]);
    if (result !== 'entered') {
      throw new Error(`${label} ${result} before dispatch entry`);
    }
  } finally {
    if (watchdog !== undefined) {
      clearTimeout(watchdog);
    }
  }
}

async function settlePendingRequests(requests: readonly Promise<unknown>[]): Promise<void> {
  await Promise.allSettled(requests);
}
function opaqueToken(fill: number, byteLength = 32): string {
  return Buffer.alloc(byteLength, fill).toString('base64url');
}

function verifiedNormalAuth(token: string, origin: string): AuthContext {
  const verifier = new LocalTokenVerifier(
    [
      createLocalTokenCredential({
        mode: 'restart-bound',
        token,
        subject: createCredentialSubject({
          audience: SCENE_GLASS_AUDIENCE,
          projectId: ALPHA_PROJECT,
        }),
      }),
    ],
    { onRevocationCheckFailed: () => {} },
  );
  const verified = verifier.verify({
    authorization: `Bearer ${token}`,
    audience: SCENE_GLASS_AUDIENCE,
    origin,
  });
  if (!verified.ok) {
    throw new Error(`normal verifier rejected fixture credential: ${verified.code}`);
  }
  return verified.context;
}

function issueFromLifecycle(
  lifecycle: ReturnType<typeof createDiagnosticsLifecycle>,
  auth: AuthContext,
  limits: {
    readonly diagnosticActiveRunsGlobal: number;
    readonly diagnosticActiveRunsPerProject: number;
    readonly diagnosticRunsPerProjectPerMinute: number;
  },
): {
  readonly expiresAt: number;
  readonly runId: string;
  readonly token: string;
} {
  const issued = lifecycle.issuer.issue({ auth, limits });
  if (!issued.ok) {
    throw new Error(`diagnostic issuer rejected fixture credential: ${issued.code}`);
  }
  return issued;
}

function consumeFromLifecycle(
  lifecycle: ReturnType<typeof createDiagnosticsLifecycle>,
  issued: { readonly token: string },
): { readonly id: string } {
  const consumed = lifecycle.runStore.consumeInitialize({
    token: issued.token,
    projectId: ALPHA_PROJECT,
    origin: ALPHA_ORIGIN,
    audience: 'diagnostics',
    method: 'initialize',
  });
  if (!consumed.ok) {
    throw new Error(`diagnostic run store rejected fixture run: ${consumed.code}`);
  }
  return consumed.session;
}
