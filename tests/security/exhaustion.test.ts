import { createHash } from 'node:crypto';
import type { OutgoingHttpHeaders } from 'node:http';
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  BUILT_IN_LIMITS,
  REPLAY_RECORD_COUNT,
  assertLowercaseUuidV4,
  effectiveLimits,
  serializeCanonicalPageFileV1,
  type ElementAnnotation,
  type PageFileV1,
  type PageId,
} from '@scene-glass/contracts';
import { prepareOperationReplay, type ReplayOperation } from '@scene-glass/core/operation-replay';
import { exportReviewMarkdown } from '@scene-glass/core/prompt-export';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { AuthContext } from '../../packages/server/src/auth/auth-context.js';
import {
  createCredentialSubject,
  SCENE_GLASS_AUDIENCE,
} from '../../packages/server/src/auth/credential-subject.js';
import {
  createLocalTokenCredential,
  LocalTokenVerifier,
  type LocalTokenCredential,
  type VerifyBearerInput,
} from '../../packages/server/src/auth/local-token-verifier.js';
import { DiagnosticsIssuer } from '../../packages/server/src/diagnostics/issuer.js';
import { DiagnosticRunStore } from '../../packages/server/src/diagnostics/run-store.js';
import { DiagnosticsTeardown } from '../../packages/server/src/diagnostics/teardown.js';
import {
  mcpRoute,
  type McpDispatcherInput,
  type McpSessionGateway,
} from '../../packages/server/src/http/mcp-route.js';
import { SceneGlassLogger } from '../../packages/server/src/observability/logger.js';
import { SessionManager } from '../../packages/server/src/mcp/session-manager.js';
import type {
  AuthorizedProject,
  OriginPolicy,
  ProjectRegistry,
} from '../../packages/server/src/registry/config-project-registry.js';
import { ScgAnnotationStore } from '../../packages/server/src/storage/scg-annotation-store.js';

const ORIGIN = 'http://127.0.0.1:4317';
const temporaryRoots: string[] = [];
const ADMISSION_GATE_WATCHDOG_MS = 100;
const ignoreRevocationCheckFailure = (): void => {};

const POLICY: OriginPolicy = Object.freeze({
  projectId: 'alpha',
  allowsOrigin(origin: string): boolean {
    return origin === ORIGIN;
  },
});

function opaqueToken(label: string): string {
  return createHash('sha256').update(label, 'utf8').digest('base64url');
}

function pageIdFor(canonicalIdentity: string): PageId {
  return `p_${createHash('sha256').update(canonicalIdentity, 'utf8').digest('hex')}` as PageId;
}

function pageFile(sequence: number, annotations: readonly ElementAnnotation[] = []): PageFileV1 {
  const canonicalIdentity = `https://review.scene-glass.test/exhaustion/${sequence}`;
  return {
    schemaVersion: 1,
    page: {
      policyVersion: 1,
      canonicalIdentity,
      route: `/exhaustion/${sequence}`,
      pageId: pageIdFor(canonicalIdentity),
    },
    revision: 0,
    annotations: [...annotations],
    replayWindow: [],
  };
}

function annotation(sequence: number): ElementAnnotation {
  return {
    id: assertLowercaseUuidV4(`00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}`),
    locator: { dataScgId: `limit-${sequence}` },
    memo: `Limit annotation ${sequence}`,
    surroundingText: `Limit surrounding text ${sequence}`,
    domOrder: sequence,
    resolution: { status: 'resolved', reason: null },
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
}

function project(projectId: string, limits = BUILT_IN_LIMITS): AuthorizedProject {
  return Object.freeze({ projectId, effectiveLimits: limits });
}

function credential(input: {
  readonly projectId: string;
  readonly token: string;
}): LocalTokenCredential {
  return createLocalTokenCredential({
    mode: 'restart-bound',
    token: input.token,
    subject: createCredentialSubject({
      audience: SCENE_GLASS_AUDIENCE,
      projectId: input.projectId,
    }),
    origin: ORIGIN,
  });
}

function authContext(projectId: string, label: string): AuthContext {
  const token = opaqueToken(`auth-${label}`);
  const verifier = new LocalTokenVerifier([credential({ projectId, token })], {
    onRevocationCheckFailed: ignoreRevocationCheckFailure,
  });
  const verified = verifier.verify({
    authorization: `Bearer ${token}`,
    origin: ORIGIN,
    now: 0,
  });
  if (!verified.ok) {
    throw new Error(`Expected active ${projectId} authentication context`);
  }
  return verified.context;
}

function errorCode(error: unknown): string | undefined {
  if (
    typeof error !== 'object' ||
    error === null ||
    !('code' in error) ||
    typeof error.code !== 'string'
  ) {
    return undefined;
  }
  return error.code;
}

function captureSyncResult<T>(action: () => T): {
  readonly error: unknown;
  readonly value: T | undefined;
} {
  try {
    return { error: undefined, value: action() };
  } catch (error: unknown) {
    return { error, value: undefined };
  }
}

async function expectAsyncCode(action: () => Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await action();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toMatchObject({ code });
}

function expectAllowedCors(response: { headers: OutgoingHttpHeaders }): void {
  expect(response.headers['access-control-allow-origin']).toBe(ORIGIN);
  expect(response.headers.vary).toBe('Origin');
  expect(response.headers['access-control-allow-credentials']).toBeUndefined();
}

function problemCode(response: { json(): unknown }): string {
  const payload = response.json() as { code?: unknown };
  expect(typeof payload.code).toBe('string');
  return payload.code as string;
}

async function createTemporaryRoot(prefix: string): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe('effective resource exhaustion', () => {
  it('rejects diagnostics-enabled routes without rootless admission metadata at registration', async () => {
    const app = Fastify({ logger: false });
    const diagnosticsTeardown = new DiagnosticsTeardown();
    const sessions = new SessionManager();
    app.register(mcpRoute, {
      diagnosticRunStore: new DiagnosticRunStore(
        new DiagnosticsIssuer(diagnosticsTeardown),
        diagnosticsTeardown,
      ),
      dispatcher: { dispatch: () => undefined },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry: {
        getOriginPolicy: () => POLICY,
        resolveAuthorizedProject: () => undefined,
      },
      sessions,
      verifier: new LocalTokenVerifier([], {
        onRevocationCheckFailed: ignoreRevocationCheckFailure,
      }),
    });

    try {
      await expect(app.ready()).rejects.toThrow('MCP route options are invalid');
    } finally {
      await app.close();
      sessions.shutdown();
      diagnosticsTeardown.shutdown();
    }
  });
  it('registers diagnostics-enabled routes with rootless admission metadata', async () => {
    const app = Fastify({ logger: false });
    const diagnosticsTeardown = new DiagnosticsTeardown();
    const sessions = new SessionManager();
    const activeProject = project('alpha');
    app.register(mcpRoute, {
      diagnosticRunStore: new DiagnosticRunStore(
        new DiagnosticsIssuer(diagnosticsTeardown),
        diagnosticsTeardown,
      ),
      dispatcher: { dispatch: () => undefined },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry: {
        getOriginPolicy: () => POLICY,
        getRequestAdmissionProject: () => activeProject,
        resolveAuthorizedProject: () => activeProject,
      },
      sessions,
      verifier: new LocalTokenVerifier([], {
        onRevocationCheckFailed: ignoreRevocationCheckFailure,
      }),
    });

    try {
      await expect(app.ready()).resolves.toBe(app);
    } finally {
      await app.close();
      sessions.shutdown();
      diagnosticsTeardown.shutdown();
    }
  });
  it('admits authenticated diagnostic traffic before parsing and releases malformed capacity', async () => {
    const normalToken = opaqueToken('diagnostic-admission-normal');
    const limits = Object.freeze({
      ...BUILT_IN_LIMITS,
      concurrentRequestsGlobal: 1,
      concurrentRequestsPerProject: 1,
      normalSessionsGlobal: 3,
      normalSessionsPerProject: 3,
    });
    const activeProject = project('alpha', limits);
    let admissionMetadataLookups = 0;
    const diagnosticsTeardown = new DiagnosticsTeardown();
    const diagnosticsIssuer = new DiagnosticsIssuer(diagnosticsTeardown);
    const diagnosticRunStore = new DiagnosticRunStore(diagnosticsIssuer, diagnosticsTeardown);
    const diagnostic = diagnosticsIssuer.issue({
      auth: authContext('alpha', 'diagnostic-admission'),
      limits,
    });
    if (!diagnostic.ok) {
      throw new Error(`Expected diagnostic credential: ${diagnostic.code}`);
    }

    let markDispatchStarted!: () => void;
    let releaseDispatch!: () => void;
    const dispatchStarted = new Promise<void>((resolve) => {
      markDispatchStarted = resolve;
    });
    const dispatchRelease = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    const sessions = new SessionManager();
    const app = Fastify({ logger: false });
    await app.register(mcpRoute, {
      diagnosticRunStore,
      dispatcher: {
        async dispatch(input: McpDispatcherInput) {
          if (input.message.id === 2) {
            markDispatchStarted();
            await dispatchRelease;
          }
          return {
            id: input.message.id ?? null,
            jsonrpc: '2.0',
            result: {
              capabilities: {},
              protocolVersion: '2025-11-25',
              serverInfo: { name: 'test', version: '1.0.0' },
            },
          };
        },
      },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry: {
        getOriginPolicy: () => POLICY,
        getRequestAdmissionProject: () => {
          admissionMetadataLookups += 1;
          return activeProject;
        },
        resolveAuthorizedProject: () => activeProject,
      },
      sessions,
      verifier: new LocalTokenVerifier([credential({ projectId: 'alpha', token: normalToken })], {
        onRevocationCheckFailed: ignoreRevocationCheckFailure,
      }),
    });
    await app.ready();

    const pendingRequests: Promise<unknown>[] = [];

    try {
      const parserFailure = await app.inject({
        method: 'POST',
        url: '/mcp/v1/projects/alpha',
        headers: {
          authorization: `Bearer ${diagnostic.token}`,
          'content-type': 'application/json',
          origin: ORIGIN,
        },
        payload: '{"jsonrpc":',
      });
      expect(parserFailure.statusCode).toBe(400);
      expect(problemCode(parserFailure)).toBe('SCG_JSON_INVALID');

      const reallocated = await app.inject(initializeRequest(normalToken, 'alpha', 1));
      expect(reallocated.statusCode).toBe(200);

      const heldNormalRequest = app.inject(initializeRequest(normalToken, 'alpha', 2));
      pendingRequests.push(heldNormalRequest);
      await awaitHeldRequestEntries(
        [dispatchStarted],
        [heldNormalRequest],
        'diagnostic admission holder',
      );

      admissionMetadataLookups = 0;
      for (const [name, projectId, token, status, code] of [
        [
          'invalid-token',
          'alpha',
          opaqueToken('diagnostic-admission-invalid'),
          401,
          'SCG_AUTH_INVALID',
        ],
        ['wrong-project', 'beta', normalToken, 403, 'SCG_PROJECT_FORBIDDEN'],
      ] as const) {
        for (const method of ['POST', 'GET', 'DELETE'] as const) {
          const rejected = await app.inject({
            method,
            url: `/mcp/v1/projects/${projectId}`,
            headers: {
              authorization: `Bearer ${token}`,
              origin: ORIGIN,
              ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
            },
            ...(method === 'POST'
              ? { payload: { id: 4, jsonrpc: '2.0', method: 'initialize' } }
              : {}),
          });
          expect([name, method, rejected.statusCode]).toEqual([name, method, status]);
          expect(problemCode(rejected)).toBe(code);
        }
      }
      expect(admissionMetadataLookups).toBe(0);

      const negotiationRejected = await app.inject({
        method: 'POST',
        url: '/mcp/v1/projects/alpha',
        headers: {
          accept: 'text/plain',
          authorization: `Bearer ${diagnostic.token}`,
          'content-type': 'application/json',
          origin: ORIGIN,
        },
        payload: { id: 3, jsonrpc: '2.0', method: 'initialize' },
      });
      expect(negotiationRejected.statusCode).toBe(429);
      expect(problemCode(negotiationRejected)).toBe('SCG_REQUEST_LIMIT_GLOBAL');

      releaseDispatch();
      expect((await heldNormalRequest).statusCode).toBe(200);
    } finally {
      releaseDispatch();
      await settlePendingRequests(pendingRequests);
      await app.close();
      sessions.shutdown();
      sessions.assertEmpty();
      diagnosticsTeardown.shutdown();
    }
  });
  it('accepts exactly N body bytes and leaves session and dispatch state unchanged at N-1', async () => {
    const payload = JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'initialize' });
    const exactBytes = Buffer.byteLength(payload, 'utf8');

    for (const [name, maxBodyBytes, expectedStatus] of [
      ['N-1', exactBytes - 1, 413],
      ['N', exactBytes, 200],
      ['N+1', exactBytes + 1, 200],
    ] as const) {
      const harness = await createBodyLimitHarness(maxBodyBytes);
      try {
        const response = await harness.app.inject({
          method: 'POST',
          url: '/mcp/v1/projects/alpha',
          headers: {
            authorization: `Bearer ${harness.token}`,
            'content-length': String(exactBytes),
            'content-type': 'application/json',
            origin: ORIGIN,
          },
          payload,
        });

        const expectedState =
          expectedStatus === 413
            ? {
                dispatches: 0,
                problemCode: 'SCG_BODY_TOO_LARGE',
                rootResolutions: 0,
                sessionCount: 0,
              }
            : {
                dispatches: 1,
                problemCode: undefined,
                rootResolutions: 1,
                sessionCount: 1,
              };
        const receivedProblemCode = expectedStatus === 413 ? problemCode(response) : undefined;

        expect([name, response.statusCode]).toEqual([name, expectedStatus]);
        expectAllowedCors(response);
        expect(receivedProblemCode).toBe(expectedState.problemCode);
        expect(harness.dispatches).toBe(expectedState.dispatches);
        expect(harness.authentications).toBe(1);
        expect(harness.rootResolutions).toBe(expectedState.rootResolutions);
        expect(harness.sessions.activeSessionCount).toBe(expectedState.sessionCount);
      } finally {
        await harness.close();
      }
    }
  });

  it('enforces exact page-file bytes without persisting an N-1 candidate', async () => {
    const candidate = pageFile(1);
    const exactBytes = Buffer.byteLength(serializeCanonicalPageFileV1(candidate), 'utf8');

    for (const [name, pageFileBytes, shouldWrite] of [
      ['N-1', exactBytes - 1, false],
      ['N', exactBytes, true],
      ['N+1', exactBytes + 1, true],
    ] as const) {
      const root = await createTemporaryRoot(`scene-glass-page-file-${name}-`);
      const limits = effectiveLimits({ pageFileBytes });
      const scopedProject = project(`page-${name}`, limits);
      let resolverCalls = 0;
      const store = new ScgAnnotationStore({
        getAuthorizedRoot: () => {
          resolverCalls += 1;
          return root;
        },
      });
      const annotationDirectory = join(root, '.scg', 'annotations');

      const commitError = await store.commitPage(scopedProject, candidate, activeSignal()).then(
        () => undefined,
        (error: unknown) => error,
      );
      expect([name, commitError === undefined]).toEqual([name, shouldWrite]);
      expect(errorCode(commitError)).toBe(shouldWrite ? undefined : 'SCG_LIMIT_FILE');
      expect(resolverCalls).toBe(shouldWrite ? 1 : 0);

      const target = join(annotationDirectory, `${candidate.page.pageId}.json`);
      const expectedContent = serializeCanonicalPageFileV1(candidate);
      const persistedContent = shouldWrite ? await readFile(target, 'utf8') : undefined;
      expect(persistedContent).toBe(shouldWrite ? expectedContent : undefined);

      const directory = await readdir(annotationDirectory).then(
        (entries) => ({ entries, error: undefined }),
        (error: unknown) => ({ entries: undefined, error }),
      );
      expect(errorCode(directory.error)).toBe(shouldWrite ? undefined : 'ENOENT');
      expect(directory.entries).toEqual(
        shouldWrite ? [`${candidate.page.pageId}.json`] : undefined,
      );
    }
  });

  it('keeps a lower pages-per-project cap for project A isolated from project B', async () => {
    const alphaRoot = await createTemporaryRoot('scene-glass-pages-alpha-');
    const betaRoot = await createTemporaryRoot('scene-glass-pages-beta-');
    const alpha = project('alpha', effectiveLimits(undefined, { pagesPerProject: 1 }));
    const beta = project('beta', effectiveLimits(undefined, { pagesPerProject: 2 }));
    const roots = new Map([
      [alpha.projectId, alphaRoot],
      [beta.projectId, betaRoot],
    ]);
    const store = new ScgAnnotationStore({
      getAuthorizedRoot(authorizedProject: AuthorizedProject) {
        const root = roots.get(authorizedProject.projectId);
        if (root === undefined) {
          throw new Error('missing authorized root');
        }
        return root;
      },
    });
    const alphaFirst = pageFile(10);
    const alphaSecond = pageFile(11);
    const betaFirst = pageFile(20);
    const betaSecond = pageFile(21);

    await store.commitPage(alpha, alphaFirst, activeSignal());
    const alphaBefore = await collectPages(store, alpha);
    await expectAsyncCode(
      () => store.commitPage(alpha, alphaSecond, activeSignal()),
      'SCG_LIMIT_FILE',
    );
    expect(await collectPages(store, alpha)).toEqual(alphaBefore);

    await store.commitPage(beta, betaFirst, activeSignal());
    await store.commitPage(beta, betaSecond, activeSignal());
    expect(await collectPages(store, beta)).toHaveLength(2);
    expect(await collectPages(store, alpha)).toHaveLength(1);
  });

  it('allows N scan and render bytes and returns the stable file-limit code at N-1', () => {
    const candidate = pageFile(30, [annotation(1)]);
    const scanBytes = Buffer.byteLength(serializeCanonicalPageFileV1(candidate), 'utf8');
    const markdown = exportReviewMarkdown([candidate], {
      limits: {
        ...BUILT_IN_LIMITS,
        exportRenderBytes: Number.MAX_SAFE_INTEGER,
        exportScanBytes: Number.MAX_SAFE_INTEGER,
      },
      mode: 'project',
    });
    const renderBytes = Buffer.byteLength(markdown, 'utf8');

    for (const [name, limit, shouldExport] of [
      ['scan N-1', scanBytes - 1, false],
      ['scan N', scanBytes, true],
      ['scan N+1', scanBytes + 1, true],
    ] as const) {
      const action = () =>
        exportReviewMarkdown([candidate], {
          limits: {
            ...BUILT_IN_LIMITS,
            exportRenderBytes: Number.MAX_SAFE_INTEGER,
            exportScanBytes: limit,
          },
          mode: 'project',
        });
      const result = captureSyncResult(action);
      expect([name, result.error === undefined]).toEqual([name, shouldExport]);
      expect(errorCode(result.error)).toBe(shouldExport ? undefined : 'SCG_LIMIT_FILE');
      expect(result.value).toBe(shouldExport ? markdown : undefined);
    }

    for (const [name, limit, shouldExport] of [
      ['render N-1', renderBytes - 1, false],
      ['render N', renderBytes, true],
      ['render N+1', renderBytes + 1, true],
    ] as const) {
      const action = () =>
        exportReviewMarkdown([candidate], {
          limits: {
            ...BUILT_IN_LIMITS,
            exportRenderBytes: limit,
            exportScanBytes: Number.MAX_SAFE_INTEGER,
          },
          mode: 'project',
        });
      const result = captureSyncResult(action);
      expect([name, result.error === undefined]).toEqual([name, shouldExport]);
      expect(errorCode(result.error)).toBe(shouldExport ? undefined : 'SCG_LIMIT_FILE');
      expect(result.value).toBe(shouldExport ? markdown : undefined);
    }
  });

  it('independently enforces and releases project and global request admission limits', async () => {
    const alphaToken = opaqueToken('concurrent-alpha');
    const betaToken = opaqueToken('concurrent-beta');
    const alphaLimits = Object.freeze({
      ...BUILT_IN_LIMITS,
      concurrentRequestsGlobal: 3,
      concurrentRequestsPerProject: 2,
      normalSessionsGlobal: 10,
      normalSessionsPerProject: 10,
    });
    const betaLimits = Object.freeze({
      ...BUILT_IN_LIMITS,
      concurrentRequestsGlobal: 3,
      concurrentRequestsPerProject: 3,
      normalSessionsGlobal: 10,
      normalSessionsPerProject: 10,
    });
    const alpha = project('alpha', alphaLimits);
    const beta = project('beta', betaLimits);
    const sessions = new SessionManager();
    const verifier = new LocalTokenVerifier(
      [
        credential({ projectId: alpha.projectId, token: alphaToken }),
        credential({ projectId: beta.projectId, token: betaToken }),
      ],
      { onRevocationCheckFailed: ignoreRevocationCheckFailure },
    );
    const registry: ProjectRegistry = {
      getOriginPolicy(projectId: string): OriginPolicy | undefined {
        return projectId === alpha.projectId || projectId === beta.projectId ? POLICY : undefined;
      },
      resolveAuthorizedProject(auth: AuthContext): AuthorizedProject | undefined {
        if (auth.projectId === alpha.projectId) {
          return alpha;
        }
        return auth.projectId === beta.projectId ? beta : undefined;
      },
    };
    type DispatchGate = {
      readonly started: Promise<void>;
      readonly wait: Promise<void>;
      release(): void;
      start(): void;
    };
    const dispatchGates = new Map<number, DispatchGate>();
    const gates: DispatchGate[] = [];
    const pendingRequests: Promise<unknown>[] = [];
    function blockDispatch(id: number): DispatchGate {
      let markStarted!: () => void;
      let releaseWait!: () => void;
      const gate: DispatchGate = {
        started: new Promise<void>((resolve) => {
          markStarted = resolve;
        }),
        wait: new Promise<void>((resolve) => {
          releaseWait = resolve;
        }),
        release: () => {
          releaseWait();
        },
        start: () => {
          markStarted();
        },
      };
      dispatchGates.set(id, gate);
      gates.push(gate);
      return gate;
    }

    let dispatches = 0;
    const app = Fastify({ logger: false });
    await app.register(mcpRoute, {
      dispatcher: {
        async dispatch(input: McpDispatcherInput) {
          dispatches += 1;
          const gate =
            typeof input.message.id === 'number' ? dispatchGates.get(input.message.id) : undefined;
          if (gate !== undefined) {
            gate.start();
            await gate.wait;
          }
          return {
            id: input.message.id ?? null,
            jsonrpc: '2.0',
            result:
              input.message.method === 'initialize'
                ? {
                    capabilities: {},
                    protocolVersion: '2025-11-25',
                    serverInfo: { name: 'test', version: '1.0.0' },
                  }
                : {},
          };
        },
      },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      logger: new SceneGlassLogger(),
      registry,
      sessions,
      verifier,
    });
    await app.ready();

    try {
      const alphaFirstGate = blockDispatch(1);
      const alphaSecondGate = blockDispatch(2);
      const alphaFirst = app.inject(initializeRequest(alphaToken, alpha.projectId, 1));
      const alphaSecond = app.inject(initializeRequest(alphaToken, alpha.projectId, 2));
      pendingRequests.push(alphaFirst, alphaSecond);
      await awaitHeldRequestEntries(
        [alphaFirstGate.started, alphaSecondGate.started],
        [alphaFirst, alphaSecond],
        'project request admission holders',
      );
      expect(dispatches).toBe(2);
      expect(sessions.activeSessionCount).toBe(2);

      const projectDenied = await app.inject(initializeRequest(alphaToken, alpha.projectId, 3));
      expect(projectDenied.statusCode).toBe(429);
      expect(problemCode(projectDenied)).toBe('SCG_REQUEST_LIMIT_PROJECT');
      expectAllowedCors(projectDenied);
      expect(dispatches).toBe(2);
      expect(sessions.activeSessionCount).toBe(2);

      alphaFirstGate.release();
      expect((await alphaFirst).statusCode).toBe(200);
      const projectReallocated = await app.inject(
        initializeRequest(alphaToken, alpha.projectId, 4),
      );
      expect(projectReallocated.statusCode).toBe(200);
      expectAllowedCors(projectReallocated);
      expect(dispatches).toBe(3);
      expect(sessions.activeSessionCount).toBe(3);

      alphaSecondGate.release();
      expect((await alphaSecond).statusCode).toBe(200);

      const globalAlphaGate = blockDispatch(5);
      const globalBetaFirstGate = blockDispatch(6);
      const globalBetaSecondGate = blockDispatch(7);
      const globalAlpha = app.inject(initializeRequest(alphaToken, alpha.projectId, 5));
      const globalBetaFirst = app.inject(initializeRequest(betaToken, beta.projectId, 6));
      const globalBetaSecond = app.inject(initializeRequest(betaToken, beta.projectId, 7));
      pendingRequests.push(globalAlpha, globalBetaFirst, globalBetaSecond);
      await awaitHeldRequestEntries(
        [globalAlphaGate.started, globalBetaFirstGate.started, globalBetaSecondGate.started],
        [globalAlpha, globalBetaFirst, globalBetaSecond],
        'global request admission holders',
      );
      expect(dispatches).toBe(6);
      expect(sessions.activeSessionCount).toBe(6);

      const globalDenied = await app.inject(initializeRequest(alphaToken, alpha.projectId, 8));
      expect(globalDenied.statusCode).toBe(429);
      expect(problemCode(globalDenied)).toBe('SCG_REQUEST_LIMIT_GLOBAL');
      expectAllowedCors(globalDenied);
      expect(dispatches).toBe(6);
      expect(sessions.activeSessionCount).toBe(6);

      globalBetaFirstGate.release();
      expect((await globalBetaFirst).statusCode).toBe(200);
      const globalReallocated = await app.inject(initializeRequest(alphaToken, alpha.projectId, 9));
      expect(globalReallocated.statusCode).toBe(200);
      expectAllowedCors(globalReallocated);
      expect(dispatches).toBe(7);
      expect(sessions.activeSessionCount).toBe(7);
    } finally {
      for (const gate of gates) {
        gate.release();
      }
      await settlePendingRequests(pendingRequests);
      await app.close();
      sessions.shutdown();
      sessions.assertEmpty();
    }
  });
  it('releases request admission when provisional-session abort cleanup throws', async () => {
    const token = opaqueToken('throwing-provisional-abort');
    const limits = Object.freeze({
      ...BUILT_IN_LIMITS,
      concurrentRequestsGlobal: 1,
      concurrentRequestsPerProject: 1,
      normalSessionsGlobal: 2,
      normalSessionsPerProject: 2,
    });
    const activeProject = project('alpha', limits);
    const manager = new SessionManager();
    const cleanupRecords: unknown[] = [];
    const logger = new SceneGlassLogger((record) => {
      if (record.event === 'cleanup.failed') {
        cleanupRecords.push(record.data);
      }
    });
    let abortAttempts = 0;
    let dispatches = 0;
    const sessions: McpSessionGateway = {
      initialize: (input) => manager.initialize(input),
      commit: (input) => manager.commit(input),
      lookup: (input) => manager.lookup(input),
      close: (sessionId, signal) => manager.close(sessionId, signal),
      abort(sessionId) {
        abortAttempts += 1;
        if (abortAttempts === 1) {
          throw new Error('provisional cleanup failed');
        }
        return manager.abort(sessionId);
      },
    };
    const app = Fastify({ logger: false });
    await app.register(mcpRoute, {
      dispatcher: {
        dispatch(input: McpDispatcherInput) {
          dispatches += 1;
          if (dispatches === 1) {
            return { id: input.message.id, jsonrpc: '2.0' };
          }
          return {
            id: input.message.id ?? null,
            jsonrpc: '2.0',
            result: {
              capabilities: {},
              protocolVersion: '2025-11-25',
              serverInfo: { name: 'test', version: '1.0.0' },
            },
          };
        },
      },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      logger,
      registry: {
        getOriginPolicy: () => POLICY,
        resolveAuthorizedProject: () => activeProject,
      },
      sessions,
      verifier: new LocalTokenVerifier([credential({ projectId: 'alpha', token })], {
        onRevocationCheckFailed: ignoreRevocationCheckFailure,
      }),
    });
    await app.ready();

    try {
      const first = await app.inject(initializeRequest(token, 'alpha', 1));
      expect(first.statusCode).toBe(500);
      expect(problemCode(first)).toBe('SCG_MCP_RESPONSE_INVALID');
      expectAllowedCors(first);
      expect(abortAttempts).toBe(1);
      expect(cleanupRecords).toEqual([{ resource: 'normal' }]);

      const reallocated = await app.inject(initializeRequest(token, 'alpha', 2));
      expect(reallocated.statusCode).toBe(200);
      expectAllowedCors(reallocated);
      expect(dispatches).toBe(2);
    } finally {
      await app.close();
      manager.shutdown();
      manager.assertEmpty();
    }
  });

  it('enforces N-1, N, and N+1 session caps and releases a slot after close', () => {
    const now = 10_000;
    const manager = new SessionManager({ now: () => now });
    const alpha = authContext('alpha', 'session-alpha');
    const beta = authContext('beta', 'session-beta');
    const alphaInput = {
      auth: alpha,
      normalSessionsGlobal: 3,
      normalSessionsPerProject: 2,
      sessionIdleMs: 1_000,
      sessionMaxAgeMs: 10_000,
    };
    const betaInput = {
      ...alphaInput,
      auth: beta,
      normalSessionsPerProject: 2,
    };

    const first = manager.initialize(alphaInput);
    expect(first.ok).toBe(true);
    expect(manager.sessionCountForProject(alpha.projectId)).toBe(1);
    if (!first.ok) {
      throw new Error('Expected first session');
    }
    expect(manager.commit({ auth: alpha, sessionId: first.session.id })).toMatchObject({
      ok: true,
      session: first.session,
    });
    const second = manager.initialize(alphaInput);
    expect(second.ok).toBe(true);
    expect(manager.sessionCountForProject(alpha.projectId)).toBe(2);
    if (!second.ok) {
      throw new Error('Expected second session');
    }
    expect(manager.commit({ auth: alpha, sessionId: second.session.id })).toMatchObject({
      ok: true,
      session: second.session,
    });

    const denied = manager.initialize(alphaInput);
    expect(denied).toEqual({
      code: 'SCG_SESSION_LIMIT_PROJECT',
      ok: false,
      status: 429,
    });
    expect(manager.activeSessionCount).toBe(2);
    expect(manager.sessionCountForProject(alpha.projectId)).toBe(2);

    expect(
      manager.lookup({ auth: alpha, method: 'DELETE', sessionId: first.session.id }),
    ).toMatchObject({ ok: true });
    expect(manager.activeSessionCount).toBe(2);
    expect(manager.close(first.session.id)).toEqual({
      tornDown: true,
      reason: 'client-close',
    });
    expect(manager.activeSessionCount).toBe(1);

    const reallocated = manager.initialize(alphaInput);
    expect(reallocated.ok).toBe(true);
    expect(manager.sessionCountForProject(alpha.projectId)).toBe(2);
    if (!reallocated.ok) {
      throw new Error('Expected reallocated session');
    }
    expect(manager.commit({ auth: alpha, sessionId: reallocated.session.id })).toMatchObject({
      ok: true,
      session: reallocated.session,
    });

    const betaFirst = manager.initialize(betaInput);
    expect(betaFirst.ok).toBe(true);
    expect(manager.activeSessionCount).toBe(3);
    if (!betaFirst.ok) {
      throw new Error('Expected beta session');
    }
    expect(manager.commit({ auth: beta, sessionId: betaFirst.session.id })).toMatchObject({
      ok: true,
      session: betaFirst.session,
    });
    const globalDenied = manager.initialize(betaInput);
    expect(globalDenied).toEqual({
      code: 'SCG_SESSION_LIMIT_GLOBAL',
      ok: false,
      status: 429,
    });
    expect(manager.activeSessionCount).toBe(3);
    manager.shutdown();
    manager.assertEmpty();
  });

  it('enforces N-1, N, and N+1 diagnostic active-run and rate caps without retaining denied runs', () => {
    let now = 100_000;
    let randomByte = 0;
    const teardown = new DiagnosticsTeardown({ now: () => now });
    const issuer = new DiagnosticsIssuer(teardown, {
      now: () => now,
      random: (byteLength: number) => {
        const bytes = Uint8Array.from({ length: byteLength }, () => randomByte);
        randomByte = (randomByte + 1) % 256;
        return bytes;
      },
    });
    const alpha = authContext('alpha', 'diagnostic-alpha');
    const beta = authContext('beta', 'diagnostic-beta');
    const limits = {
      diagnosticActiveRunsGlobal: 3,
      diagnosticActiveRunsPerProject: 2,
      diagnosticRunsPerProjectPerMinute: 3,
    };

    const first = issuer.issue({ auth: alpha, limits });
    expect(first.ok).toBe(true);
    expect(issuer.activeRunCount).toBe(1);
    const second = issuer.issue({ auth: alpha, limits });
    expect(second.ok).toBe(true);
    expect(issuer.activeRunCount).toBe(2);

    const activeDenied = issuer.issue({ auth: alpha, limits });
    expect(activeDenied).toEqual({
      code: 'SCG_DIAGNOSTIC_LIMIT_PROJECT',
      ok: false,
      status: 429,
    });
    expect(issuer.activeRunCount).toBe(2);
    expect(teardown.evidence()).toEqual({
      activeProjectCount: 1,
      activeRunCount: 2,
      activeTimerCount: 2,
      shutDown: false,
    });

    if (!first.ok) {
      throw new Error('Expected first diagnostic run');
    }
    expect(teardown.close(first.runId)).toBe(true);
    expect(issuer.activeRunCount).toBe(1);
    const reallocated = issuer.issue({ auth: alpha, limits });
    expect(reallocated.ok).toBe(true);
    expect(issuer.activeRunCount).toBe(2);

    teardown.shutdown();
    issuer.clearShutdownState();
    expect(issuer.isEmpty()).toBe(true);
    const globalTeardown = new DiagnosticsTeardown({ now: () => now });
    const globalIssuer = new DiagnosticsIssuer(globalTeardown, {
      now: () => now,
      random: (byteLength: number) => {
        const bytes = Uint8Array.from({ length: byteLength }, () => randomByte);
        randomByte = (randomByte + 1) % 256;
        return bytes;
      },
    });
    const globalLimits = {
      diagnosticActiveRunsGlobal: 3,
      diagnosticActiveRunsPerProject: 3,
      diagnosticRunsPerProjectPerMinute: 3,
    };
    try {
      const globalAlphaFirst = globalIssuer.issue({ auth: alpha, limits: globalLimits });
      const globalAlphaSecond = globalIssuer.issue({ auth: alpha, limits: globalLimits });
      const globalBetaFirst = globalIssuer.issue({ auth: beta, limits: globalLimits });
      expect([globalAlphaFirst.ok, globalAlphaSecond.ok, globalBetaFirst.ok]).toEqual([
        true,
        true,
        true,
      ]);
      expect(globalIssuer.activeRunCount).toBe(3);
      const evidenceAtGlobalLimit = globalTeardown.evidence();
      expect(evidenceAtGlobalLimit).toEqual({
        activeProjectCount: 2,
        activeRunCount: 3,
        activeTimerCount: 3,
        shutDown: false,
      });

      const globalDenied = globalIssuer.issue({ auth: beta, limits: globalLimits });
      expect(globalDenied).toEqual({
        code: 'SCG_DIAGNOSTIC_LIMIT_GLOBAL',
        ok: false,
        status: 429,
      });
      expect(globalIssuer.activeRunCount).toBe(3);
      expect(globalTeardown.evidence()).toEqual(evidenceAtGlobalLimit);

      if (!globalAlphaFirst.ok) {
        throw new Error('Expected first global diagnostic run');
      }
      expect(globalTeardown.close(globalAlphaFirst.runId)).toBe(true);
      expect(globalIssuer.activeRunCount).toBe(2);
      expect(globalTeardown.evidence()).toEqual({
        activeProjectCount: 2,
        activeRunCount: 2,
        activeTimerCount: 2,
        shutDown: false,
      });

      const globalReallocated = globalIssuer.issue({ auth: beta, limits: globalLimits });
      expect(globalReallocated.ok).toBe(true);
      expect(globalIssuer.activeRunCount).toBe(3);
      expect(globalTeardown.evidence()).toEqual(evidenceAtGlobalLimit);

      globalTeardown.shutdown();
      globalIssuer.clearShutdownState();
      expect(globalIssuer.isEmpty()).toBe(true);
    } finally {
      globalTeardown.shutdown();
      globalIssuer.clearShutdownState();
    }

    now = 200_000;
    const rateTeardown = new DiagnosticsTeardown({ now: () => now });
    const rateIssuer = new DiagnosticsIssuer(rateTeardown, {
      now: () => now,
      random: (byteLength: number) => {
        const bytes = Uint8Array.from({ length: byteLength }, () => randomByte);
        randomByte = (randomByte + 1) % 256;
        return bytes;
      },
    });
    const rateLimits = {
      diagnosticActiveRunsGlobal: 3,
      diagnosticActiveRunsPerProject: 3,
      diagnosticRunsPerProjectPerMinute: 2,
    };
    expect(rateIssuer.issue({ auth: alpha, limits: rateLimits }).ok).toBe(true);
    expect(rateIssuer.issue({ auth: alpha, limits: rateLimits }).ok).toBe(true);
    const rateDenied = rateIssuer.issue({ auth: alpha, limits: rateLimits });
    expect(rateDenied).toEqual({
      code: 'SCG_DIAGNOSTIC_RATE_LIMIT',
      ok: false,
      status: 429,
    });
    expect(rateIssuer.activeRunCount).toBe(2);
    now += 60_000;
    expect(rateIssuer.issue({ auth: alpha, limits: rateLimits }).ok).toBe(true);
    rateTeardown.shutdown();
    rateIssuer.clearShutdownState();
  });

  it('rejects replay-count configuration before any startup root probe can run', async () => {
    for (const config of [
      {
        globalLimits: { replayCount: REPLAY_RECORD_COUNT },
        projects: [
          {
            allowedOrigins: [ORIGIN],
            projectId: 'alpha',
            root: '/not/visited',
            tokenEnv: 'SCG_ALPHA_TOKEN',
          },
        ],
        schemaVersion: 1,
      },
      {
        projects: [
          {
            allowedOrigins: [ORIGIN],
            limits: { replayWindowSize: REPLAY_RECORD_COUNT },
            projectId: 'alpha',
            root: '/not/visited',
            tokenEnv: 'SCG_ALPHA_TOKEN',
          },
        ],
        schemaVersion: 1,
      },
    ]) {
      const directory = await createTemporaryRoot('scene-glass-replay-config-');
      const configPath = join(directory, 'scene-glass.json');
      await writeFile(configPath, JSON.stringify(config));
      let rootProbes = 0;

      await expect(
        createSceneGlassAppForTest({
          configPath,
          projectRootProbe: async () => {
            rootProbes += 1;
            throw new Error('invalid configuration must not probe a root');
          },
        }),
      ).rejects.toMatchObject({
        code: 'SCG_CONFIG_LIMIT_INVALID',
        message: 'server configuration limits are invalid',
      });
      expect(rootProbes).toBe(0);
    }
  });

  it('never evicts an existing replay record when a lower byte cap rejects 31→32 or 32→33', async () => {
    for (const existingCount of [REPLAY_RECORD_COUNT - 1, REPLAY_RECORD_COUNT]) {
      const existing = await pageFileWithReplayRecords(existingCount);
      const before = structuredClone(existing);
      const nextSequence = existingCount + 1;
      const operation = replayOperation(nextSequence, existing.revision);
      const preview = await prepareOperationReplay({
        annotations: [...existing.annotations, annotation(nextSequence)],
        limits: BUILT_IN_LIMITS,
        operation,
        pageFile: existing,
        result: replayResult(nextSequence, existing.revision + 1),
      });
      if (preview.status !== 'apply') {
        throw new Error(`Expected ${existingCount}→${nextSequence} preview to apply`);
      }

      const denied = await prepareOperationReplay({
        annotations: [...existing.annotations, annotation(nextSequence)],
        limits: {
          ...BUILT_IN_LIMITS,
          pageFileBytes: preview.byteSizes.pageFile - 1,
        },
        operation,
        pageFile: existing,
        result: replayResult(nextSequence, existing.revision + 1),
      });
      expect(denied).toMatchObject({ reason: 'page-file-bytes', status: 'no-write' });
      expect(existing).toEqual(before);
      expect(existing.replayWindow).toHaveLength(existingCount);
      expect(existing.replayWindow[0]).toEqual(before.replayWindow[0]);
      expect(existing.replayWindow.at(-1)).toEqual(before.replayWindow.at(-1));
    }
  });
});

async function collectPages(
  store: ScgAnnotationStore,
  authorizedProject: AuthorizedProject,
): Promise<PageFileV1[]> {
  const pages: PageFileV1[] = [];
  for await (const page of store.listPages(authorizedProject, activeSignal())) {
    pages.push(page);
  }
  return pages;
}
function activeSignal(): AbortSignal {
  return new AbortController().signal;
}

function initializeRequest(token: string, projectId: string, id: number) {
  return {
    method: 'POST' as const,
    url: `/mcp/v1/projects/${projectId}`,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      origin: ORIGIN,
    },
    payload: { id, jsonrpc: '2.0', method: 'initialize' },
  };
}

async function createBodyLimitHarness(maxBodyBytes: number): Promise<{
  readonly app: FastifyInstance;
  readonly authentications: number;
  readonly close: () => Promise<void>;
  readonly dispatches: number;
  readonly rootResolutions: number;
  readonly sessions: SessionManager;
  readonly token: string;
}> {
  const token = opaqueToken(`body-${maxBodyBytes}`);
  const activeProject = project('alpha');
  const sessions = new SessionManager();
  const verifier = new LocalTokenVerifier([credential({ projectId: 'alpha', token })], {
    onRevocationCheckFailed: ignoreRevocationCheckFailure,
  });
  let authentications = 0;
  let dispatches = 0;
  let rootResolutions = 0;
  const app = Fastify({ logger: false });
  await app.register(mcpRoute, {
    dispatcher: {
      dispatch(input: McpDispatcherInput) {
        dispatches += 1;
        return {
          id: input.message.id ?? null,
          jsonrpc: '2.0',
          result:
            input.message.method === 'initialize'
              ? {
                  capabilities: {},
                  protocolVersion: '2025-11-25',
                  serverInfo: { name: 'test', version: '1.0.0' },
                }
              : {},
        };
      },
    },
    maxBodyBytes,
    logger: new SceneGlassLogger(),
    registry: {
      getOriginPolicy: () => POLICY,
      resolveAuthorizedProject: () => {
        rootResolutions += 1;
        return activeProject;
      },
    },
    sessions,
    verifier: {
      verify(input: VerifyBearerInput) {
        authentications += 1;
        return verifier.verify(input);
      },
    },
  });
  await app.ready();
  return {
    app,
    async close() {
      await app.close();
      sessions.shutdown();
      sessions.assertEmpty();
    },
    get authentications() {
      return authentications;
    },
    get dispatches() {
      return dispatches;
    },
    get rootResolutions() {
      return rootResolutions;
    },
    token,
    sessions,
  };
}

async function awaitHeldRequestEntries(
  entries: readonly Promise<unknown>[],
  heldRequests: readonly Promise<unknown>[],
  label: string,
): Promise<void> {
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      Promise.all(
        entries.map((entry) =>
          entry.then(
            () => 'entered' as const,
            () => 'entry-failed' as const,
          ),
        ),
      ).then((outcomes) =>
        outcomes.every((outcome) => outcome === 'entered') ? 'entered' : 'entry-failed',
      ),
      Promise.race(
        heldRequests.map((heldRequest) =>
          heldRequest.then(
            () => 'request-completed' as const,
            () => 'request-failed' as const,
          ),
        ),
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
function replayOperation(sequence: number, expectedRevision: number): ReplayOperation {
  return {
    expectedRevision,
    kind: 'create',
    operationId: assertLowercaseUuidV4(
      `00000000-0000-4000-8000-${(10_000 + sequence).toString(16).padStart(12, '0')}`,
    ),
    payload: { action: 'create', sequence },
    projectId: 'replay-project',
  };
}

function replayResult(sequence: number, revision: number) {
  return { annotation: annotation(sequence), kind: 'create' as const, revision };
}

async function pageFileWithReplayRecords(count: number): Promise<PageFileV1> {
  let current = pageFile(40);
  for (let sequence = 1; sequence <= count; sequence += 1) {
    const operation = replayOperation(sequence, current.revision);
    const applied = await prepareOperationReplay({
      annotations: [...current.annotations, annotation(sequence)],
      limits: BUILT_IN_LIMITS,
      operation,
      pageFile: current,
      result: replayResult(sequence, current.revision + 1),
    });
    if (applied.status !== 'apply') {
      throw new Error(`Expected replay record ${sequence} to apply`);
    }
    current = applied.pageFile;
  }
  return current;
}
