import { createHash } from 'node:crypto';

import { BUILT_IN_LIMITS } from '@scene-glass/contracts';
import Fastify, { type FastifyInstance } from 'fastify';
import type { Response as LightMyRequestResponse } from 'light-my-request';
import { describe, expect, it } from 'vitest';

import {
  createCredentialSubject,
  DIAGNOSTICS_AUDIENCE,
  SCENE_GLASS_AUDIENCE,
} from '../../packages/server/src/auth/credential-subject.js';
import type { AuthContext } from '../../packages/server/src/auth/auth-context.js';
import {
  createLocalTokenCredential,
  LocalTokenVerifier,
  type LocalTokenCredential,
  type LocalTokenCredentialInput,
  type RevocationCheckFailedEvidence,
  type VerifyBearerInput,
} from '../../packages/server/src/auth/local-token-verifier.js';
import { diagnosticRoute } from '../../packages/server/src/http/diagnostic-route.js';
import { mcpRoute, type McpDispatcherInput } from '../../packages/server/src/http/mcp-route.js';
import {
  SessionManager,
  type SessionInitializeInput,
  type SessionCommitInput,
  type SessionLookupInput,
} from '../../packages/server/src/mcp/session-manager.js';
import { SceneGlassLogger } from '../../packages/server/src/observability/logger.js';
import type {
  AuthorizedProject,
  OriginPolicy,
  ProjectRegistry,
} from '../../packages/server/src/registry/config-project-registry.js';

const ORIGIN = 'http://127.0.0.1:4317';
const PROJECT_ID = 'alpha';
const OTHER_PROJECT_ID = 'beta';
const MANAGED_CREDENTIAL_EXPIRY = Number.MAX_SAFE_INTEGER;
const ignoreRevocationCheckFailure = (): void => {};

const ALPHA_PROJECT: AuthorizedProject = Object.freeze({
  projectId: PROJECT_ID,
  effectiveLimits: BUILT_IN_LIMITS,
});

const BETA_PROJECT: AuthorizedProject = Object.freeze({
  projectId: OTHER_PROJECT_ID,
  effectiveLimits: BUILT_IN_LIMITS,
});

function opaqueToken(label: string): string {
  return createHash('sha256').update(label, 'utf8').digest('base64url');
}

type CredentialInput =
  | {
      readonly audience?: typeof SCENE_GLASS_AUDIENCE | typeof DIAGNOSTICS_AUDIENCE;
      readonly mode: 'restart-bound';
      readonly origin?: string;
      readonly projectId?: string;
      readonly token: string;
    }
  | {
      readonly audience?: typeof SCENE_GLASS_AUDIENCE | typeof DIAGNOSTICS_AUDIENCE;
      readonly expiresAt: number;
      readonly isRevoked: () => boolean;
      readonly mode: 'managed';
      readonly origin?: string;
      readonly projectId?: string;
      readonly token: string;
    };

function credential(input: CredentialInput): LocalTokenCredential {
  const projectId = input.projectId ?? PROJECT_ID;
  const subject = createCredentialSubject({
    audience: input.audience ?? SCENE_GLASS_AUDIENCE,
    projectId,
  });
  const origin = input.origin ?? ORIGIN;

  if (input.mode === 'restart-bound') {
    return createLocalTokenCredential({
      mode: 'restart-bound',
      origin,
      subject,
      token: input.token,
    });
  }

  return createLocalTokenCredential({
    expiresAt: input.expiresAt,
    isRevoked: input.isRevoked,
    mode: 'managed',
    origin,
    subject,
    token: input.token,
  });
}

function problemCode(response: LightMyRequestResponse): string {
  const payload = response.json<unknown>();
  const code =
    typeof payload === 'object' && payload !== null && 'code' in payload ? payload.code : undefined;

  expect(typeof code).toBe('string');
  if (typeof code !== 'string') {
    throw new Error('Expected problem response body to contain a string code');
  }
  return code;
}

function headerValue(response: LightMyRequestResponse, name: string): string | undefined {
  const value = response.headers[name];
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return value === undefined ? undefined : String(value);
}

function expectAllowedCors(response: LightMyRequestResponse): void {
  expect(headerValue(response, 'access-control-allow-origin')).toBe(ORIGIN);
  expect(headerValue(response, 'vary')).toBe('Origin');
  expect(headerValue(response, 'access-control-allow-credentials')).toBeUndefined();
  expect(headerValue(response, 'access-control-allow-origin')).not.toBe('*');
}

function expectOriginDisclosureDenied(response: LightMyRequestResponse): void {
  expect(response.body).toBe('');
  expect(headerValue(response, 'access-control-allow-origin')).toBeUndefined();
  expect(headerValue(response, 'vary')).toBeUndefined();
  expect(headerValue(response, 'www-authenticate')).toBeUndefined();
}

interface RouteHarness {
  readonly app: FastifyInstance;
  readonly calls: {
    auth: number;
    dispatch: number;
    origin: number;
    root: number;
    session: number;
  };
  readonly events: string[];
  readonly sessions: SessionManager;
  readonly revocationCheckFailures: readonly RevocationCheckFailedEvidence[];
}

async function createMcpHarness(input: {
  readonly credentials: readonly LocalTokenCredential[];
  readonly policy?: OriginPolicy | undefined;
  readonly policyForProject?: (projectId: string) => OriginPolicy | undefined;
  readonly projects?: readonly AuthorizedProject[];
}): Promise<RouteHarness> {
  const calls = { auth: 0, dispatch: 0, origin: 0, root: 0, session: 0 };
  const events: string[] = [];
  const policy =
    input.policy ??
    Object.freeze({
      projectId: PROJECT_ID,
      allowsOrigin(origin: string): boolean {
        return origin === ORIGIN;
      },
    });
  const projects = input.projects ?? [ALPHA_PROJECT];
  const sessions = new SessionManager();
  const revocationCheckFailures: RevocationCheckFailedEvidence[] = [];
  const verifier = new LocalTokenVerifier(input.credentials, {
    onRevocationCheckFailed: input.credentials.every(
      (credential) => credential.mode === 'restart-bound',
    )
      ? ignoreRevocationCheckFailure
      : (evidence) => {
          revocationCheckFailures.push(evidence);
        },
  });
  const registry: ProjectRegistry = {
    getOriginPolicy(projectId: string): OriginPolicy | undefined {
      calls.origin += 1;
      events.push('origin');
      return (
        input.policyForProject?.(projectId) ??
        (projects.some((project: AuthorizedProject) => project.projectId === projectId)
          ? policy
          : undefined)
      );
    },
    resolveAuthorizedProject(auth: AuthContext) {
      calls.root += 1;
      events.push('root');
      return projects.find((project: AuthorizedProject) => project.projectId === auth.projectId);
    },
  };
  const app = Fastify({ logger: false });
  await app.register(mcpRoute, {
    dispatcher: {
      dispatch(input: McpDispatcherInput) {
        calls.dispatch += 1;
        return {
          jsonrpc: '2.0',
          id: input.message.id ?? null,
          result:
            input.message.method === 'initialize'
              ? {
                  capabilities: {},
                  protocolVersion: '2025-11-25',
                  serverInfo: { name: 'test', version: '1.0.0' },
                }
              : { projectId: input.project.projectId },
        };
      },
    },
    maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
    logger: new SceneGlassLogger(),
    registry,
    sessions: {
      initialize(input: SessionInitializeInput) {
        calls.session += 1;
        return sessions.initialize(input);
      },
      commit(input: SessionCommitInput) {
        return sessions.commit(input);
      },
      lookup(input: SessionLookupInput) {
        calls.session += 1;
        return sessions.lookup(input);
      },
      abort(sessionId: string | undefined) {
        return sessions.abort(sessionId);
      },
      close(sessionId: string) {
        return sessions.close(sessionId);
      },
    },
    verifier: {
      verify(input: VerifyBearerInput) {
        calls.auth += 1;
        events.push('auth');
        return verifier.verify(input);
      },
    },
  });
  await app.ready();
  return { app, calls, events, revocationCheckFailures, sessions };
}

async function closeHarness(harness: RouteHarness): Promise<void> {
  await harness.app.close();
  harness.sessions.shutdown();
}

function initializeRequest(token: string, projectId = PROJECT_ID) {
  return {
    method: 'POST' as const,
    url: `/mcp/v1/projects/${projectId}`,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      origin: ORIGIN,
    },
    payload: { id: 1, jsonrpc: '2.0', method: 'initialize' },
  };
}

describe('MCP exact Origin, authentication, and root ordering', () => {
  it('accepts only the configured scheme, host, and port without origin disclosure', async () => {
    const token = opaqueToken('cors-exact-origin');
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', token })],
    });

    try {
      for (const origin of [
        'https://127.0.0.1:4317',
        'http://127.0.0.1',
        'http://127.0.0.1:4318',
        'http://127.0.0.1:4317.evil.test',
        'http://evil.test/127.0.0.1:4317',
        '*',
        'null',
      ]) {
        const response = await harness.app.inject({
          ...initializeRequest(token),
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
            origin,
          },
        });

        expect(response.statusCode).toBe(403);
        expectOriginDisclosureDenied(response);
      }

      expect(harness.calls).toEqual({
        auth: 0,
        dispatch: 0,
        origin: 7,
        root: 0,
        session: 0,
      });
      expect(harness.sessions.activeSessionCount).toBe(0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('handles PNA only when a valid preflight asks for it and rejects malicious header requests', async () => {
    const token = opaqueToken('cors-preflight');
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', token })],
    });

    try {
      const pna = await harness.app.inject({
        method: 'OPTIONS',
        url: `/mcp/v1/projects/${PROJECT_ID}`,
        headers: {
          'access-control-request-headers': 'authorization, content-type',
          'access-control-request-method': 'POST',
          'access-control-request-private-network': 'true',
          origin: ORIGIN,
        },
      });
      expect(pna.statusCode).toBe(204);
      expectAllowedCors(pna);
      expect(headerValue(pna, 'access-control-allow-methods')).toBe('POST');
      expect(headerValue(pna, 'access-control-allow-headers')).toBe('authorization, content-type');
      expect(headerValue(pna, 'access-control-allow-private-network')).toBe('true');

      const ordinary = await harness.app.inject({
        method: 'OPTIONS',
        url: `/mcp/v1/projects/${PROJECT_ID}`,
        headers: {
          'access-control-request-headers': 'authorization',
          'access-control-request-method': 'POST',
          'access-control-request-private-network': 'false',
          origin: ORIGIN,
        },
      });
      expect(ordinary.statusCode).toBe(204);
      expectAllowedCors(ordinary);
      expect(headerValue(ordinary, 'access-control-allow-private-network')).toBeUndefined();

      for (const headers of [
        {
          'access-control-request-headers': 'authorization, x-admin',
          'access-control-request-method': 'POST',
        },
        {
          'access-control-request-headers': 'authorization, authorization',
          'access-control-request-method': 'POST',
        },
        {
          'access-control-request-headers': 'authorization, Content Type',
          'access-control-request-method': 'POST',
        },
        {
          'access-control-request-headers': 'authorization',
          'access-control-request-method': 'PATCH',
        },
      ]) {
        const response = await harness.app.inject({
          method: 'OPTIONS',
          url: `/mcp/v1/projects/${PROJECT_ID}`,
          headers: { ...headers, origin: ORIGIN },
        });
        expect(response.statusCode).toBe(400);
        expect(problemCode(response)).toBe('SCG_CORS_PREFLIGHT_INVALID');
        expectAllowedCors(response);
        expect(headerValue(response, 'access-control-allow-private-network')).toBeUndefined();
      }

      expect(harness.calls).toEqual({
        auth: 0,
        dispatch: 0,
        origin: 6,
        root: 0,
        session: 0,
      });
      expect(harness.sessions.activeSessionCount).toBe(0);
    } finally {
      await closeHarness(harness);
    }
  });
  it('keeps diagnostic preflight root-free with route-specific headers and conditional PNA', async () => {
    const calls = { auth: 0, issue: 0, origin: 0, root: 0 };
    const registry: ProjectRegistry = {
      getOriginPolicy(projectId: string) {
        calls.origin += 1;
        return projectId === PROJECT_ID
          ? {
              projectId: PROJECT_ID,
              allowsOrigin(origin: string): boolean {
                return origin === ORIGIN;
              },
            }
          : undefined;
      },
      resolveAuthorizedProject() {
        calls.root += 1;
        return ALPHA_PROJECT;
      },
    };
    const app = Fastify({ logger: false });
    await app.register(diagnosticRoute, {
      endpointForProject: () => 'http://127.0.0.1:4317/mcp/v1/projects/alpha',
      issuer: {
        issue() {
          calls.issue += 1;
          return { code: 'SCG_DIAGNOSTIC_INVALID', ok: false, status: 401 };
        },
      },
      maxBodyBytes: BUILT_IN_LIMITS.httpBodyBytes,
      registry,
      verifier: {
        verify() {
          calls.auth += 1;
          return { code: 'SCG_AUTH_INVALID', ok: false, status: 401 };
        },
      },
    });
    await app.ready();

    try {
      const pna = await app.inject({
        method: 'OPTIONS',
        url: `/mcp/v1/projects/${PROJECT_ID}/diagnostic-runs`,
        headers: {
          'access-control-request-headers': 'authorization, content-type',
          'access-control-request-method': 'POST',
          'access-control-request-private-network': 'true',
          origin: ORIGIN,
        },
      });
      expect(pna.statusCode).toBe(204);
      expectAllowedCors(pna);
      expect(headerValue(pna, 'access-control-allow-methods')).toBe('POST');
      expect(headerValue(pna, 'access-control-allow-headers')).toBe('authorization, content-type');
      expect(headerValue(pna, 'access-control-allow-private-network')).toBe('true');

      const malicious = await app.inject({
        method: 'OPTIONS',
        url: `/mcp/v1/projects/${PROJECT_ID}/diagnostic-runs`,
        headers: {
          'access-control-request-headers': 'authorization, mcp-session-id',
          'access-control-request-method': 'POST',
          origin: ORIGIN,
        },
      });
      expect(malicious.statusCode).toBe(400);
      expect(problemCode(malicious)).toBe('SCG_CORS_PREFLIGHT_INVALID');
      expectAllowedCors(malicious);
      expect(headerValue(malicious, 'access-control-allow-private-network')).toBeUndefined();

      const denied = await app.inject({
        method: 'OPTIONS',
        url: `/mcp/v1/projects/${PROJECT_ID}/diagnostic-runs`,
        headers: {
          'access-control-request-headers': 'authorization',
          'access-control-request-method': 'POST',
          origin: 'http://127.0.0.1:4317.evil.test',
        },
      });
      expect(denied.statusCode).toBe(403);
      expectOriginDisclosureDenied(denied);
      expect(calls).toEqual({ auth: 0, issue: 0, origin: 3, root: 0 });
    } finally {
      await app.close();
    }
  });

  it('does not authenticate or resolve a root for a repeated or unconfigured Origin', async () => {
    const token = opaqueToken('cors-repeated-origin');
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', token })],
    });

    try {
      const repeated = await harness.app.inject({
        ...initializeRequest(token),
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          origin: `${ORIGIN}, ${ORIGIN}`,
        },
      });
      expect(repeated.statusCode).toBe(403);
      expectOriginDisclosureDenied(repeated);

      const unknownProject = await harness.app.inject({
        ...initializeRequest(token, 'unknown'),
      });
      expect(unknownProject.statusCode).toBe(403);
      expectOriginDisclosureDenied(unknownProject);

      expect(harness.calls).toEqual({
        auth: 0,
        dispatch: 0,
        origin: 2,
        root: 0,
        session: 0,
      });
      expect(harness.sessions.activeSessionCount).toBe(0);
    } finally {
      await closeHarness(harness);
    }
  });
  it('keeps lifecycle-transformed Origins exact and withholds CORS and root access across projects', async () => {
    const transformedOrigin = 'http://127.0.0.1:4175';
    const token = opaqueToken('cors-transformed-origin');
    const transformedPolicy: OriginPolicy = Object.freeze({
      projectId: PROJECT_ID,
      allowsOrigin: (origin: string) => origin === transformedOrigin,
    });
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', origin: transformedOrigin, token })],
      policyForProject: (projectId) => (projectId === PROJECT_ID ? transformedPolicy : undefined),
      projects: [ALPHA_PROJECT, BETA_PROJECT],
    });

    try {
      const transformed = await harness.app.inject({
        ...initializeRequest(token),
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          origin: transformedOrigin,
        },
      });
      expect(transformed.statusCode).toBe(200);
      expect(headerValue(transformed, 'access-control-allow-origin')).toBe(transformedOrigin);

      for (const origin of [ORIGIN, 'http://localhost:4175']) {
        const denied = await harness.app.inject({
          ...initializeRequest(token),
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
            origin,
          },
        });
        expect(denied.statusCode).toBe(403);
        expectOriginDisclosureDenied(denied);
      }

      const crossProject = await harness.app.inject({
        ...initializeRequest(token, OTHER_PROJECT_ID),
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          origin: transformedOrigin,
        },
      });
      expect(crossProject.statusCode).toBe(403);
      expectOriginDisclosureDenied(crossProject);
      expect(harness.calls).toEqual({
        auth: 1,
        dispatch: 1,
        origin: 4,
        root: 1,
        session: 1,
      });
    } finally {
      await closeHarness(harness);
    }
  });

  it('requires explicit credential lifecycles and rejects invalid lifecycle values', () => {
    const input = {
      origin: ORIGIN,
      subject: createCredentialSubject({
        audience: SCENE_GLASS_AUDIENCE,
        projectId: PROJECT_ID,
      }),
      token: opaqueToken('cors-credential-input'),
    };
    const restartBound = createLocalTokenCredential({
      ...input,
      mode: 'restart-bound',
    });

    expect(restartBound.expiresAt).toBe(Number.POSITIVE_INFINITY);
    expect(restartBound.scopes).toEqual([]);
    expect(restartBound.isRevoked()).toBe(false);

    const malformedInputs = [
      { ...input, expiresAt: undefined, mode: 'restart-bound' },
      { ...input, isRevoked: undefined, mode: 'restart-bound' },
      {
        ...input,
        expiresAt: null,
        isRevoked: () => false,
        mode: 'managed',
      },
      {
        ...input,
        expiresAt: Number.NaN,
        isRevoked: () => false,
        mode: 'managed',
      },
      {
        ...input,
        expiresAt: MANAGED_CREDENTIAL_EXPIRY,
        isRevoked: () => false,
        mode: 'managed',
        scopes: null,
      },
      {
        ...input,
        expiresAt: MANAGED_CREDENTIAL_EXPIRY,
        isRevoked: () => false,
        mode: 'managed',
        scopes: 'project:read',
      },
      {
        ...input,
        expiresAt: MANAGED_CREDENTIAL_EXPIRY,
        isRevoked: null,
        mode: 'managed',
      },
      {
        ...input,
        expiresAt: MANAGED_CREDENTIAL_EXPIRY,
        isRevoked: false,
        mode: 'managed',
      },
      {
        ...input,
        expiresAt: MANAGED_CREDENTIAL_EXPIRY,
        isRevoked: Promise.resolve(false),
        mode: 'managed',
      },
    ] as const;

    for (const malformedInput of malformedInputs) {
      expect(() =>
        createLocalTokenCredential(malformedInput as unknown as LocalTokenCredentialInput),
      ).toThrow(TypeError);
    }
  });

  it('fails revocation checks closed unless they return literal false', () => {
    const callbackFailureToken = opaqueToken('cors-revocation-a thrown error');
    const callbackFailureRoot = '/private/revocation-root';
    const callbackFailureSubject = 'private-revocation-subject';
    const revocationCheckFailures: RevocationCheckFailedEvidence[] = [];
    const cases: readonly { readonly check: () => unknown; readonly name: string }[] = [
      { check: () => true, name: 'true' },
      { check: () => undefined, name: 'undefined' },
      { check: () => 'false', name: 'a string' },
      { check: () => Promise.resolve(false), name: 'a promise' },
      {
        check: () => {
          throw new Error(
            `issuer unavailable ${callbackFailureToken} ${callbackFailureRoot} ${callbackFailureSubject}`,
          );
        },
        name: 'a thrown error',
      },
    ];

    for (const testCase of cases) {
      const token = opaqueToken(`cors-revocation-${testCase.name}`);
      const verifier = new LocalTokenVerifier(
        [
          credential({
            expiresAt: MANAGED_CREDENTIAL_EXPIRY,
            isRevoked: testCase.check as unknown as () => boolean,
            mode: 'managed',
            token,
          }),
        ],
        {
          onRevocationCheckFailed(evidence) {
            revocationCheckFailures.push(evidence);
          },
        },
      );

      expect(
        verifier.verify({
          authorization: `Bearer ${token}`,
          origin: ORIGIN,
          now: 1,
        }),
      ).toEqual({
        ok: false,
        status: 401,
        code: 'SCG_AUTH_EXPIRED',
      });
    }

    expect(revocationCheckFailures).toStrictEqual([
      { credentialMode: 'managed', event: 'revocation-check-failed' },
    ]);
    const serializedEvidence = JSON.stringify(revocationCheckFailures);
    expect(serializedEvidence).not.toContain(callbackFailureToken);
    expect(serializedEvidence).not.toContain(callbackFailureRoot);
    expect(serializedEvidence).not.toContain(callbackFailureSubject);
  });

  it('retains strict revocation semantics in verified session contexts', () => {
    let result: unknown = false;
    const token = opaqueToken('cors-revocation-session');
    const revocationCheckFailures: RevocationCheckFailedEvidence[] = [];
    const verifier = new LocalTokenVerifier(
      [
        credential({
          expiresAt: MANAGED_CREDENTIAL_EXPIRY,
          isRevoked: (() => result) as unknown as () => boolean,
          mode: 'managed',
          token,
        }),
      ],
      {
        onRevocationCheckFailed(evidence) {
          revocationCheckFailures.push(evidence);
        },
      },
    );
    const verified = verifier.verify({
      authorization: `Bearer ${token}`,
      origin: ORIGIN,
      now: 1,
    });

    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      throw new Error('Expected an active credential');
    }

    result = Promise.resolve(false);
    expect(verified.context.isActiveAt(1)).toBe(false);
    expect(revocationCheckFailures).toEqual([]);
  });

  it('snapshots accessor-backed credentials before validating retained values', () => {
    const token = opaqueToken('cors-accessor-credential');
    const source = credential({
      expiresAt: 1,
      isRevoked: () => false,
      mode: 'managed',
      token,
    });
    const reads = {
      expiresAt: 0,
      isRevoked: 0,
      origin: 0,
      scopes: 0,
      subject: 0,
      tokenDigest: 0,
      mode: 0,
    };
    const accessorCredential = {
      get mode() {
        reads.mode += 1;
        return source.mode;
      },
      get subject() {
        reads.subject += 1;
        return source.subject;
      },
      get tokenDigest() {
        reads.tokenDigest += 1;
        return source.tokenDigest;
      },
      get expiresAt() {
        reads.expiresAt += 1;
        return reads.expiresAt === 1 ? 1 : Number.POSITIVE_INFINITY;
      },
      get origin() {
        reads.origin += 1;
        return source.origin;
      },
      get scopes() {
        reads.scopes += 1;
        return source.scopes;
      },
      get isRevoked() {
        reads.isRevoked += 1;
        return source.isRevoked;
      },
    } as LocalTokenCredential;
    const revocationCheckFailures: RevocationCheckFailedEvidence[] = [];
    const verifier = new LocalTokenVerifier([accessorCredential], {
      onRevocationCheckFailed(evidence) {
        revocationCheckFailures.push(evidence);
      },
    });

    expect(reads).toEqual({
      expiresAt: 1,
      isRevoked: 1,
      origin: 1,
      scopes: 1,
      subject: 1,
      mode: 1,
      tokenDigest: 1,
    });
    expect(
      verifier.verify({
        authorization: `Bearer ${token}`,
        origin: ORIGIN,
        now: 1,
      }),
    ).toEqual({
      ok: false,
      status: 401,
      code: 'SCG_AUTH_EXPIRED',
    });
    expect(reads).toEqual({
      expiresAt: 1,
      isRevoked: 1,
      origin: 1,
      scopes: 1,
      subject: 1,
      mode: 1,
      tokenDigest: 1,
    });
    expect(revocationCheckFailures).toEqual([]);
  });
  it('rejects malformed bearer values before revocation and root resolution', async () => {
    let revocationChecks = 0;
    const token = opaqueToken('cors-bearer');
    const harness = await createMcpHarness({
      credentials: [
        credential({
          isRevoked: () => {
            revocationChecks += 1;
            return false;
          },
          token,
          expiresAt: MANAGED_CREDENTIAL_EXPIRY,
          mode: 'managed',
        }),
      ],
    });

    try {
      for (const authorization of [
        'Basic ignored',
        `Bearer ${token} trailing`,
        `Bearer ${token}.suffix`,
        `Bearer  ${token}`,
        `Bearer${token}`,
      ]) {
        const response = await harness.app.inject({
          ...initializeRequest(token),
          headers: {
            authorization,
            'content-type': 'application/json',
            origin: ORIGIN,
          },
        });
        expect(response.statusCode).toBe(401);
        expect(problemCode(response)).toBe('SCG_AUTH_INVALID');
        expectAllowedCors(response);
        expect(headerValue(response, 'www-authenticate')).toBe('Bearer');
      }

      expect(revocationChecks).toBe(0);
      expect(harness.calls).toEqual({
        auth: 5,
        dispatch: 0,
        origin: 5,
        root: 0,
        session: 0,
      });
      expect(harness.sessions.activeSessionCount).toBe(0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('denies wrong audience, project binding, expiry, and revocation with stable codes before root use', async () => {
    const audienceToken = opaqueToken('cors-audience');
    const expiredToken = opaqueToken('cors-expired');
    const revokedToken = opaqueToken('cors-revoked');
    const cases = [
      {
        name: 'wrong audience',
        credential: credential({
          audience: DIAGNOSTICS_AUDIENCE,
          mode: 'restart-bound',
          token: audienceToken,
        }),
        expectedCode: 'SCG_AUTH_INVALID',
        projectId: PROJECT_ID,
        token: audienceToken,
      },
      {
        name: 'expired credential',
        credential: credential({
          expiresAt: 1,
          isRevoked: () => false,
          mode: 'managed',
          token: expiredToken,
        }),
        expectedCode: 'SCG_AUTH_EXPIRED',
        projectId: PROJECT_ID,
        token: expiredToken,
      },
      {
        name: 'revoked credential',
        credential: credential({
          isRevoked: () => true,
          expiresAt: MANAGED_CREDENTIAL_EXPIRY,
          mode: 'managed',
          token: revokedToken,
        }),
        expectedCode: 'SCG_AUTH_EXPIRED',
        projectId: PROJECT_ID,
        token: revokedToken,
      },
    ] as const;

    for (const testCase of cases) {
      const harness = await createMcpHarness({ credentials: [testCase.credential] });
      try {
        const response = await harness.app.inject(
          initializeRequest(testCase.token, testCase.projectId),
        );
        expect(response.statusCode).toBe(401);
        expect(problemCode(response)).toBe(testCase.expectedCode);
        expectAllowedCors(response);
        expect(harness.calls).toEqual({
          auth: 1,
          dispatch: 0,
          origin: 1,
          root: 0,
          session: 0,
        });
        expect(harness.sessions.activeSessionCount).toBe(0);
      } finally {
        await closeHarness(harness);
      }
    }

    const projectToken = opaqueToken('cors-project-binding');
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', token: projectToken })],
      projects: [ALPHA_PROJECT, BETA_PROJECT],
    });
    try {
      const response = await harness.app.inject(initializeRequest(projectToken, OTHER_PROJECT_ID));
      expect(response.statusCode).toBe(403);
      expect(problemCode(response)).toBe('SCG_PROJECT_FORBIDDEN');
      expectAllowedCors(response);
      expect(harness.calls).toEqual({
        auth: 1,
        dispatch: 0,
        origin: 1,
        root: 0,
        session: 0,
      });
      expect(harness.sessions.activeSessionCount).toBe(0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('uses the literal Origin, then bearer verification, then project resolution on a successful request', async () => {
    const token = opaqueToken('cors-order');
    const harness = await createMcpHarness({
      credentials: [credential({ mode: 'restart-bound', token })],
    });

    try {
      const response = await harness.app.inject(initializeRequest(token));
      expect(response.statusCode).toBe(200);
      expectAllowedCors(response);
      expect(harness.events).toEqual(['origin', 'auth', 'root']);
      expect(harness.calls).toEqual({
        auth: 1,
        dispatch: 1,
        origin: 1,
        root: 1,
        session: 1,
      });
      expect(harness.sessions.activeSessionCount).toBe(1);
    } finally {
      await closeHarness(harness);
    }
  });
});
