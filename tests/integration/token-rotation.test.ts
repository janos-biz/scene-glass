import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { MCP_PROTOCOL_VERSION } from '../../packages/server/src/mcp/dispatcher.js';
import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';
import {
  createManagedLocalTokenCredential,
  createLocalTokenCredential,
  createRestartBoundLocalTokenCredential,
  LocalTokenVerifier,
} from '../../packages/server/src/auth/local-token-verifier.js';
import {
  createCredentialSubject,
  SCENE_GLASS_AUDIENCE,
} from '../../packages/server/src/auth/credential-subject.js';

const ORIGIN = 'https://rotation.scene-glass.test';
const PROJECT_ID = 'rotation';
const OLD_TOKEN = opaqueToken(11);
const NEW_TOKEN = opaqueToken(12);
const runningServers = new Set<RunningServer>();
const temporaryWorkspaces = new Set<string>();

afterEach(async () => {
  await Promise.all([...runningServers].map((server) => closeServer(server)));
  await Promise.all(
    [...temporaryWorkspaces].map(async (workspace) => {
      temporaryWorkspaces.delete(workspace);
      await rm(workspace, { force: true, recursive: true });
    }),
  );
});
describe('explicit local credential lifecycle', () => {
  it('requires an explicit lifecycle and permits only the matching factory inputs', () => {
    const base = {
      token: OLD_TOKEN,
      subject: createCredentialSubject({
        audience: SCENE_GLASS_AUDIENCE,
        projectId: PROJECT_ID,
      }),
      origin: ORIGIN,
    };

    expect(() =>
      createLocalTokenCredential(
        base as unknown as Parameters<typeof createLocalTokenCredential>[0],
      ),
    ).toThrow('credential lifecycle mode is invalid');
    expect(() =>
      createRestartBoundLocalTokenCredential({
        ...base,
        expiresAt: 1,
      } as unknown as Parameters<typeof createRestartBoundLocalTokenCredential>[0]),
    ).toThrow('restart-bound credential factory does not accept lifecycle overrides');
    expect(() =>
      createRestartBoundLocalTokenCredential({
        ...base,
        isRevoked: () => false,
      } as unknown as Parameters<typeof createRestartBoundLocalTokenCredential>[0]),
    ).toThrow('restart-bound credential factory does not accept lifecycle overrides');

    const restartBound = createRestartBoundLocalTokenCredential(base);
    const managed = createManagedLocalTokenCredential({
      ...base,
      expiresAt: 1_700_000_060_000,
      isRevoked: () => false,
    });

    expect(restartBound).toMatchObject({
      mode: 'restart-bound',
      expiresAt: Number.POSITIVE_INFINITY,
    });
    expect(managed).toMatchObject({
      mode: 'managed',
      expiresAt: 1_700_000_060_000,
    });
  });

  it('snapshots issuer fields while applying captured managed revocation to verification and issued contexts', () => {
    let revoked = false;
    const sourceSubject: {
      audience: typeof SCENE_GLASS_AUDIENCE;
      projectId: string;
      id: string;
    } = {
      audience: SCENE_GLASS_AUDIENCE,
      projectId: PROJECT_ID,
      id: `${SCENE_GLASS_AUDIENCE}:${PROJECT_ID}`,
    };
    const sourceScopes = ['project:read'];
    const issuer = {
      token: OLD_TOKEN,
      subject: sourceSubject,
      origin: ORIGIN,
      scopes: sourceScopes,
      expiresAt: 1_700_000_060_000,
      isRevoked: () => revoked,
    };
    const credential = createManagedLocalTokenCredential(issuer);
    const verifierSource = {
      mode: 'managed' as const,
      subject: sourceSubject,
      tokenDigest: credential.tokenDigest,
      expiresAt: issuer.expiresAt,
      origin: issuer.origin,
      scopes: sourceScopes,
      isRevoked: issuer.isRevoked,
    };
    const verifier = new LocalTokenVerifier([verifierSource], {
      onRevocationCheckFailed: () => undefined,
    });

    sourceSubject.projectId = 'mutated-project';
    sourceSubject.id = `${SCENE_GLASS_AUDIENCE}:mutated-project`;
    sourceScopes[0] = 'project:write';
    issuer.origin = 'https://mutated.scene-glass.test';
    issuer.expiresAt = 1_700_000_120_000;
    issuer.isRevoked = () => false;
    verifierSource.origin = 'https://other-mutated.scene-glass.test';
    verifierSource.expiresAt = 1_700_000_180_000;
    verifierSource.isRevoked = () => false;

    const verified = verifier.verify({
      authorization: `Bearer ${OLD_TOKEN}`,
      origin: ORIGIN,
      now: 1_700_000_000_000,
    });
    if (!verified.ok) {
      throw new Error('expected initial managed credential verification');
    }
    expect(verified.context.subject).toEqual(
      createCredentialSubject({
        audience: SCENE_GLASS_AUDIENCE,
        projectId: PROJECT_ID,
      }),
    );
    expect(verified.context.scopes).toEqual(['project:read']);

    revoked = true;

    expect(
      verifier.verify({
        authorization: `Bearer ${OLD_TOKEN}`,
        origin: ORIGIN,
        now: 1_700_000_000_000,
      }),
    ).toEqual({ ok: false, status: 401, code: 'SCG_AUTH_EXPIRED' });
    expect(verified.context.isRevoked()).toBe(true);
    expect(verified.context.isActiveAt(1_700_000_000_000)).toBe(false);
  });

  it('fails closed and emits redacted structured evidence when managed revocation throws', () => {
    const sentinel = 'REVOCATION_CALLBACK_SENTINEL';
    let throwRevocation = false;
    const evidence: unknown[] = [];
    const verifier = new LocalTokenVerifier(
      [
        createManagedLocalTokenCredential({
          token: OLD_TOKEN,
          subject: createCredentialSubject({
            audience: SCENE_GLASS_AUDIENCE,
            projectId: PROJECT_ID,
          }),
          origin: ORIGIN,
          expiresAt: 1_700_000_060_000,
          isRevoked: () => {
            if (throwRevocation) {
              throw new Error(sentinel, { cause: new Error(sentinel) });
            }
            return false;
          },
        }),
      ],
      {
        onRevocationCheckFailed: (record) => evidence.push(record),
      },
    );

    const issued = verifier.verify({
      authorization: `Bearer ${OLD_TOKEN}`,
      origin: ORIGIN,
      now: 1_700_000_000_000,
    });
    if (!issued.ok) {
      throw new Error('expected an issued managed auth context');
    }

    throwRevocation = true;

    expect(issued.context.isRevoked()).toBe(true);
    expect(
      verifier.verify({
        authorization: `Bearer ${OLD_TOKEN}`,
        origin: ORIGIN,
        now: 1_700_000_000_000,
      }),
    ).toEqual({ ok: false, status: 401, code: 'SCG_AUTH_EXPIRED' });
    expect(evidence).toEqual([
      { event: 'revocation-check-failed', credentialMode: 'managed' },
      { event: 'revocation-check-failed', credentialMode: 'managed' },
    ]);
    expect(JSON.stringify(evidence)).not.toContain(sentinel);
  });
});

describe('normal bearer rotation across a coordinated authority restart', () => {
  it('tears down old sessions, accepts no dual-token overlap, and never logs either raw token', async () => {
    const fixture = await createFixture();
    const logRecords: SceneGlassLogRecord[] = [];
    const oldLogger = new SceneGlassLogger({ sink: (record) => logRecords.push(record) });
    const oldServer = await startServer(fixture, OLD_TOKEN, oldLogger);

    const oldInitialized = await postMcp(oldServer, {
      token: OLD_TOKEN,
      message: initializeMessage(1),
    });
    expect(oldInitialized.status).toBe(200);
    expectNoStore(oldInitialized);
    const oldSessionId = oldInitialized.headers.get('mcp-session-id');
    if (oldSessionId === null) {
      throw new Error('old initialize response omitted mcp-session-id');
    }
    expect(await oldInitialized.json()).toEqual({
      jsonrpc: '2.0',
      id: 1,
      result: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'scene-glass', version: '0.1.0' },
      },
    });

    await closeServer(oldServer);
    expect(oldServer.app.server.listening).toBe(false);

    const newLogger = new SceneGlassLogger({ sink: (record) => logRecords.push(record) });
    const newServer = await startServer(fixture, NEW_TOKEN, newLogger);

    const oldTokenRejected = await postMcp(newServer, {
      token: OLD_TOKEN,
      sessionId: oldSessionId,
      message: { jsonrpc: '2.0', id: 2, method: 'ping', params: {} },
    });
    await expectProblem(oldTokenRejected, 401, 'SCG_AUTH_INVALID');
    expect(oldTokenRejected.headers.get('retry-after')).toBeNull();

    const oldSessionRejected = await postMcp(newServer, {
      token: NEW_TOKEN,
      sessionId: oldSessionId,
      message: { jsonrpc: '2.0', id: 3, method: 'ping', params: {} },
    });
    await expectProblem(oldSessionRejected, 404, 'SCG_SESSION_NOT_FOUND');

    const newInitialized = await postMcp(newServer, {
      token: NEW_TOKEN,
      message: initializeMessage(4),
    });
    expect(newInitialized.status).toBe(200);
    expectNoStore(newInitialized);
    expect(newInitialized.headers.get('mcp-session-id')).not.toBeNull();

    const serializedLogs = logRecords.map((record) => newLogger.serialize(record));
    expect(JSON.stringify(logRecords)).not.toContain(OLD_TOKEN);
    expect(JSON.stringify(logRecords)).not.toContain(NEW_TOKEN);
    expect(JSON.stringify(serializedLogs)).not.toContain(OLD_TOKEN);
    expect(JSON.stringify(serializedLogs)).not.toContain(NEW_TOKEN);
  });
});

interface Fixture {
  readonly configPath: string;
  readonly workspace: string;
}

interface RunningServer {
  readonly app: Awaited<ReturnType<typeof createSceneGlassAppForTest>>;
  readonly endpoint: string;
}

async function createFixture(): Promise<Fixture> {
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-token-rotation-')));
  temporaryWorkspaces.add(workspace);
  const root = join(workspace, 'root');
  await mkdir(root);
  const canonicalRoot = await realpath(root);
  const configPath = join(workspace, 'scene-glass.json');
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      projects: [
        {
          projectId: PROJECT_ID,
          root: canonicalRoot,
          allowedOrigins: [ORIGIN],
          tokenEnv: 'SCG_ROTATION_TOKEN',
        },
      ],
    }),
  );
  return { configPath, workspace };
}

async function startServer(
  fixture: Fixture,
  token: string,
  logger: SceneGlassLogger,
): Promise<RunningServer> {
  const app = await createSceneGlassAppForTest({
    configPath: fixture.configPath,
    environment: { SCG_ROTATION_TOKEN: token },
    logger,
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
  const server = { app, endpoint };
  runningServers.add(server);
  return server;
}

async function closeServer(server: RunningServer): Promise<void> {
  if (!runningServers.delete(server)) {
    return;
  }
  await server.app.close();
}

async function postMcp(
  server: RunningServer,
  input: {
    readonly message: unknown;
    readonly sessionId?: string;
    readonly token: string;
  },
): Promise<Response> {
  return fetch(`${server.endpoint}/mcp/v1/projects/${PROJECT_ID}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${input.token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      origin: ORIGIN,
      ...(input.sessionId === undefined ? {} : { 'mcp-session-id': input.sessionId }),
    },
    body: JSON.stringify(input.message),
  });
}

function initializeMessage(id: number): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'rotation-integration', version: '1.0.0' },
    },
  };
}

async function expectProblem(response: Response, status: 401 | 404, code: string): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.get('content-type')).toContain('application/problem+json');
  expectNoStore(response);
  expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN);
  if (status === 401) {
    expect(response.headers.get('www-authenticate')).toBe('Bearer');
  }
  expect(await response.json()).toEqual({
    type: `urn:scene-glass:problem:${code.toLowerCase()}`,
    title: status === 401 ? 'Unauthorized' : 'Not Found',
    status,
    code,
  });
}

function expectNoStore(response: Response): void {
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('etag')).toBeNull();
  expect(response.headers.get('last-modified')).toBeNull();
}

function opaqueToken(fill: number): string {
  return Buffer.alloc(32, fill).toString('base64url');
}
