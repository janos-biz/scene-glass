import { access, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSceneGlassAppForTest,
  type ProjectRootProbe,
} from '../../packages/server/src/app.js';
import type { ProjectRootProbeResult } from '../../packages/server/src/platform/probe.js';

const ALPHA_ORIGIN = 'http://127.0.0.1:43201';
const BETA_ORIGIN = 'http://127.0.0.1:43202';
const ALPHA_TOKEN = Buffer.alloc(32, 0x31).toString('base64url');
const BETA_TOKEN = Buffer.alloc(32, 0x32).toString('base64url');
const activeHarnesses: Harness[] = [];

interface Clock {
  now: number;
}

interface Harness {
  readonly alphaRoot: string;
  readonly app: Awaited<ReturnType<typeof createSceneGlassAppForTest>>;
  readonly baseUrl: string;
  readonly betaRoot: string;
  readonly rootProbeCalls: ReadonlyMap<string, number>;
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

describe('MCP HTTP transport', () => {
  it('initializes a server-generated session and accepts an initialized notification over TCP', async () => {
    const harness = await startHarness({ now: 1_000 });

    const initialized = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 'initialize',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });

    expect(initialized.status).toBe(200);
    expect(initialized.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(initialized.headers.get('access-control-expose-headers')).toBe('mcp-session-id');
    const sessionId = initialized.headers.get('mcp-session-id');
    expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await initialized.json()).toEqual({
      id: 'initialize',
      jsonrpc: '2.0',
      result: {
        capabilities: { tools: { listChanged: false } },
        protocolVersion: '2025-11-25',
        serverInfo: { name: 'scene-glass', version: '0.1.0' },
      },
    });

    const notification = await jsonRequest(
      harness,
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      {
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {},
      },
      sessionId!,
    );
    expect(notification.status).toBe(202);
    expect(await notification.text()).toBe('');
    expect(notification.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(notification.headers.get('cache-control')).toBe('no-store');
    expect(notification.headers.get('mcp-session-id')).toBeNull();

    const ping = await jsonRequest(
      harness,
      'alpha',
      ALPHA_TOKEN,
      ALPHA_ORIGIN,
      { id: 'ping', jsonrpc: '2.0', method: 'ping', params: {} },
      sessionId!,
    );
    expect(ping.status).toBe(200);
    expect(ping.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(ping.headers.get('mcp-session-id')).toBeNull();
    expect(await ping.json()).toEqual({ id: 'ping', jsonrpc: '2.0', result: {} });
  });

  it('does not generate a session or touch an authorized root for invalid JSON-RPC', async () => {
    const harness = await startHarness({ now: 1_000 });
    const baselineProbeCalls = new Map(harness.rootProbeCalls);

    const response = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 9,
      jsonrpc: '1.0',
      method: 'initialize',
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('mcp-session-id')).toBeNull();
    expect(await response.json()).toMatchObject({
      error: { code: -32600 },
      id: null,
      jsonrpc: '2.0',
    });
    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });

  it('keeps the approved CORS envelope when an allowed request fails with 5xx', async () => {
    const harness = await startHarness({ now: -1 });
    const baselineProbeCalls = new Map(harness.rootProbeCalls);

    const response = await jsonRequest(harness, 'alpha', ALPHA_TOKEN, ALPHA_ORIGIN, {
      id: 'internal-failure',
      jsonrpc: '2.0',
      method: 'initialize',
      params: initializeParams(),
    });

    expect(response.status).toBe(500);
    expect(response.headers.get('access-control-allow-origin')).toBe(ALPHA_ORIGIN);
    expect(response.headers.get('vary')).toBe('Origin');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/problem+json');
    expect(await response.json()).toEqual({
      code: 'SCG_HTTP_INTERNAL',
      status: 500,
      title: 'Internal Server Error',
      type: 'urn:scene-glass:problem:scg_http_internal',
    });
    expect(harness.rootProbeCalls).toEqual(baselineProbeCalls);
    await expectNoStoreRoots(harness);
  });
});

async function startHarness(clock: Clock): Promise<Harness> {
  const alphaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-mcp-alpha-')));
  const betaRoot = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-mcp-beta-')));
  const configPath = join(alphaRoot, 'scene-glass.config.json');
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      projects: [
        {
          allowedOrigins: [ALPHA_ORIGIN],
          projectId: 'alpha',
          root: alphaRoot,
          tokenEnv: 'SCG_MCP_ALPHA_TOKEN',
        },
        {
          allowedOrigins: [BETA_ORIGIN],
          projectId: 'beta',
          root: betaRoot,
          tokenEnv: 'SCG_MCP_BETA_TOKEN',
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
    environment: {
      SCG_MCP_ALPHA_TOKEN: ALPHA_TOKEN,
      SCG_MCP_BETA_TOKEN: BETA_TOKEN,
    },
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
    rootProbeCalls,
  };
  activeHarnesses.push(harness);
  return harness;
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

function jsonRequest(
  harness: Harness,
  projectId: 'alpha' | 'beta',
  token: string,
  origin: string,
  body: unknown,
  sessionId?: string,
): Promise<Response> {
  return fetch(`${harness.baseUrl}/mcp/v1/projects/${projectId}`, {
    body: JSON.stringify(body),
    headers: {
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': '2025-11-25',
      ...(sessionId === undefined ? {} : { 'mcp-session-id': sessionId }),
      Origin: origin,
    },
    method: 'POST',
  });
}

function initializeParams(): Record<string, unknown> {
  return {
    capabilities: {},
    clientInfo: { name: 'mcp-http', version: '1.0.0' },
    protocolVersion: '2025-11-25',
  };
}

async function expectNoStoreRoots(harness: Harness): Promise<void> {
  await Promise.all(
    [harness.alphaRoot, harness.betaRoot].map((root) =>
      expect(access(join(root, '.scg'))).rejects.toMatchObject({ code: 'ENOENT' }),
    ),
  );
}
