import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer as createNetServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page, type Response } from '@playwright/test';
import type { FastifyInstance } from 'fastify';
import { build as buildVite, preview as createVitePreview, type PreviewServer } from 'vite';

import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { rootSupportedResult } from '../../packages/server/src/platform/probe.js';

const configuredLoaderUrl = requiredEnvironment('SCENE_GLASS_TEST_LOADER_URL');
const testProjectId = 'e2e-token-rotation';
const tokenEnvironmentName = 'SCENE_GLASS_E2E_TOKEN';
const fixtureRoots = {
  static: fileURLToPath(new URL('../../fixtures/static-html', import.meta.url)),
  vue: fileURLToPath(new URL('../../fixtures/vue3-spa', import.meta.url)),
} as const;

declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

type FixtureKind = keyof typeof fixtureRoots;

type FixtureHost = {
  readonly kind: FixtureKind;
  readonly origin: string;
  readonly url: string;
  close(): Promise<void>;
  restart(token: string): Promise<void>;
};

type RotationHarness = {
  readonly origin: string;
  readonly projectId: string;
  readonly root: string;
  close(): Promise<void>;
  rotate(nextToken: string): Promise<void>;
};
type RotationScenario = {
  readonly harness: RotationHarness;
  readonly host: FixtureHost;
};

type AuthorizationClassification = 'matches-expected-token' | 'missing' | 'mismatched-token';

const rotationSetupAttempts = 5;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} must be configured for browser acceptance tests`);
  }
  return value;
}

function opaqueToken(): string {
  return randomBytes(32).toString('base64url');
}
function classifyBearerAuthorization(
  authorization: string | undefined,
  expectedToken: string,
): AuthorizationClassification {
  if (authorization === undefined) {
    return 'missing';
  }
  return authorization === `Bearer ${expectedToken}`
    ? 'matches-expected-token'
    : 'mismatched-token';
}

function fixtureUrl(kind: FixtureKind, origin: string): string {
  return kind === 'static' ? `${origin}/index.html` : `${origin}/`;
}

function fixtureHeading(kind: FixtureKind): string {
  return kind === 'static' ? 'Scene Glass document navigation' : 'Scene Glass Vue SPA fixture';
}

async function reserveLoopbackPort(): Promise<number> {
  const reservation = createNetServer();

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        reservation.off('listening', onListening);
        reject(error);
      };
      const onListening = (): void => {
        reservation.off('error', onError);
        resolve();
      };

      reservation.once('error', onError);
      reservation.once('listening', onListening);
      reservation.listen({ host: '127.0.0.1', port: 0 });
    });

    const address = reservation.address();
    if (address === null || typeof address === 'string') {
      throw new Error('loopback port reservation has no TCP address');
    }
    return address.port;
  } finally {
    if (reservation.listening) {
      await new Promise<void>((resolve, reject) => {
        reservation.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  }
}
async function reserveDistinctLoopbackPorts(): Promise<readonly [number, number]> {
  const hostPort = await reserveLoopbackPort();
  for (let attempt = 1; attempt <= rotationSetupAttempts; attempt += 1) {
    const authorityPort = await reserveLoopbackPort();
    if (authorityPort !== hostPort) {
      return [hostPort, authorityPort];
    }
  }
  throw new Error('unable to reserve distinct loopback ports');
}

function isAddressInUse(error: unknown): boolean {
  let candidate = error;
  const visited = new Set<unknown>();

  while (typeof candidate === 'object' && candidate !== null && !visited.has(candidate)) {
    visited.add(candidate);
    if ('code' in candidate && candidate.code === 'EADDRINUSE') {
      return true;
    }
    if (
      candidate instanceof Error &&
      /^Port \d+ is already in use$/u.test(candidate.message.trim())
    ) {
      return true;
    }
    candidate = 'cause' in candidate ? candidate.cause : undefined;
  }

  return false;
}

async function createRotationHarness(
  kind: FixtureKind,
  initialToken: string,
  allowedOrigins: readonly string[],
  port: number,
): Promise<RotationHarness> {
  const loaderResponse = await fetch(configuredLoaderUrl);
  expect(loaderResponse.ok).toBe(true);
  const loaderSource = await loaderResponse.text();
  const root = await mkdtemp(join(tmpdir(), 'scene-glass-e2e-rotation-'));
  const configPath = join(root, 'scene-glass.json');
  let app: FastifyInstance | undefined;
  const closeApp = async (): Promise<void> => {
    const runningApp = app;
    if (runningApp === undefined) {
      return;
    }

    try {
      runningApp.server.closeIdleConnections();
      await runningApp.close();
    } finally {
      if (app === runningApp) {
        app = undefined;
      }
    }
  };

  const start = async (token: string): Promise<void> => {
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        projects: [
          {
            projectId: testProjectId,
            root,
            allowedOrigins,
            tokenEnv: tokenEnvironmentName,
            framework: kind === 'vue' ? 'vue3' : 'html',
          },
        ],
      }),
    );
    const next = await createSceneGlassAppForTest({
      configPath,
      environment: { [tokenEnvironmentName]: token },
      projectRootProbe: async (canonicalRoot) =>
        rootSupportedResult('darwin', 'macos-authoritative', {
          realPath: canonicalRoot,
          device: 1,
          fileSystemType: 26,
          identityStableAtProbe: true,
          inode: 1,
        }),
    });
    try {
      next.addHook('onSend', (_request, reply, payload, done) => {
        reply.header('connection', 'close');
        done(null, payload);
      });
      next.get('/scene-glass-loader.js', (_request, reply) =>
        reply.type('application/javascript; charset=utf-8').send(loaderSource),
      );
      await next.listen({ host: '127.0.0.1', port });
      const address = next.server.address();
      if (
        address === null ||
        typeof address === 'string' ||
        (address as AddressInfo).port !== port
      ) {
        throw new Error('rotation server did not bind its reserved loopback port');
      }
      app = next;
    } catch (error: unknown) {
      await next.close();
      throw error;
    }
  };

  try {
    await start(initialToken);
  } catch (error: unknown) {
    await rm(root, { force: true, recursive: true });
    throw error;
  }

  return {
    origin: `http://127.0.0.1:${port}`,
    projectId: testProjectId,
    root,
    async close(): Promise<void> {
      try {
        await closeApp();
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    },
    async rotate(nextToken: string): Promise<void> {
      await closeApp();
      await start(nextToken);
    },
  };
}

async function createFixtureHost(
  kind: FixtureKind,
  port: number,
  authorityOrigin: string,
  temporaryRoot: string,
  initialToken: string,
): Promise<FixtureHost> {
  const origin = `http://127.0.0.1:${port}`;
  const environmentRoot = join(temporaryRoot, `vite-${kind}`);
  const environmentPath = join(environmentRoot, '.env');
  const outDir = join(environmentRoot, 'dist');
  let server: PreviewServer | undefined;
  await mkdir(environmentRoot, { recursive: true });

  const buildFixture = async (token: string): Promise<void> => {
    await writeFile(
      environmentPath,
      [
        `VITE_SCENE_GLASS_LOADER_URL=${authorityOrigin}/scene-glass-loader.js`,
        `VITE_SCENE_GLASS_PROJECT_ID=${testProjectId}`,
        `VITE_SCENE_GLASS_PROJECT_TOKEN=${token}`,
        '',
      ].join('\n'),
    );
    await buildVite({
      build: {
        emptyOutDir: true,
        outDir,
      },
      configFile: join(fixtureRoots[kind], 'vite.config.ts'),
      envDir: environmentRoot,
      root: fixtureRoots[kind],
    });
  };

  const startPreview = async (): Promise<void> => {
    const next = await createVitePreview({
      build: { outDir },
      configFile: join(fixtureRoots[kind], 'vite.config.ts'),
      envDir: environmentRoot,
      preview: {
        host: '127.0.0.1',
        port,
        strictPort: true,
      },
      root: fixtureRoots[kind],
    });
    try {
      const address = next.httpServer.address();
      if (
        address === null ||
        typeof address === 'string' ||
        (address as AddressInfo).port !== port
      ) {
        throw new Error(`${kind} fixture preview did not bind its reserved loopback port`);
      }
      server = next;
    } catch (error: unknown) {
      await next.close();
      throw error;
    }
  };

  const deploy = async (token: string): Promise<void> => {
    await server?.close();
    server = undefined;
    await buildFixture(token);
    await startPreview();
  };

  try {
    await deploy(initialToken);
  } catch (error: unknown) {
    await server?.close();
    throw error;
  }

  return {
    kind,
    origin,
    url: fixtureUrl(kind, origin),
    async close(): Promise<void> {
      await server?.close();
      server = undefined;
    },
    async restart(token: string): Promise<void> {
      await deploy(token);
    },
  };
}
async function createRotationScenario(
  kind: FixtureKind,
  initialToken: string,
): Promise<RotationScenario> {
  for (let attempt = 1; attempt <= rotationSetupAttempts; attempt += 1) {
    const [hostPort, authorityPort] = await reserveDistinctLoopbackPorts();
    const hostOrigin = `http://127.0.0.1:${hostPort}`;
    let harness: RotationHarness | undefined;

    try {
      harness = await createRotationHarness(kind, initialToken, [hostOrigin], authorityPort);
      const host = await createFixtureHost(
        kind,
        hostPort,
        harness.origin,
        harness.root,
        initialToken,
      );
      return { harness, host };
    } catch (error: unknown) {
      await harness?.close();
      if (!isAddressInUse(error)) {
        throw error;
      }
    }
  }

  throw new Error(
    `unable to start ${kind} rotation fixture after ${rotationSetupAttempts} port allocation attempts`,
  );
}

async function expectHostProvisioning(
  host: FixtureHost,
  authority: RotationHarness,
  token: string,
): Promise<void> {
  const response = await fetch(host.url);
  expect(response.ok).toBe(true);
  const source = await response.text();
  const hasLoader = source.includes(`src="${authority.origin}/scene-glass-loader.js"`);
  const hasProject = source.includes(`data-scg-project="${authority.projectId}"`);
  const hasToken = source.includes(`data-scg-token="${token}"`);
  expect(hasLoader, 'Served fixture document omits the loader script.').toBe(true);
  expect(hasProject, 'Served fixture document omits the project identifier.').toBe(true);
  expect(hasToken, 'Served fixture document omits the loader token.').toBe(true);
}

async function expectSceneGlassReady(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('ready');
}

async function loadFixtureDocument(
  page: Page,
  host: FixtureHost,
  authority: RotationHarness,
): Promise<string> {
  const initialized = page.waitForResponse(
    (response) =>
      response.url() === `${authority.origin}/mcp/v1/projects/${authority.projectId}` &&
      response.status() === 200 &&
      response.headers()['mcp-session-id'] !== undefined,
  );

  await page.goto(host.url);
  await expect(page.getByRole('heading', { name: fixtureHeading(host.kind) })).toBeVisible();
  await expectSceneGlassReady(page);

  const response = await initialized;
  expect(response.headers()['access-control-allow-origin']).toBe(host.origin);
  const sessionId = response.headers()['mcp-session-id'];
  if (sessionId === undefined || sessionId.length === 0) {
    throw new Error('initial Scene Glass connection omitted an MCP session ID');
  }
  return sessionId;
}

function waitForAccessDenied(page: Page, authority: RotationHarness): Promise<Response> {
  return page.waitForResponse(
    (response) =>
      response.url() === `${authority.origin}/mcp/v1/projects/${authority.projectId}` &&
      response.status() === 401,
  );
}

async function assertAccessDenied(
  page: Page,
  host: FixtureHost,
  denied: Promise<Response>,
): Promise<Response> {
  const response = await denied;
  expect(response.status()).toBe(401);
  expect(response.headers()['access-control-allow-origin']).toBe(host.origin);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['www-authenticate']).toBe('Bearer');
  expect(response.headers()['content-type']).toContain('application/problem+json');
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('access-error');
  return response;
}

async function triggerOldDocumentRequest(page: Page): Promise<void> {
  await page.evaluate(() => {
    const sceneGlass = window.SceneGlass as { notifyReady(): void } | undefined;
    if (sceneGlass === undefined) {
      throw new Error('Scene Glass is unavailable in the old document');
    }
    sceneGlass.notifyReady();
  });
}

async function inspectTokenExposure(page: Page, token: string): Promise<Record<string, boolean>> {
  return page.evaluate(async (tokenToInspect) => {
    const storageValues = (storage: Storage): string[] => {
      const values: string[] = [];
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (key === null) {
          continue;
        }
        values.push(key);
        const value = storage.getItem(key);
        if (value !== null) {
          values.push(value);
        }
      }
      return values;
    };
    const cacheKeys: string[] = [];
    const cacheRequestUrls: string[] = [];
    const cacheResponseTexts: string[] = [];
    let cacheRequestHeaders = false;
    let cacheResponseHeaders = false;

    if (typeof globalThis.caches === 'undefined') {
      throw new Error('CacheStorage is unavailable in Chromium.');
    }

    const names = await globalThis.caches.keys();
    cacheKeys.push(...names);
    for (const name of names) {
      const cache = await globalThis.caches.open(name);
      const requests = await cache.keys();
      for (const request of requests) {
        cacheRequestUrls.push(request.url);
        cacheRequestHeaders ||= [...request.headers.values()].some((value) =>
          value.includes(tokenToInspect),
        );
        const response = await cache.match(request);
        if (response === undefined) {
          throw new Error('A CacheStorage entry disappeared during inspection.');
        }
        cacheResponseHeaders ||= [...response.headers.values()].some((value) =>
          value.includes(tokenToInspect),
        );
        cacheResponseTexts.push(await response.clone().text());
      }
    }

    const surfaces = {
      cacheKeys,
      cacheRequestUrls,
      cacheResponseTexts,
      dom: [document.documentElement.outerHTML],
      localStorage: storageValues(localStorage),
      resourceUrls: performance.getEntriesByType('resource').map((entry) => entry.name),
      sessionStorage: storageValues(sessionStorage),
      url: [location.href],
    };
    return {
      ...Object.fromEntries(
        Object.entries(surfaces).map(([surface, values]) => [
          surface,
          values.some((value) => value.includes(tokenToInspect)),
        ]),
      ),
      cacheRequestHeaders,
      cacheResponseHeaders,
    };
  }, token);
}

async function verifyCacheHeaderInspection(page: Page): Promise<void> {
  const cacheName = 'scene-glass-token-residue-negative-control';
  const sentinel = 'scene-glass-cache-header-sentinel';

  await page.evaluate(
    async ({ name, value }) => {
      const cache = await globalThis.caches.open(name);
      await cache.put(
        new Request('/scene-glass-cache-header-probe', {
          headers: { authorization: `Bearer ${value}` },
        }),
        new Response('header probe', {
          headers: { 'x-scene-glass-token-probe': value },
        }),
      );
    },
    { name: cacheName, value: sentinel },
  );

  try {
    const exposure = await inspectTokenExposure(page, sentinel);
    expect(exposure.cacheRequestHeaders).toBe(true);
    expect(exposure.cacheResponseHeaders).toBe(true);
  } finally {
    await page.evaluate(async (name) => {
      await globalThis.caches.delete(name);
    }, cacheName);
  }
}

async function expectNoTokenExposure(
  page: Page,
  tokens: readonly string[],
  consoleMessages: readonly string[],
): Promise<void> {
  for (const token of tokens) {
    const exposedSurfaces = await inspectTokenExposure(page, token);

    for (const [surface, exposed] of Object.entries(exposedSurfaces)) {
      expect(exposed, `A loader token is exposed in ${surface}.`).toBe(false);
    }
    expect(
      consoleMessages.some((message) => message.includes(token)),
      'A loader token is exposed in console output.',
    ).toBe(false);
  }
}

for (const kind of ['vue', 'static'] as const) {
  test(`${kind} host restart invalidates the old document and provisions a fresh document @chromium-full`, async ({
    page,
  }) => {
    const oldToken = opaqueToken();
    const replacementToken = opaqueToken();
    const rotationTokens = [oldToken, replacementToken] as const;
    const { harness, host } = await createRotationScenario(kind, oldToken);
    let freshPage: Page | undefined;

    try {
      await expectHostProvisioning(host, harness, oldToken);

      const consoleMessages: string[] = [];
      page.on('console', (message) => consoleMessages.push(message.text()));
      const oldSessionId = await loadFixtureDocument(page, host, harness);
      await expectNoTokenExposure(page, rotationTokens, consoleMessages);
      await verifyCacheHeaderInspection(page);

      const denied = waitForAccessDenied(page, harness);
      await harness.rotate(replacementToken);
      await host.restart(replacementToken);
      await expectHostProvisioning(host, harness, replacementToken);

      const oldDocumentState = await page.evaluate(() => window.SceneGlass?.state);
      if (oldDocumentState === 'ready') {
        await triggerOldDocumentRequest(page);
      } else {
        expect(oldDocumentState).toBe('access-error');
      }

      const deniedResponse = await assertAccessDenied(page, host, denied);
      const deniedHeaders = deniedResponse.request().headers();
      expect({
        authorization: classifyBearerAuthorization(deniedHeaders.authorization, oldToken),
        sessionIdMatchesOldSession: deniedHeaders['mcp-session-id'] === oldSessionId,
      }).toEqual({
        authorization: 'matches-expected-token',
        sessionIdMatchesOldSession: true,
      });

      await expectNoTokenExposure(page, rotationTokens, consoleMessages);

      freshPage = await page.context().newPage();
      const freshConsole: string[] = [];
      freshPage.on('console', (message) => freshConsole.push(message.text()));
      const freshSessionId = await loadFixtureDocument(freshPage, host, harness);
      expect(freshSessionId).not.toBe(oldSessionId);
      await expectNoTokenExposure(freshPage, rotationTokens, freshConsole);
    } finally {
      try {
        await freshPage?.close();
      } finally {
        try {
          await host.close();
        } finally {
          await harness.close();
        }
      }
    }
  });
}
