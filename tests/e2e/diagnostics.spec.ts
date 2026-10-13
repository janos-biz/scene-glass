import { randomBytes } from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import type { AddressInfo } from 'node:net';

import { expect, test, type Page, type Route } from '@playwright/test';
import type { FastifyInstance } from 'fastify';

import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { MCP_PROTOCOL_VERSION } from '../../packages/server/src/mcp/dispatcher.js';

const VUE_FIXTURE_URL = 'http://127.0.0.1:4173/';
const configuredLoaderUrl = requiredEnvironment('SCENE_GLASS_TEST_LOADER_URL');
const projectId = 'e2e-diagnostics';
const tokenEnvironmentName = 'SCENE_GLASS_E2E_DIAGNOSTICS_TOKEN';
const loaderFetchTimeoutMilliseconds = 10_000;
const harnessCleanupTimeoutMilliseconds = 10_000;

declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

type DiagnosticsHarness = {
  readonly endpoint: string;
  readonly normalToken: string;
  readonly root: string;
  readonly now: () => number;
  advance(milliseconds: number): void;
  close(): Promise<void>;
};

type IssuedDiagnostic = {
  readonly endpoint: string;
  readonly expiresAt: string;
  readonly runId: string;
  readonly token: string;
};

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

function aggregateErrors(error: unknown): readonly unknown[] {
  return error instanceof AggregateError ? [...error.errors] : [error];
}

async function closeDiagnosticsHarnessResources(
  app: FastifyInstance | undefined,
  workspace: string,
): Promise<void> {
  const failures: unknown[] = [];

  if (app !== undefined) {
    try {
      await closeDiagnosticsHarnessWithinTimeout(app.close(), 'app close');
    } catch (error) {
      failures.push(error);
    }
  }

  try {
    await closeDiagnosticsHarnessWithinTimeout(
      rm(workspace, { force: true, recursive: true }),
      'workspace removal',
    );
  } catch (error) {
    failures.push(error);
  }

  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      'SCENE_GLASS_E2E_DIAGNOSTICS_CLEANUP_FAILED: app close and workspace removal were attempted.',
    );
  }
}
async function closeDiagnosticsHarnessWithinTimeout(
  operation: Promise<void>,
  phase: string,
): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(
            new Error(
              `SCENE_GLASS_E2E_DIAGNOSTICS_CLEANUP_TIMEOUT: ${phase} exceeded ${harnessCleanupTimeoutMilliseconds}ms.`,
            ),
          );
        }, harnessCleanupTimeoutMilliseconds);
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

async function fetchConfiguredLoaderSource(): Promise<string> {
  let phase = 'request';
  let status: number | undefined;

  try {
    const response = await fetch(configuredLoaderUrl, {
      signal: AbortSignal.timeout(loaderFetchTimeoutMilliseconds),
    });
    status = response.status;
    phase = 'response';
    if (!response.ok) {
      throw new Error('loader response was not successful');
    }

    phase = 'body';
    const source = await response.text();
    phase = 'complete';
    return source;
  } catch (error) {
    const reason = error instanceof Error && error.name === 'TimeoutError' ? 'timeout' : 'error';
    throw new Error(
      `SCENE_GLASS_E2E_DIAGNOSTICS_LOADER_FETCH_FAILED: phase=${phase}; status=${status ?? 'unavailable'}; reason=${reason}.`,
    );
  }
}

async function createDiagnosticsHarness(): Promise<DiagnosticsHarness> {
  const workspace = await mkdtemp(join(tmpdir(), 'scene-glass-e2e-diagnostics-'));
  let app: FastifyInstance | undefined;
  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closePromise ??= closeDiagnosticsHarnessResources(app, workspace);
    return closePromise;
  };

  try {
    const root = join(workspace, 'project');
    const normalToken = opaqueToken();
    let now = Date.now();
    await mkdir(join(root, '.scg'), { recursive: true });
    await writeFile(join(root, '.scg', 'diagnostic-sentinel'), 'unchanged\n');
    const canonicalRoot = await realpath(root);
    const configPath = join(workspace, 'scene-glass.json');
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        globalLimits: { diagnosticActiveRunsGlobal: 1 },
        projects: [
          {
            projectId,
            root: canonicalRoot,
            allowedOrigins: [VUE_FIXTURE_URL.slice(0, -1)],
            tokenEnv: tokenEnvironmentName,
            framework: 'vue3',
            limits: {
              diagnosticActiveRunsPerProject: 1,
              diagnosticRunsPerProjectPerMinute: 5,
            },
          },
        ],
      }),
    );
    const loaderSource = await fetchConfiguredLoaderSource();
    app = await createSceneGlassAppForTest({
      configPath,
      environment: { [tokenEnvironmentName]: normalToken },
      now: () => now,
      projectRootProbe: async (configuredRoot) => ({
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
        facts: {
          realPath: configuredRoot,
          device: 1,
          inode: 1,
          fileSystemType: 26,
          identityStableAtProbe: true,
        },
      }),
    });
    app.get('/scene-glass-loader.js', (_request, reply) =>
      reply.type('application/javascript; charset=utf-8').send(loaderSource),
    );
    await app.listen({ host: '127.0.0.1', port: 0 });
    const address = app.server.address() as AddressInfo;
    const endpoint = `http://127.0.0.1:${address.port}`;

    return {
      endpoint,
      normalToken,
      root: canonicalRoot,
      now: () => now,
      advance(milliseconds: number): void {
        now += milliseconds;
      },
      close,
    };
  } catch (setupError) {
    try {
      await close();
    } catch (cleanupError) {
      throw new AggregateError(
        [setupError, ...aggregateErrors(cleanupError)],
        'SCENE_GLASS_E2E_DIAGNOSTICS_SETUP_FAILED: setup failed and cleanup was attempted.',
      );
    }
    throw setupError;
  }
}

async function loadVueWithHarness(page: Page, harness: DiagnosticsHarness): Promise<void> {
  let originalLoaderFailed = false;
  const blockOriginalLoader = async (route: Route): Promise<void> => {
    originalLoaderFailed = true;
    await route.abort('failed');
  };

  await page.route(configuredLoaderUrl, blockOriginalLoader);
  await page.goto(VUE_FIXTURE_URL);
  await expect.poll(() => originalLoaderFailed).toBe(true);
  await page.evaluate(() => document.querySelector('script[data-scg-project]')?.remove());
  await page.unroute(configuredLoaderUrl, blockOriginalLoader);
  await page.evaluate(
    ({ source, token }) => {
      const script = document.createElement('script');
      script.async = true;
      script.src = source;
      script.dataset.scgProject = 'e2e-diagnostics';
      script.dataset.scgToken = token;
      script.dataset.scgNavigation = 'spa';
      document.body.append(script);
    },
    { source: `${harness.endpoint}/scene-glass-loader.js`, token: harness.normalToken },
  );
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('ready');
}

type ScgTreeSnapshotEntry = readonly [
  path: string,
  type: 'directory' | 'file' | 'symlink',
  content: string | null,
];

async function scgTreeSnapshot(root: string): Promise<readonly ScgTreeSnapshotEntry[]> {
  const scgRoot = join(root, '.scg');
  const entries: ScgTreeSnapshotEntry[] = [];

  const visit = async (directory: string): Promise<void> => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children.sort((left, right) => left.name.localeCompare(right.name))) {
      const path = join(directory, child.name);
      const relativePath = relative(scgRoot, path);

      if (child.isDirectory()) {
        entries.push([relativePath, 'directory', null]);
        await visit(path);
      } else if (child.isFile()) {
        entries.push([relativePath, 'file', (await readFile(path)).toString('base64')]);
      } else if (child.isSymbolicLink()) {
        entries.push([relativePath, 'symlink', await readlink(path)]);
      } else {
        throw new Error(`SCENE_GLASS_E2E_SCG_SNAPSHOT_UNSUPPORTED_ENTRY: path=${relativePath}.`);
      }
    }
  };

  await visit(scgRoot);
  return entries;
}

function parseIssuedDiagnostic(body: string, source: string): IssuedDiagnostic {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    throw new Error(`${source} response was not valid JSON.`);
  }

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${source} response did not contain a diagnostic capability.`);
  }

  const capability = value as Record<string, unknown>;
  if (
    typeof capability.endpoint !== 'string' ||
    capability.endpoint.length === 0 ||
    typeof capability.expiresAt !== 'string' ||
    capability.expiresAt.length === 0 ||
    typeof capability.runId !== 'string' ||
    capability.runId.length === 0 ||
    typeof capability.token !== 'string' ||
    capability.token.length === 0
  ) {
    throw new Error(`${source} response did not contain a valid diagnostic capability.`);
  }

  return {
    endpoint: capability.endpoint,
    expiresAt: capability.expiresAt,
    runId: capability.runId,
    token: capability.token,
  };
}

async function issueDiagnostic(page: Page, harness: DiagnosticsHarness): Promise<IssuedDiagnostic> {
  const response = await page.evaluate(
    async ({ endpoint, token }) => {
      const issued = await fetch(`${endpoint}/mcp/v1/projects/e2e-diagnostics/diagnostic-runs`, {
        method: 'POST',
        credentials: 'omit',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ schemaVersion: 1 }),
      });
      return { body: await issued.text(), status: issued.status };
    },
    { endpoint: harness.endpoint, token: harness.normalToken },
  );
  expect(response.status).toBe(201);
  return parseIssuedDiagnostic(response.body, 'direct diagnostic issuance');
}

async function diagnosticMcpRequest(
  page: Page,
  input: {
    readonly endpoint: string;
    readonly message: Record<string, unknown>;
    readonly sessionId?: string;
    readonly token: string;
  },
): Promise<{ readonly body: string; readonly sessionId: string | null; readonly status: number }> {
  return page.evaluate(
    async ({ endpoint, message, sessionId, token, protocolVersion }) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        credentials: 'omit',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'mcp-protocol-version': protocolVersion,
          ...(sessionId === undefined ? {} : { 'mcp-session-id': sessionId }),
        },
        body: JSON.stringify(message),
      });
      return {
        body: await response.text(),
        sessionId: response.headers.get('mcp-session-id'),
        status: response.status,
      };
    },
    { ...input, protocolVersion: MCP_PROTOCOL_VERSION },
  );
}

async function closeDiagnosticSession(
  page: Page,
  input: { readonly endpoint: string; readonly sessionId: string; readonly token: string },
): Promise<{ readonly body: string; readonly status: number }> {
  return page.evaluate(
    async ({ endpoint, sessionId, token, protocolVersion }) => {
      const response = await fetch(endpoint, {
        method: 'DELETE',
        credentials: 'omit',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'mcp-protocol-version': protocolVersion,
          'mcp-session-id': sessionId,
        },
      });
      return { body: await response.text(), status: response.status };
    },
    { ...input, protocolVersion: MCP_PROTOCOL_VERSION },
  );
}
async function assertUiDiagnosticSecretsAbsent(
  page: Page,
  input: {
    readonly consoleMessages: readonly string[];
    readonly pageErrors: readonly string[];
    readonly root: string;
    readonly token: string;
  },
): Promise<void> {
  const sensitiveValues = [input.token, input.root];
  const browserSurfaceExposure = await page.evaluate((values) => {
    const documentMarkup = document.documentElement.outerHTML;
    const statusText = document.querySelector('.scg-diag-run-state')?.textContent ?? '';
    const url = window.location.href;
    return values.map((value) => ({
      document: documentMarkup.includes(value),
      status: statusText.includes(value),
      url: url.includes(value),
    }));
  }, sensitiveValues);

  expect(browserSurfaceExposure).toEqual([
    { document: false, status: false, url: false },
    { document: false, status: false, url: false },
  ]);
  expect(
    sensitiveValues.map((value) =>
      input.consoleMessages.some((message) => message.includes(value)),
    ),
  ).toEqual([false, false]);
  expect(
    sensitiveValues.map((value) => input.pageErrors.some((error) => error.includes(value))),
  ).toEqual([false, false]);
}

function expectDiagnosticSecretsAbsentFromText(text: string, token: string, root: string): void {
  expect([text.includes(token), text.includes(root)]).toEqual([false, false]);
}

function expectDiagnosticFailureBody(
  body: string,
  code: string,
  token: string,
  root: string,
): void {
  expect(body.includes(code)).toBe(true);
  expectDiagnosticSecretsAbsentFromText(body, token, root);
}

test('diagnostics presents the ordered lifecycle and uses the real diagnostic capability without changing .scg @chromium-full', async ({
  page,
}) => {
  const harness = await createDiagnosticsHarness();
  let before: Awaited<ReturnType<typeof scgTreeSnapshot>>;
  const wireLifecycle: string[] = [];
  let captureLifecycle = false;
  const consoleMessages: string[] = [];
  const pageErrors: string[] = [];
  page.on('console', (message) => {
    consoleMessages.push(message.text());
  });
  page.on('pageerror', (error) => {
    pageErrors.push(error.stack ?? error.message);
  });
  page.on('request', (request) => {
    if (!captureLifecycle || !request.url().startsWith(`${harness.endpoint}/mcp/v1/projects/`)) {
      return;
    }
    if (request.method() === 'DELETE') {
      wireLifecycle.push('DELETE close');
      return;
    }
    const body = request.postData();
    if (body === null) {
      return;
    }
    const message = JSON.parse(body) as { method?: unknown };
    if (typeof message.method === 'string') {
      wireLifecycle.push(message.method);
    }
  });
  let testFailed = false;
  let testFailure: unknown;

  try {
    await loadVueWithHarness(page, harness);
    await expect(page.getByRole('heading', { name: 'Scene Glass Vue SPA fixture' })).toBeVisible();
    before = await scgTreeSnapshot(harness.root);

    let releaseDiagnosticCapability = (): void => {};
    let signalDiagnosticCapabilityHeld = (): void => {};
    let signalDiagnosticCapabilityFulfilled = (): void => {};
    let issuedUiDiagnosticToken: string | undefined;
    const diagnosticCapabilityReleased = new Promise<void>((resolve) => {
      releaseDiagnosticCapability = () => resolve();
    });
    const diagnosticCapabilityHeld = new Promise<void>((resolve) => {
      signalDiagnosticCapabilityHeld = () => resolve();
    });
    const diagnosticCapabilityFulfilled = new Promise<void>((resolve) => {
      signalDiagnosticCapabilityFulfilled = () => resolve();
    });
    const delayDiagnosticCapability = async (route: Route): Promise<void> => {
      const response = await route.fetch();
      if (response.status() !== 201) {
        throw new Error(
          `intercepted UI diagnostic issuance returned unexpected status=${response.status()}.`,
        );
      }
      issuedUiDiagnosticToken = parseIssuedDiagnostic(
        await response.text(),
        'intercepted UI diagnostic issuance',
      ).token;
      signalDiagnosticCapabilityHeld();
      await diagnosticCapabilityReleased;
      await route.fulfill({ response });
      signalDiagnosticCapabilityFulfilled();
    };
    await page.route(
      '**/mcp/v1/projects/e2e-diagnostics/diagnostic-runs',
      delayDiagnosticCapability,
    );

    const diagnosticsButton = page.getByRole('button', { name: '진단 열기' });
    const panel = page.getByRole('complementary', { name: 'Scene Glass 진단' });
    try {
      await diagnosticsButton.click();
      await diagnosticCapabilityHeld;
      await expect(diagnosticsButton).toBeDisabled();
      await expect(panel).toHaveCount(0);

      releaseDiagnosticCapability();
      await diagnosticCapabilityFulfilled;
    } finally {
      releaseDiagnosticCapability();
      await page.unroute(
        '**/mcp/v1/projects/e2e-diagnostics/diagnostic-runs',
        delayDiagnosticCapability,
      );
    }

    await expect(panel).toBeVisible();
    await expect(panel.locator('ol.scg-diag-steps .scg-diag-step-label')).toHaveText([
      '토큰 테스트',
      '연결',
      '인증',
      '왕복 통신',
    ]);

    captureLifecycle = true;
    await panel.getByRole('button', { name: '진단 실행' }).click();
    await expect(panel.locator('.scg-diag-step[data-state="passed"]')).toHaveCount(4);
    await expect(panel.locator('.scg-diag-cleanup[data-state="cleaned"]')).toBeVisible();
    await expect(panel.locator('.scg-diag-run-state')).toContainText('진단 정리가 완료되었습니다.');
    expect(wireLifecycle).toEqual([
      'initialize',
      'notifications/initialized',
      'ping',
      'DELETE close',
    ]);
    await expect(panel.getByRole('button', { name: '진단 실행' })).toBeDisabled();
    if (issuedUiDiagnosticToken === undefined) {
      throw new Error('intercepted UI diagnostic issuance omitted the capability token.');
    }
    await assertUiDiagnosticSecretsAbsent(page, {
      consoleMessages,
      pageErrors,
      root: harness.root,
      token: issuedUiDiagnosticToken,
    });

    const afterSuccessfulRun = await scgTreeSnapshot(harness.root);
    expect(afterSuccessfulRun).toEqual(before);
    const singleUse = await issueDiagnostic(page, harness);
    const initialized = await diagnosticMcpRequest(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      message: diagnosticInitializeMessage('single-use-initialize'),
    });
    expect(initialized.status).toBe(200);
    if (initialized.sessionId === null) {
      throw new Error('diagnostic initialize response omitted mcp-session-id');
    }
    const sessionId = initialized.sessionId;

    const reusedBeforeCleanup = await diagnosticMcpRequest(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      sessionId,
      message: diagnosticInitializeMessage('single-use-reused'),
    });
    expect(reusedBeforeCleanup.status).toBe(403);
    expect(reusedBeforeCleanup.sessionId).toBeNull();
    expectDiagnosticFailureBody(
      reusedBeforeCleanup.body,
      'SCG_DIAGNOSTIC_METHOD_FORBIDDEN',
      singleUse.token,
      harness.root,
    );
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);

    const initializedNotification = await diagnosticMcpRequest(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      sessionId,
      message: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    });
    expect(initializedNotification.status).toBe(202);
    const ping = await diagnosticMcpRequest(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      sessionId,
      message: { jsonrpc: '2.0', id: 'single-use-ping', method: 'ping', params: {} },
    });
    expect(ping.status).toBe(200);
    const closed = await closeDiagnosticSession(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      sessionId,
    });
    expect(closed.status).toBe(204);
    expect(closed.body.length).toBe(0);
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);

    const reusedAfterCleanup = await diagnosticMcpRequest(page, {
      endpoint: singleUse.endpoint,
      token: singleUse.token,
      sessionId,
      message: diagnosticInitializeMessage('single-use-after-delete'),
    });
    expect(reusedAfterCleanup.status).toBe(401);
    expect(reusedAfterCleanup.sessionId).toBeNull();
    expectDiagnosticFailureBody(
      reusedAfterCleanup.body,
      'SCG_DIAGNOSTIC_INVALID',
      singleUse.token,
      harness.root,
    );
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);

    const replacement = await issueDiagnostic(page, harness);
    const replacementInitialized = await diagnosticMcpRequest(page, {
      endpoint: replacement.endpoint,
      token: replacement.token,
      message: diagnosticInitializeMessage('replacement-initialize'),
    });
    expect(replacementInitialized.status).toBe(200);
    if (replacementInitialized.sessionId === null) {
      throw new Error('replacement diagnostic initialize response omitted mcp-session-id');
    }
    expect(
      (
        await closeDiagnosticSession(page, {
          endpoint: replacement.endpoint,
          token: replacement.token,
          sessionId: replacementInitialized.sessionId,
        })
      ).status,
    ).toBe(204);
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);
    expect(wireLifecycle).toEqual([
      'initialize',
      'notifications/initialized',
      'ping',
      'DELETE close',
      'initialize',
      'initialize',
      'notifications/initialized',
      'ping',
      'DELETE close',
      'initialize',
      'initialize',
      'DELETE close',
    ]);

    const forbidden = await issueDiagnostic(page, harness);
    expect(Date.parse(forbidden.expiresAt) - harness.now()).toBe(60_000);
    const forbiddenResult = await diagnosticMcpRequest(page, {
      endpoint: forbidden.endpoint,
      token: forbidden.token,
      message: {
        jsonrpc: '2.0',
        id: 'forbidden',
        method: 'tools/call',
        params: { name: 'annotations.list', arguments: {} },
      },
    });
    expect(forbiddenResult.status).toBe(403);
    expectDiagnosticFailureBody(
      forbiddenResult.body,
      'SCG_DIAGNOSTIC_METHOD_FORBIDDEN',
      forbidden.token,
      harness.root,
    );
    harness.advance(60_000);
    const expiredForbidden = await diagnosticMcpRequest(page, {
      endpoint: forbidden.endpoint,
      token: forbidden.token,
      message: diagnosticInitializeMessage('forbidden-expired'),
    });
    expect(expiredForbidden.status).toBe(401);
    expectDiagnosticFailureBody(
      expiredForbidden.body,
      'SCG_DIAGNOSTIC_EXPIRED',
      forbidden.token,
      harness.root,
    );
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);

    const expired = await issueDiagnostic(page, harness);
    harness.advance(60_000);
    const expiredResult = await diagnosticMcpRequest(page, {
      endpoint: expired.endpoint,
      token: expired.token,
      message: diagnosticInitializeMessage('expired'),
    });
    expect(expiredResult.status).toBe(401);
    expectDiagnosticFailureBody(
      expiredResult.body,
      'SCG_DIAGNOSTIC_EXPIRED',
      expired.token,
      harness.root,
    );
    expect(await scgTreeSnapshot(harness.root)).toEqual(before);
    await expect(page.getByRole('button', { name: '진단 닫기' })).toBeVisible();
    await page.getByRole('button', { name: '진단 닫기' }).click();
    await expect(panel).toHaveCount(0);
    await expect(page.getByRole('button', { name: '진단 열기' })).toBeVisible();
  } catch (error) {
    testFailed = true;
    testFailure = error;
  }

  try {
    await harness.close();
  } catch (cleanupError) {
    if (testFailed) {
      throw new AggregateError(
        [testFailure, ...aggregateErrors(cleanupError)],
        'SCENE_GLASS_E2E_DIAGNOSTICS_TEST_FAILED: test failed and harness cleanup also failed.',
      );
    }
    throw cleanupError;
  }

  if (testFailed) {
    throw testFailure;
  }
});

function diagnosticInitializeMessage(id: string) {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'scene-glass-e2e', version: '0.1.0' },
    },
  };
}
