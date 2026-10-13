import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  expect,
  test,
  type Locator,
  type Page,
  type Response as PlaywrightResponse,
  type Route,
} from '@playwright/test';
import type { FastifyInstance } from 'fastify';

import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { MCP_PROTOCOL_VERSION } from '../../packages/server/src/mcp/dispatcher.js';

const VUE_FIXTURE_URL = 'http://127.0.0.1:4173/';
const configuredLoaderUrl = requiredEnvironment('SCENE_GLASS_TEST_LOADER_URL');
const projectId = 'e2e-export';
const tokenEnvironmentName = 'SCENE_GLASS_E2E_EXPORT_TOKEN';
const loaderSourceFetchTimeoutMs = 10_000;
const rootMemo = 'Root export `*_{}[]()#+.!>|~- 🧪 ``````';
const siblingMemo = 'Sibling project export memo';

declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

type ExportHarness = {
  readonly canonicalRoot: string;
  readonly endpoint: string;
  readonly normalToken: string;
  close(): Promise<void>;
};

type PageIdentity = {
  readonly canonicalIdentity: string;
  readonly pageId: string;
  readonly policyVersion: number;
  readonly route: string;
};

type AnnotationSummary = {
  readonly id: string;
  readonly memo: string;
};

type NormalMcpResponse = {
  readonly body: string;
  readonly sessionId: string | null;
  readonly status: number;
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

async function fetchLoaderSource(): Promise<string> {
  let loaderResponse: globalThis.Response;
  try {
    loaderResponse = await fetch(configuredLoaderUrl, {
      signal: AbortSignal.timeout(loaderSourceFetchTimeoutMs),
    });
  } catch (error: unknown) {
    throw new Error(
      `loader source fetch request phase failed within ${loaderSourceFetchTimeoutMs}ms`,
      { cause: error },
    );
  }

  if (!loaderResponse.ok) {
    throw new Error(
      `loader source fetch response phase returned HTTP ${loaderResponse.status} ${loaderResponse.statusText}`,
    );
  }

  try {
    return await loaderResponse.text();
  } catch (error: unknown) {
    throw new Error(
      `loader source fetch body phase failed after HTTP ${loaderResponse.status} ${loaderResponse.statusText}`,
      { cause: error },
    );
  }
}

async function closeExportResources(
  app: FastifyInstance | undefined,
  workspace: string,
): Promise<void> {
  const [appResult, workspaceResult] = await Promise.allSettled([
    app === undefined ? Promise.resolve() : app.close(),
    rm(workspace, { force: true, recursive: true }),
  ]);
  const failures: unknown[] = [];
  if (appResult.status === 'rejected') {
    failures.push(appResult.reason);
  }
  if (workspaceResult.status === 'rejected') {
    failures.push(workspaceResult.reason);
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, 'export harness cleanup failed');
  }
}

async function createExportHarness(): Promise<ExportHarness> {
  const workspace = await mkdtemp(join(tmpdir(), 'scene-glass-e2e-export-'));
  const root = join(workspace, 'project');
  const normalToken = opaqueToken();
  let app: FastifyInstance | undefined;
  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closePromise ??= closeExportResources(app, workspace);
    return closePromise;
  };

  try {
    await mkdir(join(root, '.scg'), { recursive: true });
    const canonicalRoot = await realpath(root);
    const configPath = join(workspace, 'scene-glass.json');
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        projects: [
          {
            projectId,
            root: canonicalRoot,
            allowedOrigins: [VUE_FIXTURE_URL.slice(0, -1)],
            tokenEnv: tokenEnvironmentName,
            framework: 'vue3',
          },
        ],
      }),
    );
    const loaderSource = await fetchLoaderSource();
    app = await createSceneGlassAppForTest({
      configPath,
      environment: { [tokenEnvironmentName]: normalToken },
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

    return {
      canonicalRoot,
      endpoint: `http://127.0.0.1:${address.port}`,
      normalToken,
      close,
    };
  } catch (error: unknown) {
    try {
      await close();
    } catch (cleanupError: unknown) {
      throw new AggregateError(
        [error, cleanupError],
        'export harness setup failed and cleanup also failed',
      );
    }
    throw error;
  }
}

function controls(page: Page): Locator {
  return page.getByRole('complementary', { name: 'Scene Glass 메모 제어' });
}

async function loadVueWithHarness(page: Page, harness: ExportHarness): Promise<void> {
  let originalLoaderFailed = false;
  const blockOriginalLoader = async (route: Route): Promise<void> => {
    originalLoaderFailed = true;
    await route.abort('failed');
  };

  await page.route(configuredLoaderUrl, blockOriginalLoader);
  await page.goto(`${VUE_FIXTURE_URL}?export-query=ignored#export-fragment`);
  await expect.poll(() => originalLoaderFailed).toBe(true);
  await page.evaluate(() => document.querySelector('script[data-scg-project]')?.remove());
  await page.unroute(configuredLoaderUrl, blockOriginalLoader);
  await page.evaluate(
    ({ source, token }) => {
      const script = document.createElement('script');
      script.async = true;
      script.src = source;
      script.dataset.scgProject = 'e2e-export';
      script.dataset.scgToken = token;
      script.dataset.scgNavigation = 'spa';
      document.body.append(script);
    },
    { source: `${harness.endpoint}/scene-glass-loader.js`, token: harness.normalToken },
  );
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('ready');
  await expect(controls(page)).toBeVisible();
}

async function selectAndCreateMemo(page: Page, target: Locator, memo: string): Promise<void> {
  const overlay = controls(page);
  await overlay.getByRole('button', { name: '요소 선택' }).click();
  await target.click();
  await overlay.getByLabel('새 메모').fill(memo);
  await overlay.getByRole('button', { name: '메모 작성' }).click();
  const memoToggle = overlay.getByRole('button', { name: /메모 \(\d+\)/ });
  if ((await memoToggle.getAttribute('aria-expanded')) !== 'true') {
    await memoToggle.click();
  }
  await expect(overlay.getByText(memo, { exact: true })).toBeVisible();
}

async function normalMcpRequest(
  page: Page,
  input: {
    readonly endpoint: string;
    readonly message: Record<string, unknown>;
    readonly sessionId?: string;
    readonly token: string;
  },
): Promise<NormalMcpResponse> {
  return page.evaluate(
    async ({ endpoint, message, protocolVersion, sessionId, token }) => {
      const response = await fetch(`${endpoint}/mcp/v1/projects/e2e-export`, {
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

async function closeNormalMcpSession(
  page: Page,
  input: { readonly endpoint: string; readonly sessionId: string; readonly token: string },
): Promise<number> {
  return page.evaluate(
    async ({ endpoint, protocolVersion, sessionId, token }) => {
      const response = await fetch(`${endpoint}/mcp/v1/projects/e2e-export`, {
        method: 'DELETE',
        credentials: 'omit',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'mcp-protocol-version': protocolVersion,
          'mcp-session-id': sessionId,
        },
      });
      return response.status;
    },
    { ...input, protocolVersion: MCP_PROTOCOL_VERSION },
  );
}

async function markMemoUnresolved(
  page: Page,
  harness: ExportHarness,
  pageIdentity: PageIdentity,
  memo: string,
): Promise<string> {
  const initialized = await normalMcpRequest(page, {
    endpoint: harness.endpoint,
    token: harness.normalToken,
    message: {
      jsonrpc: '2.0',
      id: 'export-normal-initialize',
      method: 'initialize',
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'export-e2e', version: '1.0.0' },
      },
    },
  });
  expect(initialized.status).toBe(200);
  if (initialized.sessionId === null) {
    throw new Error('normal export acceptance session omitted mcp-session-id');
  }

  const sessionId = initialized.sessionId;
  try {
    const notification = await normalMcpRequest(page, {
      endpoint: harness.endpoint,
      token: harness.normalToken,
      sessionId,
      message: {
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {},
      },
    });
    expect(notification.status).toBe(202);

    const listed = await normalMcpRequest(page, {
      endpoint: harness.endpoint,
      token: harness.normalToken,
      sessionId,
      message: {
        jsonrpc: '2.0',
        id: 'export-list-root',
        method: 'tools/call',
        params: { name: 'annotations.list', arguments: { page: pageIdentity } },
      },
    });
    expect(listed.status).toBe(200);
    const review = structuredContent<{
      readonly annotations: readonly AnnotationSummary[];
      readonly revision: number;
    }>(listed.body);
    const annotation = review.annotations.find((candidate) => candidate.memo === memo);
    if (annotation === undefined) {
      throw new Error('root export annotation was not returned by the real annotation authority');
    }

    const updated = await normalMcpRequest(page, {
      endpoint: harness.endpoint,
      token: harness.normalToken,
      sessionId,
      message: {
        jsonrpc: '2.0',
        id: 'export-mark-unresolved',
        method: 'tools/call',
        params: {
          name: 'annotations.update',
          arguments: {
            page: pageIdentity,
            annotationId: annotation.id,
            expectedRevision: review.revision,
            operationId: randomUUID(),
            patch: { resolution: { status: 'ambiguous', reason: 'ambiguous' } },
          },
        },
      },
    });
    expect(updated.status).toBe(200);
  } finally {
    expect(
      await closeNormalMcpSession(page, {
        endpoint: harness.endpoint,
        sessionId,
        token: harness.normalToken,
      }),
    ).toBe(204);
  }
  return sessionId;
}

function structuredContent<T>(body: string): T {
  const parsed = JSON.parse(body) as { result?: { structuredContent?: unknown } };
  if (parsed.result?.structuredContent === undefined) {
    throw new Error('MCP tool response omitted structured content');
  }
  return parsed.result.structuredContent as T;
}
type ExportMode = 'page' | 'project';

type PromptExport = {
  readonly markdown: string;
  readonly sessionId: string | undefined;
};

function mcpProjectEndpoint(endpoint: string): string {
  return `${endpoint}/mcp/v1/projects/${projectId}`;
}

function isPromptExportResponse(
  response: PlaywrightResponse,
  endpoint: string,
  mode: ExportMode,
): boolean {
  if (response.url() !== mcpProjectEndpoint(endpoint)) {
    return false;
  }

  const request = response.request();
  if (
    request.method() !== 'POST' ||
    request.headers()['mcp-protocol-version'] !== MCP_PROTOCOL_VERSION
  ) {
    return false;
  }

  const body = request.postData();
  if (body === null) {
    return false;
  }

  try {
    const message = JSON.parse(body) as {
      readonly method?: unknown;
      readonly params?: {
        readonly arguments?: { readonly mode?: unknown };
        readonly name?: unknown;
      };
    };
    return (
      message.method === 'tools/call' &&
      message.params?.name === 'prompt.export' &&
      message.params?.arguments?.mode === mode
    );
  } catch {
    return false;
  }
}

async function clickAndReadPromptExport(
  page: Page,
  overlay: Locator,
  endpoint: string,
  mode: ExportMode,
): Promise<PromptExport> {
  const endpointUrl = mcpProjectEndpoint(endpoint);
  const responsePromise = page.waitForResponse((response) =>
    isPromptExportResponse(response, endpoint, mode),
  );
  const [response] = await Promise.all([
    responsePromise,
    overlay
      .getByRole('button', {
        name: mode === 'page' ? '현재 페이지 복사' : '프로젝트 전체 복사',
      })
      .click(),
  ]);
  expect(response.url()).toBe(endpointUrl);
  expect(response.request().method()).toBe('POST');
  expect(response.status()).toBe(200);
  const body = await response.text();
  const content = structuredContent<{ readonly markdown?: unknown }>(body);
  if (typeof content.markdown !== 'string') {
    throw new Error('prompt export response structured content omitted Markdown');
  }

  return {
    markdown: content.markdown,
    sessionId: response.request().headers()['mcp-session-id'],
  };
}

async function expectPromptExcludesInternalData(
  output: Locator,
  markdown: string,
  harness: ExportHarness,
  sessionIds: Iterable<string>,
): Promise<void> {
  await expect.poll(async () => (await output.inputValue()) === markdown).toBe(true);
  const browserOutput = await output.inputValue();
  const outputs = [
    ['exported Markdown', markdown],
    ['browser generated prompt', browserOutput],
  ] as const;

  for (const [surface, value] of outputs) {
    expect(value.includes(harness.normalToken), `${surface} exposed the authority token`).toBe(
      false,
    );
    expect(value.includes(harness.canonicalRoot), `${surface} exposed the canonical root`).toBe(
      false,
    );
    expect(value.includes(harness.endpoint), `${surface} exposed the server endpoint`).toBe(false);
    for (const sessionId of sessionIds) {
      expect(value.includes(sessionId), `${surface} exposed an MCP session ID`).toBe(false);
    }
    expect(
      /(?:authorization|bearer\s|mcp-session-id)/i.test(value),
      `${surface} exposed authorization material`,
    ).toBe(false);
  }
}

async function returnToRoute(page: Page, route: '/' | '/pushed'): Promise<void> {
  const pathname = await page.evaluate(() => window.location.pathname);
  if (pathname === route) {
    return;
  }

  await page.getByRole('button', { name: route === '/' ? 'Back' : 'Push route' }).click();
  await expect.poll(() => page.evaluate(() => window.location.pathname)).toBe(route);
}

async function deleteMemoOnCurrentPage(page: Page, memo: string): Promise<void> {
  const overlay = controls(page);
  const toggle = overlay.getByRole('button', { name: /메모 \(\d+\)/ });
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
    await toggle.click();
  }
  await expect(overlay.locator('.scg-ui-annotations')).toBeVisible();
  const row = overlay.locator('.scg-ui-annotation').filter({ hasText: memo });
  await expect(row).toHaveCount(1);
  await row.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText(memo, { exact: true })).toHaveCount(0);
}

test('Vue overlay exports deterministic current-page and project Markdown through the real authority @chromium-full', async ({
  page,
}) => {
  const harness = await createExportHarness();
  const observedPages: PageIdentity[] = [];
  const createdMemos: { readonly memo: string; readonly route: '/' | '/pushed' }[] = [];
  page.on('request', (request) => {
    const body = request.postData();
    if (request.url() !== mcpProjectEndpoint(harness.endpoint) || body === null) {
      return;
    }

    try {
      const message = JSON.parse(body) as {
        readonly method?: unknown;
        readonly params?: {
          readonly arguments?: { readonly page?: PageIdentity };
          readonly name?: unknown;
        };
      };
      if (message.method !== 'tools/call' || message.params?.name !== 'annotations.list') {
        return;
      }
      const pageIdentity = message.params?.arguments?.page;
      if (pageIdentity !== undefined) {
        observedPages.push(pageIdentity);
      }
    } catch {
      return;
    }
  });

  let testFailed = false;
  let testFailure: unknown;
  try {
    await loadVueWithHarness(page, harness);
    await expect(page.getByRole('heading', { name: 'Scene Glass Vue SPA fixture' })).toBeVisible();
    await expect
      .poll(() => observedPages.some((identity) => identity.canonicalIdentity === '/'))
      .toBe(true);
    const rootPage = observedPages.find((identity) => identity.canonicalIdentity === '/');
    if (rootPage === undefined) {
      throw new Error('root annotation load did not expose a page identity');
    }
    expect(rootPage).toMatchObject({ canonicalIdentity: '/', route: '/' });

    await selectAndCreateMemo(page, page.locator('[data-scg-id="annotation-target"]'), rootMemo);
    createdMemos.push({ memo: rootMemo, route: '/' });
    const normalSessionId = await markMemoUnresolved(page, harness, rootPage, rootMemo);
    const sessionIds = new Set<string>([normalSessionId]);

    await page.getByRole('button', { name: 'Push route' }).click();
    await expect(page.getByText('/pushed', { exact: true })).toBeVisible();
    await expect
      .poll(() => observedPages.some((identity) => identity.canonicalIdentity === '/pushed'))
      .toBe(true);
    await selectAndCreateMemo(page, page.locator('[data-scg-id="annotation-target"]'), siblingMemo);
    createdMemos.push({ memo: siblingMemo, route: '/pushed' });

    const overlay = controls(page);
    const output = overlay.getByLabel('생성된 프롬프트');
    const currentPageExport = await clickAndReadPromptExport(
      page,
      overlay,
      harness.endpoint,
      'page',
    );
    if (currentPageExport.sessionId !== undefined) {
      sessionIds.add(currentPageExport.sessionId);
    }
    const currentPageMarkdown = currentPageExport.markdown;
    await expectPromptExcludesInternalData(output, currentPageMarkdown, harness, sessionIds);
    expect(currentPageMarkdown).toContain('## Page Feedback: /pushed');
    expect(currentPageMarkdown).toContain('**Location:**');
    expect(currentPageMarkdown).toContain('**Position:**');
    expect(currentPageMarkdown).toContain(`**Memo:** ${siblingMemo}`);
    expect(currentPageMarkdown).not.toContain(rootMemo);
    expect(currentPageMarkdown).not.toContain('## Page Feedback: /\n');
    expectStableMarkdownDocument(currentPageMarkdown);

    const repeatedCurrentPageExport = await clickAndReadPromptExport(
      page,
      overlay,
      harness.endpoint,
      'page',
    );
    if (repeatedCurrentPageExport.sessionId !== undefined) {
      sessionIds.add(repeatedCurrentPageExport.sessionId);
    }
    await expectPromptExcludesInternalData(
      output,
      repeatedCurrentPageExport.markdown,
      harness,
      sessionIds,
    );
    expect(
      repeatedCurrentPageExport.markdown === currentPageMarkdown,
      'repeated current-page export was not deterministic',
    ).toBe(true);

    const projectExport = await clickAndReadPromptExport(
      page,
      overlay,
      harness.endpoint,
      'project',
    );
    if (projectExport.sessionId !== undefined) {
      sessionIds.add(projectExport.sessionId);
    }
    const projectMarkdown = projectExport.markdown;
    await expectPromptExcludesInternalData(output, projectMarkdown, harness, sessionIds);
    expect(projectMarkdown).toContain('## Page Feedback: /\n');
    expect(projectMarkdown).toContain('## Page Feedback: /pushed');
    expect(projectMarkdown.indexOf('## Page Feedback: /\n')).toBeLessThan(
      projectMarkdown.indexOf('## Page Feedback: /pushed'),
    );
    expect(projectMarkdown).toContain('> WARNING: unresolved (ambiguous)');
    expect(projectMarkdown).toContain('**Location:**');
    expect(projectMarkdown).toContain('**Position:**');
    expect(projectMarkdown).toContain(
      '**Memo:** Root export \\`\\*\\_{}\\[\\]()#+.!>|~- 🧪 \\`\\`\\`\\`\\`\\`',
    );
    expect(projectMarkdown).toContain(`**Memo:** ${siblingMemo}`);
    expectStableMarkdownDocument(projectMarkdown);

    const repeatedProjectExport = await clickAndReadPromptExport(
      page,
      overlay,
      harness.endpoint,
      'project',
    );
    if (repeatedProjectExport.sessionId !== undefined) {
      sessionIds.add(repeatedProjectExport.sessionId);
    }
    await expectPromptExcludesInternalData(
      output,
      repeatedProjectExport.markdown,
      harness,
      sessionIds,
    );
    expect(
      repeatedProjectExport.markdown === projectMarkdown,
      'repeated project export was not deterministic',
    ).toBe(true);

    await page.getByRole('button', { name: 'Render delayed content' }).click();
    await expect(page.getByText('Delayed content is rendered.', { exact: true })).toBeVisible();
  } catch (error: unknown) {
    testFailed = true;
    testFailure = error;
  }

  const cleanupFailures: unknown[] = [];
  for (const created of [...createdMemos].reverse()) {
    try {
      await returnToRoute(page, created.route);
      await deleteMemoOnCurrentPage(page, created.memo);
    } catch (error: unknown) {
      cleanupFailures.push(error);
    }
  }
  try {
    await harness.close();
  } catch (error: unknown) {
    cleanupFailures.push(error);
  }

  if (testFailed) {
    if (cleanupFailures.length > 0) {
      throw new AggregateError(
        [testFailure, ...cleanupFailures],
        'export acceptance test failed and cleanup also failed',
      );
    }
    throw testFailure;
  }
  if (cleanupFailures.length > 0) {
    throw new AggregateError(cleanupFailures, 'export acceptance cleanup failed');
  }
});

function expectStableMarkdownDocument(markdown: string): void {
  expect(markdown.startsWith('\uFEFF')).toBe(false);
  expect(markdown.startsWith('# Scene Glass Review\n')).toBe(true);
  expect(markdown.endsWith('\n')).toBe(true);
  expect(markdown.endsWith('\n\n')).toBe(false);
  expect(markdown).not.toContain('\r');
  expect(markdown).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
}
