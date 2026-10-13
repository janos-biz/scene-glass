import {
  expect,
  test,
  type Locator,
  type Page,
  type Request,
  type Response,
  type Route,
} from '@playwright/test';
declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

const VUE_FIXTURE_URL = 'http://127.0.0.1:4173/';
const QUIET_RENDER_TIMEOUT_MS = 2_000;
const LIST_REQUEST_IDLE_BASELINE_MS = 100;

async function sceneGlassState(page: Page): Promise<string | undefined> {
  return page.evaluate(() => window.SceneGlass?.state);
}

async function expectSceneGlassReady(page: Page): Promise<void> {
  await expect.poll(() => sceneGlassState(page)).toBe('ready');
}

function controls(page: Page): Locator {
  return page.getByRole('complementary', {
    name: 'Scene Glass 메모 제어',
  });
}
/**
 * 선택 모드에서는 패널이 접혀 화면을 가리지 않는다. 목록을 보려면 사람이 하듯 런처로 먼저
 * 펼쳐야 하며, 접힌 패널은 접근성 트리에도 없으므로 역할로 찾아지지 않는다.
 */
async function ensurePanelExpanded(overlay: Locator): Promise<void> {
  const page = overlay.page();
  const panel = page.locator('aside.scg-ui-overlay');
  if (await panel.isHidden()) {
    await page.locator('.scg-ui-launcher').click();
    await expect(panel).toBeVisible();
  }
}

async function ensureMemoListExpanded(overlay: Locator): Promise<void> {
  await ensurePanelExpanded(overlay);
  const toggle = overlay.getByRole('button', { name: /메모 \(\d+\)/ });
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
    await toggle.click();
  }
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
}
async function ensureOrphanListExpanded(overlay: Locator): Promise<void> {
  await ensurePanelExpanded(overlay);
  const toggle = overlay.getByRole('button', { name: /유실 데이터 \(\d+\)/ });
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
    await toggle.click();
  }
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
}

type TrackedMemo = {
  readonly route: string;
  text: string;
};

async function selectAndCreateMemo(
  page: Page,
  target: Locator,
  memo: string,
  trackCreatedMemo: () => void,
): Promise<void> {
  const overlay = controls(page);
  await overlay.getByRole('button', { name: '요소 선택' }).click();
  await target.click();
  await overlay.getByLabel('새 메모').fill(memo);
  await overlay.getByRole('button', { name: '메모 작성' }).click();
  trackCreatedMemo();
  await expect(overlay.getByText(memo, { exact: true })).toHaveCount(1);
}

async function cleanupTrackedMemos(page: Page, memos: readonly TrackedMemo[]): Promise<void> {
  const failures: unknown[] = [];

  for (const memo of [...memos].reverse()) {
    try {
      const canonicalIdentity = new URL(memo.route, VUE_FIXTURE_URL).pathname;
      const listResponseReceived = waitForCanonicalListResponse(
        page,
        canonicalIdentity,
        `loading tracked memo cleanup page ${memo.route}`,
      );
      await navigateWithHistory(page, memo.route);
      const listResponse = await listResponseReceived;
      await waitForResponseCompletion(
        listResponse,
        `loading tracked memo cleanup page ${memo.route}`,
      );

      const overlay = controls(page);
      await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toHaveAttribute(
        'data-state',
        'ready',
        {
          timeout: QUIET_RENDER_TIMEOUT_MS,
        },
      );
      await ensureMemoListExpanded(overlay);
      const memoLocator = overlay.locator('.scg-ui-annotation').filter({ hasText: memo.text });
      if (
        (await overlay
          .locator('.scg-ui-orphans .scg-ui-annotation')
          .filter({ hasText: memo.text })
          .count()) > 0
      ) {
        await ensureOrphanListExpanded(overlay);
      }
      const memoCount = await memoLocator.count();
      for (let remaining = memoCount; remaining > 0; remaining -= 1) {
        await memoLocator.first().getByRole('button', { name: '삭제' }).click({
          timeout: QUIET_RENDER_TIMEOUT_MS,
        });
        await expect(memoLocator).toHaveCount(remaining - 1, {
          timeout: QUIET_RENDER_TIMEOUT_MS,
        });
      }
    } catch (error) {
      failures.push(error);
    }
  }

  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      'SCENE_GLASS_E2E_VUE_SPA_CLEANUP_FAILED: tracked memos could not all be removed.',
    );
  }
}
async function navigateWithHistory(page: Page, target: string): Promise<void> {
  await page.evaluate((route) => {
    window.history.pushState({ fixtureRoute: route }, '', route);
  }, target);
}
type LoaderPageIdentityAttributes = {
  readonly includeHash: string;
  readonly includeQuery: string;
  readonly pageIdentity?: string;
  readonly pathname: string;
};

async function configureLoaderPageIdentityAttributes(
  page: Page,
  configurations: readonly LoaderPageIdentityAttributes[],
): Promise<void> {
  await page.addInitScript((attributeConfigurations) => {
    const applyConfiguration = (script: HTMLScriptElement): void => {
      if (script.getAttribute('data-scg-navigation') !== 'spa') {
        return;
      }

      const configuration = attributeConfigurations.find(
        (candidate) => candidate.pathname === window.location.pathname,
      );
      if (configuration === undefined) {
        return;
      }

      script.setAttribute('data-scg-include-query', configuration.includeQuery);
      script.setAttribute('data-scg-include-hash', configuration.includeHash);
      if (configuration.pageIdentity === undefined) {
        script.removeAttribute('data-scg-page-identity');
      } else {
        script.setAttribute('data-scg-page-identity', configuration.pageIdentity);
      }
    };

    const applyToAddedNode = (node: Node): void => {
      if (node instanceof HTMLScriptElement) {
        applyConfiguration(node);
      }
      if (node instanceof Element) {
        for (const script of node.querySelectorAll<HTMLScriptElement>(
          'script[data-scg-navigation="spa"]',
        )) {
          applyConfiguration(script);
        }
      }
    };

    const observer = new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          applyToAddedNode(node);
        }
      }
    });
    observer.observe(document, { childList: true, subtree: true });

    for (const script of document.querySelectorAll<HTMLScriptElement>(
      'script[data-scg-navigation="spa"]',
    )) {
      applyConfiguration(script);
    }
  }, configurations);
}
function isAnnotationsListRequest(request: Request): boolean {
  const body = request.postData();
  return (
    request.url().includes('/mcp/v1/projects/') &&
    typeof body === 'string' &&
    body.includes('"annotations.list"')
  );
}

function isCanonicalListRequest(request: Request, canonicalIdentity: string): boolean {
  const body = request.postData();
  return (
    isAnnotationsListRequest(request) &&
    typeof body === 'string' &&
    body.includes(`"canonicalIdentity":"${canonicalIdentity}"`) &&
    body.includes(`"route":"${canonicalIdentity}"`)
  );
}
function isCreateRequestForMemo(request: Request, memo: string): boolean {
  const body = request.postData();
  return (
    request.url().includes('/mcp/v1/projects/') &&
    typeof body === 'string' &&
    body.includes('"annotations.create"') &&
    body.includes(memo)
  );
}

async function waitForCanonicalListRequest(
  page: Page,
  canonicalIdentity: string,
  phase: string,
): Promise<Request> {
  try {
    return await page.waitForRequest(
      (request) => isCanonicalListRequest(request, canonicalIdentity),
      { timeout: QUIET_RENDER_TIMEOUT_MS },
    );
  } catch (error: unknown) {
    throw new Error(
      `${phase}: expected annotations.list for canonical page ${canonicalIdentity}. ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

async function waitForCanonicalListResponse(
  page: Page,
  canonicalIdentity: string,
  phase: string,
): Promise<Response> {
  try {
    return await page.waitForResponse(
      (response) => isCanonicalListRequest(response.request(), canonicalIdentity),
      { timeout: QUIET_RENDER_TIMEOUT_MS },
    );
  } catch (error: unknown) {
    throw new Error(
      `${phase}: expected annotations.list response for canonical page ${canonicalIdentity}. ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
async function waitForNoListRequest(page: Page, phase: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onRequest = (request: Request): void => {
      if (isAnnotationsListRequest(request)) {
        cleanup();
        reject(new Error(`${phase}: loader sent an unexpected annotations.list request.`));
      }
    };
    const timeout = setTimeout(() => {
      cleanup();
      resolve();
    }, QUIET_RENDER_TIMEOUT_MS);
    const cleanup = (): void => {
      page.off('request', onRequest);
      clearTimeout(timeout);
    };

    page.on('request', onRequest);
  });
}
async function waitForCreateResponse(page: Page, memo: string, phase: string): Promise<Response> {
  try {
    return await page.waitForResponse(
      (response) => isCreateRequestForMemo(response.request(), memo),
      { timeout: QUIET_RENDER_TIMEOUT_MS },
    );
  } catch (error: unknown) {
    throw new Error(
      `${phase}: expected annotations.create response for the held memo. ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
async function waitForBarrier(isComplete: () => boolean, phase: string): Promise<void> {
  await expect
    .poll(isComplete, {
      message: `${phase}: did not reach the required completion barrier.`,
      timeout: QUIET_RENDER_TIMEOUT_MS,
    })
    .toBe(true);
}
async function waitForResponseCompletion(response: Response, phase: string): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const completion = async (): Promise<void> => {
    try {
      await response.body();
    } catch (error) {
      const requestFailure = response.request().failure();
      if (requestFailure !== null) {
        throw new Error(`${phase}: response failed: ${requestFailure.errorText}`);
      }
      if (error instanceof Error && error.message.includes('No data found for resource')) {
        return;
      }
      throw new Error(
        `${phase}: response body was unavailable: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };
  try {
    await Promise.race([
      completion(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(
            new Error(
              `${phase}: response body was not available within ${QUIET_RENDER_TIMEOUT_MS}ms.`,
            ),
          );
        }, QUIET_RENDER_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

function observeListRequestActivity(page: Page): {
  readonly dispose: () => void;
  readonly waitForIdle: (phase: string) => Promise<void>;
} {
  const activeRequests = new Set<Request>();
  let idleSince = Date.now();
  const onRequest = (request: Request): void => {
    if (isAnnotationsListRequest(request)) {
      activeRequests.add(request);
      idleSince = 0;
    }
  };
  const onRequestDone = (request: Request): void => {
    if (activeRequests.delete(request) && activeRequests.size === 0) {
      idleSince = Date.now();
    }
  };
  page.on('request', onRequest);
  page.on('requestfailed', onRequestDone);
  page.on('requestfinished', onRequestDone);

  return Object.freeze({
    dispose: (): void => {
      page.off('request', onRequest);
      page.off('requestfailed', onRequestDone);
      page.off('requestfinished', onRequestDone);
    },
    waitForIdle: async (phase: string): Promise<void> => {
      await expect
        .poll(
          () =>
            activeRequests.size === 0 &&
            idleSince !== 0 &&
            Date.now() - idleSince >= LIST_REQUEST_IDLE_BASELINE_MS,
          {
            message: `${phase}: expected a quiet annotations.list baseline before triggering the action.`,
            timeout: QUIET_RENDER_TIMEOUT_MS,
          },
        )
        .toBe(true);
    },
  });
}

test('Vue SPA uses the quiet-DOM fallback when no host readiness callback follows a render @chromium-full', async ({
  page,
}) => {
  const listActivity = observeListRequestActivity(page);

  try {
    await page.goto(VUE_FIXTURE_URL);
    await expectSceneGlassReady(page);
    await listActivity.waitForIdle('quiet-DOM fallback baseline');

    const fallbackListRequest = waitForCanonicalListRequest(
      page,
      '/',
      'quiet-DOM fallback after host mutation',
    );
    await page.evaluate(() => {
      const fallbackMarker = document.createElement('p');
      fallbackMarker.textContent = 'Fallback render marker';
      document.querySelector('main')?.append(fallbackMarker);
    });
    await expect(page.getByText('Fallback render marker', { exact: true })).toBeVisible();
    await fallbackListRequest;
  } finally {
    listActivity.dispose();
  }
});
// Programmatic authority, frozen resolver context/generation, and stale async completion are covered
// directly by the "passes a snapshotted static override and explicit query/hash policy to core
// resolution", "gives async resolvers distinct frozen location snapshots for each navigation
// generation", and "keeps stale async page-identity overrides from publishing an older page"
// tests in tests/contract/runtime-lifecycle.test.ts; loader E2E remains attribute-only.
test('Vue SPA loader page-identity attributes preserve override authority and explicit policies @chromium-full', async ({
  page,
}) => {
  const staticOverride = '/approved/static-identity';
  const staticHostRoute = '/loader-static-override?host-query=ignored#host-hash';
  const policyHostRoute = '/loader-explicit-policy?included-query=yes#included-hash';
  const falsePolicyHostRoute = '/loader-explicit-false?excluded-query=yes#excluded-hash';
  await configureLoaderPageIdentityAttributes(page, [
    {
      pathname: '/loader-static-override',
      pageIdentity: staticOverride,
      includeQuery: 'true',
      includeHash: 'true',
    },
    {
      pathname: '/loader-explicit-policy',
      includeQuery: 'true',
      includeHash: 'true',
    },
    {
      pathname: '/loader-explicit-false',
      includeQuery: 'false',
      includeHash: 'false',
    },
  ]);

  const staticIdentityRequest = waitForCanonicalListRequest(
    page,
    staticOverride,
    'static loader identity override',
  );
  await page.goto(new URL(staticHostRoute, VUE_FIXTURE_URL).toString());
  await expectSceneGlassReady(page);
  const loader = page.locator('script[data-scg-navigation="spa"]');
  await expect(loader).toHaveCount(1);
  await expect(loader).toHaveAttribute('data-scg-page-identity', staticOverride);
  await expect(loader).toHaveAttribute('data-scg-include-query', 'true');
  await expect(loader).toHaveAttribute('data-scg-include-hash', 'true');
  const staticRequest = await staticIdentityRequest;
  expect(staticRequest.postData()).not.toContain('host-query=ignored');
  expect(staticRequest.postData()).not.toContain('host-hash');

  const reloadedStaticIdentityRequest = waitForCanonicalListRequest(
    page,
    staticOverride,
    'static loader identity direct reload',
  );
  await page.reload();
  await reloadedStaticIdentityRequest;

  const policyIdentity = '/loader-explicit-policy?included-query=yes#included-hash';
  const policyIdentityRequest = waitForCanonicalListRequest(
    page,
    policyIdentity,
    'explicit query and hash loader policy',
  );
  await page.goto(new URL(policyHostRoute, VUE_FIXTURE_URL).toString());
  await expectSceneGlassReady(page);
  await expect(loader).toHaveAttribute('data-scg-include-query', 'true');
  await expect(loader).toHaveAttribute('data-scg-include-hash', 'true');
  expect(await loader.getAttribute('data-scg-page-identity')).toBeNull();
  await policyIdentityRequest;

  const falsePolicyIdentityRequest = waitForCanonicalListRequest(
    page,
    '/loader-explicit-false',
    'explicit false query and hash loader policy',
  );
  await page.goto(new URL(falsePolicyHostRoute, VUE_FIXTURE_URL).toString());
  await expectSceneGlassReady(page);
  await expect(loader).toHaveAttribute('data-scg-include-query', 'false');
  await expect(loader).toHaveAttribute('data-scg-include-hash', 'false');
  const falsePolicyRequest = await falsePolicyIdentityRequest;
  expect(falsePolicyRequest.postData()).not.toContain('excluded-query=yes');
  expect(falsePolicyRequest.postData()).not.toContain('excluded-hash');
});
test('Vue SPA loader rejects malformed identity booleans without blocking host controls @chromium-full', async ({
  page,
}) => {
  const malformedConfigurations: readonly LoaderPageIdentityAttributes[] = [
    { pathname: '/loader-invalid-true', includeQuery: 'TRUE', includeHash: 'false' },
    { pathname: '/loader-invalid-false', includeQuery: 'False', includeHash: 'false' },
    { pathname: '/loader-invalid-one', includeQuery: '1', includeHash: 'false' },
    { pathname: '/loader-invalid-empty', includeQuery: '', includeHash: 'false' },
  ];
  await configureLoaderPageIdentityAttributes(page, malformedConfigurations);

  for (const configuration of malformedConfigurations) {
    const malformedValue = configuration.includeQuery === '' ? 'empty' : configuration.includeQuery;
    const phase = `malformed loader boolean ${malformedValue}`;
    const noListRequest = waitForNoListRequest(page, phase);

    await page.goto(new URL(configuration.pathname, VUE_FIXTURE_URL).toString());
    await expect
      .poll(() => sceneGlassState(page), { timeout: QUIET_RENDER_TIMEOUT_MS })
      .toBe('unavailable');
    const loader = page.locator('script[data-scg-navigation="spa"]');
    await expect(loader).toHaveAttribute('data-scg-include-query', configuration.includeQuery, {
      timeout: QUIET_RENDER_TIMEOUT_MS,
    });

    await expect(page.getByRole('button', { name: 'Push route' })).toBeEnabled({
      timeout: QUIET_RENDER_TIMEOUT_MS,
    });
    await page.getByRole('button', { name: 'Push route' }).click();
    await expect(page.getByText('/pushed', { exact: true })).toBeVisible({
      timeout: QUIET_RENDER_TIMEOUT_MS,
    });
    await page.getByRole('button', { name: 'Replace route' }).click();
    await expect(page.getByText('/replaced', { exact: true })).toBeVisible({
      timeout: QUIET_RENDER_TIMEOUT_MS,
    });
    await page.getByRole('button', { name: 'Render delayed content' }).click();
    await expect(page.getByText('Delayed content is rendered.', { exact: true })).toBeVisible({
      timeout: QUIET_RENDER_TIMEOUT_MS,
    });
    await noListRequest;
  }
});
async function runVueSpaScenario(page: Page, trackedMemos: TrackedMemo[]): Promise<void> {
  await page.addInitScript(() => {
    document.addEventListener('DOMContentLoaded', () => {
      const root = document.querySelector('main');
      if (root === null) {
        return;
      }

      const fingerprintTarget = document.createElement('button');
      fingerprintTarget.id = 'vue-fingerprint-target';
      fingerprintTarget.type = 'button';
      fingerprintTarget.textContent = 'Fingerprint-only review target';
      root.append(fingerprintTarget);

      for (let index = 0; index < 2; index += 1) {
        const ambiguousTarget = document.createElement('button');
        ambiguousTarget.type = 'button';
        ambiguousTarget.dataset.scgId = 'vue-ambiguous-target';
        ambiguousTarget.textContent = 'Ambiguous review target';
        root.append(ambiguousTarget);
      }
    });
  });

  await page.goto(VUE_FIXTURE_URL);
  await expect(page.getByRole('heading', { name: 'Scene Glass Vue SPA fixture' })).toBeVisible();

  const loader = page.locator('script[data-scg-navigation="spa"]');
  await expect(loader).toHaveCount(1);
  await expect(loader).toHaveAttribute('data-scg-project', /.+/);
  expect(await loader.getAttribute('data-scg-token')).toBeNull();
  await expect(loader).toHaveAttribute('src', /^http:\/\/127\.0\.0\.1:/);
  expect(await loader.evaluate((element) => element.outerHTML)).not.toContain('\n');

  await expectSceneGlassReady(page);
  await expect(controls(page)).toBeVisible();

  await page.getByRole('button', { name: 'Push route' }).click();
  await expect(page.getByText('/pushed', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Replace route' }).click();
  await expect(page.getByText('/replaced', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Back' }).click();
  await expect(page.getByText('/', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Hash route' }).click();
  await expect(page.getByText('/#fixture-hash', { exact: true })).toBeVisible();

  await expect(page.getByText(/Ready signals: [1-9]/)).toBeVisible();
  await page.getByRole('button', { name: 'Render delayed content' }).click();
  await expect(page.getByText('Delayed content is rendered.')).toBeVisible();

  const listActivity = observeListRequestActivity(page);
  try {
    await listActivity.waitForIdle('SPA pathname push baseline');
    const pushedListRequestReceived = waitForCanonicalListRequest(
      page,
      '/pushed',
      'SPA pathname push navigation',
    );
    const pushedListResponseReceived = waitForCanonicalListResponse(
      page,
      '/pushed',
      'SPA pathname push navigation',
    );
    await page.getByRole('button', { name: 'Push route' }).click();
    await pushedListRequestReceived;
    await waitForResponseCompletion(
      await pushedListResponseReceived,
      'SPA pathname push navigation',
    );

    await listActivity.waitForIdle('SPA pathname replace baseline');
    const replacedListRequestReceived = waitForCanonicalListRequest(
      page,
      '/replaced',
      'SPA pathname replace navigation',
    );
    const replacedListResponseReceived = waitForCanonicalListResponse(
      page,
      '/replaced',
      'SPA pathname replace navigation',
    );
    await page.getByRole('button', { name: 'Replace route' }).click();
    await replacedListRequestReceived;
    await waitForResponseCompletion(
      await replacedListResponseReceived,
      'SPA pathname replace navigation',
    );

    await listActivity.waitForIdle('SPA hash navigation baseline');
    const hashListRequestReceived = waitForCanonicalListRequest(
      page,
      '/replaced',
      'SPA hash navigation',
    );
    const hashListResponseReceived = waitForCanonicalListResponse(
      page,
      '/replaced',
      'SPA hash navigation',
    );
    await page.getByRole('button', { name: 'Hash route' }).click();
    await expect(page.getByText('/replaced#fixture-hash', { exact: true })).toBeVisible();
    const hashListRequest = await hashListRequestReceived;
    expect(hashListRequest.postData()).not.toContain('fixture-hash');
    await waitForResponseCompletion(await hashListResponseReceived, 'SPA hash navigation');

    await listActivity.waitForIdle('SPA query navigation baseline');
    const queryListRequestReceived = waitForCanonicalListRequest(
      page,
      '/replaced',
      'SPA query navigation',
    );
    const queryListResponseReceived = waitForCanonicalListResponse(
      page,
      '/replaced',
      'SPA query navigation',
    );
    await navigateWithHistory(page, '?fixture-query=retained');
    await expect(page).toHaveURL(/\/replaced\?fixture-query=retained$/);
    const queryListRequest = await queryListRequestReceived;
    expect(queryListRequest.postData()).not.toContain('fixture-query=retained');
    await waitForResponseCompletion(await queryListResponseReceived, 'SPA query navigation');
  } finally {
    listActivity.dispose();
  }

  const overlay = controls(page);
  const annotationTarget = page.locator('[data-scg-id="annotation-target"]');
  const olderRoute = '/generation-older';
  const newerRoute = '/generation-newer';
  const olderMemoText = 'Older generation annotation';
  const newerMemoText = 'Newer generation annotation';

  const olderListRequestReceived = waitForCanonicalListRequest(
    page,
    olderRoute,
    'loading older generation page',
  );
  const olderListResponseReceived = waitForCanonicalListResponse(
    page,
    olderRoute,
    'loading older generation page',
  );
  await navigateWithHistory(page, olderRoute);
  await olderListRequestReceived;
  await waitForResponseCompletion(await olderListResponseReceived, 'loading older generation page');
  await selectAndCreateMemo(page, annotationTarget, olderMemoText, () => {
    trackedMemos.push({ route: olderRoute, text: olderMemoText });
  });

  const newerListRequestReceived = waitForCanonicalListRequest(
    page,
    newerRoute,
    'loading newer generation page',
  );
  const newerListResponseReceived = waitForCanonicalListResponse(
    page,
    newerRoute,
    'loading newer generation page',
  );
  await navigateWithHistory(page, newerRoute);
  await newerListRequestReceived;
  await waitForResponseCompletion(await newerListResponseReceived, 'loading newer generation page');
  await selectAndCreateMemo(page, annotationTarget, newerMemoText, () => {
    trackedMemos.push({ route: newerRoute, text: newerMemoText });
  });
  let rejectedCreateRequests = 0;
  page.on('request', (request) => {
    if (
      request.url().includes('/mcp/v1/projects/') &&
      request.postData()?.includes('"annotations.create"')
    ) {
      rejectedCreateRequests += 1;
    }
  });
  await overlay.getByRole('button', { name: '요소 선택' }).click();
  await annotationTarget.click();
  await expect(overlay.getByLabel('새 메모')).toBeEnabled();
  await overlay.getByLabel('새 메모').fill('Rejected transition create');
  const newerMemo = overlay.locator('.scg-ui-annotation').filter({ hasText: newerMemoText });

  let releaseOlderListResponse = (): void => {};
  const olderListResponseReleased = new Promise<void>((resolve) => {
    releaseOlderListResponse = () => resolve();
  });
  let olderListResponseWasIntercepted = false;
  let olderListResponseIsHeld = false;
  let olderListResponseFulfilled = false;
  const delayOlderListResponse = async (route: Route): Promise<void> => {
    if (olderListResponseWasIntercepted || !isCanonicalListRequest(route.request(), olderRoute)) {
      await route.continue();
      return;
    }

    olderListResponseWasIntercepted = true;
    const response = await route.fetch();
    olderListResponseIsHeld = true;
    await olderListResponseReleased;
    await route.fulfill({ response });
    olderListResponseFulfilled = true;
  };
  await page.route('**/mcp/v1/projects/**', delayOlderListResponse);
  try {
    try {
      await navigateWithHistory(page, olderRoute);
      await waitForBarrier(
        () => olderListResponseIsHeld,
        'holding older generation annotations.list response',
      );
      await expect(overlay.getByRole('button', { name: '현재 페이지 복사' })).toBeDisabled();
      await expect(overlay.getByLabel('새 메모')).toBeDisabled();
      await expect(overlay.locator('form.scg-ui-editor')).toBeHidden();
      await overlay
        .locator('form.scg-ui-editor')
        .evaluate((form: HTMLFormElement) =>
          form.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true })),
        );
      await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toContainText(
        'SCG_PAGE_UNREADY',
      );

      await navigateWithHistory(page, newerRoute);
      await ensureMemoListExpanded(overlay);
      await expect(newerMemo).toHaveCount(1);

      const olderListResponseReceived = waitForCanonicalListResponse(
        page,
        olderRoute,
        'releasing held older generation response',
      );
      releaseOlderListResponse();
      await waitForBarrier(
        () => olderListResponseFulfilled,
        'fulfilling held older generation annotations.list response',
      );
      await olderListResponseReceived;

      await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toHaveAttribute(
        'data-state',
        'ready',
      );
      expect(
        rejectedCreateRequests,
        'A create request escaped while the older page was unready or its stale response completed.',
      ).toBe(0);
      await expect(newerMemo).toHaveCount(1);
      await expect(overlay.getByText(newerMemoText, { exact: true })).toHaveCount(1);
      await expect(overlay.getByText(olderMemoText, { exact: true })).toHaveCount(0);
    } finally {
      releaseOlderListResponse();
    }
  } finally {
    await page.unroute('**/mcp/v1/projects/**', delayOlderListResponse);
  }

  await newerMemo.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText(newerMemoText, { exact: true })).toHaveCount(0);
  await navigateWithHistory(page, olderRoute);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText(olderMemoText, { exact: true })).toBeVisible();
  const olderMemo = overlay.locator('.scg-ui-annotation').filter({ hasText: olderMemoText });
  await olderMemo.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText(olderMemoText, { exact: true })).toHaveCount(0);
  await navigateWithHistory(page, '/replaced?fixture-query=retained');

  const exactMemoTracking: TrackedMemo = {
    route: '/replaced?fixture-query=retained',
    text: 'Exact locator memo',
  };
  await selectAndCreateMemo(
    page,
    page.locator('[data-scg-id="annotation-target"]'),
    exactMemoTracking.text,
    () => {
      trackedMemos.push(exactMemoTracking);
    },
  );
  await expect(overlay.getByRole('button', { name: '요소 선택' })).toBeInViewport();
  await selectAndCreateMemo(
    page,
    page.getByRole('button', { name: 'Fingerprint-only review target' }),
    'Fingerprint locator memo',
    () => {
      trackedMemos.push({
        route: '/replaced?fixture-query=retained',
        text: 'Fingerprint locator memo',
      });
    },
  );

  await expect(overlay.getByText('Exact locator memo', { exact: true })).toBeVisible();
  await expect(overlay.getByText('Fingerprint locator memo', { exact: true })).toBeVisible();
  await page.reload();
  await expectSceneGlassReady(page);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Exact locator memo', { exact: true })).toBeVisible();
  await expect(overlay.getByText('Fingerprint locator memo', { exact: true })).toBeVisible();
  await expect(overlay.getByText('연결됨', { exact: true })).toHaveCount(2);
  await expect
    .poll(() => page.locator('button.scg-ui-badge[data-scg-badge-for]').count())
    .toBeGreaterThan(0);
  const exactBadge = page
    .locator('button.scg-ui-badge[data-scg-badge-for]')
    .filter({ hasText: exactMemoTracking.text });
  await expect(exactBadge).toHaveCount(1);
  await exactBadge.click();
  await expect(exactBadge.locator('.scg-ui-badge-popover')).toBeVisible();
  await expect(exactBadge.locator('.scg-ui-badge-memo')).toHaveText(exactMemoTracking.text);

  const exactMemo = overlay.locator('.scg-ui-annotation').filter({ hasText: 'Exact locator memo' });
  await exactMemo.getByRole('button', { name: '수정' }).click();
  await overlay.getByLabel('메모 편집').fill('Exact locator memo revised');
  await overlay.getByRole('button', { name: '메모 저장' }).click();
  exactMemoTracking.text = 'Exact locator memo revised';
  await expect(overlay.getByText('Exact locator memo revised', { exact: true })).toBeVisible();
  await page.reload();
  await expectSceneGlassReady(page);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Exact locator memo revised', { exact: true })).toBeVisible();
  const revisedExactMemo = overlay
    .locator('.scg-ui-annotation')
    .filter({ hasText: 'Exact locator memo revised' });
  await revisedExactMemo.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText('Exact locator memo revised', { exact: true })).toHaveCount(0);
  await page.reload();
  await expectSceneGlassReady(page);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Exact locator memo revised', { exact: true })).toHaveCount(0);
  const fingerprintMemo = overlay
    .locator('.scg-ui-annotation')
    .filter({ hasText: 'Fingerprint locator memo' });
  await fingerprintMemo.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText('Fingerprint locator memo', { exact: true })).toHaveCount(0);
  await page.reload();
  await expectSceneGlassReady(page);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Fingerprint locator memo', { exact: true })).toHaveCount(0);

  await selectAndCreateMemo(
    page,
    page.getByRole('button', { name: 'Ambiguous review target' }).first(),
    'Ambiguous locator memo',
    () => {
      trackedMemos.push({
        route: '/replaced?fixture-query=retained',
        text: 'Ambiguous locator memo',
      });
    },
  );
  await expect(overlay.getByRole('button', { name: '▸ 유실 데이터 (1)' })).toBeVisible();
  await expect(overlay.locator('.scg-ui-annotations')).not.toContainText('Ambiguous locator memo');
  await overlay.getByRole('button', { name: '▸ 유실 데이터 (1)' }).click();
  const orphanList = overlay.locator('.scg-ui-orphans');
  await expect(orphanList).toContainText('Ambiguous locator memo');
  await expect(orphanList.getByText('검토 필요', { exact: true })).toBeVisible();
  await expect(
    page
      .locator('button.scg-ui-badge[data-scg-badge-for]')
      .filter({ hasText: 'Ambiguous locator memo' }),
  ).toHaveCount(0);
  const ambiguousMemo = orphanList
    .locator('.scg-ui-annotation')
    .filter({ hasText: 'Ambiguous locator memo' });
  await ambiguousMemo.getByRole('button', { name: '삭제' }).click();
  await expect(overlay.getByText('Ambiguous locator memo', { exact: true })).toHaveCount(0);

  await overlay.getByRole('button', { name: '요소 선택' }).click();
  await page
    .frameLocator('[data-scg-id="iframe-host"]')
    .getByRole('button', { name: 'Iframe child' })
    .click();
  await expect(overlay.getByText('Iframe child', { exact: true })).toHaveCount(0);
  // 선택 모드에서는 패널이 접혀 고르려는 요소를 가리지 않는다. 그래서 "모드가 유지된다" 는
  // 패널 버튼이 보이는지가 아니라 런처와 버튼 상태로 확인한다.
  await expect(page.locator('.scg-ui-launcher')).toBeVisible();
  await expect(page.locator('.scg-ui-selection')).toHaveAttribute('aria-pressed', 'true');
}

test('Vue SPA loader settles navigation, persists exact and fingerprint memos, and fails closed @chromium-full', async ({
  page,
}) => {
  const trackedMemos: TrackedMemo[] = [];
  let testFailed = false;
  let testFailure: unknown;

  try {
    await runVueSpaScenario(page, trackedMemos);
  } catch (error) {
    testFailed = true;
    testFailure = error;
  }

  let cleanupFailed = false;
  let cleanupFailure: unknown;
  try {
    await cleanupTrackedMemos(page, trackedMemos);
  } catch (error) {
    cleanupFailed = true;
    cleanupFailure = error;
  }

  if (testFailed) {
    if (cleanupFailed) {
      const cleanupFailures =
        cleanupFailure instanceof AggregateError ? [...cleanupFailure.errors] : [cleanupFailure];
      throw new AggregateError(
        [testFailure, ...cleanupFailures],
        'SCENE_GLASS_E2E_VUE_SPA_TEST_FAILED: test failed and tracked memo cleanup also failed.',
      );
    }
    throw testFailure;
  }

  if (cleanupFailed) {
    throw cleanupFailure;
  }
});
test('Vue SPA deletes every memo on the current page after a second confirmation click @chromium-full', async ({
  page,
}) => {
  await page.goto(VUE_FIXTURE_URL);
  await expectSceneGlassReady(page);

  const overlay = controls(page);
  const target = page.locator('[data-scg-id="annotation-target"]');
  await selectAndCreateMemo(page, target, 'Delete-all memo one', () => {});
  await selectAndCreateMemo(page, target, 'Delete-all memo two', () => {});

  await expect(page.locator('.scg-ui-badge-memo')).toHaveCount(2);
  const deleteAll = overlay.locator('.scg-ui-delete-all');
  await deleteAll.click();
  await expect(deleteAll).toHaveText('정말 전체 삭제? 다시 클릭');
  await expect(overlay.locator('.scg-ui-delete-all-cancel')).toBeVisible();
  await deleteAll.click();

  await expect(page.locator('.scg-ui-badge-memo')).toHaveCount(0);
  await expect(overlay.getByRole('button', { name: /메모 \(0\)/ })).toBeVisible();
  await ensureMemoListExpanded(overlay);
  await expect(overlay.locator('.scg-ui-annotations .scg-ui-annotation')).toHaveCount(0);
});
test('Vue SPA ignores a delayed page action after navigation reaches a newer page @chromium-full', async ({
  page,
}) => {
  await page.goto(VUE_FIXTURE_URL);
  await expectSceneGlassReady(page);

  const overlay = controls(page);
  const target = page.locator('[data-scg-id="annotation-target"]');
  const olderRoute = '/stale-action-older';
  const newerRoute = '/stale-action-newer';
  const staleMemo = 'Stale action must not update the newer page';

  await navigateWithHistory(page, olderRoute);
  await expect(overlay.getByRole('button', { name: '요소 선택' })).toBeEnabled();

  let releaseCreateResponse = (): void => {};
  const createResponseReleased = new Promise<void>((resolve) => {
    releaseCreateResponse = () => resolve();
  });
  let createResponseWasIntercepted = false;
  let createResponseIsHeld = false;
  let createResponseFulfilled = false;
  const delayCreateResponse = async (route: Route): Promise<void> => {
    if (createResponseWasIntercepted || !isCreateRequestForMemo(route.request(), staleMemo)) {
      await route.continue();
      return;
    }

    createResponseWasIntercepted = true;
    const response = await route.fetch();
    createResponseIsHeld = true;
    await createResponseReleased;
    await route.fulfill({ response });
    createResponseFulfilled = true;
  };

  try {
    await page.route('**/mcp/v1/projects/**', delayCreateResponse);
    try {
      try {
        await overlay.getByRole('button', { name: '요소 선택' }).click();
        await target.click();
        await overlay.getByLabel('새 메모').fill(staleMemo);
        await overlay.getByRole('button', { name: '메모 작성' }).click();
        await waitForBarrier(
          () => createResponseIsHeld,
          'holding stale annotations.create response',
        );

        const newerListResponseReceived = waitForCanonicalListResponse(
          page,
          newerRoute,
          'settling newer generation before releasing held create response',
        );
        await navigateWithHistory(page, newerRoute);
        const newerListResponse = await newerListResponseReceived;
        await waitForResponseCompletion(
          newerListResponse,
          'settling newer generation annotations.list response',
        );
        await expect(overlay.getByRole('button', { name: '요소 선택' })).toBeEnabled();
        await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toHaveAttribute(
          'data-state',
          'ready',
        );

        const staleCreateResponseReceived = waitForCreateResponse(
          page,
          staleMemo,
          'releasing stale create response',
        );
        releaseCreateResponse();
        await waitForBarrier(
          () => createResponseFulfilled,
          'fulfilling held stale annotations.create response',
        );
        await staleCreateResponseReceived;

        await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toHaveAttribute(
          'data-state',
          'ready',
        );
        await expect(page.locator('.scg-ui-overlay .scg-ui-status')).not.toContainText(
          'SCG_PAGE_TRANSITION',
        );
        await ensureMemoListExpanded(overlay);
        await expect(overlay.getByText(staleMemo, { exact: true })).toHaveCount(0);
        await expect(overlay.getByLabel('새 메모')).toBeEnabled();
      } finally {
        releaseCreateResponse();
      }
    } finally {
      await page.unroute('**/mcp/v1/projects/**', delayCreateResponse);
    }
  } finally {
    if (createResponseWasIntercepted) {
      await waitForBarrier(
        () => createResponseFulfilled,
        'confirming stale annotations.create completion before cleanup',
      );
      const persistedStaleMemoResponse = waitForCanonicalListResponse(
        page,
        olderRoute,
        'loading persisted stale-action memo for cleanup',
      );
      await navigateWithHistory(page, olderRoute);
      const staleMemoListResponse = await persistedStaleMemoResponse;
      await waitForResponseCompletion(
        staleMemoListResponse,
        'loading persisted stale-action memo for cleanup',
      );
      await ensureMemoListExpanded(overlay);

      const persistedStaleMemo = overlay
        .locator('.scg-ui-annotation')
        .filter({ hasText: staleMemo });
      await expect(
        persistedStaleMemo,
        'The held stale create was not persisted exactly once for deterministic cleanup.',
      ).toHaveCount(1);
      await persistedStaleMemo.getByRole('button', { name: '삭제' }).click();
      await expect(overlay.getByText(staleMemo, { exact: true })).toHaveCount(0);
    }
  }
});

test('Vue SPA retries navigation after the initial History patch fails @chromium-full', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const originalPushState = window.history.pushState;
    let rejectInitialPatch = true;
    Object.defineProperty(window.history, 'pushState', {
      configurable: true,
      get(): History['pushState'] {
        return originalPushState;
      },
      set(next: History['pushState']): void {
        if (rejectInitialPatch) {
          rejectInitialPatch = false;
          throw new Error('History patch is temporarily unavailable');
        }
        Object.defineProperty(window.history, 'pushState', {
          configurable: true,
          value: next,
          writable: true,
        });
      },
    });
  });

  const listActivity = observeListRequestActivity(page);

  try {
    await page.goto(VUE_FIXTURE_URL);
    await expectSceneGlassReady(page);

    const overlay = controls(page);
    await expect(page.locator('.scg-ui-overlay .scg-ui-status')).toContainText(
      'SCG_NAVIGATION_UNAVAILABLE',
    );
    await expect(overlay.getByRole('button', { name: '요소 선택' })).toBeDisabled();
    await expect(overlay.getByRole('button', { name: '재연결' })).toBeEnabled();

    await overlay.getByRole('button', { name: '재연결' }).click();
    await expect(overlay.getByRole('button', { name: '요소 선택' })).toBeEnabled();
    await listActivity.waitForIdle('History retry baseline');

    const retryListRequest = waitForCanonicalListRequest(
      page,
      '/history-patch-retry',
      'History retry navigation',
    );
    await navigateWithHistory(page, '/history-patch-retry');
    await retryListRequest;
  } finally {
    listActivity.dispose();
  }
});

test('Vue SPA teardown preserves a host History wrapper installed after Scene Glass @chromium-full', async ({
  page,
}) => {
  await page.goto(VUE_FIXTURE_URL);
  await expectSceneGlassReady(page);

  const result = await page.evaluate(async (timeoutMs) => {
    const sceneGlass = window.SceneGlass;
    if (sceneGlass === undefined) {
      throw new Error('Scene Glass API is unavailable');
    }

    const sceneGlassPushState = window.history.pushState;
    let hostCalls = 0;
    const hostPushState: History['pushState'] = function (
      this: History,
      ...args: Parameters<History['pushState']>
    ): void {
      hostCalls += 1;
      Reflect.apply(sceneGlassPushState, this, args);
    };
    window.history.pushState = hostPushState;

    let destroyTimeout: number | undefined;
    try {
      await Promise.race([
        (sceneGlass as typeof sceneGlass & { destroy(): Promise<void> }).destroy(),
        new Promise<never>((_resolve, reject) => {
          destroyTimeout = window.setTimeout(() => {
            reject(
              new Error(
                `Vue SPA teardown: SceneGlass.destroy() did not complete within ${timeoutMs}ms.`,
              ),
            );
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (destroyTimeout !== undefined) {
        window.clearTimeout(destroyTimeout);
      }
    }
    const preserved = window.history.pushState === hostPushState;
    window.history.pushState({ hostOwned: true }, '', '/host-owned-after-destroy');

    return {
      hostCalls,
      pathname: window.location.pathname,
      preserved,
      state: sceneGlass.state,
    };
  }, QUIET_RENDER_TIMEOUT_MS);

  expect(result).toEqual({
    hostCalls: 1,
    pathname: '/host-owned-after-destroy',
    preserved: true,
    state: 'destroyed',
  });
});
