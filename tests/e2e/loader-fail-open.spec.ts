import { expect, test, type Page, type Route } from '@playwright/test';

const STATIC_FIXTURE_URL = 'http://127.0.0.1:4174/index.html';
const VUE_FIXTURE_URL = 'http://127.0.0.1:4173/';
const loaderUrl = requiredEnvironment('SCENE_GLASS_TEST_LOADER_URL');
const projectId = requiredEnvironment('SCENE_GLASS_TEST_PROJECT_ID');
const configuredToken = requiredEnvironment('SCENE_GLASS_TEST_TOKEN');
const configuredOrigin = 'http://127.0.0.1:4174';
const mcpUrl = `${new URL(loaderUrl).origin}/mcp/v1/projects/${encodeURIComponent(projectId)}`;

declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} must be configured for browser acceptance tests`);
  }
  return value;
}

async function expectHostControls(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Increment count' }).click();
  await expect(page.locator('[data-scg-id="static-home-count"]')).toHaveText('Count: 1');
  await page.getByLabel('Host note').fill('The host remains usable');
  await page.getByRole('button', { name: 'Show note' }).click();
  await expect(page.locator('[data-scg-id="static-home-note-output"]')).toHaveText(
    'The host remains usable',
  );
}

async function loadFixtureWithInjectedToken(page: Page, token: string): Promise<void> {
  let originalLoaderFailed = false;
  const blockOriginalLoader = async (route: Route): Promise<void> => {
    originalLoaderFailed = true;
    await route.abort('failed');
  };

  await page.route(loaderUrl, blockOriginalLoader);
  await page.goto(STATIC_FIXTURE_URL);
  await expect.poll(() => originalLoaderFailed).toBe(true);
  await page.evaluate(() => document.querySelector('script[data-scg-project]')?.remove());
  await page.unroute(loaderUrl, blockOriginalLoader);
  await page.evaluate(
    ({ source, nextProjectId, nextToken }) => {
      const script = document.createElement('script');
      script.async = true;
      script.src = source;
      script.dataset.scgProject = nextProjectId;
      script.dataset.scgToken = nextToken;
      script.dataset.scgNavigation = 'document';
      document.head.append(script);
    },
    { source: loaderUrl, nextProjectId: projectId, nextToken: token },
  );
}

async function expectSceneGlassState(page: Page, state: string): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe(state);
}

test('a missing loader is fail-open for the static host @chromium-full', async ({ page }) => {
  await page.route(loaderUrl, (route) => route.abort('failed'));
  await page.goto(STATIC_FIXTURE_URL);

  await expect(
    page.getByRole('heading', { name: 'Scene Glass document navigation' }),
  ).toBeVisible();
  await expectHostControls(page);
});

test('a missing local server is unavailable without blocking Vue navigation @chromium-full', async ({
  page,
}) => {
  await page.route(`${new URL(loaderUrl).origin}/mcp/v1/projects/**`, (route) =>
    route.abort('connectionrefused'),
  );
  await page.goto(VUE_FIXTURE_URL);
  await expectSceneGlassState(page, 'unavailable');

  await page.getByRole('button', { name: 'Push route' }).click();
  await expect(page.getByText('/pushed', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Render delayed content' }).click();
  await expect(page.getByText('Delayed content is rendered.')).toBeVisible();
});

test('an opaque Origin is rejected as a browser network failure without exposing server details @chromium-full', async ({
  page,
}) => {
  const loaderResponse = await fetch(loaderUrl);
  expect(loaderResponse.ok).toBe(true);
  const loaderSource = await loaderResponse.text();
  await page.goto(
    `data:text/html,${encodeURIComponent(
      '<!doctype html><button id="host-control" type="button">Host control</button><output id="host-output"></output><script>document.querySelector("#host-control").addEventListener("click", () => { document.querySelector("#host-output").textContent = "Host control worked"; });</script>',
    )}`,
  );
  await page.evaluate(
    ({ endpoint, nextProjectId, source, token }) => {
      const script = document.createElement('script');
      script.async = true;
      script.dataset.scgEndpoint = endpoint;
      script.dataset.scgProject = nextProjectId;
      script.dataset.scgToken = token;
      script.dataset.scgNavigation = 'document';
      script.textContent = source;
      document.head.append(script);
    },
    {
      endpoint: `${new URL(loaderUrl).origin}/`,
      nextProjectId: projectId,
      source: loaderSource,
      token: configuredToken,
    },
  );

  await expectSceneGlassState(page, 'unavailable');
  await page.getByRole('button', { name: 'Host control' }).click();
  await expect(page.locator('#host-output')).toHaveText('Host control worked');
});

test('allowed 401 and 403 responses become an access error without automatic retries @chromium-full', async ({
  page,
}) => {
  for (const status of [401, 403]) {
    let postCount = 0;
    await page.route(mcpUrl, async (route) => {
      const request = route.request();
      if (request.method() === 'OPTIONS') {
        await route.fulfill({
          status: 204,
          headers: {
            'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version',
            'access-control-allow-methods': 'POST',
            'access-control-allow-origin': configuredOrigin,
          },
        });
        return;
      }
      postCount += 1;
      await route.fulfill({
        status,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': configuredOrigin },
        body: JSON.stringify({ code: 'SCG_AUTH_INVALID' }),
      });
    });

    await loadFixtureWithInjectedToken(page, configuredToken);
    await expectSceneGlassState(page, 'access-error');
    const requestsAtAccessError = postCount;
    await page.waitForTimeout(400);
    expect(postCount).toBe(requestsAtAccessError);
    await expectHostControls(page);

    await page.unroute(mcpUrl);
    await page.goto('about:blank');
  }
});

test('a 5xx failure stays unavailable until the user manually retries @chromium-full', async ({
  page,
}) => {
  let initializePosts = 0;
  let failFirstInitialize = true;
  await page.route(mcpUrl, async (route) => {
    const request = route.request();
    if (request.method() === 'OPTIONS') {
      await route.continue();
      return;
    }
    if (failFirstInitialize && request.postData()?.includes('"method":"initialize"')) {
      failFirstInitialize = false;
      initializePosts += 1;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': configuredOrigin },
        body: JSON.stringify({ code: 'SCG_HTTP_INTERNAL' }),
      });
      return;
    }
    if (request.postData()?.includes('"method":"initialize"')) {
      initializePosts += 1;
    }
    await route.continue();
  });

  await loadFixtureWithInjectedToken(page, configuredToken);
  await expectSceneGlassState(page, 'unavailable');
  await expectHostControls(page);
  await page.waitForTimeout(400);
  expect(initializePosts).toBe(1);

  await page.getByRole('button', { name: '재연결' }).click();
  await expectSceneGlassState(page, 'ready');
  expect(initializePosts).toBe(2);
});

test('the missing-loader host fallback works in Firefox @firefox-smoke', async ({
  browserName,
  page,
}) => {
  test.skip(browserName !== 'firefox', 'The firefox-smoke project owns this browser check.');

  await page.route(loaderUrl, (route) => route.abort('failed'));
  await page.goto(STATIC_FIXTURE_URL);
  await expectHostControls(page);
});
