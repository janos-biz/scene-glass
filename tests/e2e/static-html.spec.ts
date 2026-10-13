import { expect, test, type Locator, type Page } from '@playwright/test';

const STATIC_FIXTURE_URL = 'http://127.0.0.1:4174/index.html';
const configuredToken = requiredEnvironment('SCENE_GLASS_TEST_TOKEN');

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} must be configured for browser acceptance tests`);
  }
  return value;
}

function controls(page: Page): Locator {
  return page.getByRole('complementary', {
    name: 'Scene Glass 메모 제어',
  });
}
async function ensureMemoListExpanded(overlay: Locator): Promise<void> {
  const toggle = overlay.getByRole('button', { name: /메모 \(\d+\)/ });
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
    await toggle.click();
  }
  await expect(overlay.locator('.scg-ui-annotations')).toBeVisible();
}

async function expectSceneGlassReady(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('ready');
}
async function expectNoTokenExposure(
  page: Page,
  token: string,
  consoleMessages: readonly string[],
): Promise<void> {
  const exposedSurfaces = await page.evaluate(async (tokenToInspect) => {
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
    if (typeof caches !== 'undefined') {
      try {
        const names = await caches.keys();
        cacheKeys.push(...names);
        for (const name of names) {
          let cache: Cache;
          try {
            cache = await caches.open(name);
          } catch {
            continue;
          }

          let requests: readonly Request[];
          try {
            requests = await cache.keys();
          } catch {
            continue;
          }

          for (const request of requests) {
            cacheRequestUrls.push(request.url);
            try {
              const response = await cache.match(request);
              if (response !== undefined) {
                cacheResponseTexts.push(await response.clone().text());
              }
            } catch {
              // Some cache response bodies are intentionally unreadable.
            }
          }
        }
      } catch {
        // CacheStorage is optional in browser contexts.
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
    return Object.fromEntries(
      Object.entries(surfaces).map(([surface, values]) => [
        surface,
        values.some((value) => value.includes(tokenToInspect)),
      ]),
    );
  }, token);

  for (const [surface, exposed] of Object.entries(exposedSurfaces)) {
    expect(exposed, `The configured loader token is exposed in ${surface}.`).toBe(false);
  }
  expect(
    consoleMessages.some((message) => message.includes(token)),
    'The configured loader token is exposed in console output.',
  ).toBe(false);
}

declare global {
  interface Window {
    SceneGlass?: { readonly state: string };
  }
}

test('static HTML documents preserve their logical annotation identity through direct load, navigation, and reload', async ({
  page,
}) => {
  const observedPages: string[] = [];
  const consoleMessages: string[] = [];
  page.on('console', (message) => consoleMessages.push(message.text()));
  page.on('request', (request) => {
    if (!request.url().includes('/mcp/v1/projects/')) {
      return;
    }
    const body = request.postData();
    if (body?.includes('"annotations.list"')) {
      observedPages.push(body);
    }
  });

  await page.goto(STATIC_FIXTURE_URL);
  await expect(
    page.getByRole('heading', { name: 'Scene Glass document navigation' }),
  ).toBeVisible();
  await expect(page.locator('[data-scg-id="static-home-lifecycle"]')).toContainText(
    /document; pageshow (loaded|restored from bfcache)\./,
  );
  await expectSceneGlassReady(page);
  const loader = page.locator('script[data-scg-navigation="document"]');
  expect(await loader.count(), 'Expected exactly one static HTML loader script.').toBe(1);
  expect(
    await loader.evaluate((element) => element.getAttribute('data-scg-token') === null),
    'The static HTML loader token attribute was not removed.',
  ).toBe(true);
  await expectNoTokenExposure(page, configuredToken, consoleMessages);

  const overlay = controls(page);
  await expect(overlay).toBeVisible();
  await overlay.getByRole('button', { name: '요소 선택' }).click();
  await page.locator('[data-scg-id="static-home-document-path"]').click();
  await overlay.getByLabel('새 메모').fill('Static document identity memo');
  await overlay.getByRole('button', { name: '메모 작성' }).click();
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Static document identity memo', { exact: true })).toBeVisible();
  await expect.poll(() => observedPages.length).toBeGreaterThan(0);
  const homeIdentity = observedPages.at(-1);
  expect(homeIdentity).toBeDefined();

  await page.getByRole('link', { name: 'Open page two' }).click();
  await expect(page.getByRole('heading', { name: 'Page two document navigation' })).toBeVisible();
  await expect(page.locator('[data-scg-id="static-page-two-lifecycle"]')).toContainText(
    /document; pageshow (loaded|restored from bfcache)\./,
  );
  await page.getByRole('button', { name: 'Show review details' }).click();
  await expect(page.getByText('This panel is controlled entirely by the host page')).toBeVisible();
  await page.getByRole('button', { name: 'Acknowledge review' }).click();
  await expect(page.getByText('Review acknowledged by the host page.')).toBeVisible();

  await page.getByRole('link', { name: 'Return home' }).click();
  await expect(
    page.getByRole('heading', { name: 'Scene Glass document navigation' }),
  ).toBeVisible();
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Static document identity memo', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Reload document' }).click();
  await expect(page.locator('[data-scg-id="static-home-lifecycle"]')).toContainText(
    /reload document; pageshow (loaded|restored from bfcache)\./,
  );
  await expectSceneGlassReady(page);
  await ensureMemoListExpanded(overlay);
  await expect(overlay.getByText('Static document identity memo', { exact: true })).toBeVisible();
  await expect.poll(() => observedPages.some((identity) => identity === homeIdentity)).toBe(true);

  await page.getByRole('button', { name: 'Increment count' }).click();
  await page.getByRole('button', { name: 'Increment count' }).click();
  await expect(page.locator('[data-scg-id="static-home-count"]')).toHaveText('Count: 2');
  await page.getByLabel('Host note').fill('Host controls remain available');
  await page.getByRole('button', { name: 'Show note' }).click();
  await expect(page.locator('[data-scg-id="static-home-note-output"]')).toHaveText(
    'Host controls remain available',
  );
  await page.getByRole('button', { name: 'Next rows' }).click();
  await expect(page.locator('[data-scg-id="static-home-virtual-range"]')).toHaveText(
    'Rows 6-10 of 25',
  );
});

test('static HTML host controls remain usable in Firefox @firefox-smoke', async ({
  browserName,
  page,
}) => {
  test.skip(browserName !== 'firefox', 'The firefox-smoke project owns this browser check.');

  await page.goto(STATIC_FIXTURE_URL);
  await expect(
    page.getByRole('heading', { name: 'Scene Glass document navigation' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Increment count' }).click();
  await expect(page.locator('[data-scg-id="static-home-count"]')).toHaveText('Count: 1');
  await page.getByRole('link', { name: 'Open page two' }).click();
  await page.getByRole('button', { name: 'Acknowledge review' }).click();
  await expect(page.getByText('Review acknowledged by the host page.')).toBeVisible();
});
