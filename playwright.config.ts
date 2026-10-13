import { randomBytes } from 'node:crypto';
import { defineConfig, devices } from '@playwright/test';

const loaderUrl = 'http://127.0.0.1:4175/scene-glass-loader.js';
const projectId = 'e2e-base';
const testToken =
  process.env.SCENE_GLASS_PLAYWRIGHT_RUN_TOKEN ?? randomBytes(32).toString('base64url');

Object.assign(process.env, {
  SCENE_GLASS_TEST_LOADER_URL: loaderUrl,
  SCENE_GLASS_TEST_PROJECT_ID: projectId,
  SCENE_GLASS_TEST_TOKEN: testToken,
  SCENE_GLASS_PLAYWRIGHT_RUN_TOKEN: testToken,
});

const fixtureEnvironment = {
  SCENE_GLASS_TEST_LOADER_URL: loaderUrl,
  SCENE_GLASS_TEST_PROJECT_ID: projectId,
  SCENE_GLASS_TEST_TOKEN: testToken,
  VITE_SCENE_GLASS_LOADER_URL: loaderUrl,
  VITE_SCENE_GLASS_PROJECT_ID: projectId,
  VITE_SCENE_GLASS_PROJECT_TOKEN: testToken,
};

export default defineConfig({
  testDir: './tests/e2e',
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox-smoke',
      grep: /@firefox-smoke/,
      use: { ...devices['Desktop Firefox'] },
    },
  ],
  webServer: [
    {
      command:
        'corepack pnpm --filter @scene-glass/browser-client run build && corepack pnpm exec tsx tests/e2e/base-authority.ts',
      url: loaderUrl,
      reuseExistingServer: false,
      env: fixtureEnvironment,
    },
    {
      command:
        'corepack pnpm --dir fixtures/vue3-spa exec vite --host 127.0.0.1 --port 4173 --strictPort',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      env: fixtureEnvironment,
    },
    {
      command:
        'corepack pnpm --dir fixtures/static-html exec vite --host 127.0.0.1 --port 4174 --strictPort',
      url: 'http://127.0.0.1:4174',
      reuseExistingServer: false,
      env: fixtureEnvironment,
    },
  ],
});
