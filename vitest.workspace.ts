import { defineConfig } from 'vitest/config';
const sourceUrl = (path: string) => new URL(path, import.meta.url).href;

const sourceAliases = [
  {
    find: /^@scene-glass\/contracts$/,
    replacement: sourceUrl('./packages/contracts/src/index.ts'),
  },
  {
    find: /^@scene-glass\/core$/,
    replacement: sourceUrl('./packages/core/src/screen-review.ts'),
  },
  {
    find: /^@scene-glass\/core\/(.+)$/,
    replacement: `${sourceUrl('./packages/core/src/')}$1.ts`,
  },
  {
    find: /^@scene-glass\/server$/,
    replacement: sourceUrl('./packages/server/src/app.ts'),
  },
  {
    find: /^@scene-glass\/browser-client$/,
    replacement: sourceUrl('./packages/browser-client/src/loader.ts'),
  },
];

export default defineConfig({
  resolve: {
    alias: sourceAliases,
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'package-unit',
          include: ['packages/*/{src,test}/**/*.{test,spec}.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'contract',
          include: ['tests/contract/**/*.{test,spec}.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'integration',
          include: ['tests/integration/**/*.{test,spec}.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'security',
          include: ['tests/security/**/*.{test,spec}.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'platform',
          include: ['tests/platform/**/*.{test,spec}.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'observability',
          include: ['tests/observability/**/*.{test,spec}.ts'],
        },
      },
    ],
  },
});
