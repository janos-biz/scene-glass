import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  HOST_PLAN_SCHEMA_VERSION,
  MANAGED_VITE_CONTRACT,
  HostPlanError,
  finalizeHostIntegrationPlan,
  managedVitePluginFromConfig,
  planHostIntegration,
  canonicalDeclaredViteOrigins,
  isHistoricalDeclaredViteOriginPair,
  replaceHistoricalDeclaredViteOriginPair,
  resolveDeclaredViteOriginPolicy,
  type HostCandidateFact,
  type HostIntegrationPlan,
  type HostPlanInput,
} from '../../packages/onboarding/src/lifecycle/host-plan.js';
import { parseViteHostDescriptorV1 } from '../../packages/onboarding/src/descriptors.js';

const AUTHORITY = {
  projectId: 'alpha',
  path: '/var/lib/scene-glass/alpha.credential',
  device: '10',
  inode: '20',
} as const;

function descriptor() {
  return {
    projectId: 'alpha',
    port: 4173,
    installId: 'install-alpha',
    approvedRootIdentity: { device: '1', inode: '2' },
    credentialAuthorities: [AUTHORITY],
  } as const;
}

function packageFacts(framework: 'vue3' | 'react') {
  return {
    name: 'host-app',
    resolvedDependencies:
      framework === 'vue3'
        ? [
            { name: 'vite', version: '^7.4.0' },
            { name: 'vue', version: '~3.5.0' },
            { name: '@vitejs/plugin-vue', version: '^6.1.0' },
          ]
        : [
            { name: 'vite', version: '^7.4.0' },
            { name: 'react', version: '>=18.2.0 <19.0.0' },
            { name: 'react-dom', version: '~18.3.1' },
            { name: '@vitejs/plugin-react', version: '^5.1.0' },
          ],
  } as const;
}

function viteCandidate(framework: 'vue3' | 'react'): HostCandidateFact {
  const plugin = framework === 'vue3' ? '@vitejs/plugin-vue' : '@vitejs/plugin-react';
  const entry =
    framework === 'vue3'
      ? {
          path: 'src/main.ts',
          source: "import { createApp } from 'vue';\ncreateApp({}).mount('#app');\n",
        }
      : {
          path: 'src/main.tsx',
          source:
            "import { createRoot } from 'react-dom/client';\ncreateRoot(document.body).render(null);\n",
        };
  const app =
    framework === 'vue3'
      ? {
          path: 'src/App.vue',
          source: '<script setup lang="ts">\n</script>\n<template><main /></template>\n',
        }
      : {
          path: 'src/App.tsx',
          source:
            "import type { JSX } from 'react';\nexport function App(): JSX.Element { return <main />; }\n",
        };
  return {
    rootPath: `/workspace/${framework}`,
    descriptor: descriptor(),
    package: packageFacts(framework),
    viteConfig: {
      path: 'vite.config.ts',
      contract: MANAGED_VITE_CONTRACT,
      plugin,
      aliases: [],
    },
    sourceScan: {
      complete: true,
      sources: [
        { path: 'vite.config.ts', source: 'export default {};\n' },
        {
          path: 'index.html',
          source: '<html><head></head><body><div id="app"></div></body></html>\n',
        },
        entry,
        app,
      ],
    },
  };
}

function staticCandidate(
  source = '<html><head>\n</head><body>static</body></html>\n',
): HostCandidateFact {
  return {
    rootPath: '/workspace/html',
    descriptor: descriptor(),
    package: undefined,
    viteConfig: undefined,
    sourceScan: {
      complete: true,
      sources: [{ path: 'public/index.html', source }],
    },
  };
}

function input(candidate: HostCandidateFact): HostPlanInput {
  return {
    schemaVersion: HOST_PLAN_SCHEMA_VERSION,
    candidates: [candidate],
    credential: { kind: 'adopt', authority: AUTHORITY },
  };
}

function plan(candidate: HostCandidateFact): HostIntegrationPlan {
  return planHostIntegration(input(candidate));
}

describe('onboarding host integration planning', () => {
  it('detects the supported plugin in ordinary Vite configs and rejects ambiguity', () => {
    const cases = [
      {
        name: 'bare Vue config',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';

          export default defineConfig({
            plugins: [vue()],
          });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'bare React config',
        source: `
          import { defineConfig } from "vite"
          import react from "@vitejs/plugin-react"
          export default defineConfig({ plugins: [react()] })
        `,
        expected: '@vitejs/plugin-react',
      },
      {
        name: 'Vue config with double quotes, no semicolons, and a trailing plugin comma',
        source: `

          import { defineConfig } from "vite"
          import vue from "@vitejs/plugin-vue"

          export default defineConfig({ plugins: [vue(),], })

        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'React config with surrounding whitespace and optional semicolons',
        source: `

          import { defineConfig } from 'vite'
          import react from '@vitejs/plugin-react';

          export default defineConfig(
            { plugins: [react()] },
          );

        `,
        expected: '@vitejs/plugin-react',
      },
      {
        name: 'pinned ordinary Vue fixture bytes',
        source: readFileSync(
          new URL('../../fixtures/vue3-ordinary/vite.config.ts', import.meta.url),
          'utf8',
        ),
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'server configuration',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], server: { host: '0.0.0.0' } });
        `,
        expected: undefined,
      },
      {
        name: 'preview configuration is ignored (only server affects the dev origin)',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], preview: { host: '0.0.0.0' } });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'resolve alias configuration is ignored',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], resolve: { alias: { '@': '/src' } } });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'additional config keys are ignored',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], base: '/app/' });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'additional plugins are ignored',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          import inspect from 'vite-plugin-inspect';
          export default defineConfig({ plugins: [vue(), inspect()] });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'a custom-named config is accepted',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          const appConfig = defineConfig({ plugins: [vue()] });
          export default appConfig;
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'the plugin specifier alone selects the framework',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          // g001-managed-vite-v1
          export default defineConfig({ plugins: [] });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'a Next.js-style config',
        source: `
          import nextConfig from 'next';
          export default nextConfig({ reactStrictMode: true });
        `,
        expected: undefined,
      },
      {
        name: 'a PWA-style config',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          import { VitePWA } from 'vite-plugin-pwa';
          export default defineConfig({ plugins: [vue(), VitePWA()] });
        `,
        expected: undefined,
      },
      {
        name: 'an ordinary rich config (extra plugins, alias, strictPort, fs) with a literal port',
        source: `
          import { fileURLToPath, URL } from 'node:url';
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          import tailwindcss from '@tailwindcss/vite';
          const icons = () => ({ name: 'icons' });
          export default defineConfig({
            plugins: [vue(), tailwindcss(), icons()],
            resolve: { alias: [{ find: '@', replacement: fileURLToPath(new URL('./src', import.meta.url)) }] },
            server: { port: 5273, strictPort: true, fs: { allow: ['..'] } },
          });
        `,
        expected: '@vitejs/plugin-vue',
      },
      {
        name: 'both supported plugins are ambiguous',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          import react from '@vitejs/plugin-react';
          export default defineConfig({ plugins: [vue(), react()] });
        `,
        expected: undefined,
      },
      {
        name: 'a dynamic server port cannot be authorized statically',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], server: { port: Number(process.env.PORT) } });
        `,
        expected: undefined,
      },
      {
        name: 'an explicit localhost host is loopback and accepted',
        source: `
          import { defineConfig } from 'vite';
          import vue from '@vitejs/plugin-vue';
          export default defineConfig({ plugins: [vue()], server: { host: 'localhost', port: 5273 } });
        `,
        expected: '@vitejs/plugin-vue',
      },
    ] as const;

    for (const { source, expected } of cases) {
      expect(managedVitePluginFromConfig(source)).toBe(expected);
    }
  });
  it('plans a Vue 3 Vite SPA with the canonical async SPA loader', () => {
    const result = plan(viteCandidate('vue3'));

    expect(result.host).toBe('vue3');
    expect(result.descriptor).toMatchObject({
      framework: 'vue3',
      frameworkVersion: '3.5.40',
      frameworkPluginVersion: '6.0.8',
      loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
      navigation: 'spa',
    });
    expect(result.loader).toEqual({
      async: true,
      navigation: 'spa',
      dataScgNavigation: 'spa',
      sourceMarker: false,
      sourceMarkerPlacement: 'immediately-before-unique-head',
      targetPath: 'index.html',
      insertionStrategy: 'immediately-before-unique-head',
    });
    expect(result.artifacts.map(({ role }) => role)).toEqual(['loader', 'descriptor', 'helper']);
    expect(result.artifacts[0]?.artifact.path).toBe('/workspace/vue3/index.html');
  });
  it('accepts minimal Vite framework evidence without declared framework dependencies', () => {
    const vue = viteCandidate('vue3');
    const react = viteCandidate('react');
    const minimalVue = {
      ...vue,
      package: { name: 'minimal-vue-host', resolvedDependencies: [] },
    };
    const minimalReact = {
      ...react,
      package: { name: 'minimal-react-host', resolvedDependencies: [] },
    };

    expect(plan(minimalVue).host).toBe('vue3');
    expect(plan(minimalReact).host).toBe('react');
  });
  it('fails closed when declared framework versions are incompatible or unbounded', () => {
    const vue = viteCandidate('vue3');
    const incompatible = {
      ...vue,
      package: {
        name: 'incompatible-vue-host',
        resolvedDependencies: [
          { name: 'vite', version: '^7.4.0' },
          { name: 'vue', version: '^2.7.0' },
          { name: '@vitejs/plugin-vue', version: '^6.1.0' },
        ],
      },
    };
    const unbounded = {
      ...incompatible,
      package: {
        ...incompatible.package,
        resolvedDependencies: [
          { name: 'vite', version: '^7.4.0' },
          { name: 'vue', version: '>=3.5.0' },
          { name: '@vitejs/plugin-vue', version: '^6.1.0' },
        ],
      },
    };

    expect(() => plan(incompatible)).toThrow(HostPlanError);
    expect(() => plan(unbounded)).toThrow(HostPlanError);
  });
  it('targets the root template without requiring or modifying an App component', () => {
    const vue = viteCandidate('vue3');
    const react = viteCandidate('react');
    const missingVueApp = {
      ...vue,
      sourceScan: {
        ...vue.sourceScan,
        sources: vue.sourceScan.sources.filter(({ path }) => path !== 'src/App.vue'),
      },
    };
    const missingReactApp = {
      ...react,
      sourceScan: {
        ...react.sourceScan,
        sources: react.sourceScan.sources.filter(({ path }) => path !== 'src/App.tsx'),
      },
    };

    expect(plan(react).loader).toMatchObject({
      targetPath: 'index.html',
      insertionStrategy: 'immediately-before-unique-head',
    });
    expect(plan(missingVueApp).loader.targetPath).toBe('index.html');
    expect(plan(missingReactApp).loader.targetPath).toBe('index.html');
    const markedVue = {
      ...vue,
      sourceScan: {
        ...vue.sourceScan,
        sources: vue.sourceScan.sources.map((source) =>
          source.path === 'src/App.vue'
            ? { ...source, source: `${source.source}data-scg-token` }
            : source,
        ),
      },
    };
    expect(() => plan(markedVue)).toThrow(/loader evidence is ambiguous/);
    expect(JSON.stringify(plan(vue))).not.toContain('token');
  });

  it('plans a React Vite SPA only when the React DOM client discriminator is present', () => {
    const result = plan(viteCandidate('react'));
    const missingDiscriminator = viteCandidate('react');
    const source = missingDiscriminator.sourceScan.sources[2];
    if (source === undefined) {
      throw new Error('expected React entry source');
    }
    const unsupported = {
      ...missingDiscriminator,
      sourceScan: {
        ...missingDiscriminator.sourceScan,
        sources: [
          ...missingDiscriminator.sourceScan.sources.slice(0, 2),
          { ...source, source: 'export {};\n' },
        ],
      },
    };

    expect(result.host).toBe('react');
    expect(result.descriptor).toMatchObject({ framework: 'react', navigation: 'spa' });
    expect(() => plan(unsupported)).toThrow(HostPlanError);
    expect(() => plan(unsupported)).toThrow(/React Vite evidence is incomplete/);
  });

  it('plans static HTML as document navigation and reserves a single source marker before head', () => {
    const result = plan(staticCandidate());

    expect(result.host).toBe('html');
    expect(result.descriptor).toMatchObject({
      template: 'public/index.html',
      publicRoot: 'public',
      navigation: 'document',
    });
    expect(result.loader).toEqual({
      async: true,
      navigation: 'document',
      dataScgNavigation: 'document',
      sourceMarker: true,
      sourceMarkerPlacement: 'immediately-before-unique-head',
      targetPath: 'public/index.html',
      insertionStrategy: 'immediately-before-unique-head',
    });
    expect(result.artifacts.map(({ role }) => role)).toEqual(['loader', 'descriptor', 'helper']);
    expect(result.artifacts[0]?.artifact.hunks[0]).toMatchObject({
      operation: 'insert',
      subject: 'scg-html-loader',
    });
  });

  it('accepts only a matching explicit topology override', () => {
    const supported = {
      ...input(viteCandidate('vue3')),
      override: 'vue3' as const,
    };
    const unsupported = {
      ...input(viteCandidate('vue3')),
      override: 'html' as const,
    };

    expect(planHostIntegration(supported).host).toBe('vue3');
    expect(() => planHostIntegration(unsupported)).toThrow(/override is not supported/);
  });

  it('plans a create request with an identity-free blueprint and finalizes it after staged lstat', () => {
    const candidate = viteCandidate('react');
    const created = {
      ...input({
        ...candidate,
        descriptor: { ...candidate.descriptor, credentialAuthorities: [] },
      }),
      credential: {
        kind: 'create' as const,
        requestId: 'candidate-alpha-1',
        bits: 256 as const,
        projectId: 'alpha',
        path: AUTHORITY.path,
      },
    };
    const preliminary = planHostIntegration(created);
    const stagedFileLstat = {
      projectId: 'alpha',
      path: AUTHORITY.path,
      device: '101',
      inode: '202',
    } as const;

    expect(preliminary.credential).toMatchObject({
      kind: 'setup-created-candidate',
      requestId: 'candidate-alpha-1',
      bits: 256,
      projectId: 'alpha',
      path: AUTHORITY.path,
      artifact: {
        kind: 'credential',
        ownership: 'setup-created',
        inverse: { kind: 'delete-created-credential', path: AUTHORITY.path },
      },
    });
    expect(preliminary.credential).not.toHaveProperty('authority');
    expect(preliminary.descriptor).toMatchObject({ kind: 'host-descriptor-blueprint-v1' });
    expect(preliminary.descriptor.credentialAuthorities).toEqual([
      { projectId: 'alpha', path: AUTHORITY.path },
    ]);
    expect(Object.keys(preliminary.descriptor.credentialAuthorities[0] ?? {})).toEqual([
      'projectId',
      'path',
    ]);
    expect(() =>
      parseViteHostDescriptorV1(preliminary.descriptor, [{ projectId: 'alpha' }]),
    ).toThrow();
    const preview = JSON.stringify(preliminary);
    expect(preview).toContain(AUTHORITY.path);
    expect(preview).not.toContain('"device":"101"');
    expect(preview).not.toContain('"inode":"202"');
    expect(preview).not.toContain('tokenDigest');

    const first = finalizeHostIntegrationPlan(preliminary, stagedFileLstat);
    const second = finalizeHostIntegrationPlan(preliminary, stagedFileLstat);

    expect(second).toEqual(first);
    expect(second.artifacts.map(({ artifact }) => artifact.hunks[0]?.fingerprint)).toEqual(
      first.artifacts.map(({ artifact }) => artifact.hunks[0]?.fingerprint),
    );
    expect(first.descriptor).not.toHaveProperty('kind');
    expect(first.descriptor.credentialAuthorities).toEqual([stagedFileLstat]);
    expect(parseViteHostDescriptorV1(first.descriptor, [{ projectId: 'alpha' }])).toEqual(
      first.descriptor,
    );
    expect(first.artifacts).toEqual(preliminary.artifacts);
    expect(JSON.stringify(first)).not.toContain('tokenDigest');
  });

  it('finalizes adopted credentials without a post-write authority', () => {
    const preliminary = plan(viteCandidate('vue3'));
    expect(() =>
      parseViteHostDescriptorV1(preliminary.descriptor as unknown, [{ projectId: 'alpha' }]),
    ).toThrow();
    const finalized = finalizeHostIntegrationPlan(preliminary);

    expect(finalized.descriptor).not.toHaveProperty('kind');
    expect(finalized.descriptor.credentialAuthorities).toEqual([AUTHORITY]);
    expect(() => finalizeHostIntegrationPlan(preliminary, AUTHORITY)).toThrow(HostPlanError);
  });

  it('uses stable bounded hunk identifiers and fingerprints for equivalent facts', () => {
    const first = plan(viteCandidate('vue3'));
    const second = plan(viteCandidate('vue3'));

    expect(second).toEqual(first);
    for (const { artifact } of first.artifacts) {
      expect(artifact.fingerprint).toMatch(/^sha256:[a-f0-9]{64}$/);
      for (const hunk of artifact.hunks) {
        expect(hunk.id).toMatch(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/);
        expect(hunk.fingerprint).toMatch(/^sha256:[a-f0-9]{64}$/);
      }
    }
  });
});

describe('declared Vite start policy', () => {
  const config = (framework: 'vue3' | 'react', server = 'port: 5173, strictPort: true') => {
    const plugin = framework === 'vue3' ? 'vue' : 'react';
    const module = framework === 'vue3' ? '@vitejs/plugin-vue' : '@vitejs/plugin-react';
    return `import { defineConfig } from 'vite';\nimport ${plugin} from '${module}';\nexport default defineConfig({ plugins: [${plugin}()], server: { ${server} } });\n`;
  };
  const input = (
    overrides: Partial<{
      framework: 'vue3' | 'react';
      projectId: string;
      script: string;
      config: string;
      allowedOrigins: readonly string[];
    }> = {},
  ) => {
    const framework = overrides.framework ?? 'vue3';
    const projectId = overrides.projectId ?? 'alpha';
    return {
      framework,
      projectId,
      packageJson: JSON.stringify({
        name: projectId,
        scripts: { dev: overrides.script ?? 'vite' },
      }),
      viteConfig: overrides.config ?? config(framework),
      ...(overrides.allowedOrigins === undefined
        ? {}
        : { allowedOrigins: overrides.allowedOrigins }),
    };
  };

  it('resolves direct declarations with CLI precedence and canonical pair ordering', () => {
    expect(
      resolveDeclaredViteOriginPolicy(input({ script: 'vite --port=5174 --strictPort' })),
    ).toEqual({
      ok: true,
      policy: {
        framework: 'vue3',
        projectId: 'alpha',
        port: 5174,
        origins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
      },
    });
  });

  it('accepts a config without strictness and still rejects non-direct scripts', () => {
    // strictPort 는 더 이상 요구하지 않는다. 없으면 Vite 가 포트를 옮길 수 있고 그때 로더가
    // 붙지 않을 뿐이라, 그 정도로 기동 전체를 막지 않는다.
    expect(
      resolveDeclaredViteOriginPolicy(input({ config: config('vue3', 'port: 5173') })),
    ).toEqual({
      ok: true,
      policy: {
        framework: 'vue3',
        projectId: 'alpha',
        port: 5173,
        origins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
      },
    });
    for (const script of [
      'vite --strictPort=true',
      'pnpm vite --strictPort',
      'vite --no-strictPort',
    ]) {
      expect(resolveDeclaredViteOriginPolicy(input({ script }))).toEqual({
        ok: false,
        reason: 'SCG_START_VITE_DECLARATION_INVALID',
      });
    }
  });

  it('reads an ordinary config and rejects only what it cannot resolve statically', () => {
    // 호스트의 플러그인·옵션은 호스트 것이다. 아래는 모두 받아들여야 한다.
    for (const source of [
      config('vue3', 'port: 5173, strictPort: true, https: false'),
      config('vue3').replace('plugins: [vue()]', 'plugins: [vue(), local()]'),
      `import { defineConfig } from 'vite';\nimport vue from '@vitejs/plugin-vue';\nconst config = { plugins: [vue()], server: { port: 5173, strictPort: true } };\nexport default defineConfig(config);`,
    ]) {
      expect(resolveDeclaredViteOriginPolicy(input({ config: source }))).toEqual({
        ok: true,
        policy: {
          framework: 'vue3',
          projectId: 'alpha',
          port: 5173,
          origins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
        },
      });
    }

    // 정적으로 확정할 수 없거나 http 루프백이 아닌 것은 그대로 닫는다.
    for (const source of [
      config('vue3', 'port: 5173, https: true'),
      config('vue3', "host: '0.0.0.0', port: 5173"),
      config('vue3', 'port: resolvePort()'),
      config('vue3', 'port: 5173, port: 5174'),
    ]) {
      expect(resolveDeclaredViteOriginPolicy(input({ config: source }))).toEqual({
        ok: false,
        reason: 'SCG_START_VITE_DECLARATION_INVALID',
      });
    }

    expect(
      resolveDeclaredViteOriginPolicy(
        input({ config: config('vue3', 'port: 4175, strictPort: true') }),
      ),
    ).toEqual({
      ok: false,
      reason: 'SCG_START_VITE_PORT_DISALLOWED',
    });
    expect(
      resolveDeclaredViteOriginPolicy(input({ framework: 'react', config: config('vue3') })),
    ).toEqual({
      ok: false,
      reason: 'SCG_START_VITE_DECLARATION_INVALID',
    });
  });

  it('validates and replaces only exact persisted baselines before declaration parsing', () => {
    const baseline = ['http://127.0.0.1:5173', 'http://localhost:5173'] as const;
    const invalidBaselines = [
      [...baseline].reverse(),
      ['http://127.0.0.1:5173'],
      [...baseline, 'http://localhost:5173'],
      ['http://127.0.0.1:80', 'http://localhost:80'],
      ['http://127.0.0.1:5173', 'http://localhost:5174'],
      ['https://127.0.0.1:5173', 'http://localhost:5173'],
    ] as const;

    expect(canonicalDeclaredViteOrigins(80)).toBeUndefined();
    expect(isHistoricalDeclaredViteOriginPair(baseline)).toBe(true);
    for (const invalidBaseline of invalidBaselines) {
      expect(isHistoricalDeclaredViteOriginPair(invalidBaseline)).toBe(false);
      expect(replaceHistoricalDeclaredViteOriginPair(invalidBaseline, 5174)).toBeUndefined();
      expect(
        resolveDeclaredViteOriginPolicy(
          input({ allowedOrigins: invalidBaseline, script: 'pnpm vite --strictPort' }),
        ),
      ).toEqual({
        ok: false,
        reason: 'SCG_START_VITE_PERSISTED_BASELINE_INVALID',
      });
    }
    expect(replaceHistoricalDeclaredViteOriginPair(baseline, 5174)).toEqual([
      'http://127.0.0.1:5174',
      'http://localhost:5174',
    ]);
  });
  describe('with an ordinary, non-canonical vite.config.ts', () => {
    const script = 'vite --port 5173 --strictPort';
    // Nothing here is canonical: extra imports, module-scope statements, a local
    // plugin, a regex holding a backtick, and options the grammar never allowed.
    const arbitrary = (server = 'port: 5173,\n    strictPort: true,') =>
      `import { readFile } from 'node:fs/promises';\n` +
      `import { defineConfig, type Plugin } from 'vite';\n` +
      `import vue from '@vitejs/plugin-vue';\n` +
      `import tailwindcss from '@tailwindcss/vite';\n\n` +
      'function skeletonOf(source: string): string | null {\n' +
      '  return /skeleton:\\s*`([^`]+)`/.exec(source)?.[1] ?? null;\n' +
      '}\n\n' +
      `function localPlugin(): Plugin {\n` +
      `  return { name: 'local', async load() { await readFile('x'); return skeletonOf(''); } };\n` +
      '}\n\n' +
      'export default defineConfig({\n' +
      '  plugins: [vue(), tailwindcss(), localPlugin()],\n' +
      "  resolve: { alias: [{ find: '@', replacement: './src' }] },\n" +
      `  server: {\n    ${server}\n  },\n` +
      '});\n';

    it('accepts an arbitrary config and reads no declaration from it', () => {
      expect(resolveDeclaredViteOriginPolicy(input({ script, config: arbitrary() }))).toEqual({
        ok: true,
        policy: {
          framework: 'vue3',
          projectId: 'alpha',
          port: 5173,
          origins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
        },
      });
      // The CLI is authoritative, so a conflicting config port changes nothing.
      expect(
        resolveDeclaredViteOriginPolicy(
          input({ script, config: arbitrary('port: 4000,\n    strictPort: false,') }),
        ),
      ).toEqual({
        ok: true,
        policy: {
          framework: 'vue3',
          projectId: 'alpha',
          port: 5173,
          origins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
        },
      });
    });

    it('still rejects framework mismatch, non-loopback hosts, and PWA evidence', () => {
      for (const candidate of [
        input({ script, framework: 'react', config: arbitrary() }),
        input({ script, config: arbitrary("host: '0.0.0.0',\n    port: 5173,") }),
        input({
          script,
          config: arbitrary().replace(
            "import tailwindcss from '@tailwindcss/vite';",
            "import { VitePWA } from 'vite-plugin-pwa';",
          ),
        }),
      ]) {
        expect(resolveDeclaredViteOriginPolicy(candidate)).toEqual({
          ok: false,
          reason: 'SCG_START_VITE_DECLARATION_INVALID',
        });
      }
    });

    it('needs no CLI flags at all — a bare vite script reads the same config', () => {
      // 이 계약이 요점이다. 호스트가 자기 `dev` 스크립트를 고치지 않아도 통과해야 한다.
      for (const partial of ['vite', 'vite --strictPort', 'vite --host 127.0.0.1']) {
        expect(
          resolveDeclaredViteOriginPolicy(input({ script: partial, config: arbitrary() })),
        ).toEqual({
          ok: true,
          policy: {
            framework: 'vue3',
            projectId: 'alpha',
            port: 5173,
            origins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
          },
        });
      }
    });
  });

  it('gives explicit CLI declarations precedence over config declarations', () => {
    expect(
      resolveDeclaredViteOriginPolicy(
        input({
          script: 'vite --port=5174 --strictPort',
          config: config('vue3', 'port: 5173'),
          allowedOrigins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
        }),
      ),
    ).toEqual({
      ok: true,
      policy: {
        framework: 'vue3',
        projectId: 'alpha',
        port: 5174,
        origins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
      },
    });
  });
});
