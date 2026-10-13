import { lstat, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { SceneGlassContractError, type ProjectFramework } from '@scene-glass/contracts';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  createLifecycleOriginAuthority,
  createSceneGlassApp,
  createSceneGlassAppForTest,
  createSceneGlassLifecycleApp,
  preflightSceneGlassStartup,
} from '../../packages/server/src/app.js';
import { probeProjectRoot } from '../../packages/server/src/platform/probe.js';
import {
  buildSceneGlassStartupSnapshotForTest,
  type ProjectRootProbe,
} from '../../packages/server/src/startup/snapshot.js';
import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';

const authorityConstructors = vi.hoisted(() => ({
  registry: vi.fn(),
  verifier: vi.fn(),
}));
const lifecycleShutdowns = vi.hoisted(() => ({
  diagnostics: vi.fn(),
  sessions: vi.fn(),
}));

vi.mock('../../packages/server/src/auth/local-token-verifier.js', async () => {
  const actual = await vi.importActual<
    typeof import('../../packages/server/src/auth/local-token-verifier.js')
  >('../../packages/server/src/auth/local-token-verifier.js');
  return {
    ...actual,
    LocalTokenVerifier: class extends actual.LocalTokenVerifier {
      public constructor(...args: ConstructorParameters<typeof actual.LocalTokenVerifier>) {
        super(...args);
        authorityConstructors.verifier(args[0]);
      }
    },
  };
});

vi.mock('../../packages/server/src/registry/memory-project-registry.js', async () => {
  const actual = await vi.importActual<
    typeof import('../../packages/server/src/registry/memory-project-registry.js')
  >('../../packages/server/src/registry/memory-project-registry.js');
  return {
    ...actual,
    MemoryProjectRegistry: class extends actual.MemoryProjectRegistry {
      public constructor(...args: ConstructorParameters<typeof actual.MemoryProjectRegistry>) {
        super(...args);
        authorityConstructors.registry();
      }
    },
  };
});
vi.mock('../../packages/server/src/diagnostics/index.js', async () => {
  const actual = await vi.importActual<
    typeof import('../../packages/server/src/diagnostics/index.js')
  >('../../packages/server/src/diagnostics/index.js');
  return {
    ...actual,
    createDiagnosticsLifecycle: (...args: Parameters<typeof actual.createDiagnosticsLifecycle>) => {
      const lifecycle = actual.createDiagnosticsLifecycle(...args);
      return {
        ...lifecycle,
        shutdown: (): number => {
          lifecycleShutdowns.diagnostics();
          return lifecycle.shutdown();
        },
      };
    },
  };
});

vi.mock('../../packages/server/src/mcp/session-manager.js', async () => {
  const actual = await vi.importActual<
    typeof import('../../packages/server/src/mcp/session-manager.js')
  >('../../packages/server/src/mcp/session-manager.js');
  return {
    ...actual,
    SessionManager: class extends actual.SessionManager {
      public shutdown(): number {
        lifecycleShutdowns.sessions();
        return super.shutdown();
      }
    },
  };
});

vi.mock('../../packages/server/src/platform/probe.js', async () => {
  const actual = await vi.importActual<
    typeof import('../../packages/server/src/platform/probe.js')
  >('../../packages/server/src/platform/probe.js');
  return { ...actual, probeProjectRoot: vi.fn(actual.probeProjectRoot) };
});

const ALPHA_ORIGIN = 'https://alpha.preflight.scene-glass.test';
const BETA_ORIGIN = 'https://beta.preflight.scene-glass.test';
const ALPHA_VITE_ORIGINS = ['http://127.0.0.1:5173', 'http://localhost:5173'] as const;
const BETA_VITE_ORIGINS = ['http://127.0.0.1:5174', 'http://localhost:5174'] as const;
const ALPHA_TOKEN = opaqueToken(1);
const BETA_TOKEN = opaqueToken(2);
const MUTATED_ALPHA_TOKEN = opaqueToken(3);
const MUTATED_BETA_TOKEN = opaqueToken(4);
const temporaryWorkspaces = new Set<string>();

afterEach(async () => {
  await Promise.all(
    [...temporaryWorkspaces].map(async (workspace) => {
      temporaryWorkspaces.delete(workspace);
      await rm(workspace, { force: true, recursive: true });
    }),
  );
  vi.mocked(probeProjectRoot).mockReset();
  vi.restoreAllMocks();
  authorityConstructors.registry.mockReset();
  authorityConstructors.verifier.mockReset();
  lifecycleShutdowns.diagnostics.mockReset();
  lifecycleShutdowns.sessions.mockReset();
  vi.unstubAllEnvs();
});

describe('startup preflight', () => {
  it('returns a deeply frozen secretless snapshot without binding a socket or creating storage', async () => {
    useNativeRootProbe(supportedRootProbe);
    const fixture = await createFixture();
    const listen = vi.spyOn(Server.prototype, 'listen');

    const preflight = await preflightSceneGlassStartup({
      configPath: fixture.configPath,
      environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
    });

    const preflightProject = preflight.projects[0];
    if (preflightProject === undefined) {
      throw new Error('preflight omitted the configured project');
    }

    expect(preflight.globalLimits.memoBytes).toBe(1_024);
    expect(preflightProject).toMatchObject({
      allowedOrigins: [ALPHA_ORIGIN],
      canonicalRoot: fixture.root,
      projectId: 'alpha',
    });
    const framework: ProjectFramework = preflightProject.framework;
    expect(framework).toBe('html');
    expect(preflightProject.limits.memoBytes).toBe(1_024);
    expect(Object.isFrozen(preflight)).toBe(true);
    expect(Object.isFrozen(preflight.globalLimits)).toBe(true);
    expect(Object.isFrozen(preflight.projects)).toBe(true);
    expect(Object.isFrozen(preflightProject)).toBe(true);
    expect(Object.isFrozen(preflightProject.allowedOrigins)).toBe(true);
    expect(Object.isFrozen(preflightProject.limits)).toBe(true);
    expect(JSON.stringify(preflight)).not.toContain(ALPHA_TOKEN);
    expect(preflight).not.toHaveProperty('configPath');
    expect(preflight).not.toHaveProperty('sourcePath');
    expect(preflight).not.toHaveProperty('digest');
    expect(preflight).not.toHaveProperty('rawConfig');
    expect(preflight).not.toHaveProperty('registry');
    expect(preflight).not.toHaveProperty('verifier');
    expect(authorityConstructors.registry).not.toHaveBeenCalled();
    expect(authorityConstructors.verifier).not.toHaveBeenCalled();
    expect(fixture.configuredRoot).not.toBe(fixture.root);
    expect(vi.mocked(probeProjectRoot)).toHaveBeenCalledWith(fixture.root);
    expect(listen).not.toHaveBeenCalled();
    await expect(lstat(join(fixture.root, '.scg'))).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it.each(['vue3', 'react'] as const)(
    'copies the configured %s framework exactly',
    async (framework) => {
      useNativeRootProbe(supportedRootProbe);
      const fixture = await createFixture({
        projects: [project('alpha', { framework })],
      });

      const preflight = await preflightSceneGlassStartup({
        configPath: fixture.configPath,
        environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
      });
      const preflightProject = preflight.projects[0];
      if (preflightProject === undefined) {
        throw new Error('preflight omitted the configured project');
      }

      const normalizedFramework: ProjectFramework = preflightProject.framework;
      expect(normalizedFramework).toBe(framework);
    },
  );

  it('redacts parser, token, root, duplicate, and config-I/O failures without side effects', async () => {
    const parserCanary = 'PARSER_FAILURE_CANARY';
    const tokenCanary = 'TOKEN_FAILURE_CANARY';
    const rootResultCanary = 'ROOT_RESULT_FAILURE_CANARY';
    const rootThrowCanary = 'ROOT_THROW_FAILURE_CANARY';
    const configIoCanary = 'CONFIG_IO_FAILURE_CANARY';
    const malformed = await createFixture({ source: `{${parserCanary}` });
    const invalidToken = await createFixture();
    const rejectedRoot = await createFixture();
    const thrownRoot = await createFixture();
    const duplicateRoot = await createFixture({
      symlinkRootNames: ['configured-root-alias-two'],
      projects: [
        project('alpha', { root: 'configured-root-alias' }),
        project('beta', {
          root: 'configured-root-alias-two',
          tokenEnv: 'SCG_BETA_TOKEN',
        }),
      ],
    });
    const configIo = await createFixture();
    const listen = vi.spyOn(Server.prototype, 'listen');

    useNativeRootProbe(supportedRootProbe);
    const failures = [
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: malformed.configPath,
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        }),
      ),
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: invalidToken.configPath,
          environment: { SCG_ALPHA_TOKEN: tokenCanary },
        }),
      ),
    ];

    useNativeRootProbe(async (root) => supportedRoot(root, { realPath: rootResultCanary }));
    failures.push(
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: rejectedRoot.configPath,
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        }),
      ),
    );

    useNativeRootProbe(async () => {
      throw new Error(rootThrowCanary);
    });
    failures.push(
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: thrownRoot.configPath,
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        }),
      ),
    );

    const duplicateProbeRoots: string[] = [];
    useNativeRootProbe(async (root) => {
      duplicateProbeRoots.push(root);
      return supportedRoot(root);
    });
    failures.push(
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: duplicateRoot.configPath,
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN, SCG_BETA_TOKEN: BETA_TOKEN },
        }),
      ),
    );
    expect(duplicateRoot.configuredProjectRoots.alpha).not.toBe(
      duplicateRoot.configuredProjectRoots.beta,
    );
    expect(duplicateRoot.projectRoots.alpha).toBe(duplicateRoot.projectRoots.beta);
    expect(duplicateProbeRoots).toEqual([]);

    useNativeRootProbe(supportedRootProbe);
    failures.push(
      await expectPreflightFailure(
        preflightSceneGlassStartup({
          configPath: join(configIo.root, configIoCanary),
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        }),
      ),
    );

    for (const failure of failures) {
      expectPublicPreflightFailure(failure, [
        parserCanary,
        tokenCanary,
        rootResultCanary,
        rootThrowCanary,
        configIoCanary,
        ALPHA_TOKEN,
        BETA_TOKEN,
      ]);
    }
    expect(listen).not.toHaveBeenCalled();
    await Promise.all(
      [malformed, invalidToken, rejectedRoot, thrownRoot, duplicateRoot, configIo].map(
        async (fixture) =>
          expect(lstat(join(fixture.root, '.scg'))).rejects.toMatchObject({ code: 'ENOENT' }),
      ),
    );
  });

  it('allows custom root probes only through the internal test factory', async () => {
    const fixture = await createFixture();
    const nativeRoots: string[] = [];
    const testOnlyRoots: string[] = [];
    const nativeRootProbe: ProjectRootProbe = async (root) => {
      nativeRoots.push(root);
      return supportedRoot(root);
    };
    useNativeRootProbe(nativeRootProbe);

    const options = {
      configPath: fixture.configPath,
      environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
    };
    assertProductionStartupOptionExcludesProjectRootProbe<
      Parameters<typeof preflightSceneGlassStartup>[0]
    >(options);
    assertProductionStartupOptionExcludesProjectRootProbe<
      Parameters<typeof createSceneGlassApp>[0]
    >(options);
    assertProductionStartupOptionExcludesFastifyFactory<Parameters<typeof createSceneGlassApp>[0]>(
      options,
    );

    await buildSceneGlassStartupSnapshotForTest({
      ...options,
      projectRootProbe: async (root) => {
        testOnlyRoots.push(root);
        return supportedRoot(root);
      },
    });
    expect(authorityConstructors.registry).not.toHaveBeenCalled();
    expect(authorityConstructors.verifier).not.toHaveBeenCalled();
    const preflight = await preflightSceneGlassStartup(options);
    const app = await createSceneGlassApp(options);
    await app.close();
    expect(authorityConstructors.registry).toHaveBeenCalledTimes(1);
    expect(authorityConstructors.verifier).toHaveBeenCalledTimes(1);

    expect(fixture.configuredRoot).not.toBe(fixture.root);
    expect(preflight.projects).toHaveLength(1);
    expect(preflight.projects[0]?.canonicalRoot).toBe(fixture.root);
    expect(nativeRoots).toEqual([fixture.root, fixture.root]);
    expect(testOnlyRoots).toEqual([fixture.root]);
  });
  it('applies only an exact, bound lifecycle Vite Origin replacement before constructing Fastify', async () => {
    useNativeRootProbe(supportedRootProbe);
    const fixture = await createFixture({
      projects: [
        project('alpha', { framework: 'vue3', allowedOrigins: ALPHA_VITE_ORIGINS }),
        project('beta', { framework: 'html', root: 'beta-root' }),
      ],
    });
    const options = {
      configPath: fixture.configPath,
      environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN, SCG_BETA_TOKEN: BETA_TOKEN },
    };
    const snapshot = await buildSceneGlassStartupSnapshotForTest({
      ...options,
      projectRootProbe: supportedRootProbe,
    });
    const alpha = snapshot.validated.projects.find((project) => project.projectId === 'alpha');
    if (alpha === undefined) {
      throw new Error('expected alpha startup project');
    }
    const baseline = [...alpha.allowedOrigins];
    const replacements = [
      {
        baseline,
        origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
        projectId: 'alpha',
      },
    ] as const;
    const authority = createLifecycleOriginAuthority({
      binding: snapshot.lifecycleBinding,
      replacements,
    });
    baseline.push('http://attacker.invalid');
    const app = await createSceneGlassLifecycleApp({
      ...options,
      lifecycleOriginAuthority: authority,
    });
    await app.close();

    expect(replacements[0].baseline).toStrictEqual([
      ...ALPHA_VITE_ORIGINS,
      'http://attacker.invalid',
    ]);
    expect(replacements[0].origins).toStrictEqual([
      'http://127.0.0.1:5273',
      'http://localhost:5273',
    ]);
    const stableReplacements = [
      {
        baseline: alpha.allowedOrigins,
        origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
        projectId: 'alpha',
      },
    ] as const;
    const mutableBinding = JSON.parse(
      JSON.stringify(snapshot.lifecycleBinding),
    ) as typeof snapshot.lifecycleBinding;
    const snapshottedAuthority = createLifecycleOriginAuthority({
      binding: mutableBinding,
      replacements: stableReplacements,
    });
    (mutableBinding.projects[0] as { root: string }).root = '/attacker-controlled-root';
    const snapshottedApp = await createSceneGlassLifecycleApp({
      ...options,
      lifecycleOriginAuthority: snapshottedAuthority,
    });
    await snapshottedApp.close();

    await expect(
      createSceneGlassLifecycleApp({
        ...options,
        diagnosticAdditionalAllowedOrigin: {
          origin: 'http://127.0.0.1:6000',
          projectId: 'alpha',
        },
        lifecycleOriginAuthority: createLifecycleOriginAuthority({
          binding: snapshot.lifecycleBinding,
          replacements: stableReplacements,
        }),
      }),
    ).rejects.toBeInstanceOf(TypeError);

    const reject = async (
      lifecycleOriginAuthority: Parameters<
        typeof createSceneGlassLifecycleApp
      >[0]['lifecycleOriginAuthority'],
    ) => {
      const records: SceneGlassLogRecord[] = [];
      const logger = new SceneGlassLogger((record) => records.push(record));
      authorityConstructors.registry.mockReset();
      authorityConstructors.verifier.mockReset();
      await expect(
        createSceneGlassLifecycleApp({ ...options, lifecycleOriginAuthority, logger }),
      ).rejects.toBeInstanceOf(TypeError);
      expect(records.filter((record) => record.event === 'origin.applied')).toHaveLength(0);
      expect(authorityConstructors.registry).not.toHaveBeenCalled();
      expect(authorityConstructors.verifier).not.toHaveBeenCalled();
    };

    await reject(authority);
    await reject(
      {} as Parameters<typeof createSceneGlassLifecycleApp>[0]['lifecycleOriginAuthority'],
    );
    expect(() =>
      createLifecycleOriginAuthority({
        binding: {} as typeof snapshot.lifecycleBinding,
        replacements: stableReplacements,
      }),
    ).toThrow(TypeError);
    await reject(
      createLifecycleOriginAuthority({
        binding: snapshot.lifecycleBinding,
        replacements: [
          {
            baseline: [ALPHA_ORIGIN],
            origins: ['http://127.0.0.1:4175'],
            projectId: 'alpha',
          },
        ],
      }),
    );
    await reject(
      createLifecycleOriginAuthority({
        binding: snapshot.lifecycleBinding,
        replacements: [
          {
            baseline: [ALPHA_ORIGIN],
            origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
            projectId: 'missing',
          },
        ],
      }),
    );
    await reject(
      createLifecycleOriginAuthority({
        binding: snapshot.lifecycleBinding,
        replacements: [
          {
            baseline: [BETA_ORIGIN],
            origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
            projectId: 'beta',
          },
        ],
      }),
    );
  });
  it('rejects missing, extra, and cross-project lifecycle replacements before Fastify construction', async () => {
    useNativeRootProbe(supportedRootProbe);
    const fixture = await createFixture({
      projects: [
        project('alpha', { framework: 'vue3', allowedOrigins: ALPHA_VITE_ORIGINS }),
        project('beta', {
          framework: 'react',
          root: 'beta-root',
          allowedOrigins: BETA_VITE_ORIGINS,
        }),
      ],
    });
    const options = {
      configPath: fixture.configPath,
      environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN, SCG_BETA_TOKEN: BETA_TOKEN },
    };
    const snapshot = await buildSceneGlassStartupSnapshotForTest({
      ...options,
      projectRootProbe: supportedRootProbe,
    });
    const projectById = new Map(
      snapshot.validated.projects.map((configured) => [configured.projectId, configured]),
    );
    const alpha = projectById.get('alpha');
    const beta = projectById.get('beta');
    if (alpha === undefined || beta === undefined) {
      throw new Error('expected configured lifecycle projects');
    }
    const replacement = (projectId: 'alpha' | 'beta', baseline: readonly string[]) => ({
      baseline,
      origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
      projectId,
    });

    for (const replacements of [
      [],
      [replacement('alpha', alpha.allowedOrigins), replacement('beta', beta.allowedOrigins)],
      [
        replacement('alpha', alpha.allowedOrigins),
        {
          baseline: beta.allowedOrigins,
          origins: ['http://127.0.0.1:5273', 'http://localhost:5273'],
          projectId: 'beta',
        },
      ],
    ]) {
      authorityConstructors.registry.mockReset();
      authorityConstructors.verifier.mockReset();
      await expect(
        createSceneGlassLifecycleApp({
          ...options,
          lifecycleOriginAuthority: createLifecycleOriginAuthority({
            binding: snapshot.lifecycleBinding,
            replacements,
          }),
        }),
      ).rejects.toBeInstanceOf(TypeError);
      expect(authorityConstructors.registry).not.toHaveBeenCalled();
      expect(authorityConstructors.verifier).not.toHaveBeenCalled();
    }
  });
  it.each([
    ['MCP', 1],
    ['diagnostic', 2],
  ] as const)(
    'closes the partial app exactly once when %s route registration fails',
    async (route, failureBoundary) => {
      const fixture = await createFixture();
      const registrationFailure = new Error(`${route}_ROUTE_REGISTRATION_FAILURE`);
      const testFastify = createFailingRegistrationFastifyFactory({
        failureBoundary,
        registrationFailure,
      });

      await expect(
        createSceneGlassAppForTest({
          configPath: fixture.configPath,
          environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
          fastifyFactory: testFastify.fastifyFactory,
          projectRootProbe: supportedRootProbe,
        }),
      ).rejects.toBe(registrationFailure);

      expect(testFastify.closeCalls()).toBe(1);
      expect(lifecycleShutdowns.sessions).toHaveBeenCalledTimes(1);
      expect(lifecycleShutdowns.diagnostics).toHaveBeenCalledTimes(1);
    },
  );

  it('aggregates cleanup failure after registration failure without exposing credentials', async () => {
    const fixture = await createFixture();
    const registrationFailure = new Error('MCP_ROUTE_REGISTRATION_FAILURE');
    const cleanupFailure = new Error('APP_CLOSE_FAILURE');
    const testFastify = createFailingRegistrationFastifyFactory({
      cleanupFailure,
      failureBoundary: 1,
      registrationFailure,
    });

    const failure = await expectAppFactoryFailure(
      createSceneGlassAppForTest({
        configPath: fixture.configPath,
        environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        fastifyFactory: testFastify.fastifyFactory,
        projectRootProbe: supportedRootProbe,
      }),
    );

    expect(failure).toBeInstanceOf(AggregateError);
    if (!(failure instanceof AggregateError)) {
      throw new Error('expected registration cleanup failure to be aggregated');
    }

    expect(failure.cause).toBe(registrationFailure);
    expect(failure.errors).toEqual([registrationFailure, cleanupFailure]);
    expect(testFastify.closeCalls()).toBe(1);
    expect(lifecycleShutdowns.sessions).toHaveBeenCalledTimes(1);
    expect(lifecycleShutdowns.diagnostics).toHaveBeenCalledTimes(1);

    const exposed = [
      failure.message,
      failure.stack ?? '',
      String(failure.cause),
      ...failure.errors.map((error) => String(error)),
      JSON.stringify(failure),
      ...Object.values(failure).map((value) => String(value)),
    ].join('\n');
    expect(exposed).not.toContain(ALPHA_TOKEN);
  });

  it('accepts only omitted or own string environment bindings without ambient fallback', async () => {
    const fixture = await createFixture();
    vi.stubEnv('SCG_ALPHA_TOKEN', ALPHA_TOKEN);

    await expect(
      buildSceneGlassStartupSnapshotForTest({
        configPath: fixture.configPath,
        projectRootProbe: supportedRootProbe,
      }),
    ).resolves.toBeDefined();

    const inheritedEnvironment = Object.create({ SCG_ALPHA_TOKEN: ALPHA_TOKEN });
    for (const environment of [
      null,
      [],
      {},
      inheritedEnvironment,
      { SCG_ALPHA_TOKEN: undefined },
      { SCG_ALPHA_TOKEN: 1 },
    ]) {
      await expect(
        buildSceneGlassStartupSnapshotForTest({
          configPath: fixture.configPath,
          environment: environment as never,
          projectRootProbe: supportedRootProbe,
        }),
      ).rejects.toThrow();
    }

    await expect(
      buildSceneGlassStartupSnapshotForTest({
        configPath: fixture.configPath,
        environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN },
        projectRootProbe: supportedRootProbe,
      }),
    ).resolves.toBeDefined();
  });
  it('completes sequential root preflights before returning authority-free validation state', async () => {
    const fixture = await createFixture({
      projects: [
        project('alpha', { root: 'alpha-root' }),
        project('beta', { root: 'beta-root', tokenEnv: 'SCG_BETA_TOKEN' }),
      ],
    });
    const completedRoots: string[] = [];
    let inFlight = 0;
    let maximumConcurrency = 0;
    const startup = await buildSceneGlassStartupSnapshotForTest({
      configPath: fixture.configPath,
      environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN, SCG_BETA_TOKEN: BETA_TOKEN },
      projectRootProbe: async (root) => {
        inFlight += 1;
        maximumConcurrency = Math.max(maximumConcurrency, inFlight);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 0);
        });
        completedRoots.push(root);
        inFlight -= 1;
        return supportedRoot(root);
      },
    });

    expect(maximumConcurrency).toBe(1);
    const expectedProjectIds = ['alpha', 'beta'];
    const expectedRoots = [fixture.projectRoots.alpha, fixture.projectRoots.beta];
    expect(completedRoots).toEqual(expectedRoots);
    expect(startup.validated.projects).toHaveLength(2);
    expect(startup.validated.projects.map((project) => project.projectId)).toEqual(
      expectedProjectIds,
    );
    expect(startup.validated.projects.map((project) => project.canonicalRoot)).toEqual(
      expectedRoots,
    );
    const startupProject = startup.validated.projects[0];
    if (startupProject === undefined) {
      throw new Error('startup validation omitted the configured project');
    }
    const framework: ProjectFramework = startupProject.framework;
    expect(framework).toBe('html');
    expect(startup).not.toHaveProperty('registry');
    expect(startup).not.toHaveProperty('verifier');

    const probeFailure = new Error('ROOT_PROBE_FAILURE_IDENTITY');
    let laterRootProbes = 0;
    await expect(
      buildSceneGlassStartupSnapshotForTest({
        configPath: fixture.configPath,
        environment: { SCG_ALPHA_TOKEN: ALPHA_TOKEN, SCG_BETA_TOKEN: BETA_TOKEN },
        projectRootProbe: async () => {
          if (laterRootProbes === 0) {
            laterRootProbes += 1;
            throw probeFailure;
          }
          laterRootProbes += 1;
          return supportedRoot(fixture.root);
        },
      }),
    ).rejects.toBe(probeFailure);
    expect(laterRootProbes).toBe(1);
  });
  it('binds reversed two-project credentials to immutable startup snapshots after caller and ambient mutation', async () => {
    useNativeRootProbe(supportedRootProbe);
    const fixture = await createFixture({
      projects: [project('beta', { root: 'beta-root' }), project('alpha', { root: 'alpha-root' })],
    });
    const environment: Record<string, string> = {
      SCG_ALPHA_TOKEN: ALPHA_TOKEN,
      SCG_BETA_TOKEN: BETA_TOKEN,
    };
    const app = await createSceneGlassApp({
      configPath: fixture.configPath,
      environment,
    });
    await app.listen({ host: '127.0.0.1', port: 0 });

    try {
      const capturedCredentials = authorityConstructors.verifier.mock.calls[0]?.[0];
      if (!Array.isArray(capturedCredentials)) {
        throw new Error('startup did not provide credentials to the local verifier');
      }
      expect(capturedCredentials.map((credential) => credential.subject.projectId)).toEqual([
        'beta',
        'alpha',
      ]);
      expect(capturedCredentials.every((credential) => Object.isFrozen(credential))).toBe(true);
      expect(capturedCredentials.every((credential) => Object.isFrozen(credential.subject))).toBe(
        true,
      );

      environment.SCG_ALPHA_TOKEN = MUTATED_ALPHA_TOKEN;
      environment.SCG_BETA_TOKEN = MUTATED_BETA_TOKEN;

      expect(
        (
          await issueDiagnosticRun(app, {
            origin: BETA_ORIGIN,
            projectId: 'beta',
            token: BETA_TOKEN,
          })
        ).statusCode,
      ).toBe(201);
      expect(
        (
          await issueDiagnosticRun(app, {
            origin: ALPHA_ORIGIN,
            projectId: 'alpha',
            token: ALPHA_TOKEN,
          })
        ).statusCode,
      ).toBe(201);
      expect(
        (
          await issueDiagnosticRun(app, {
            origin: ALPHA_ORIGIN,
            projectId: 'alpha',
            token: BETA_TOKEN,
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await issueDiagnosticRun(app, {
            origin: BETA_ORIGIN,
            projectId: 'beta',
            token: MUTATED_BETA_TOKEN,
          })
        ).statusCode,
      ).toBe(401);
    } finally {
      await app.close();
    }

    vi.stubEnv('SCG_ALPHA_TOKEN', ALPHA_TOKEN);
    vi.stubEnv('SCG_BETA_TOKEN', BETA_TOKEN);
    const ambientApp = await createSceneGlassApp({ configPath: fixture.configPath });
    await ambientApp.listen({ host: '127.0.0.1', port: 0 });
    try {
      vi.stubEnv('SCG_ALPHA_TOKEN', MUTATED_ALPHA_TOKEN);
      vi.stubEnv('SCG_BETA_TOKEN', MUTATED_BETA_TOKEN);

      expect(
        (
          await issueDiagnosticRun(ambientApp, {
            origin: BETA_ORIGIN,
            projectId: 'beta',
            token: BETA_TOKEN,
          })
        ).statusCode,
      ).toBe(201);
      expect(
        (
          await issueDiagnosticRun(ambientApp, {
            origin: ALPHA_ORIGIN,
            projectId: 'alpha',
            token: MUTATED_ALPHA_TOKEN,
          })
        ).statusCode,
      ).toBe(401);
    } finally {
      await ambientApp.close();
    }
  });
});

interface Fixture {
  readonly configPath: string;
  readonly configuredProjectRoots: Readonly<Record<string, string>>;
  readonly configuredRoot: string;
  readonly projectRoots: Readonly<Record<string, string>>;
  readonly root: string;
}

interface FixtureOptions {
  readonly projects?: readonly ProjectDefinition[];
  readonly source?: string;
  readonly symlinkRootNames?: readonly string[];
}

interface ProjectDefinition {
  readonly allowedOrigins: readonly string[];
  readonly projectId: string;
  readonly root?: string;
  readonly framework?: ProjectFramework;
  readonly tokenEnv: string;
}

async function createFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-preflight-')));
  temporaryWorkspaces.add(workspace);
  const projects = options.projects ?? [project('alpha')];
  const rootPath = join(workspace, 'canonical-root');
  const configuredRoot = join(workspace, 'configured-root-alias');
  const symlinkRootNames = new Set(options.symlinkRootNames ?? []);
  await mkdir(rootPath);
  await symlink(rootPath, configuredRoot);
  for (const rootName of symlinkRootNames) {
    await symlink(rootPath, join(workspace, rootName));
  }
  for (const projectDefinition of projects) {
    if (
      projectDefinition.root !== undefined &&
      projectDefinition.root !== 'configured-root-alias' &&
      !symlinkRootNames.has(projectDefinition.root)
    ) {
      await mkdir(join(workspace, projectDefinition.root), { recursive: true });
    }
  }

  const configuredProjectRoots: Record<string, string> = {};
  const projectRoots: Record<string, string> = {};
  for (const projectDefinition of projects) {
    const configuredProjectRoot =
      projectDefinition.root === undefined
        ? configuredRoot
        : join(workspace, projectDefinition.root);
    configuredProjectRoots[projectDefinition.projectId] = configuredProjectRoot;
    projectRoots[projectDefinition.projectId] = await realpath(configuredProjectRoot);
  }

  const root = await realpath(rootPath);
  const configPath = join(workspace, 'scene-glass.json');
  const source =
    options.source ??
    JSON.stringify({
      schemaVersion: 1,
      globalLimits: { memoBytes: 1_024 },
      projects: projects.map((configured) => ({
        allowedOrigins: configured.allowedOrigins,
        ...(configured.framework === undefined ? {} : { framework: configured.framework }),
        projectId: configured.projectId,
        root: configured.root === undefined ? configuredRoot : join(workspace, configured.root),
        tokenEnv: configured.tokenEnv,
      })),
    });
  await writeFile(configPath, source);
  return { configPath, configuredProjectRoots, configuredRoot, projectRoots, root };
}

function project(
  projectId: 'alpha' | 'beta',
  overrides: Partial<
    Pick<ProjectDefinition, 'allowedOrigins' | 'framework' | 'root' | 'tokenEnv'>
  > = {},
): ProjectDefinition {
  return {
    allowedOrigins: projectId === 'alpha' ? [ALPHA_ORIGIN] : [BETA_ORIGIN],
    projectId,
    tokenEnv: projectId === 'alpha' ? 'SCG_ALPHA_TOKEN' : 'SCG_BETA_TOKEN',
    ...overrides,
  };
}

const supportedRootProbe: ProjectRootProbe = async (root) => supportedRoot(root);

function supportedRoot(
  root: string,
  facts: Partial<{
    readonly device: number;
    readonly fileSystemType: number;
    readonly identityStableAtProbe: boolean;
    readonly inode: number;
    readonly realPath: string;
  }> = {},
) {
  return {
    authority: 'macos-authoritative' as const,
    code: null,
    failStopReason: null,
    facts: {
      device: 1,
      fileSystemType: 1,
      identityStableAtProbe: true,
      inode: 1,
      realPath: root,
      ...facts,
    },
    platform: 'darwin' as const,
    supported: true,
  };
}

async function expectPreflightFailure(
  preflight: Promise<unknown>,
): Promise<SceneGlassContractError> {
  try {
    await preflight;
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      return error;
    }
    throw new Error(`Expected SceneGlassContractError, received ${String(error)}`);
  }
  throw new Error('preflight unexpectedly succeeded');
}
function useNativeRootProbe(probe: ProjectRootProbe): void {
  vi.mocked(probeProjectRoot).mockImplementation((root) => probe(root));
}
interface FailingRegistrationFastifyFactoryOptions {
  readonly cleanupFailure?: Error;
  readonly failureBoundary: 1 | 2;
  readonly registrationFailure: Error;
}

interface FailingRegistrationFastifyFactory {
  closeCalls(): number;
  readonly fastifyFactory: () => FastifyInstance;
}

function createFailingRegistrationFastifyFactory(
  options: FailingRegistrationFastifyFactoryOptions,
): FailingRegistrationFastifyFactory {
  let closeCalls = 0;
  return {
    closeCalls: () => closeCalls,
    fastifyFactory: () => {
      const app = Fastify({ logger: false });
      let registrationCalls = 0;
      const register = app.register.bind(app);
      Object.defineProperty(app, 'register', {
        value: (...args: unknown[]) => {
          registrationCalls += 1;
          if (registrationCalls === options.failureBoundary) {
            throw options.registrationFailure;
          }
          return Reflect.apply(register, app, args);
        },
      });

      const close = app.close.bind(app);
      Object.defineProperty(app, 'close', {
        value: () => {
          closeCalls += 1;
          return close().then(() => {
            if (options.cleanupFailure !== undefined) {
              throw options.cleanupFailure;
            }
          });
        },
      });
      return app;
    },
  };
}

async function expectAppFactoryFailure(appFactory: Promise<unknown>): Promise<unknown> {
  try {
    await appFactory;
  } catch (error: unknown) {
    return error;
  }
  throw new Error('app factory unexpectedly succeeded');
}

function assertProductionStartupOptionExcludesFastifyFactory<Options>(
  options: 'fastifyFactory' extends keyof Options ? never : Options,
): void {
  void options;
}
function assertProductionStartupOptionExcludesProjectRootProbe<Options>(
  options: 'projectRootProbe' extends keyof Options ? never : Options,
): void {
  void options;
}

function expectPublicPreflightFailure(
  failure: SceneGlassContractError,
  canaries: readonly string[],
): void {
  expect(failure.code).toBe('SCG_STARTUP_PREFLIGHT_FAILED');
  expect(failure.message).toBe('Scene Glass startup preflight failed');
  expect(Object.keys(failure).sort()).toEqual(['code', 'name']);
  expect(Object.hasOwn(failure, 'cause')).toBe(false);
  expect(JSON.parse(JSON.stringify(failure))).toEqual({
    code: 'SCG_STARTUP_PREFLIGHT_FAILED',
    name: 'SceneGlassContractError',
  });

  const exposed = [
    failure.message,
    failure.stack ?? '',
    JSON.stringify(failure),
    ...Object.values(failure).map((value) => String(value)),
  ].join('\n');
  for (const canary of canaries) {
    expect(exposed).not.toContain(canary);
  }
}

function opaqueToken(fill: number): string {
  return Buffer.alloc(32, fill).toString('base64url');
}
function issueDiagnosticRun(
  app: Awaited<ReturnType<typeof createSceneGlassApp>>,
  input: { readonly origin: string; readonly projectId: string; readonly token: string },
) {
  return app.inject({
    method: 'POST',
    url: `/mcp/v1/projects/${input.projectId}/diagnostic-runs`,
    headers: {
      authorization: `Bearer ${input.token}`,
      'content-type': 'application/json',
      origin: input.origin,
    },
    payload: { schemaVersion: 1 },
  });
}
