import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  REPLAY_RECORD_COUNT_OVERRIDE_ALIASES,
  SceneGlassContractError,
  effectiveLimits,
  parseGlobalLowerLimitOverrides,
  parseProjectLowerLimitOverrides,
  parseServerConfigV1,
  type SceneGlassContractErrorCode,
} from '@scene-glass/contracts';

const PROJECT_ALPHA = {
  projectId: 'alpha',
  root: '/srv/alpha',
  allowedOrigins: ['https://alpha.example.test'],
  tokenEnv: 'SCG_ALPHA_TOKEN',
} as const;

const PROJECT_BETA = {
  projectId: 'beta',
  root: '/srv/beta',
  allowedOrigins: ['https://beta.example.test'],
  tokenEnv: 'SCG_BETA_TOKEN',
} as const;

function expectContractError(action: () => unknown, code: SceneGlassContractErrorCode): void {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe(code);
}

describe('configuration lower-limit contracts', () => {
  it('uses built-ins, accepts equal limits, and accepts lower limits', () => {
    const defaults = effectiveLimits();
    const equal = parseGlobalLowerLimitOverrides({
      memoBytes: BUILT_IN_LIMITS.memoBytes,
    });
    const lower = parseGlobalLowerLimitOverrides({ memoBytes: 1_024 });

    expect(defaults.memoBytes).toBe(BUILT_IN_LIMITS.memoBytes);
    expect(equal).toEqual({ memoBytes: BUILT_IN_LIMITS.memoBytes });
    expect(effectiveLimits(lower).memoBytes).toBe(1_024);
  });

  it('takes the minimum global and project limit without leaking project limits', () => {
    const config = parseServerConfigV1({
      schemaVersion: 1,
      globalLimits: {
        memoBytes: 8_000,
        pagesPerProject: 1_500,
      },
      projects: [
        {
          ...PROJECT_ALPHA,
          limits: {
            memoBytes: 4_000,
            pagesPerProject: 1_800,
          },
        },
        PROJECT_BETA,
      ],
    });
    const alpha = config.projects[0];
    const beta = config.projects[1];

    expect(alpha).toBeDefined();
    expect(beta).toBeDefined();
    if (alpha === undefined || beta === undefined) {
      throw new Error('Expected both configured projects');
    }

    const alphaLimits = effectiveLimits(config.globalLimits, alpha.limits);
    const betaLimits = effectiveLimits(config.globalLimits, beta.limits);

    expect(alphaLimits.memoBytes).toBe(4_000);
    expect(alphaLimits.pagesPerProject).toBe(1_500);
    expect(betaLimits.memoBytes).toBe(8_000);
    expect(betaLimits.pagesPerProject).toBe(1_500);
    expect(betaLimits.routeBytes).toBe(BUILT_IN_LIMITS.routeBytes);
  });

  it.each([
    ['above built-in', { memoBytes: BUILT_IN_LIMITS.memoBytes + 1 }],
    ['zero', { memoBytes: 0 }],
    ['fraction', { memoBytes: 1.5 }],
    ['unknown', { futureLimit: 1 }],
  ] as const)('rejects %s global limit overrides', (_name, overrides) => {
    expect.hasAssertions();
    expectContractError(
      () => parseGlobalLowerLimitOverrides(overrides),
      'SCG_CONFIG_LIMIT_INVALID',
    );
  });

  it('rejects global-only limits in a project override', () => {
    expect.hasAssertions();
    expectContractError(
      () => parseProjectLowerLimitOverrides({ httpBodyBytes: 1_024 }),
      'SCG_CONFIG_LIMIT_INVALID',
    );
  });

  it.each(REPLAY_RECORD_COUNT_OVERRIDE_ALIASES)(
    'rejects replay-count override alias %s in global and project limits',
    (alias) => {
      expect.hasAssertions();
      expectContractError(
        () => parseGlobalLowerLimitOverrides({ [alias]: 32 }),
        'SCG_CONFIG_LIMIT_INVALID',
      );
      expectContractError(
        () => parseProjectLowerLimitOverrides({ [alias]: 32 }),
        'SCG_CONFIG_LIMIT_INVALID',
      );
    },
  );

  it('rejects unknown fields in server and project configuration', () => {
    expect.hasAssertions();
    expectContractError(
      () =>
        parseServerConfigV1({
          schemaVersion: 1,
          projects: [PROJECT_ALPHA],
          unsupported: true,
        }),
      'SCG_CONFIG_INVALID',
    );
    expectContractError(
      () =>
        parseServerConfigV1({
          schemaVersion: 1,
          projects: [{ ...PROJECT_ALPHA, unsupported: true }],
        }),
      'SCG_CONFIG_INVALID',
    );
  });

  it('rejects duplicate project IDs without returning a partial configuration', () => {
    let parsed: ReturnType<typeof parseServerConfigV1> | undefined;

    expectContractError(() => {
      parsed = parseServerConfigV1({
        schemaVersion: 1,
        projects: [
          PROJECT_ALPHA,
          {
            ...PROJECT_BETA,
            projectId: PROJECT_ALPHA.projectId,
          },
        ],
      });
    }, 'SCG_CONFIG_INVALID');

    expect(parsed).toBeUndefined();
  });

  it('rejects origins shared by distinct projects without returning a partial configuration', () => {
    let parsed: ReturnType<typeof parseServerConfigV1> | undefined;

    expectContractError(() => {
      parsed = parseServerConfigV1({
        schemaVersion: 1,
        projects: [
          PROJECT_ALPHA,
          {
            ...PROJECT_BETA,
            allowedOrigins: [...PROJECT_ALPHA.allowedOrigins],
          },
        ],
      });
    }, 'SCG_CONFIG_INVALID');

    expect(parsed).toBeUndefined();
  });
});
