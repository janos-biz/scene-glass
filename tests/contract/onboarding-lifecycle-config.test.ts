import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CONFIG_MODE,
  applyProjectOperation,
  canonicalServerTokenEnvForProjectId,
  inspectConfigHomes,
  planConfigOperation,
  projectConfigForSetup,
  serializeConfigV1,
  type ConfigFileFact,
  type ConfigHomeFacts,
} from '../../packages/onboarding/src/lifecycle/config.js';

const PROJECT = {
  projectId: 'alpha',
  root: '/srv/alpha',
  allowedOrigins: ['https://alpha.example.test'],
  tokenEnv: 'SCG_ALPHA_TOKEN',
  framework: 'react',
} as const;

function bytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'utf8'));
}

function text(value: Uint8Array): string {
  return Buffer.from(value).toString('utf8');
}

function config(projects: readonly unknown[]): string {
  return serializeConfigV1({ schemaVersion: 1, projects });
}

function fact(value: string, mode = 0o640): ConfigFileFact {
  return { bytes: bytes(value), mode };
}

function homes(
  legacy: ConfigFileFact | undefined,
  current: ConfigFileFact | undefined,
): ConfigHomeFacts {
  return {
    legacyPath: '~/.config/scene-glass/config.json',
    newPath: '~/.scg/config.json',
    legacy,
    new: current,
  };
}

describe('onboarding lifecycle config algebra', () => {
  it.each([
    ['neither', homes(undefined, undefined), 'config-create', 'project-insert'],
    ['legacy insert', homes(fact(config([])), undefined), 'legacy-move', 'project-insert'],
    ['legacy noop', homes(fact(config([PROJECT])), undefined), 'legacy-move', 'project-noop'],
    [
      'legacy update',
      homes(fact(config([{ ...PROJECT, root: '/srv/old-alpha' }])), undefined),
      'legacy-move',
      'project-update',
    ],
    ['new insert', homes(undefined, fact(config([]))), 'new-use', 'project-insert'],
    ['new noop', homes(undefined, fact(config([PROJECT]))), 'new-use', 'project-noop'],
    [
      'new update',
      homes(undefined, fact(config([{ ...PROJECT, root: '/srv/old-alpha' }]))),
      'new-use',
      'project-update',
    ],
  ] as const)('%s selects %s × %s', (_name, input, configOperation, projectOperation) => {
    const plan = planConfigOperation({ homes: input, project: PROJECT });

    expect(plan.configOperation).toBe(configOperation);
    expect(plan.projectOperation).toBe(projectOperation);
    expect(plan.config.projects).toHaveLength(1);
    expect(plan.config.projects[0]).toMatchObject({ ...PROJECT, framework: 'react' });
  });

  it('uses new config facts when both homes exist and never plans legacy mutation', () => {
    const legacy = fact('{ not valid JSON', 0o600);
    const current = fact(config([]), 0o640);
    const inspection = inspectConfigHomes(homes(legacy, current));
    const plan = planConfigOperation({ homes: homes(legacy, current), project: PROJECT });

    expect(inspection.operation).toBe('new-use');
    expect(plan.configOperation).toBe('new-use');
    expect(plan.mutatesLegacy).toBe(false);
    expect(plan.writes).toHaveLength(1);
    expect(plan.writes[0]).toMatchObject({ path: '~/.scg/config.json', mode: 0o640 });
  });

  it('preserves legacy bytes and mode for a pure legacy move', () => {
    const legacyBytes =
      '{\n  "schemaVersion": 1,\n  "projects": [\n    {\n      "projectId": "alpha",\n      "root": "/srv/alpha",\n      "allowedOrigins": [\n        "https://alpha.example.test"\n      ],\n      "tokenEnv": "SCG_ALPHA_TOKEN",\n      "framework": "react"\n    }\n  ]\n}\n';
    const plan = planConfigOperation({
      homes: homes(fact(legacyBytes, 0o640), undefined),
      project: PROJECT,
    });

    expect(plan.writes).toHaveLength(1);
    expect(plan.writes[0]).toMatchObject({
      kind: 'move-config',
      sourcePath: '~/.config/scene-glass/config.json',
      mode: 0o640,
      preservesSourceBytes: true,
    });
    expect(text(plan.writes[0]?.bytes ?? new Uint8Array())).toBe(legacyBytes);
  });

  it('creates exact canonical schema-v1 bytes with a restrictive default mode', () => {
    const plan = planConfigOperation({ homes: homes(undefined, undefined), project: PROJECT });
    const expected = `{
  "schemaVersion": 1,
  "projects": [
    {
      "projectId": "alpha",
      "root": "/srv/alpha",
      "allowedOrigins": [
        "https://alpha.example.test"
      ],
      "tokenEnv": "SCG_ALPHA_TOKEN",
      "framework": "react"
    }
  ]
}
`;

    expect(DEFAULT_CONFIG_MODE).toBe(0o600);
    expect(text(plan.writes[0]?.bytes ?? new Uint8Array())).toBe(expected);
    expect(serializeConfigV1({ schemaVersion: 1, projects: [PROJECT] })).toBe(expected);
  });

  it('rejects raw secret and token-digest fields because only contract config is parsed', () => {
    const rawTokenConfig = JSON.stringify({
      schemaVersion: 1,
      projects: [{ ...PROJECT, token: 'not-allowed' }],
    });
    const digestConfig = JSON.stringify({
      schemaVersion: 1,
      projects: [{ ...PROJECT, tokenDigest: 'sha256:deadbeef' }],
    });

    expect(() => inspectConfigHomes(homes(undefined, fact(rawTokenConfig)))).toThrow(
      'project config contains an unknown field',
    );
    expect(() => inspectConfigHomes(homes(undefined, fact(digestConfig)))).toThrow(
      'project config contains an unknown field',
    );
  });
  it('generates deterministic injective server token bindings without aliasing inputs', () => {
    const alpha = canonicalServerTokenEnvForProjectId('alpha');
    const beta = canonicalServerTokenEnvForProjectId('beta');
    const punctuation = canonicalServerTokenEnvForProjectId('alpha-beta');

    expect(alpha).toBe('SCENE_GLASS_SERVER_TOKEN_MFWHA2DB');
    expect(canonicalServerTokenEnvForProjectId('alpha')).toBe(alpha);
    expect(new Set([alpha, beta, punctuation]).size).toBe(3);
    expect(alpha).not.toBe('SCENE_GLASS_HOST_TOKEN');
  });

  it('preserves an existing binding and generates a selected new-project binding without mutation', () => {
    const existing = { ...PROJECT, tokenEnv: 'SCG_ALPHA_EXISTING_TOKEN' };
    const current = {
      schemaVersion: 1 as const,
      projects: [
        existing,
        {
          ...PROJECT,
          projectId: 'beta',
          root: '/srv/beta',
          tokenEnv: 'SCG_BETA',
          allowedOrigins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
        },
      ],
    };
    const selected = projectConfigForSetup(PROJECT, current);
    const inserted = projectConfigForSetup(
      { ...PROJECT, projectId: 'gamma', root: '/srv/gamma' },
      current,
    );

    expect(selected.tokenEnv).toBe(existing.tokenEnv);
    expect(inserted).toMatchObject({
      projectId: 'gamma',
      tokenEnv: canonicalServerTokenEnvForProjectId('gamma'),
    });
    expect(current.projects).toEqual([
      existing,
      {
        ...PROJECT,
        projectId: 'beta',
        root: '/srv/beta',
        tokenEnv: 'SCG_BETA',
        allowedOrigins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
      },
    ]);
    expect(inserted).not.toBe(current.projects[0]);
  });

  it('rejects a generated binding collision with a different configured project', () => {
    const tokenEnv = canonicalServerTokenEnvForProjectId('gamma');

    expect(() =>
      projectConfigForSetup(
        { ...PROJECT, projectId: 'gamma', root: '/srv/gamma' },
        {
          schemaVersion: 1,
          projects: [{ ...PROJECT, projectId: 'other', root: '/srv/other', tokenEnv }],
        },
      ),
    ).toThrow('server token binding collides with another project');
  });

  it('accepts React and converges after its canonical planned bytes are observed', () => {
    const first = planConfigOperation({ homes: homes(undefined, undefined), project: PROJECT });
    const write = first.writes[0];
    if (write === undefined) {
      throw new Error('expected initial config write');
    }
    const second = planConfigOperation({
      homes: homes(undefined, { bytes: write.bytes, mode: write.mode }),
      project: PROJECT,
    });

    expect(applyProjectOperation(first.config, PROJECT).operation).toBe('project-noop');
    expect(second.configOperation).toBe('new-use');
    expect(second.projectOperation).toBe('project-noop');
    expect(second.writes).toEqual([]);
  });
});
