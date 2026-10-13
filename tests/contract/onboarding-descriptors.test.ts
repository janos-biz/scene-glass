import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  SceneGlassContractError,
  isServerConfigV1,
  parseServerConfigV1,
} from '@scene-glass/contracts';
import {
  STATIC_HOST_DESCRIPTOR_V1_KEYS,
  isDecimalString,
  isFileIdentity,
  VITE_HOST_DESCRIPTOR_V1_KEYS,
  isStaticHostDescriptorV1,
  isViteHostDescriptorV1,
  parseStaticHostDescriptorJsonV1,
  parseStaticHostDescriptorV1,
  parseViteHostDescriptorJsonV1,
  parseViteHostDescriptorV1,
  serializeStaticHostDescriptorV1,
  serializeViteHostDescriptorV1,
  snapshotTrustedStaticRuntimeAuthority,
} from '../../packages/onboarding/src/descriptors.js';
import type {
  DescriptorProjectSet,
  ViteFrameworkVersionTuple,
} from '../../packages/onboarding/src/types.js';

const CONFIGURED_PROJECTS = [{ projectId: 'alpha' }, { projectId: 'beta' }] as const;
function trustedStaticProjects(): {
  projects: Array<{
    projectId: string;
    canonicalRoot: string;
    publicRootIdentity: {
      device: string;
      inode: string;
    };
    tokenEnv: string;
    credentialAuthority: {
      projectId: string;
      path: string;
      device: string;
      inode: string;
    };
  }>;
} {
  return {
    projects: [
      {
        projectId: 'alpha',
        canonicalRoot: '/projects/alpha',
        publicRootIdentity: { device: '1', inode: '2' },
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        credentialAuthority: {
          projectId: 'alpha',
          path: '/projects/alpha/.env.scene-glass.local',
          device: '1',
          inode: '3',
        },
      },
      {
        projectId: 'beta',
        canonicalRoot: '/projects/beta',
        publicRootIdentity: { device: '1', inode: '5' },
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        credentialAuthority: {
          projectId: 'beta',
          path: '/projects/beta/.env.scene-glass.local',
          device: '1',
          inode: '4',
        },
      },
    ],
  };
}
const SYNTHETIC_TOKEN_CANARY = 'synthetic-token-canary-not-a-secret';
const SYNTHETIC_DIGEST_CANARY = 'synthetic-digest-canary-not-a-digest';
const MAX_DESCRIPTOR_JSON_BYTES = 1024 * 1024;
const BOUNDED_LONG_DECIMAL_IDENTITY = '9'.repeat(1_024);
const CONFIG_SERVER_PROJECT = {
  projectId: 'alpha',
  root: '/projects/alpha',
  allowedOrigins: ['https://alpha.example.test'],
  tokenEnv: 'SCENE_GLASS_ALPHA_TOKEN',
  framework: 'html',
} as const;

const STATIC_DESCRIPTOR_KEYS = [
  'schemaVersion',
  'template',
  'publicRoot',
  'host',
  'port',
  'projectId',
  'loaderUrl',
  'credentialProjectId',
  'credentialKey',
  'navigation',
  'readinessPath',
  'approvedRootIdentity',
  'credentialAuthorities',
] as const;

const VITE_DESCRIPTOR_KEYS = [
  'schemaVersion',
  'viteVersion',
  'framework',
  'frameworkVersion',
  'frameworkPluginVersion',
  'projectId',
  'rootTemplate',
  'loaderUrl',
  'host',
  'port',
  'credentialProjectId',
  'credentialKey',
  'navigation',
  'readinessPath',
  'approvedRootIdentity',
  'credentialAuthorities',
  'installId',
] as const;

const STATIC_CANONICAL_JSON = `{
  "schemaVersion": 1,
  "template": "public/index.html",
  "publicRoot": "public",
  "host": "127.0.0.1",
  "port": 4174,
  "projectId": "alpha",
  "loaderUrl": "http://127.0.0.1:4175/scene-glass-loader.js",
  "credentialProjectId": "alpha",
  "credentialKey": "SCENE_GLASS_HOST_TOKEN",
  "navigation": "document",
  "readinessPath": "/__scene-glass/ready",
  "approvedRootIdentity": {
    "device": "1",
    "inode": "2"
  },
  "credentialAuthorities": [
    {
      "projectId": "alpha",
      "path": "/projects/alpha/.env.scene-glass.local",
      "device": "1",
      "inode": "3"
    }
  ]
}
`;

const VUE_VITE_CANONICAL_JSON = `{
  "schemaVersion": 1,
  "viteVersion": "7.3.6",
  "framework": "vue3",
  "frameworkVersion": "3.5.40",
  "frameworkPluginVersion": "6.0.8",
  "projectId": "alpha",
  "rootTemplate": "index.html",
  "loaderUrl": "http://127.0.0.1:4175/scene-glass-loader.js",
  "host": "127.0.0.1",
  "port": 5173,
  "credentialProjectId": "alpha",
  "credentialKey": "SCENE_GLASS_HOST_TOKEN",
  "navigation": "spa",
  "readinessPath": "/__scene-glass/ready",
  "approvedRootIdentity": {
    "device": "1",
    "inode": "2"
  },
  "credentialAuthorities": [
    {
      "projectId": "alpha",
      "path": "/projects/alpha/.env.scene-glass.local",
      "device": "1",
      "inode": "3"
    }
  ],
  "installId": "installation_1"
}
`;

const REACT_VITE_CANONICAL_JSON = `{
  "schemaVersion": 1,
  "viteVersion": "7.3.6",
  "framework": "react",
  "frameworkVersion": "19.1.1",
  "frameworkPluginVersion": "5.0.4",
  "projectId": "alpha",
  "rootTemplate": "index.html",
  "loaderUrl": "http://127.0.0.1:4175/scene-glass-loader.js",
  "host": "127.0.0.1",
  "port": 5173,
  "credentialProjectId": "alpha",
  "credentialKey": "SCENE_GLASS_HOST_TOKEN",
  "navigation": "spa",
  "readinessPath": "/__scene-glass/ready",
  "approvedRootIdentity": {
    "device": "1",
    "inode": "2"
  },
  "credentialAuthorities": [
    {
      "projectId": "alpha",
      "path": "/projects/alpha/.env.scene-glass.local",
      "device": "1",
      "inode": "3"
    }
  ],
  "installId": "installation_1"
}
`;

const staticallyValidVueTuple: ViteFrameworkVersionTuple = {
  framework: 'vue3',
  frameworkVersion: '3.5.40',
  frameworkPluginVersion: '6.0.8',
};
const staticallyValidReactTuple: ViteFrameworkVersionTuple = {
  framework: 'react',
  frameworkVersion: '19.1.1',
  frameworkPluginVersion: '5.0.4',
};
const staticallyRejectedVueVersionTuple = {
  framework: 'vue3',
  frameworkVersion: '19.1.1',
  frameworkPluginVersion: '6.0.8',
} as const;
const staticallyRejectedVuePluginTuple = {
  framework: 'vue3',
  frameworkVersion: '3.5.40',
  frameworkPluginVersion: '5.0.4',
} as const;
const staticallyRejectedReactVersionTuple = {
  framework: 'react',
  frameworkVersion: '3.5.40',
  frameworkPluginVersion: '5.0.4',
} as const;
const staticallyRejectedReactPluginTuple = {
  framework: 'react',
  frameworkVersion: '19.1.1',
  frameworkPluginVersion: '6.0.8',
} as const;

function acceptViteFrameworkVersionTuple(tuple: ViteFrameworkVersionTuple): void {
  void tuple;
}

acceptViteFrameworkVersionTuple(staticallyValidVueTuple);
acceptViteFrameworkVersionTuple(staticallyValidReactTuple);
// @ts-expect-error Vue cannot use React's framework version.
acceptViteFrameworkVersionTuple(staticallyRejectedVueVersionTuple);
// @ts-expect-error Vue cannot use React's plugin version.
acceptViteFrameworkVersionTuple(staticallyRejectedVuePluginTuple);
// @ts-expect-error React cannot use Vue's framework version.
acceptViteFrameworkVersionTuple(staticallyRejectedReactVersionTuple);
// @ts-expect-error React cannot use Vue's plugin version.
acceptViteFrameworkVersionTuple(staticallyRejectedReactPluginTuple);

function staticDescriptor(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    template: 'public/index.html',
    publicRoot: 'public',
    host: '127.0.0.1',
    port: 4174,
    projectId: 'alpha',
    loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
    credentialProjectId: 'alpha',
    credentialKey: 'SCENE_GLASS_HOST_TOKEN',
    navigation: 'document',
    readinessPath: '/__scene-glass/ready',
    approvedRootIdentity: { device: '1', inode: '2' },
    credentialAuthorities: [
      {
        projectId: 'alpha',
        path: '/projects/alpha/.env.scene-glass.local',
        device: '1',
        inode: '3',
      },
    ],
  };
}

function viteDescriptor(framework: 'vue3' | 'react' = 'vue3'): Record<string, unknown> {
  const versions =
    framework === 'vue3'
      ? { frameworkVersion: '3.5.40', frameworkPluginVersion: '6.0.8' }
      : { frameworkVersion: '19.1.1', frameworkPluginVersion: '5.0.4' };

  return {
    schemaVersion: 1,
    viteVersion: '7.3.6',
    framework,
    ...versions,
    projectId: 'alpha',
    rootTemplate: 'index.html',
    loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
    host: '127.0.0.1',
    port: 5173,
    credentialProjectId: 'alpha',
    credentialKey: 'SCENE_GLASS_HOST_TOKEN',
    navigation: 'spa',
    readinessPath: '/__scene-glass/ready',
    approvedRootIdentity: { device: '1', inode: '2' },
    credentialAuthorities: [
      {
        projectId: 'alpha',
        path: '/projects/alpha/.env.scene-glass.local',
        device: '1',
        inode: '3',
      },
    ],
    installId: 'installation_1',
  };
}
function descriptorJsonAtByteLimit(serialized: string): string {
  const paddingLength = MAX_DESCRIPTOR_JSON_BYTES - Buffer.byteLength(serialized, 'utf8');
  if (paddingLength < 0) {
    throw new Error('Descriptor fixture exceeds its byte limit');
  }

  const path = '/projects/alpha/.env.scene-glass.local';
  const padded = serialized.replace(path, `${path}${'x'.repeat(paddingLength)}`);
  if (Buffer.byteLength(padded, 'utf8') !== MAX_DESCRIPTOR_JSON_BYTES) {
    throw new Error('Descriptor fixture byte padding is inconsistent');
  }
  return padded;
}

function expectDescriptorError(action: () => unknown): SceneGlassContractError {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  return caught;
}
function expectThrownIdentity(action: () => unknown, expected: unknown): void {
  try {
    action();
  } catch (error: unknown) {
    expect(error).toBe(expected);
    return;
  }

  throw new Error('Expected action to throw');
}

function expectRedactedDescriptorError(action: () => unknown): SceneGlassContractError {
  const error = expectDescriptorError(action);
  const ownKeys = Reflect.ownKeys(error);
  expect(new Set(ownKeys)).toEqual(new Set(['stack', 'message', 'name', 'code']));
  expect(Object.hasOwn(error, 'cause')).toBe(false);

  const publicError = [
    error.name,
    error.code,
    error.message,
    error.stack,
    String(error.cause),
    JSON.stringify(error),
    JSON.stringify(ownKeys),
  ].join('\n');
  expect(publicError).not.toContain(SYNTHETIC_TOKEN_CANARY);
  expect(publicError).not.toContain(SYNTHETIC_DIGEST_CANARY);
  return error;
}

function expectDeeplyFrozen(descriptor: {
  readonly approvedRootIdentity: object;
  readonly credentialAuthorities: readonly object[];
}): void {
  expect(Object.isFrozen(descriptor)).toBe(true);
  expect(Object.isFrozen(descriptor.approvedRootIdentity)).toBe(true);
  expect(Object.isFrozen(descriptor.credentialAuthorities)).toBe(true);
  for (const authority of descriptor.credentialAuthorities) {
    expect(Object.isFrozen(authority)).toBe(true);
  }
}

type DescriptorParser = (value: unknown) => unknown;

type DescriptorFixture = {
  readonly label: string;
  readonly errorCode: 'SCG_STATIC_DESCRIPTOR_INVALID' | 'SCG_VITE_CONFIG_UNSUPPORTED';
  readonly create: () => Record<string, unknown>;
  readonly is: DescriptorParser;
  readonly parse: DescriptorParser;
};

const DESCRIPTOR_FIXTURES: readonly DescriptorFixture[] = [
  {
    label: 'static',
    errorCode: 'SCG_STATIC_DESCRIPTOR_INVALID',
    create: staticDescriptor,
    parse: (value) => parseStaticHostDescriptorV1(value, CONFIGURED_PROJECTS),
    is: (value) => isStaticHostDescriptorV1(value, CONFIGURED_PROJECTS),
  },
  {
    label: 'Vite',
    errorCode: 'SCG_VITE_CONFIG_UNSUPPORTED',
    create: viteDescriptor,
    parse: (value) => parseViteHostDescriptorV1(value, CONFIGURED_PROJECTS),
    is: (value) => isViteHostDescriptorV1(value, CONFIGURED_PROJECTS),
  },
];

function parseWithConfiguredProjects(
  fixture: DescriptorFixture,
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): unknown {
  return fixture.label === 'static'
    ? parseStaticHostDescriptorV1(value, configuredProjects)
    : parseViteHostDescriptorV1(value, configuredProjects);
}

function isWithConfiguredProjects(
  fixture: DescriptorFixture,
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): boolean {
  return fixture.label === 'static'
    ? isStaticHostDescriptorV1(value, configuredProjects)
    : isViteHostDescriptorV1(value, configuredProjects);
}

const AUTHORITY_CASES = [
  {
    label: 'missing selected authority',
    message: 'credentialAuthorities must contain exactly one selected authority',
    apply: (descriptor: Record<string, unknown>): void => {
      descriptor.credentialAuthorities = [];
    },
  },
  {
    label: 'duplicate selected authority',
    message: 'credentialAuthorities must contain exactly one selected authority',
    apply: (descriptor: Record<string, unknown>): void => {
      descriptor.credentialAuthorities = [
        {
          projectId: 'alpha',
          path: '/projects/alpha/.env.scene-glass.local',
          device: '1',
          inode: '3',
        },
        {
          projectId: 'alpha',
          path: '/projects/alpha-copy/.env.scene-glass.local',
          device: '1',
          inode: '4',
        },
      ];
    },
  },
  {
    label: 'foreign selected authority',
    message: 'credentialAuthorities must match the selected project',
    apply: (descriptor: Record<string, unknown>): void => {
      descriptor.credentialAuthorities = [
        {
          projectId: 'beta',
          path: '/projects/beta/.env.scene-glass.local',
          device: '1',
          inode: '4',
        },
      ];
    },
  },
  {
    label: 'mismatched credential selection',
    message: 'descriptor project must be a configured credential project',
    apply: (descriptor: Record<string, unknown>): void => {
      descriptor.credentialProjectId = 'beta';
    },
  },
] as const;

describe('onboarding host descriptors', () => {
  it('freezes descriptor schema key authorities at runtime', () => {
    expect(Object.isFrozen(STATIC_HOST_DESCRIPTOR_V1_KEYS)).toBe(true);
    expect(Object.isFrozen(VITE_HOST_DESCRIPTOR_V1_KEYS)).toBe(true);
  });
  it.each([
    ['zero', '0', true],
    ['unsigned 64-bit maximum', '18446744073709551615', true],
    ['unsigned 64-bit overflow', '18446744073709551616', false],
    ['non-canonical leading zero', '01', false],
  ] as const)('bounds %s decimal identities', (_label, value, expected) => {
    expect(isDecimalString(value)).toBe(expected);
  });
  it('accepts canonical descriptors through public predicates and checks exact file identity keys', () => {
    expect(isStaticHostDescriptorV1(staticDescriptor(), CONFIGURED_PROJECTS)).toBe(true);
    expect(isViteHostDescriptorV1(viteDescriptor('vue3'), CONFIGURED_PROJECTS)).toBe(true);
    expect(isViteHostDescriptorV1(viteDescriptor('react'), CONFIGURED_PROJECTS)).toBe(true);
    expect(isFileIdentity({ device: '1', inode: '2' })).toBe(true);
    expect(isFileIdentity({ inode: '2', device: '1' })).toBe(false);
    expect(isFileIdentity({ device: '1', inode: '2', extra: '3' })).toBe(false);
    expect(isFileIdentity({ device: '18446744073709551615', inode: '0' })).toBe(true);
    expect(isFileIdentity({ device: '18446744073709551616', inode: '0' })).toBe(false);
  });
  it('keeps schema parsing non-authorizing while static runtime authority snapshots trusted facts', () => {
    const descriptor = staticDescriptor();
    expect(parseStaticHostDescriptorV1(descriptor, CONFIGURED_PROJECTS)).toMatchObject({
      projectId: 'alpha',
    });

    const schemaOnlyError = expectDescriptorError(() =>
      snapshotTrustedStaticRuntimeAuthority(descriptor, CONFIGURED_PROJECTS),
    );
    expect(schemaOnlyError.code).toBe('SCG_STATIC_DESCRIPTOR_INVALID');
    expect(schemaOnlyError.message).toBe('configured project authority facts must be complete');

    const trustedProjects = trustedStaticProjects();
    const authority = snapshotTrustedStaticRuntimeAuthority(descriptor, trustedProjects);
    (descriptor.credentialAuthorities as Array<{ path: string }>)[0]!.path =
      '/projects/alpha/mutated.env';
    trustedProjects.projects[0]!.canonicalRoot = '/projects/mutated';
    trustedProjects.projects[0]!.publicRootIdentity.device = '9';
    trustedProjects.projects[0]!.credentialAuthority.path = '/projects/alpha/mutated.env';

    expect(authority.canonicalRoot).toBe('/projects/alpha');
    expect(authority.publicRootIdentity).toEqual({ device: '1', inode: '2' });
    expect(authority.descriptor.credentialAuthorities[0]?.path).toBe(
      '/projects/alpha/.env.scene-glass.local',
    );
    expect(Object.isFrozen(authority)).toBe(true);
    expect(Object.isFrozen(authority.publicRootIdentity)).toBe(true);
  });
  it('rejects a valid-shape descriptor public-root identity that differs from trusted facts', () => {
    const descriptor = staticDescriptor();
    descriptor.approvedRootIdentity = { device: '1', inode: '9' };

    const error = expectDescriptorError(() =>
      snapshotTrustedStaticRuntimeAuthority(descriptor, trustedStaticProjects()),
    );
    expect(error.code).toBe('SCG_STATIC_DESCRIPTOR_INVALID');
    expect(error.message).toBe('descriptor approved root identity is not configured');
  });
  it('rejects a valid-shape Vite descriptor root mismatch before runtime use', () => {
    const descriptor = viteDescriptor();
    expect(parseViteHostDescriptorV1(descriptor, trustedStaticProjects())).toMatchObject({
      projectId: 'alpha',
      approvedRootIdentity: { device: '1', inode: '2' },
    });
    descriptor.approvedRootIdentity = { device: '1', inode: '9' };

    const error = expectDescriptorError(() =>
      parseViteHostDescriptorV1(descriptor, trustedStaticProjects()),
    );
    expect(error.code).toBe('SCG_VITE_CONFIG_UNSUPPORTED');
    expect(error.message).toBe('descriptor approved root identity is not configured');
    expect(isViteHostDescriptorV1(descriptor, trustedStaticProjects())).toBe(false);
  });
  it.each([
    ['21-digit value', '1'.repeat(21), false],
    ['bounded deliberately-long value', BOUNDED_LONG_DECIMAL_IDENTITY, false],
  ] as const)('rejects %s decimal identities before conversion', (_label, value, expected) => {
    expect(isDecimalString(value)).toBe(expected);
  });
  it('rejects over-width decimal identities through every public descriptor parser and predicate', () => {
    for (const fixture of DESCRIPTOR_FIXTURES) {
      for (const identity of ['1'.repeat(21), BOUNDED_LONG_DECIMAL_IDENTITY]) {
        const descriptor = fixture.create();
        descriptor.approvedRootIdentity = { device: identity, inode: '2' };

        const error = expectDescriptorError(() => fixture.parse(descriptor));
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe('file identity must use canonical unsigned decimal strings');
        expect(fixture.is(descriptor)).toBe(false);
      }
    }
  });
  it('rejects hidden and symbol global/project limit keys through parser and server predicate', () => {
    const hiddenGlobalLimits = { memoBytes: 1 };
    Object.defineProperty(hiddenGlobalLimits, 'hidden', { value: true });
    const symbolGlobalLimits = { memoBytes: 1 };
    Object.defineProperty(symbolGlobalLimits, Symbol('unknown'), { value: true });
    const hiddenProjectLimits = { memoBytes: 1 };
    Object.defineProperty(hiddenProjectLimits, 'hidden', { value: true });
    const symbolProjectLimits = { memoBytes: 1 };
    Object.defineProperty(symbolProjectLimits, Symbol('unknown'), { value: true });
    const replayCountGlobalLimits = {};
    Object.defineProperty(replayCountGlobalLimits, 'replayRecordCount', { value: 32 });
    const replayCountProjectLimits = {};
    Object.defineProperty(replayCountProjectLimits, 'replayRecordCount', { value: 32 });

    const cases = [
      {
        label: 'hidden global',
        value: {
          schemaVersion: 1,
          globalLimits: hiddenGlobalLimits,
          projects: [CONFIG_SERVER_PROJECT],
        },
        message: 'limit override contains an unknown field',
      },
      {
        label: 'symbol global',
        value: {
          schemaVersion: 1,
          globalLimits: symbolGlobalLimits,
          projects: [CONFIG_SERVER_PROJECT],
        },
        message: 'limit override contains an unknown field',
      },
      {
        label: 'hidden project',
        value: {
          schemaVersion: 1,
          projects: [{ ...CONFIG_SERVER_PROJECT, limits: hiddenProjectLimits }],
        },
        message: 'limit override contains an unknown field',
      },
      {
        label: 'symbol project',
        value: {
          schemaVersion: 1,
          projects: [{ ...CONFIG_SERVER_PROJECT, limits: symbolProjectLimits }],
        },
        message: 'limit override contains an unknown field',
      },
      {
        label: 'hidden global replay count',
        value: {
          schemaVersion: 1,
          globalLimits: replayCountGlobalLimits,
          projects: [CONFIG_SERVER_PROJECT],
        },
        message: 'replay record count is not configurable',
      },
      {
        label: 'hidden project replay count',
        value: {
          schemaVersion: 1,
          projects: [{ ...CONFIG_SERVER_PROJECT, limits: replayCountProjectLimits }],
        },
        message: 'replay record count is not configurable',
      },
    ] as const;

    for (const testCase of cases) {
      const error = expectDescriptorError(() => parseServerConfigV1(testCase.value));
      expect(error.code).toBe('SCG_CONFIG_LIMIT_INVALID');
      expect(error.message).toBe(testCase.message);
      expect(isServerConfigV1(testCase.value)).toBe(false);
    }
  });
  it('enforces descriptor JSON byte limits before parsing', () => {
    const cases = [
      {
        label: 'static',
        serialized: STATIC_CANONICAL_JSON,
        parse: (value: unknown) => parseStaticHostDescriptorJsonV1(value, CONFIGURED_PROJECTS),
        errorCode: 'SCG_STATIC_DESCRIPTOR_INVALID',
      },
      {
        label: 'Vite',
        serialized: VUE_VITE_CANONICAL_JSON,
        parse: (value: unknown) => parseViteHostDescriptorJsonV1(value, CONFIGURED_PROJECTS),
        errorCode: 'SCG_VITE_CONFIG_UNSUPPORTED',
      },
    ] as const;

    for (const testCase of cases) {
      const atLimit = descriptorJsonAtByteLimit(testCase.serialized);
      const oneByteOver = `${atLimit} `;
      expect(Buffer.byteLength(atLimit, 'utf8')).toBe(MAX_DESCRIPTOR_JSON_BYTES);
      expect(testCase.parse(atLimit)).toBeDefined();
      expect(Buffer.byteLength(oneByteOver, 'utf8')).toBe(MAX_DESCRIPTOR_JSON_BYTES + 1);

      const error = expectDescriptorError(() => testCase.parse(oneByteOver));
      expect(error.code).toBe(testCase.errorCode);
      expect(error.message).toBe('descriptor JSON exceeds its UTF-8 byte limit');
    }
  });

  it('uses literal field order, canonical JSON, and deeply frozen parsed values', () => {
    const staticSerialized = serializeStaticHostDescriptorV1(
      staticDescriptor(),
      CONFIGURED_PROJECTS,
    );
    const vueSerialized = serializeViteHostDescriptorV1(
      viteDescriptor('vue3'),
      CONFIGURED_PROJECTS,
    );
    const reactSerialized = serializeViteHostDescriptorV1(
      viteDescriptor('react'),
      CONFIGURED_PROJECTS,
    );

    expect(staticSerialized).toBe(STATIC_CANONICAL_JSON);
    expect(vueSerialized).toBe(VUE_VITE_CANONICAL_JSON);
    expect(reactSerialized).toBe(REACT_VITE_CANONICAL_JSON);

    const parsedStatic = parseStaticHostDescriptorJsonV1(
      STATIC_CANONICAL_JSON,
      CONFIGURED_PROJECTS,
    );
    const parsedVue = parseViteHostDescriptorJsonV1(VUE_VITE_CANONICAL_JSON, CONFIGURED_PROJECTS);
    const parsedReact = parseViteHostDescriptorJsonV1(
      REACT_VITE_CANONICAL_JSON,
      CONFIGURED_PROJECTS,
    );

    expect(Object.keys(parsedStatic)).toEqual(STATIC_DESCRIPTOR_KEYS);
    expect(Object.keys(parsedVue)).toEqual(VITE_DESCRIPTOR_KEYS);
    expect(Object.keys(parsedReact)).toEqual(VITE_DESCRIPTOR_KEYS);
    expect(parsedStatic).toEqual(JSON.parse(STATIC_CANONICAL_JSON));
    expect(parsedVue).toEqual(JSON.parse(VUE_VITE_CANONICAL_JSON));
    expect(parsedReact).toEqual(JSON.parse(REACT_VITE_CANONICAL_JSON));
    expectDeeplyFrozen(parsedStatic);
    expectDeeplyFrozen(parsedVue);
    expectDeeplyFrozen(parsedReact);
  });

  it('rejects literal mutations of every fixed static descriptor field', () => {
    const fixedFieldMutations = [
      { key: 'schemaVersion', value: 2 },
      { key: 'template', value: 'index.html' },
      { key: 'publicRoot', value: './public' },
      { key: 'host', value: 'localhost' },
      { key: 'loaderUrl', value: 'http://127.0.0.1:4175/other.js' },
      { key: 'credentialKey', value: 'SCENE_GLASS_OTHER_TOKEN' },
      { key: 'navigation', value: 'spa' },
      { key: 'readinessPath', value: '/ready' },
    ] as const;

    for (const mutation of fixedFieldMutations) {
      const descriptor = staticDescriptor();
      descriptor[mutation.key] = mutation.value;

      expect(
        expectDescriptorError(() => parseStaticHostDescriptorV1(descriptor, CONFIGURED_PROJECTS))
          .code,
      ).toBe('SCG_STATIC_DESCRIPTOR_INVALID');
      expect(isStaticHostDescriptorV1(descriptor, CONFIGURED_PROJECTS)).toBe(false);
    }
  });
  it('rejects literal mutations of every fixed Vite descriptor field', () => {
    const fixedFieldMutations = [
      { key: 'schemaVersion', value: 2 },
      { key: 'rootTemplate', value: 'public/index.html' },
      { key: 'host', value: 'localhost' },
      { key: 'loaderUrl', value: 'http://127.0.0.1:4175/other.js' },
      { key: 'credentialKey', value: 'SCENE_GLASS_OTHER_TOKEN' },
      { key: 'navigation', value: 'document' },
      { key: 'readinessPath', value: '/ready' },
    ] as const;

    for (const mutation of fixedFieldMutations) {
      const descriptor = viteDescriptor();
      descriptor[mutation.key] = mutation.value;

      const error = expectDescriptorError(() =>
        parseViteHostDescriptorV1(descriptor, CONFIGURED_PROJECTS),
      );
      expect(error.code).toBe('SCG_VITE_CONFIG_UNSUPPORTED');
      expect(error.message).toBe('descriptor contains an unsupported fixed field value');
      expect(isViteHostDescriptorV1(descriptor, CONFIGURED_PROJECTS)).toBe(false);
    }
  });

  it('accepts static port zero and rejects signed zero through object and JSON parsing', () => {
    const staticZeroJson = STATIC_CANONICAL_JSON.replace('  "port": 4174', '  "port": 0');
    const zeroDescriptor = staticDescriptor();
    zeroDescriptor.port = 0;

    const parsed = parseStaticHostDescriptorV1(zeroDescriptor, CONFIGURED_PROJECTS);
    expect(Object.is(parsed.port, 0)).toBe(true);
    expect(Object.is(parsed.port, -0)).toBe(false);
    expect(serializeStaticHostDescriptorV1(zeroDescriptor, CONFIGURED_PROJECTS)).toBe(
      staticZeroJson,
    );
    expect(
      Object.is(parseStaticHostDescriptorJsonV1(staticZeroJson, CONFIGURED_PROJECTS).port, 0),
    ).toBe(true);

    const signedZeroDescriptor = staticDescriptor();
    signedZeroDescriptor.port = -0;
    const signedZeroObjectError = expectDescriptorError(() =>
      parseStaticHostDescriptorV1(signedZeroDescriptor, CONFIGURED_PROJECTS),
    );
    expect(signedZeroObjectError.code).toBe('SCG_STATIC_DESCRIPTOR_INVALID');
    expect(signedZeroObjectError.message).toBe('port must be a TCP port');
    expect(isStaticHostDescriptorV1(signedZeroDescriptor, CONFIGURED_PROJECTS)).toBe(false);

    const signedZeroJsonError = expectDescriptorError(() =>
      parseStaticHostDescriptorJsonV1(
        staticZeroJson.replace('  "port": 0', '  "port": -0'),
        CONFIGURED_PROJECTS,
      ),
    );
    expect(signedZeroJsonError.code).toBe('SCG_STATIC_DESCRIPTOR_INVALID');
    expect(signedZeroJsonError.message).toBe('port must be a TCP port');

    for (const framework of ['vue3', 'react'] as const) {
      for (const port of [0, -0]) {
        const descriptor = viteDescriptor(framework);
        descriptor.port = port;
        const error = expectDescriptorError(() =>
          parseViteHostDescriptorV1(descriptor, CONFIGURED_PROJECTS),
        );
        expect(error.code).toBe('SCG_VITE_CONFIG_UNSUPPORTED');
        expect(error.message).toBe('port must be a non-zero TCP port');
      }
    }
  });

  it('rejects missing, duplicate, and sparse selected authorities before parsing entries', () => {
    const cases = [
      { label: 'missing', authorities: [] },
      { label: 'duplicate', authorities: [null, null] },
      { label: 'sparse', authorities: new Array<unknown>(1) },
    ] as const;

    for (const fixture of DESCRIPTOR_FIXTURES) {
      for (const testCase of cases) {
        const descriptor = fixture.create();
        descriptor.credentialAuthorities = testCase.authorities;

        const error = expectDescriptorError(() => fixture.parse(descriptor));
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe(
          'credentialAuthorities must contain exactly one selected authority',
        );
        expect(fixture.is(descriptor)).toBe(false);
      }
    }
  });

  it('requires own, dense configured project authorities', () => {
    for (const fixture of DESCRIPTOR_FIXTURES) {
      const sparseProjects = new Array<{ readonly projectId: string }>(2);
      sparseProjects[0] = { projectId: 'alpha' };
      const inheritedProjects = Object.create({
        projects: CONFIGURED_PROJECTS,
      }) as DescriptorProjectSet;
      const inheritedProjectId = [
        Object.create({ projectId: 'alpha' }),
        { projectId: 'beta' },
      ] as DescriptorProjectSet;

      const configurations = [
        {
          configuredProjects: { projects: sparseProjects } as DescriptorProjectSet,
          message: 'configured projects must be a dense array',
        },
        {
          configuredProjects: inheritedProjects,
          message: 'configured projects must be a non-empty array',
        },
        {
          configuredProjects: inheritedProjectId,
          message: 'configured project is invalid',
        },
      ];

      for (const { configuredProjects, message } of configurations) {
        const error = expectDescriptorError(() =>
          parseWithConfiguredProjects(fixture, fixture.create(), configuredProjects),
        );
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe(message);
        expect(isWithConfiguredProjects(fixture, fixture.create(), configuredProjects)).toBe(false);
      }
    }
  });
  it('rejects a descriptor that self-authorizes an unconfigured project', () => {
    for (const fixture of DESCRIPTOR_FIXTURES) {
      const descriptor = fixture.create();
      descriptor.projectId = 'gamma';
      descriptor.credentialProjectId = 'gamma';
      descriptor.credentialAuthorities = [
        {
          projectId: 'gamma',
          path: '/projects/gamma/.env.scene-glass.local',
          device: '1',
          inode: '3',
        },
      ];

      const error = expectDescriptorError(() => fixture.parse(descriptor));
      expect(error.code).toBe(fixture.errorCode);
      expect(error.message).toBe('descriptor project must be a configured credential project');
      expect(fixture.is(descriptor)).toBe(false);
    }
  });

  it('requires ordinary descriptor records with enumerable string schema keys', () => {
    for (const fixture of DESCRIPTOR_FIXTURES) {
      const hiddenKeyDescriptor = fixture.create();
      Object.defineProperty(hiddenKeyDescriptor, 'hidden', { value: true });

      const symbolKeyDescriptor = fixture.create();
      Object.defineProperty(symbolKeyDescriptor, Symbol('unknown'), { value: true });

      const customPrototypeDescriptor = Object.assign(
        Object.create({ inherited: true }) as Record<string, unknown>,
        fixture.create(),
      );
      const cases = [
        {
          descriptor: hiddenKeyDescriptor,
          message: 'descriptor contains missing, unknown, or reordered fields',
        },
        {
          descriptor: symbolKeyDescriptor,
          message: 'descriptor contains missing, unknown, or reordered fields',
        },
        {
          descriptor: customPrototypeDescriptor,
          message: 'descriptor must be an object',
        },
      ];

      for (const { descriptor, message } of cases) {
        const error = expectDescriptorError(() => fixture.parse(descriptor));
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe(message);
        expect(fixture.is(descriptor)).toBe(false);
      }
    }
  });

  it('type guards rethrow unrelated and replayed validation errors by identity', () => {
    for (const fixture of DESCRIPTOR_FIXTURES) {
      const invalidDescriptor = fixture.create();
      invalidDescriptor.port = -1;
      const capturedValidationError = expectDescriptorError(() => fixture.parse(invalidDescriptor));
      expect(capturedValidationError.code).toBe(fixture.errorCode);
      expect(capturedValidationError.message).toBe(
        fixture.label === 'static' ? 'port must be a TCP port' : 'port must be a non-zero TCP port',
      );
      expect(fixture.is(invalidDescriptor)).toBe(false);

      const accessorErrors = [
        new SceneGlassContractError(fixture.errorCode, 'unrelated proxy accessor error'),
        capturedValidationError,
      ];
      for (const accessorError of accessorErrors) {
        const descriptor = new Proxy(fixture.create(), {
          get(target, property, receiver) {
            if (property === 'port') {
              throw accessorError;
            }
            return Reflect.get(target, property, receiver);
          },
        });

        expectThrownIdentity(() => fixture.is(descriptor), accessorError);
      }
    }
  });
  for (const fixture of DESCRIPTOR_FIXTURES) {
    for (const authorityCase of AUTHORITY_CASES) {
      it(`rejects ${authorityCase.label} through the ${fixture.label} descriptor parser`, () => {
        const descriptor = fixture.create();
        authorityCase.apply(descriptor);

        const error = expectDescriptorError(() => fixture.parse(descriptor));
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe(authorityCase.message);
        expect(fixture.is(descriptor)).toBe(false);
      });
    }
  }

  it('rejects selected authority path, device, and inode mismatches against a multi-project trusted set', () => {
    const mutations = [
      {
        key: 'path',
        value: '/projects/alpha/other.env',
        message: 'descriptor credential authority is not configured',
      },
      {
        key: 'path',
        value: '/projects/alpha/../secret',
        message: 'credential authority path must be a well-formed canonical absolute path',
      },
      {
        key: 'device',
        value: '9',
        message: 'descriptor credential authority is not configured',
      },
      {
        key: 'inode',
        value: '9',
        message: 'descriptor credential authority is not configured',
      },
    ] as const;

    for (const fixture of DESCRIPTOR_FIXTURES) {
      expect(
        parseWithConfiguredProjects(fixture, fixture.create(), trustedStaticProjects()),
      ).toBeDefined();
      for (const mutation of mutations) {
        const descriptor = fixture.create();
        const authority = (descriptor.credentialAuthorities as Array<Record<string, unknown>>)[0];
        authority![mutation.key] = mutation.value;

        const error = expectDescriptorError(() =>
          parseWithConfiguredProjects(fixture, descriptor, trustedStaticProjects()),
        );
        expect(error.code).toBe(fixture.errorCode);
        expect(error.message).toBe(mutation.message);
        expect(isWithConfiguredProjects(fixture, descriptor, trustedStaticProjects())).toBe(false);
      }
    }
  });

  it('accepts only exact Vite, Vue, and React tuples', () => {
    expect(parseViteHostDescriptorV1(viteDescriptor('vue3'), CONFIGURED_PROJECTS).framework).toBe(
      'vue3',
    );
    expect(parseViteHostDescriptorV1(viteDescriptor('react'), CONFIGURED_PROJECTS).framework).toBe(
      'react',
    );

    const unknownFramework = viteDescriptor();
    unknownFramework.framework = 'preact';
    const unknownFrameworkError = expectDescriptorError(() =>
      parseViteHostDescriptorV1(unknownFramework, CONFIGURED_PROJECTS),
    );
    expect(unknownFrameworkError.code).toBe('SCG_VITE_CONFIG_UNSUPPORTED');
    expect(unknownFrameworkError.message).toBe(
      'descriptor contains an unsupported framework version tuple',
    );
    expect(isViteHostDescriptorV1(unknownFramework, CONFIGURED_PROJECTS)).toBe(false);

    const tupleMutations = [
      { framework: 'vue3' as const, key: 'viteVersion', value: '7.3.5' },
      { framework: 'vue3' as const, key: 'viteVersion', value: '7.3.7' },
      { framework: 'vue3' as const, key: 'framework', value: 'react' },
      { framework: 'vue3' as const, key: 'frameworkVersion', value: '3.5.39' },
      { framework: 'vue3' as const, key: 'frameworkVersion', value: '3.5.41' },
      { framework: 'vue3' as const, key: 'frameworkVersion', value: '19.1.1' },
      { framework: 'vue3' as const, key: 'frameworkPluginVersion', value: '6.0.7' },
      { framework: 'vue3' as const, key: 'frameworkPluginVersion', value: '6.0.9' },
      { framework: 'vue3' as const, key: 'frameworkPluginVersion', value: '5.0.4' },
      { framework: 'react' as const, key: 'viteVersion', value: '7.3.5' },
      { framework: 'react' as const, key: 'viteVersion', value: '7.3.7' },
      { framework: 'react' as const, key: 'framework', value: 'vue3' },
      { framework: 'react' as const, key: 'frameworkVersion', value: '19.1.0' },
      { framework: 'react' as const, key: 'frameworkVersion', value: '19.1.2' },
      { framework: 'react' as const, key: 'frameworkVersion', value: '3.5.40' },
      { framework: 'react' as const, key: 'frameworkPluginVersion', value: '5.0.3' },
      { framework: 'react' as const, key: 'frameworkPluginVersion', value: '5.0.5' },
      { framework: 'react' as const, key: 'frameworkPluginVersion', value: '6.0.8' },
    ] as const;

    for (const mutation of tupleMutations) {
      const descriptor = viteDescriptor(mutation.framework);
      descriptor[mutation.key] = mutation.value;
      const error = expectDescriptorError(() =>
        parseViteHostDescriptorV1(descriptor, CONFIGURED_PROJECTS),
      );
      expect(error.code).toBe('SCG_VITE_CONFIG_UNSUPPORTED');
      expect(error.message).toBe(
        mutation.key === 'viteVersion'
          ? 'descriptor contains an unsupported fixed field value'
          : 'descriptor contains an unsupported framework version tuple',
      );
      expect(isViteHostDescriptorV1(descriptor, CONFIGURED_PROJECTS)).toBe(false);
    }
  });

  it('redacts injected token and digest canaries from parser and serializer failures', () => {
    const staticCanaryDescriptor = staticDescriptor();
    staticCanaryDescriptor.token = SYNTHETIC_TOKEN_CANARY;
    staticCanaryDescriptor.digest = SYNTHETIC_DIGEST_CANARY;
    const viteCanaryDescriptor = viteDescriptor();
    viteCanaryDescriptor.token = SYNTHETIC_TOKEN_CANARY;
    viteCanaryDescriptor.digest = SYNTHETIC_DIGEST_CANARY;
    const staticCanaryJson = `${JSON.stringify(staticCanaryDescriptor, null, 2)}\n`;
    const viteCanaryJson = `${JSON.stringify(viteCanaryDescriptor, null, 2)}\n`;

    const errors = [
      expectRedactedDescriptorError(() =>
        parseStaticHostDescriptorV1(staticCanaryDescriptor, CONFIGURED_PROJECTS),
      ),
      expectRedactedDescriptorError(() =>
        serializeStaticHostDescriptorV1(staticCanaryDescriptor, CONFIGURED_PROJECTS),
      ),
      expectRedactedDescriptorError(() =>
        parseStaticHostDescriptorJsonV1(staticCanaryJson, CONFIGURED_PROJECTS),
      ),
      expectRedactedDescriptorError(() =>
        parseViteHostDescriptorV1(viteCanaryDescriptor, CONFIGURED_PROJECTS),
      ),
      expectRedactedDescriptorError(() =>
        serializeViteHostDescriptorV1(viteCanaryDescriptor, CONFIGURED_PROJECTS),
      ),
      expectRedactedDescriptorError(() =>
        parseViteHostDescriptorJsonV1(viteCanaryJson, CONFIGURED_PROJECTS),
      ),
    ];

    expect(errors.map((error) => error.code)).toEqual([
      'SCG_STATIC_DESCRIPTOR_INVALID',
      'SCG_STATIC_DESCRIPTOR_INVALID',
      'SCG_STATIC_DESCRIPTOR_INVALID',
      'SCG_VITE_CONFIG_UNSUPPORTED',
      'SCG_VITE_CONFIG_UNSUPPORTED',
      'SCG_VITE_CONFIG_UNSUPPORTED',
    ]);
  });

  it('rejects malformed, reordered, non-canonical, and unknown descriptors with stable errors', () => {
    const vite = viteDescriptor();
    vite.unrecognized = true;
    const reorderedStatic = JSON.stringify(
      {
        publicRoot: 'public',
        ...staticDescriptor(),
      },
      null,
      2,
    ).concat('\n');

    const errors = [
      expectDescriptorError(() =>
        parseStaticHostDescriptorJsonV1(STATIC_CANONICAL_JSON.slice(0, -1), CONFIGURED_PROJECTS),
      ),
      expectDescriptorError(() =>
        parseStaticHostDescriptorJsonV1(reorderedStatic, CONFIGURED_PROJECTS),
      ),
      expectDescriptorError(() => parseViteHostDescriptorV1(vite, CONFIGURED_PROJECTS)),
      expectDescriptorError(() => parseViteHostDescriptorJsonV1('{', CONFIGURED_PROJECTS)),
    ];

    expect(errors.map((error) => error.code)).toEqual([
      'SCG_STATIC_DESCRIPTOR_INVALID',
      'SCG_STATIC_DESCRIPTOR_INVALID',
      'SCG_VITE_CONFIG_UNSUPPORTED',
      'SCG_VITE_CONFIG_UNSUPPORTED',
    ]);
  });
});
