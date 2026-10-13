import { Buffer } from 'node:buffer';
import { fileURLToPath } from 'node:url';

import { build as buildVite } from 'vite';
import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  GLOBAL_LIMIT_OVERRIDE_KEYS,
  PROJECT_LIMIT_OVERRIDE_KEYS,
  REPLAY_RECORD_COUNT_OVERRIDE_ALIASES,
  SceneGlassContractError,
  isCanonicalOpaqueToken,
  isServerConfigV1,
  parseCanonicalOpaqueToken,
  parseProjectConfigV1,
  parseServerConfigV1,
} from '@scene-glass/contracts';
import {
  parseViteCacheProvenanceJson,
  serializeViteCacheProvenanceJson,
  type ViteCacheProvenance,
} from '../../packages/onboarding/src/vite/index.js';

const PROJECT = {
  projectId: 'alpha',
  root: '/srv/alpha',
  allowedOrigins: ['https://alpha.example.test'],
  tokenEnv: 'SCG_ALPHA_TOKEN',
} as const;

const TOKEN_32_BYTES = 'A'.repeat(43);
const TOKEN_31_BYTES = 'A'.repeat(42);
const TOKEN_INVALID_MESSAGE = 'token must be canonical base64url encoding of at least 32 bytes';
const VITE_CACHE_PROVENANCE_MAX_BYTES = 16 * 1024;
const VITE_CACHE_PROVENANCE = {
  version: 1,
  installId: 'vite-cache-contract',
  canonicalParentPath: '/srv/scene-glass/.scene-glass/vite-cache',
  root: {
    identity: { device: '42', inode: '101' },
    canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache',
    device: '42',
    owner: { uid: 501, gid: 20 },
    mode: 0o700,
  },
  parent: {
    identity: { device: '42', inode: '100' },
    canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache',
    device: '42',
    owner: { uid: 501, gid: 20 },
    mode: 0o700,
  },
  parentIdentity: { device: '42', inode: '100' },
  inverse: {
    kind: 'remove-created-vite-cache',
    rootIdentity: { device: '42', inode: '101' },
    parentIdentity: { device: '42', inode: '100' },
    canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache',
  },
} as const satisfies ViteCacheProvenance;

const VITE_CACHE_PROVENANCE_JSON = `{
  "version": 1,
  "installId": "vite-cache-contract",
  "canonicalParentPath": "/srv/scene-glass/.scene-glass/vite-cache",
  "root": {
    "identity": {
      "device": "42",
      "inode": "101"
    },
    "canonicalPath": "/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache",
    "device": "42",
    "owner": {
      "uid": 501,
      "gid": 20
    },
    "mode": 448
  },
  "parent": {
    "identity": {
      "device": "42",
      "inode": "100"
    },
    "canonicalPath": "/srv/scene-glass/.scene-glass/vite-cache",
    "device": "42",
    "owner": {
      "uid": 501,
      "gid": 20
    },
    "mode": 448
  },
  "parentIdentity": {
    "device": "42",
    "inode": "100"
  },
  "inverse": {
    "kind": "remove-created-vite-cache",
    "rootIdentity": {
      "device": "42",
      "inode": "101"
    },
    "parentIdentity": {
      "device": "42",
      "inode": "100"
    },
    "canonicalPath": "/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache"
  }
}
`;

function expectTokenError(value: unknown): void {
  let caught: unknown;
  try {
    parseCanonicalOpaqueToken(value);
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe('SCG_TOKEN_INVALID');
  expect(caught.message).toBe(TOKEN_INVALID_MESSAGE);
}

const ALL_LIMIT_NAMES = [
  'httpBodyBytes',
  'canonicalIdentityBytes',
  'routeBytes',
  'memoBytes',
  'surroundingTextCodePoints',
  'surroundingTextBytes',
  'locatorFieldBytes',
  'locatorSerializedBytes',
  'annotationsPerPage',
  'pageFileBytes',
  'replayLedgerBytes',
  'replayResultBytes',
  'pagesPerProject',
  'exportScanBytes',
  'exportRenderBytes',
  'concurrentRequestsPerProject',
  'concurrentRequestsGlobal',
  'normalSessionsPerProject',
  'normalSessionsGlobal',
  'sessionMaxAgeMs',
  'sessionIdleMs',
  'diagnosticActiveRunsPerProject',
  'diagnosticActiveRunsGlobal',
  'diagnosticRunsPerProjectPerMinute',
  'requestTimeoutMs',
  'exportTimeoutMs',
] as const;

const GLOBAL_ONLY_LIMIT_NAMES = [
  'httpBodyBytes',
  'concurrentRequestsGlobal',
  'normalSessionsGlobal',
  'diagnosticActiveRunsGlobal',
] as const;

describe('onboarding contract foundations', () => {
  it('normalizes every schema-v1 project to one supported framework authority', () => {
    const reactProject = parseProjectConfigV1({ ...PROJECT, framework: 'react' });
    const htmlProject = parseProjectConfigV1({ ...PROJECT, framework: 'html' });
    const vueProject = parseProjectConfigV1({ ...PROJECT, framework: 'vue3' });
    const legacyProject = parseProjectConfigV1(PROJECT);
    const serverConfig = parseServerConfigV1({
      schemaVersion: 1,
      projects: [{ ...PROJECT, framework: 'react' }],
    });
    const legacyServerConfig = parseServerConfigV1({
      schemaVersion: 1,
      projects: [PROJECT],
    });

    expect(reactProject.framework).toBe('react');
    expect(htmlProject.framework).toBe('html');
    expect(vueProject.framework).toBe('vue3');
    expect(legacyProject.framework).toBe('html');
    expect(serverConfig.projects[0]?.framework).toBe('react');
    expect(legacyServerConfig.projects[0]?.framework).toBe('html');
    expect(Object.isFrozen(reactProject)).toBe(true);
    expect(Object.isFrozen(serverConfig)).toBe(true);
    expect(Object.isFrozen(serverConfig.projects)).toBe(true);
  });
  it('normalizes legacy frameworks without narrowing non-canonical sources', () => {
    const legacySource = { schemaVersion: 1, projects: [PROJECT] };
    const canonicalSource = {
      schemaVersion: 1,
      projects: [{ ...PROJECT, framework: 'html' }],
    };

    expect(parseServerConfigV1(legacySource).projects[0]?.framework).toBe('html');
    expect(isServerConfigV1(legacySource)).toBe(false);
    expect(isServerConfigV1(canonicalSource)).toBe(true);
    expect(isServerConfigV1({ schemaVersion: 2, projects: [PROJECT] })).toBe(false);
    expect(
      isServerConfigV1({
        schemaVersion: 1,
        globalLimits: { httpBodyBytes: 0 },
        projects: [{ ...PROJECT, framework: 'html' }],
      }),
    ).toBe(false);
  });

  it('rejects unsupported framework values through both public config parsers', () => {
    expect.assertions(4);
    expectConfigError(
      () => parseProjectConfigV1({ ...PROJECT, framework: 'svelte' }),
      'framework must be html, vue3, or react',
    );
    expectConfigError(
      () =>
        parseServerConfigV1({
          schemaVersion: 1,
          projects: [{ ...PROJECT, framework: 'svelte' }],
        }),
      'framework must be html, vue3, or react',
    );
  });

  it('continues to reject unknown project configuration fields', () => {
    expect(() => parseProjectConfigV1({ ...PROJECT, futureFramework: 'svelte' })).toThrow(
      'project config contains an unknown field',
    );
  });
  it('rejects inherited config fields by requiring ordinary config records', () => {
    expect.assertions(12);
    expectConfigError(
      () =>
        parseServerConfigV1({
          __proto__: { schemaVersion: 1 },
          projects: [PROJECT],
        }),
      'server config must be an object',
    );
    expectConfigError(
      () =>
        parseServerConfigV1({
          __proto__: { projects: [PROJECT] },
          schemaVersion: 1,
        }),
      'server config must be an object',
    );
    expectConfigError(
      () =>
        parseProjectConfigV1({
          __proto__: { projectId: PROJECT.projectId },
          root: PROJECT.root,
          allowedOrigins: PROJECT.allowedOrigins,
          tokenEnv: PROJECT.tokenEnv,
        }),
      'project config must be an object',
    );
    expectConfigError(
      () =>
        parseProjectConfigV1({
          __proto__: { root: PROJECT.root },
          projectId: PROJECT.projectId,
          allowedOrigins: PROJECT.allowedOrigins,
          tokenEnv: PROJECT.tokenEnv,
        }),
      'project config must be an object',
    );
    expectConfigError(
      () =>
        parseProjectConfigV1({
          __proto__: { allowedOrigins: PROJECT.allowedOrigins },
          projectId: PROJECT.projectId,
          root: PROJECT.root,
          tokenEnv: PROJECT.tokenEnv,
        }),
      'project config must be an object',
    );
    expectConfigError(
      () =>
        parseProjectConfigV1({
          __proto__: { tokenEnv: PROJECT.tokenEnv },
          projectId: PROJECT.projectId,
          root: PROJECT.root,
          allowedOrigins: PROJECT.allowedOrigins,
        }),
      'project config must be an object',
    );
  });
  it('rejects unknown non-enumerable and symbol config keys', () => {
    const hiddenServerKey = { schemaVersion: 1, projects: [{ ...PROJECT, framework: 'html' }] };
    Object.defineProperty(hiddenServerKey, 'hidden', { value: true });
    const symbolProjectKey = { ...PROJECT, framework: 'html' };
    Object.defineProperty(symbolProjectKey, Symbol('unknown'), { value: true });

    expectConfigError(
      () => parseServerConfigV1(hiddenServerKey),
      'server config contains an unknown field',
    );
    expect(isServerConfigV1(hiddenServerKey)).toBe(false);
    expectConfigError(
      () => parseProjectConfigV1(symbolProjectKey),
      'project config contains an unknown field',
    );
    expect(isServerConfigV1({ schemaVersion: 1, projects: [symbolProjectKey] })).toBe(false);
  });

  it('rejects sparse projects and allowed origins through parsers and the server guard', () => {
    expect.assertions(6);
    const sparseProjects: (typeof PROJECT)[] = [];
    sparseProjects.length = 2;
    sparseProjects[1] = PROJECT;
    const sparseAllowedOrigins: string[] = [];
    sparseAllowedOrigins.length = 2;
    sparseAllowedOrigins[1] = PROJECT.allowedOrigins[0];

    expectConfigError(
      () => parseServerConfigV1({ schemaVersion: 1, projects: sparseProjects }),
      'projects must not be sparse',
    );
    expect(isServerConfigV1({ schemaVersion: 1, projects: sparseProjects })).toBe(false);
    expectConfigError(
      () => parseProjectConfigV1({ ...PROJECT, allowedOrigins: sparseAllowedOrigins }),
      'allowedOrigins must not be sparse',
    );
    expect(
      isServerConfigV1({
        schemaVersion: 1,
        projects: [{ ...PROJECT, allowedOrigins: sparseAllowedOrigins }],
      }),
    ).toBe(false);
  });

  it('freezes replay record-count override aliases', () => {
    expect(Object.isFrozen(REPLAY_RECORD_COUNT_OVERRIDE_ALIASES)).toBe(true);
  });

  it('preserves unexpected global and project limit-parser failures', () => {
    expect.assertions(2);
    const globalFailure = new Error('global limit parser sentinel');
    const globalOverrides = new Proxy(
      {},
      {
        ownKeys: () => {
          throw globalFailure;
        },
      },
    );
    const projectFailure = new Error('project limit parser sentinel');
    const projectOverrides = new Proxy(
      {},
      {
        ownKeys: () => {
          throw projectFailure;
        },
      },
    );

    expectThrownIdentity(
      () =>
        parseServerConfigV1({
          globalLimits: globalOverrides,
          projects: [PROJECT],
          schemaVersion: 1,
        }),
      globalFailure,
    );
    expectThrownIdentity(
      () => parseProjectConfigV1({ ...PROJECT, limits: projectOverrides }),
      projectFailure,
    );
  });
  it('rethrows foreign and replayed contract errors from config getters and proxies by identity', () => {
    expect.hasAssertions();
    const replayed = expectConfigError(
      () => parseServerConfigV1({ schemaVersion: 2, projects: [PROJECT] }),
      'schemaVersion must be 1',
    );
    const foreign = new SceneGlassContractError('SCG_CONFIG_INVALID', 'foreign accessor error');
    const getterConfig = {
      schemaVersion: 1,
      get projects(): readonly unknown[] {
        throw foreign;
      },
    };
    const proxyConfig = new Proxy(
      { schemaVersion: 1, projects: [{ ...PROJECT, framework: 'html' }] },
      {
        get(target, property, receiver) {
          if (property === 'projects') {
            throw replayed;
          }
          return Reflect.get(target, property, receiver);
        },
      },
    );

    expectThrownIdentity(() => isServerConfigV1(getterConfig), foreign);
    expectThrownIdentity(() => isServerConfigV1(proxyConfig), replayed);
  });

  it('derives global and project limit override membership from the complete schema', () => {
    const globalOnly = new Set<string>(GLOBAL_ONLY_LIMIT_NAMES);
    const projectKeys = new Set<string>(PROJECT_LIMIT_OVERRIDE_KEYS);

    expect(Object.keys(BUILT_IN_LIMITS)).toEqual(ALL_LIMIT_NAMES);
    expect(GLOBAL_LIMIT_OVERRIDE_KEYS).toEqual(ALL_LIMIT_NAMES);
    expect(PROJECT_LIMIT_OVERRIDE_KEYS).toEqual(
      ALL_LIMIT_NAMES.filter((name) => !globalOnly.has(name)),
    );
    expect(ALL_LIMIT_NAMES.filter((name) => !projectKeys.has(name))).toEqual(
      GLOBAL_ONLY_LIMIT_NAMES,
    );
  });

  it('accepts an exactly 32-byte canonical opaque token', () => {
    expect(isCanonicalOpaqueToken(TOKEN_32_BYTES)).toBe(true);
    expect(parseCanonicalOpaqueToken(TOKEN_32_BYTES)).toBe(TOKEN_32_BYTES);
  });

  it.each([
    ['padding', `${TOKEN_32_BYTES}=`],
    ['a standard base64 character', `${TOKEN_32_BYTES.slice(0, -1)}+`],
    ['non-zero unused trailing bits', `${TOKEN_32_BYTES.slice(0, -1)}B`],
    ['a canonical 31-byte value', TOKEN_31_BYTES],
  ] as const)('rejects %s with a stable contract error', (_label, value) => {
    expect(isCanonicalOpaqueToken(value)).toBe(false);
    expectTokenError(value);
  });

  it('bundles opaque token validation for a browser runtime without Node globals', async () => {
    const result = await buildVite({
      build: {
        lib: {
          entry: fileURLToPath(new URL('../../packages/contracts/src/token.ts', import.meta.url)),
          fileName: 'opaque-token',
          formats: ['es'],
        },
        minify: false,
        sourcemap: false,
        target: 'es2022',
        write: false,
      },
      configFile: false,
      logLevel: 'silent',
    });
    if (result === undefined) {
      throw new Error('browser bundle did not produce output');
    }
    const outputs = (Array.isArray(result) ? result : [result]).flatMap((output) => {
      if (!('output' in output)) {
        throw new Error('browser bundle unexpectedly returned a watcher');
      }
      return output.output;
    });
    let browserBundle = '';
    for (const output of outputs) {
      if (output.type === 'chunk') {
        browserBundle += output.code;
      }
    }

    expect(browserBundle).toContain('parseCanonicalOpaqueToken');
    expect(browserBundle).not.toMatch(/\b(?:Buffer|process|require|__dirname|__filename)\b|node:/);
  });
  it('round-trips Vite cache provenance as exact two-space JSON with one trailing LF', () => {
    const serialized = serializeViteCacheProvenanceJson(VITE_CACHE_PROVENANCE);
    const parsed = parseViteCacheProvenanceJson(serialized);

    expect(serialized).toBe(VITE_CACHE_PROVENANCE_JSON);
    expect(parsed).toEqual(VITE_CACHE_PROVENANCE);
    expect(serializeViteCacheProvenanceJson(parsed)).toBe(VITE_CACHE_PROVENANCE_JSON);
  });

  it('returns an immutable deep snapshot for parsed Vite cache provenance', () => {
    const parsed = parseViteCacheProvenanceJson(VITE_CACHE_PROVENANCE_JSON);
    const nestedRecords = [
      parsed,
      parsed.root,
      parsed.root.identity,
      parsed.root.owner,
      parsed.parent,
      parsed.parent.identity,
      parsed.parent.owner,
      parsed.parentIdentity,
      parsed.inverse,
      parsed.inverse.rootIdentity,
      parsed.inverse.parentIdentity,
    ];

    expect(nestedRecords.map((record) => Object.isFrozen(record))).toEqual(
      Array<boolean>(nestedRecords.length).fill(true),
    );
    expect(parsed).not.toBe(VITE_CACHE_PROVENANCE);
    expect(parsed.root).not.toBe(VITE_CACHE_PROVENANCE.root);
    expect(Reflect.set(parsed.root.owner, 'uid', 999)).toBe(false);
    expect(parsed.root.owner.uid).toBe(501);
    expect(Reflect.set(parsed.inverse.rootIdentity, 'inode', '999')).toBe(false);
    expect(parsed.inverse.rootIdentity.inode).toBe('101');
  });

  it('enforces the 16 KiB Vite cache provenance transport bound', () => {
    const atLimitProvenance = viteCacheProvenanceAtSerializedByteLength(
      VITE_CACHE_PROVENANCE_MAX_BYTES,
    );
    const atLimitSerialized = serializeViteCacheProvenanceJson(atLimitProvenance);
    const overLimitProvenance = {
      ...atLimitProvenance,
      installId: `${atLimitProvenance.installId}x`,
    };

    expect(Buffer.byteLength(atLimitSerialized, 'utf8')).toBe(VITE_CACHE_PROVENANCE_MAX_BYTES);
    expect(parseViteCacheProvenanceJson(atLimitSerialized)).toEqual(atLimitProvenance);
    expect(() => parseViteCacheProvenanceJson(`${atLimitSerialized} `)).toThrow(
      'cache provenance transport is invalid',
    );
    expect(() => serializeViteCacheProvenanceJson(overLimitProvenance)).toThrow(
      'cache provenance transport is too large',
    );
  });

  it.each([
    ['compact JSON', JSON.stringify(VITE_CACHE_PROVENANCE)],
    [
      'reordered fields',
      viteCacheProvenanceJson({
        installId: VITE_CACHE_PROVENANCE.installId,
        version: VITE_CACHE_PROVENANCE.version,
        canonicalParentPath: VITE_CACHE_PROVENANCE.canonicalParentPath,
        root: VITE_CACHE_PROVENANCE.root,
        parent: VITE_CACHE_PROVENANCE.parent,
        parentIdentity: VITE_CACHE_PROVENANCE.parentIdentity,
        inverse: VITE_CACHE_PROVENANCE.inverse,
      }),
    ],
    ['an extra field', viteCacheProvenanceJson({ ...VITE_CACHE_PROVENANCE, extra: true })],
    [
      'a duplicate field',
      VITE_CACHE_PROVENANCE_JSON.replace('  "version": 1,\n', '  "version": 1,\n  "version": 1,\n'),
    ],
    ['a trailing byte', `${VITE_CACHE_PROVENANCE_JSON} `],
    ['a UTF-8 BOM', `\uFEFF${VITE_CACHE_PROVENANCE_JSON}`],
    ['malformed JSON', VITE_CACHE_PROVENANCE_JSON.slice(0, -2)],
  ] as const)('rejects Vite cache provenance transport with %s', (_label, serialized) => {
    expect(serialized).not.toBe(VITE_CACHE_PROVENANCE_JSON);
    expectViteCacheProvenanceRejection(serialized);
  });

  it.each([
    [
      'an invalid install identifier',
      { ...VITE_CACHE_PROVENANCE, installId: 'vite/cache-contract' },
    ],
    [
      'a non-canonical parent path',
      { ...VITE_CACHE_PROVENANCE, canonicalParentPath: 'srv/scene-glass/vite-cache' },
    ],
    [
      'a non-canonical root path',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/../managed-vite-cache',
        },
        inverse: {
          ...VITE_CACHE_PROVENANCE.inverse,
          canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/../managed-vite-cache',
        },
      },
    ],
    [
      'a root that is not a direct child of its parent',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache/nested-cache',
        },
        inverse: {
          ...VITE_CACHE_PROVENANCE.inverse,
          canonicalPath: '/srv/scene-glass/.scene-glass/vite-cache/managed-vite-cache/nested-cache',
        },
      },
    ],
    [
      'a parent record detached from the canonical parent path',
      {
        ...VITE_CACHE_PROVENANCE,
        parent: {
          ...VITE_CACHE_PROVENANCE.parent,
          canonicalPath: '/srv/scene-glass/.scene-glass/other-vite-cache',
        },
      },
    ],
    [
      'an invalid owner',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          owner: { uid: -1, gid: 20 },
        },
      },
    ],
    [
      'root and parent records with different owners',
      {
        ...VITE_CACHE_PROVENANCE,
        parent: {
          ...VITE_CACHE_PROVENANCE.parent,
          owner: { uid: 501, gid: 21 },
        },
      },
    ],
    [
      'an unsafe directory mode',
      {
        ...VITE_CACHE_PROVENANCE,
        root: { ...VITE_CACHE_PROVENANCE.root, mode: 0o755 },
      },
    ],
    [
      'a malformed root identity',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          identity: { device: '42', inode: '001' },
        },
      },
    ],
    [
      'a parent identity detached from the parent record',
      {
        ...VITE_CACHE_PROVENANCE,
        parentIdentity: { device: '42', inode: '999' },
        inverse: {
          ...VITE_CACHE_PROVENANCE.inverse,
          parentIdentity: { device: '42', inode: '999' },
        },
      },
    ],
    [
      'a root identity that aliases the parent',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          identity: { device: '42', inode: '100' },
        },
        inverse: {
          ...VITE_CACHE_PROVENANCE.inverse,
          rootIdentity: { device: '42', inode: '100' },
        },
      },
    ],
    [
      'root and parent records on different devices',
      {
        ...VITE_CACHE_PROVENANCE,
        root: {
          ...VITE_CACHE_PROVENANCE.root,
          identity: { device: '43', inode: '101' },
          device: '43',
        },
        inverse: {
          ...VITE_CACHE_PROVENANCE.inverse,
          rootIdentity: { device: '43', inode: '101' },
        },
      },
    ],
  ] as const)('rejects Vite cache provenance with %s', (_label, provenance) => {
    const serialized = viteCacheProvenanceJson(provenance);

    expect(serialized).not.toBe(VITE_CACHE_PROVENANCE_JSON);
    expectViteCacheProvenanceRejection(serialized);
  });

  it('does not serialize token or digest material in legitimate Vite cache provenance', () => {
    const serialized = serializeViteCacheProvenanceJson(VITE_CACHE_PROVENANCE);

    expect(serialized).not.toMatch(/\b(?:token|digest|hash|secret)\b/i);
    expect(serialized).not.toContain(TOKEN_32_BYTES);
    expect(serialized).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });
});

function expectConfigError(action: () => unknown, message: string): SceneGlassContractError {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe('SCG_CONFIG_INVALID');
  expect(caught.message).toBe(message);
  return caught;
}

function expectThrownIdentity(action: () => unknown, expected: Error): void {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  expect(caught).toBe(expected);
}
function viteCacheProvenanceJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function viteCacheProvenanceWithParentSegment(
  parentSegment: string,
  installIdSuffix = '',
): ViteCacheProvenance {
  const canonicalParentPath = `/cache/${parentSegment}`;
  const canonicalRootPath = `${canonicalParentPath}/managed-vite-cache`;
  return {
    ...VITE_CACHE_PROVENANCE,
    installId: `${VITE_CACHE_PROVENANCE.installId}${installIdSuffix}`,
    canonicalParentPath,
    root: {
      ...VITE_CACHE_PROVENANCE.root,
      canonicalPath: canonicalRootPath,
    },
    parent: {
      ...VITE_CACHE_PROVENANCE.parent,
      canonicalPath: canonicalParentPath,
    },
    inverse: {
      ...VITE_CACHE_PROVENANCE.inverse,
      canonicalPath: canonicalRootPath,
    },
  };
}

function viteCacheProvenanceAtSerializedByteLength(targetBytes: number): ViteCacheProvenance {
  const baseline = viteCacheProvenanceWithParentSegment('p');
  const baselineBytes = Buffer.byteLength(serializeViteCacheProvenanceJson(baseline), 'utf8');
  const pathPadding = Math.floor((targetBytes - baselineBytes) / 4);
  const parentSegment = `p${'x'.repeat(pathPadding)}`;
  const pathPadded = viteCacheProvenanceWithParentSegment(parentSegment);
  const pathPaddedBytes = Buffer.byteLength(serializeViteCacheProvenanceJson(pathPadded), 'utf8');
  const installIdPadding = targetBytes - pathPaddedBytes;

  if (pathPadding < 0 || installIdPadding < 0 || installIdPadding > 3) {
    throw new Error('cannot create the requested cache provenance byte length');
  }

  const result = viteCacheProvenanceWithParentSegment(parentSegment, 'i'.repeat(installIdPadding));
  if (Buffer.byteLength(serializeViteCacheProvenanceJson(result), 'utf8') !== targetBytes) {
    throw new Error('cache provenance byte-length fixture is inconsistent');
  }
  return result;
}

function expectViteCacheProvenanceRejection(serialized: string): void {
  expect(() => parseViteCacheProvenanceJson(serialized)).toThrow(
    /cache (?:provenance|install identifier)/,
  );
}
