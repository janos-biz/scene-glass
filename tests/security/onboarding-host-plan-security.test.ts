import { describe, expect, it } from 'vitest';

import {
  HOST_PLAN_SCHEMA_VERSION,
  MANAGED_VITE_CONTRACT,
  MAX_HOST_SOURCE_BYTES,
  HostPlanError,
  finalizeHostIntegrationPlan,
  planHostIntegration,
  type HostCandidateFact,
  type HostPlanInput,
} from '../../packages/onboarding/src/lifecycle/host-plan.js';

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

function staticCandidate(
  source = '<html><head>\n</head><body>static</body></html>\n',
): HostCandidateFact {
  return {
    rootPath: '/workspace/html',
    descriptor: descriptor(),
    package: undefined,
    viteConfig: undefined,
    sourceScan: { complete: true, sources: [{ path: 'public/index.html', source }] },
  };
}

function viteCandidate(): HostCandidateFact {
  return {
    rootPath: '/workspace/react',
    descriptor: descriptor(),
    package: {
      name: 'react-host',
      resolvedDependencies: [
        { name: 'vite', version: '^7.4.0' },
        { name: 'react', version: '>=18.2.0 <19.0.0' },
        { name: 'react-dom', version: '~18.3.1' },
        { name: '@vitejs/plugin-react', version: '^5.1.0' },
      ],
    },
    viteConfig: {
      path: 'vite.config.ts',
      contract: MANAGED_VITE_CONTRACT,
      plugin: '@vitejs/plugin-react',
      aliases: [],
    },
    sourceScan: {
      complete: true,
      sources: [
        { path: 'vite.config.ts', source: 'export default {};\n' },
        { path: 'index.html', source: '<html><head></head><body></body></html>\n' },
        {
          path: 'src/main.tsx',
          source:
            "import { createRoot } from 'react-dom/client';\ncreateRoot(document.body).render(null);\n",
        },
      ],
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

function rejectionFor(inputValue: unknown): HostPlanError {
  try {
    planHostIntegration(inputValue as HostPlanInput);
  } catch (error: unknown) {
    if (error instanceof HostPlanError) {
      return error;
    }
    throw error;
  }
  throw new Error('host plan unexpectedly succeeded');
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) {
      deepFreeze(item);
    }
    Object.freeze(value);
  }
  return value;
}

describe('onboarding host plan security boundaries', () => {
  it.each([
    ['explicit', "navigator.serviceWorker.register('/sw.js');\n"],
    ['hidden property', "window.navigator['serviceWorker'].register('/sw.js');\n"],
    [
      'split property',
      "const service = 'service'; const worker = 'worker'; navigator[service + worker];\n",
    ],
    ['hex-escaped property', "navigator['\\x73ervice\\x57orker'].register('/sw.js');\n"],
    ['unicode-escaped property', "navigator['\\u0073ervice\\u0057orker'].register('/sw.js');\n"],
  ])('rejects %s service-worker evidence', (_name, evidence) => {
    const candidate = staticCandidate();
    const rejected = {
      ...candidate,
      sourceScan: {
        ...candidate.sourceScan,
        sources: [...candidate.sourceScan.sources, { path: 'src/pwa.ts', source: evidence }],
      },
    };

    expect(rejectionFor(input(rejected)).code).toBe('service-worker-evidence');
  });

  it('rejects indeterminate and over-budget source scans before planning', () => {
    const incomplete = {
      ...staticCandidate(),
      sourceScan: { complete: false, sources: [] },
    };
    const tooLarge = staticCandidate(`<!-- ${'a'.repeat(MAX_HOST_SOURCE_BYTES + 1)} -->`);

    expect(rejectionFor(input(incomplete)).code).toBe('source-scan-indeterminate');
    expect(rejectionFor(input(tooLarge)).code).toBe('source-scan-over-budget');
  });

  it('rejects Next.js and multi-host ambiguity before a plan can exist', () => {
    const next = viteCandidate();
    const nextPackage = next.package;
    if (nextPackage === undefined) {
      throw new Error('expected Vite package facts');
    }
    const nextCandidate = {
      ...next,
      package: {
        ...nextPackage,
        resolvedDependencies: [
          ...nextPackage.resolvedDependencies,
          { name: 'next', version: '15.0.0' },
        ],
      },
    };
    const multiple = {
      ...input(staticCandidate()),
      candidates: [staticCandidate(), { ...staticCandidate(), rootPath: '/workspace/other' }],
    };

    expect(rejectionFor(input(nextCandidate)).code).toBe('nextjs-unsupported');
    expect(rejectionFor(multiple).code).toBe('host-ambiguous');
  });

  it('rejects duplicated static heads or markers rather than producing a partial loader plan', () => {
    const duplicateHead = staticCandidate('<html><head></head><head></head><body></body></html>');
    const duplicateMarker = staticCandidate(
      '<html><head>\n<!-- scene-glass:static-loader:v1 -->\n<!-- scene-glass:static-loader:v1 -->\n</head></html>',
    );

    expect(rejectionFor(input(duplicateHead)).code).toBe('static-template-ambiguous');
    expect(rejectionFor(input(duplicateMarker)).code).toBe('loader-already-present');
  });

  it('rejects alternate Vite config, plugin, and alias facts outside G001', () => {
    const candidate = viteCandidate();
    const config = candidate.viteConfig;
    if (config === undefined) {
      throw new Error('expected Vite config facts');
    }
    const configEscape = {
      ...candidate,
      viteConfig: { ...config, path: 'vite.config.js' },
    };
    const pluginEscape = {
      ...candidate,
      viteConfig: { ...config, plugin: 'unmanaged-plugin' },
    };
    const aliasEscape = {
      ...candidate,
      viteConfig: { ...config, aliases: [{ find: '@', replacement: 'src' }] },
    };

    const configInput = { ...input(candidate), candidates: [configEscape] };
    const pluginInput = { ...input(candidate), candidates: [pluginEscape] };
    const aliasInput = { ...input(candidate), candidates: [aliasEscape] };

    expect(rejectionFor(configInput).code).toBe('vite-contract-unsupported');
    expect(rejectionFor(pluginInput).code).toBe('vite-contract-unsupported');
    expect(rejectionFor(aliasInput).code).toBe('vite-contract-unsupported');
  });

  it('does not mutate supplied frozen facts or obtain randomness while planning', () => {
    const facts = deepFreeze(
      input(staticCandidate('<html><head>\n</head><body>do-not-leak</body></html>')),
    );
    const random = Math.random;
    Math.random = () => {
      throw new Error('randomness is forbidden during planning');
    };
    try {
      const first = planHostIntegration(facts);
      const second = planHostIntegration(facts);
      expect(second).toEqual(first);
      expect(JSON.stringify(first)).not.toContain('do-not-leak');
    } finally {
      Math.random = random;
    }
  });
  it('requires a matching post-write authority and rejects duplicate or forged finalization facts', () => {
    const candidate = staticCandidate();
    const created = planHostIntegration({
      ...input({
        ...candidate,
        descriptor: { ...candidate.descriptor, credentialAuthorities: [] },
      }),
      credential: {
        kind: 'create',
        requestId: 'candidate-alpha-1',
        bits: 256,
        projectId: 'alpha',
        path: AUTHORITY.path,
      },
    });
    const stagedAuthority = {
      projectId: 'alpha',
      path: AUTHORITY.path,
      device: '101',
      inode: '202',
    } as const;
    const duplicateExistingAuthority = {
      projectId: 'beta',
      path: '/var/lib/scene-glass/beta.credential',
      device: '101',
      inode: '202',
    } as const;
    const duplicateCandidate = staticCandidate();
    expect(() =>
      planHostIntegration({
        ...input({
          ...duplicateCandidate,
          descriptor: {
            ...duplicateCandidate.descriptor,
            credentialAuthorities: [duplicateExistingAuthority],
          },
        }),
        credential: {
          kind: 'create',
          requestId: 'candidate-alpha-2',
          bits: 256,
          projectId: 'alpha',
          path: AUTHORITY.path,
        },
      }),
    ).toThrow(HostPlanError);
    const forged = { ...created };
    Object.defineProperty(forged, 'descriptor', {
      enumerable: true,
      value: {
        ...created.descriptor,
        credentialAuthorities: [stagedAuthority],
      },
    });

    expect(() => finalizeHostIntegrationPlan(created)).toThrow(HostPlanError);
    expect(() =>
      finalizeHostIntegrationPlan(created, {
        ...stagedAuthority,
        path: '/var/lib/scene-glass/other.credential',
      }),
    ).toThrow(HostPlanError);
    expect(() => finalizeHostIntegrationPlan(forged, stagedAuthority)).toThrow(HostPlanError);
  });

  it('rejects raw credential and digest fields, inherited records, and accessor facts', () => {
    const rawCredential = {
      ...input(staticCandidate()),
      credential: { kind: 'adopt', authority: AUTHORITY, token: 'raw-secret-value' },
    };
    const createdWithAuthority = {
      ...input({
        ...staticCandidate(),
        descriptor: { ...descriptor(), credentialAuthorities: [] },
      }),
      credential: {
        kind: 'create',
        requestId: 'candidate-alpha-1',
        bits: 256,
        projectId: 'alpha',
        path: AUTHORITY.path,
        authority: AUTHORITY,
      },
    };
    const digestDescriptor = {
      ...input(staticCandidate()),
      candidates: [
        {
          ...staticCandidate(),
          descriptor: { ...descriptor(), tokenDigest: `sha256:${'a'.repeat(64)}` },
        },
      ],
    };
    const inherited = Object.create({ schemaVersion: HOST_PLAN_SCHEMA_VERSION });
    Object.assign(inherited, input(staticCandidate()));
    const accessor = input(staticCandidate());
    Object.defineProperty(accessor, 'override', {
      enumerable: true,
      get() {
        return 'html';
      },
    });

    expect(rejectionFor(rawCredential).code).toBe('invalid-facts');
    expect(rejectionFor(createdWithAuthority).code).toBe('invalid-facts');
    expect(rejectionFor(digestDescriptor).code).toBe('invalid-facts');
    expect(rejectionFor(inherited).code).toBe('invalid-facts');
    expect(rejectionFor(accessor).code).toBe('invalid-facts');
  });
});
