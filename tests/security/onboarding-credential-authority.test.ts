import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CredentialAuthority } from '../../packages/onboarding/src/types.js';

const native = vi.hoisted(() => ({
  verifyCredentialAuthoritySet: vi.fn(),
  secureReadCredential: vi.fn(),
  zeroizeBuffer: vi.fn((bytes: Buffer) => bytes.fill(0)),
}));

vi.mock('../../packages/onboarding/src/native.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../packages/onboarding/src/native.js')>()),
  ...native,
}));

import { OnboardingNativeError } from '../../packages/onboarding/src/native.js';
import {
  MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES,
  parseCredentialAuthorityRegistryJsonV1,
  parseCredentialAuthorityRegistryV1,
  serializeCredentialAuthorityRegistryV1,
  verifyCredentialAuthorities,
  withSelectedCredential,
  type CredentialAuthorityRegistryEntry,
} from '../../packages/onboarding/src/credential-authority.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('credential authority public boundary', () => {
  it('rejects oversized public identity inputs before native traversal or authority-key construction', () => {
    const options = credentialOptions();
    const invalidInputs = [
      {
        authorities: [authority()],
        selectedProjectId: 'p'.repeat(129),
      },
      {
        authorities: [authority()],
        selectedProjectId: 'é'.repeat(65),
      },
      {
        authorities: [authority({ projectId: 'p'.repeat(129) })],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [authority({ device: '1'.repeat(21) })],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [authority({ inode: '1'.repeat(21) })],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [authority({ device: '18446744073709551616' })],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [authority({ inode: '18446744073709551616' })],
        selectedProjectId: 'alpha',
      },
    ];

    for (const input of invalidInputs) {
      native.verifyCredentialAuthoritySet.mockClear();
      const error = expectNativeError(() =>
        verifyCredentialAuthorities({
          ...input,
          ...options,
        }),
      );
      expect(error.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
      expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
    }
    let authorityLookupAttempted = false;
    const selectedBeforeLookup = new Proxy(
      {
        authorities: [authority()],
        selectedProjectId: 'p'.repeat(129),
        ...options,
      },
      {
        get(target, property, receiver) {
          if (property === 'authorities') {
            authorityLookupAttempted = true;
          }
          return Reflect.get(target, property, receiver);
        },
      },
    );
    const selectedError = expectNativeError(() =>
      verifyCredentialAuthorities(selectedBeforeLookup),
    );
    expect(selectedError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    expect(authorityLookupAttempted).toBe(false);
    expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
  });

  it('accepts bounded uint64 identities and preserves one authority per project', () => {
    const capability = nativeCapability();
    const maximumUint64 = '18446744073709551615';
    const selected = authority({
      projectId: 'é'.repeat(64),
      device: maximumUint64,
      inode: maximumUint64,
    });
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);

    const verified = verifyCredentialAuthorities({
      authorities: [selected],
      selectedProjectId: selected.projectId,
      ...credentialOptions(),
    });

    expect(verified.selectedAuthority).toEqual(selected);
    expect(native.verifyCredentialAuthoritySet).toHaveBeenCalledExactlyOnceWith(
      [selected],
      selected.projectId,
      credentialOptions(),
    );
  });

  it('rejects a mismatched expected UID before native authority validation', () => {
    const options = credentialOptions();
    const mismatchedExpectedOwnerUid =
      options.expectedOwnerUid === 0 ? 1 : options.expectedOwnerUid - 1;

    const error = expectNativeError(() =>
      verifyCredentialAuthorities({
        authorities: [authority()],
        selectedProjectId: 'alpha',
        expectedOwnerUid: mismatchedExpectedOwnerUid,
        maxBytes: options.maxBytes,
      }),
    );

    expect(error.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
  });

  it('retains immutable selected authority facts when caller-owned input is mutated', async () => {
    const capability = nativeCapability();
    const mutableAuthority = { ...authority() };
    const credential = Buffer.from('credential-material-canary');
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    const verified = verifyCredentialAuthorities({
      authorities: [mutableAuthority],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    mutableAuthority.path = '/private/replaced-credential.fixture';
    mutableAuthority.inode = '3';

    await expect(withSelectedCredential(verified, (bytes) => bytes.toString('utf8'))).resolves.toBe(
      'credential-material-canary',
    );
    expect(verified.selectedAuthority).toEqual(authority());
    expect(native.secureReadCredential).toHaveBeenCalledExactlyOnceWith(
      capability,
      credentialOptions(),
    );
  });

  it('zeroizes the delivered credential buffer after a successful callback', async () => {
    const capability = nativeCapability();
    const credential = Buffer.from([1, 2, 3, 4]);
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    native.zeroizeBuffer.mockImplementation((bytes: Buffer) => bytes.fill(0));
    const verified = verifyCredentialAuthorities({
      authorities: [authority()],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    const result = await withSelectedCredential(verified, (bytes) => bytes.length);

    expect(result).toBe(4);
    expect(credential.every((byte) => byte === 0)).toBe(true);
    expect(native.zeroizeBuffer).toHaveBeenCalledExactlyOnceWith(credential);
  });
  it.each(['throws', 'rejects'] as const)(
    'zeroizes a delivered credential exactly once and consumes its capability when the callback %s',
    async (settlement) => {
      const capability = nativeCapability();
      const credential = Buffer.from('credential-callback-failure', 'utf8');
      const callbackFailure = new Error(`consumer callback ${settlement}`);
      let delivered: Buffer | undefined;
      native.verifyCredentialAuthoritySet.mockReturnValue(capability);
      native.secureReadCredential.mockReturnValue(credential);
      native.zeroizeBuffer.mockImplementation((bytes: Buffer) => bytes.fill(0));
      const verified = verifyCredentialAuthorities({
        authorities: [authority()],
        selectedProjectId: 'alpha',
        ...credentialOptions(),
      });

      const callback = withSelectedCredential(verified, (bytes) => {
        delivered = bytes;
        expect(bytes.every((byte) => byte !== 0)).toBe(true);
        if (settlement === 'throws') {
          throw callbackFailure;
        }
        return Promise.reject(callbackFailure);
      });
      try {
        await expect(callback).rejects.toBe(callbackFailure);
      } finally {
        expect(delivered).toBe(credential);
        expect(credential.every((byte) => byte === 0)).toBe(true);
        expect(native.zeroizeBuffer).toHaveBeenCalledExactlyOnceWith(credential);
      }

      expect(native.secureReadCredential).toHaveBeenCalledOnce();
    },
  );

  it('propagates native owner-or-mode denials without exposing fixture data or invoking callbacks', async () => {
    const capability = nativeCapability();
    const nativeDenial = new OnboardingNativeError(
      'SCG_NATIVE_PATH_DENIED',
      'Secure native read was denied.',
    );
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockImplementation(() => {
      throw nativeDenial;
    });
    const verified = verifyCredentialAuthorities({
      authorities: [authority()],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    let callbackCalled = false;

    const error = await expectNativeErrorAsync(() =>
      withSelectedCredential(verified, () => {
        callbackCalled = true;
      }),
    );

    expect(error).toBe(nativeDenial);
    expect(error.code).toBe('SCG_NATIVE_PATH_DENIED');
    expect(callbackCalled).toBe(false);
    expect(renderError(error)).not.toContain('/private/credential-authority.fixture');
    expect(renderError(error)).not.toContain('credential-material-canary');
  });

  it('fails closed for a native authority replacement after immutable input snapshotting', async () => {
    const capability = nativeCapability();
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockImplementation(() => {
      throw new OnboardingNativeError(
        'SCG_CREDENTIAL_AUTHORITY_INVALID',
        'Credential authority is invalid.',
      );
    });
    const verified = verifyCredentialAuthorities({
      authorities: [authority()],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    const first = await expectNativeErrorAsync(() =>
      withSelectedCredential(verified, () => 'callback must not run'),
    );
    const second = await expectNativeErrorAsync(() =>
      withSelectedCredential(verified, () => 'callback must not run'),
    );

    expect(first.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    expect(second.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    expect(native.secureReadCredential).toHaveBeenCalledOnce();
  });
});
describe('credential authority registry codec', () => {
  it('retains and canonically serializes an empty registry', () => {
    const empty = { schemaVersion: 1, projects: [] };

    const serialized = serializeCredentialAuthorityRegistryV1(empty);

    expect(serialized).toBe('{\n  "schemaVersion": 1,\n  "projects": []\n}\n');
    expect(parseCredentialAuthorityRegistryJsonV1(serialized)).toEqual(empty);
  });

  it('serializes sorted entries exactly without retaining token or digest material', () => {
    const registry = {
      schemaVersion: 1,
      projects: [
        registryEntry(),
        registryEntry({
          projectId: 'beta',
          tokenEnv: 'SCG_BETA_TOKEN',
          canonicalRoot: '/srv/beta',
          credentialPath: '/srv/beta/.scene-glass/credential',
          device: '3',
          inode: '4',
        }),
      ],
    };
    const serialized = serializeCredentialAuthorityRegistryV1(registry);

    expect(serialized).toBe(
      [
        '{',
        '  "schemaVersion": 1,',
        '  "projects": [',
        '    {',
        '      "projectId": "alpha",',
        '      "tokenEnv": "SCG_ALPHA_TOKEN",',
        '      "canonicalRoot": "/srv/alpha",',
        '      "credentialPath": "/srv/alpha/.scene-glass/credential",',
        '      "device": "1",',
        '      "inode": "2"',
        '    },',
        '    {',
        '      "projectId": "beta",',
        '      "tokenEnv": "SCG_BETA_TOKEN",',
        '      "canonicalRoot": "/srv/beta",',
        '      "credentialPath": "/srv/beta/.scene-glass/credential",',
        '      "device": "3",',
        '      "inode": "4"',
        '    }',
        '  ]',
        '}',
        '',
      ].join('\n'),
    );
    expect(serialized).not.toContain('credential-value-canary');
    expect(serialized).not.toContain('sha256:');

    expect(() =>
      parseCredentialAuthorityRegistryV1({
        schemaVersion: 1,
        projects: [{ ...registryEntry(), token: 'credential-value-canary' }],
      }),
    ).toThrow('exact canonical own keys');
    expect(() =>
      parseCredentialAuthorityRegistryV1({
        schemaVersion: 1,
        projects: [{ ...registryEntry(), tokenDigest: `sha256:${'a'.repeat(64)}` }],
      }),
    ).toThrow('exact canonical own keys');
  });

  it('accepts an exactly bounded canonical registry and rejects oversized JSON before parsing', () => {
    const registry = registryAtSerializedByteLength(MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES);
    const serialized = serializeCredentialAuthorityRegistryV1(registry);

    expect(Buffer.byteLength(serialized, 'utf8')).toBe(MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES);
    expect(parseCredentialAuthorityRegistryJsonV1(serialized)).toEqual(registry);
    expect(
      serializeCredentialAuthorityRegistryV1(parseCredentialAuthorityRegistryJsonV1(serialized)),
    ).toBe(serialized);
    expect(() => parseCredentialAuthorityRegistryJsonV1(`${serialized} `)).toThrow(
      'credential authority registry JSON is invalid',
    );
  });

  it('refuses to serialize a registry above the parser byte limit', () => {
    expect(() => serializeCredentialAuthorityRegistryV1(oversizedRegistry())).toThrow(
      'credential authority registry JSON exceeds its byte limit',
    );
  });

  it('rejects malformed, sparse, duplicate, and unsorted registry entries', () => {
    const sparseProjects = new Array<unknown>(1);
    const duplicateProjects = [registryEntry(), registryEntry({ inode: '3' })];

    expect(() => parseCredentialAuthorityRegistryJsonV1('not-json')).toThrow(
      'credential authority registry JSON is invalid',
    );
    expect(() =>
      parseCredentialAuthorityRegistryV1({ schemaVersion: 1, projects: sparseProjects }),
    ).toThrow('credential authority registry is invalid');
    expect(() =>
      parseCredentialAuthorityRegistryV1({ schemaVersion: 1, projects: duplicateProjects }),
    ).toThrow('credential authority registry is invalid');
    expect(() =>
      parseCredentialAuthorityRegistryV1({
        schemaVersion: 1,
        projects: [registryEntry({ projectId: 'beta' }), registryEntry()],
      }),
    ).toThrow('credential authority registry is invalid');
  });

  it('rejects registry credentials that escape their canonical project root', () => {
    const escapes = [
      { canonicalRoot: '/srv/alpha', credentialPath: '/srv/beta/.scene-glass/credential' },
      { canonicalRoot: '/srv/alpha', credentialPath: '/srv/alphabet/.scene-glass/credential' },
      { canonicalRoot: '/srv/alpha', credentialPath: '/srv/alpha' },
      { canonicalRoot: '/srv/alpha/nested', credentialPath: '/srv/alpha/credential' },
    ];
    for (const escape of escapes) {
      expect(() =>
        parseCredentialAuthorityRegistryV1({
          schemaVersion: 1,
          projects: [registryEntry(escape)],
        }),
      ).toThrow('credential authority registry entry is invalid');
    }
  });
});

function credentialOptions(): { readonly expectedOwnerUid: number; readonly maxBytes: number } {
  if (typeof process.geteuid !== 'function') {
    throw new Error('Credential authority tests require a POSIX effective UID.');
  }
  return Object.freeze({ expectedOwnerUid: process.geteuid(), maxBytes: 8 * 1024 });
}

function authority(overrides: Partial<CredentialAuthority> = {}): CredentialAuthority {
  return Object.freeze({
    projectId: 'alpha',
    path: '/private/credential-authority.fixture',
    device: '1',
    inode: '2',
    ...overrides,
  });
}
function registryEntry(
  overrides: Partial<CredentialAuthorityRegistryEntry> = {},
): CredentialAuthorityRegistryEntry {
  return Object.freeze({
    projectId: 'alpha',
    tokenEnv: 'SCG_ALPHA_TOKEN',
    canonicalRoot: '/srv/alpha',
    credentialPath: '/srv/alpha/.scene-glass/credential',
    device: '1',
    inode: '2',
    ...overrides,
  });
}
const FULL_ENTRY_MARKERS = '0123456789abcdef';

function containedFullRegistryEntry(
  index: number,
  tokenPrefix: string,
): CredentialAuthorityRegistryEntry {
  const marker = FULL_ENTRY_MARKERS[index];
  if (marker === undefined) {
    throw new Error('Registry fixture ran out of unique credential markers.');
  }
  const canonicalRoot = canonicalRegistryPathOfLength(2 * 1024, 'r');
  return registryEntry({
    projectId: `alpha-${marker}`,
    tokenEnv: `${tokenPrefix}_${index}`,
    canonicalRoot,
    credentialPath: `${canonicalRoot}${canonicalRegistryPathOfLength(2 * 1024, marker)}`,
    device: String(index + 1),
    inode: String(index + 100),
  });
}

function registryAtSerializedByteLength(targetByteLength: number): {
  readonly schemaVersion: 1;
  readonly projects: readonly CredentialAuthorityRegistryEntry[];
} {
  const maximumFinalRootGrowth = 15 * 256 - 2;
  const maximumFinalSuffixGrowth = 254;
  const maximumPathGrowth = 2 * maximumFinalRootGrowth + maximumFinalSuffixGrowth;
  for (let fullCount = 0; fullCount <= FULL_ENTRY_MARKERS.length; fullCount += 1) {
    const fullEntries = Array.from({ length: fullCount }, (_, index) =>
      containedFullRegistryEntry(index, 'SCG_BOUNDARY'),
    );
    const minimumFinalRoot = canonicalRegistryPathOfLength(2, 'q');
    const minimumFinalEntry = registryEntry({
      projectId: 'omega',
      tokenEnv: 'SCG_BOUNDARY_FINAL',
      canonicalRoot: minimumFinalRoot,
      credentialPath: `${minimumFinalRoot}${canonicalRegistryPathOfLength(2, 'z')}`,
      device: '99',
      inode: '199',
    });
    const minimumRegistry = {
      schemaVersion: 1 as const,
      projects: [...fullEntries, minimumFinalEntry],
    };
    let minimumBytes: number;
    try {
      minimumBytes = Buffer.byteLength(
        serializeCredentialAuthorityRegistryV1(minimumRegistry),
        'utf8',
      );
    } catch {
      break;
    }
    const remainingBytes = targetByteLength - minimumBytes;
    if (remainingBytes < 0 || remainingBytes > maximumPathGrowth) {
      continue;
    }
    const suffixGrowth =
      remainingBytes <= maximumFinalSuffixGrowth
        ? remainingBytes
        : remainingBytes % 2 === 0
          ? maximumFinalSuffixGrowth
          : maximumFinalSuffixGrowth - 1;
    const rootGrowth = (remainingBytes - suffixGrowth) / 2;
    if (!Number.isSafeInteger(rootGrowth) || rootGrowth > maximumFinalRootGrowth) {
      continue;
    }
    const finalRoot = canonicalRegistryPathOfLength(2 + rootGrowth, 'q');
    const registry = {
      schemaVersion: 1 as const,
      projects: [
        ...fullEntries,
        registryEntry({
          ...minimumFinalEntry,
          canonicalRoot: finalRoot,
          credentialPath: `${finalRoot}${canonicalRegistryPathOfLength(2 + suffixGrowth, 'z')}`,
        }),
      ],
    };
    if (
      Buffer.byteLength(serializeCredentialAuthorityRegistryV1(registry), 'utf8') !==
      targetByteLength
    ) {
      throw new Error('Unable to construct an exact registry byte boundary.');
    }
    return registry;
  }
  throw new Error('Unable to construct a registry at the requested byte boundary.');
}

function oversizedRegistry(): {
  readonly schemaVersion: 1;
  readonly projects: readonly CredentialAuthorityRegistryEntry[];
} {
  return {
    schemaVersion: 1,
    projects: Array.from({ length: 12 }, (_, index) =>
      containedFullRegistryEntry(index, 'SCG_OVERSIZED'),
    ),
  };
}

function canonicalRegistryPathOfLength(length: number, marker: string): string {
  for (let componentCount = 1; componentCount <= 16; componentCount += 1) {
    if (length < 2 * componentCount || length > 256 * componentCount) {
      continue;
    }
    let extra = length - 2 * componentCount;
    const components = Array.from({ length: componentCount }, () => {
      const componentLength = 1 + Math.min(extra, 254);
      extra -= componentLength - 1;
      return 'x'.repeat(componentLength);
    });
    const first = components[0];
    if (first === undefined) {
      throw new Error('Registry path construction failed.');
    }
    components[0] = `${marker}${first.slice(1)}`;
    return `/${components.join('/')}`;
  }
  throw new Error('Registry path length is outside the supported boundary range.');
}

function nativeCapability(): object {
  return Object.freeze(Object.create(null));
}

function expectNativeError(action: () => unknown): OnboardingNativeError {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }
  if (!(caught instanceof OnboardingNativeError)) {
    throw new Error('Expected an onboarding native error.');
  }
  return caught;
}

async function expectNativeErrorAsync(
  action: () => unknown | Promise<unknown>,
): Promise<OnboardingNativeError> {
  let caught: unknown;
  try {
    await action();
  } catch (error: unknown) {
    caught = error;
  }
  if (!(caught instanceof OnboardingNativeError)) {
    throw new Error('Expected an onboarding native error.');
  }
  return caught;
}

function renderError(error: Error): string {
  return [error.name, error.message, error.stack ?? ''].join('\n');
}
