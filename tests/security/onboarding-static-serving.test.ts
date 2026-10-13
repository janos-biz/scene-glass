import { Buffer } from 'node:buffer';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { createConnection, type Socket } from 'node:net';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => ({
  secureReadBeneath: vi.fn(),
  secureReadCredential: vi.fn(),
  verifyCredentialAuthoritySet: vi.fn(() => Object.freeze(Object.create(null))),
  revokeCredentialReadCapability: vi.fn(),
  zeroizeBuffer: vi.fn((bytes: Buffer) => bytes.fill(0)),
}));
vi.mock('../../packages/onboarding/src/native.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../packages/onboarding/src/native.js')>()),
  ...native,
}));
const credentialAuthority = vi.hoisted(() => ({
  override: undefined as ((...args: unknown[]) => unknown) | undefined,
}));
vi.mock('../../packages/onboarding/src/credential-authority.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../packages/onboarding/src/credential-authority.js')>();
  return {
    ...actual,
    verifyCredentialAuthorities: (
      ...args: Parameters<typeof actual.verifyCredentialAuthorities>
    ): unknown =>
      credentialAuthority.override?.(...args) ?? actual.verifyCredentialAuthorities(...args),
  };
});

import {
  startStaticRuntime,
  type StaticRuntime,
} from '../../packages/onboarding/src/static/runtime.js';

const TOKEN = Buffer.alloc(32, 11).toString('base64url');
const MARKER = '<!-- scene-glass:static-loader:v1 -->';
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;
const CACHE_CONTROL = 'no-store, private, max-age=0';
const RAW_SOCKET_TIMEOUT_MS = 2_000;
const MAX_RAW_SOCKET_REQUEST_BYTES = 8 * 1024;
const MAX_RAW_SOCKET_RESPONSE_BYTES = 64 * 1024;
const runtimes = new Set<StaticRuntime>();

afterEach(async () => {
  try {
    await Promise.all([...runtimes].map((runtime) => runtime.stop()));
  } finally {
    runtimes.clear();
    credentialAuthority.override = undefined;
    vi.resetAllMocks();
    native.verifyCredentialAuthoritySet.mockReturnValue(credentialCapability());
    native.revokeCredentialReadCapability.mockImplementation(() => undefined);
    native.zeroizeBuffer.mockImplementation((bytes: Buffer) => bytes.fill(0));
  }
});

describe('static serving security boundary', () => {
  it('uses every immutable authority snapshot, reads only the selected credential, and zeroizes native buffers', async () => {
    const templateBuffer = Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8');
    const servedHtmlTemplate = Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8');
    const credentialBuffer = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const servedAsset = Buffer.from('safe asset', 'utf8');
    const expectedAuthorities = [
      { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
      { projectId: 'beta', path: '/private/beta.env', device: '505', inode: '606' },
    ];
    const descriptor = {
      ...descriptorWithAuthorities(0),
      credentialAuthorities: [{ ...expectedAuthorities[0]! }],
    };
    const capability = credentialCapability();
    const operationOrder: string[] = [];
    const getEffectiveUid = process.geteuid;
    if (getEffectiveUid === undefined) {
      throw new Error('static serving security test requires a POSIX effective user identity');
    }
    const expectedOwnerUid = getEffectiveUid();

    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockImplementation(() => {
      operationOrder.push('read');
      return credentialBuffer;
    });
    native.zeroizeBuffer.mockImplementation((bytes: Buffer) => {
      operationOrder.push('zeroize');
      return bytes.fill(0);
    });
    native.revokeCredentialReadCapability.mockImplementation(() => {
      operationOrder.push('revoke');
    });
    let templateReadCount = 0;
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      operationOrder.push(input.relativePath);
      if (input.relativePath === 'index.html') {
        templateReadCount += 1;
        return { bytes: templateReadCount === 1 ? templateBuffer : servedHtmlTemplate };
      }
      if (input.relativePath === 'safe.txt') {
        return { bytes: servedAsset };
      }
      throw new Error('denied');
    });

    const configuredProjects = trustedConfiguredProjects('/private/static-security-fixture', [
      expectedAuthorities[1]!,
      expectedAuthorities[0]!,
    ]);
    const runtime = await startStaticRuntime({
      descriptor,
      configuredProjects,
      projectRoot: '/private/static-security-fixture',
    });
    runtimes.add(runtime);
    descriptor.credentialAuthorities[0]!.path = '/private/mutated-alpha.env';
    descriptor.credentialAuthorities[0]!.device = '999';
    descriptor.credentialAuthorities[0]!.inode = '998';
    configuredProjects.projects[0]!.canonicalRoot = '/private/mutated-beta-security-fixture';
    configuredProjects.projects[0]!.credentialAuthority.device = '997';
    configuredProjects.projects[0]!.credentialAuthority.inode = '996';
    configuredProjects.projects[1]!.canonicalRoot = '/private/mutated-static-security-fixture';
    configuredProjects.projects[1]!.credentialAuthority.path = '/private/mutated-alpha.env';
    configuredProjects.projects[1]!.publicRootIdentity.inode = '999';

    const html = await fetch(urlFor(runtime, '/'));
    expect(html.status).toBe(200);
    const htmlBody = await html.text();
    expect(htmlBody).toContain(TOKEN);
    expect(htmlBody).not.toContain('beta');
    expect(htmlBody).not.toContain('/private/beta.env');
    const asset = await fetch(urlFor(runtime, '/safe.txt'));
    expect(asset.status).toBe(200);
    expect(await asset.text()).toBe('safe asset');
    expect(operationOrder).toEqual([
      'read',
      'zeroize',
      'revoke',
      'index.html',
      'index.html',
      'safe.txt',
    ]);

    expect(native.verifyCredentialAuthoritySet.mock.calls).toEqual([
      [[expectedAuthorities[0]], 'alpha', { expectedOwnerUid, maxBytes: 8 * 1024 }],
    ]);
    expect(native.secureReadCredential.mock.calls).toEqual([
      [capability, { expectedOwnerUid, maxBytes: 8 * 1024 }],
    ]);
    expect(native.secureReadBeneath.mock.calls).toEqual([
      [
        {
          root: '/private/static-security-fixture/public',
          expectedRoot: { device: '101', inode: '202' },
          relativePath: 'index.html',
          deniedIdentities: [
            { device: '303', inode: '404' },
            { device: '505', inode: '606' },
          ],
          maxBytes: 8 * 1024 * 1024,
        },
      ],
      [
        {
          root: '/private/static-security-fixture/public',
          expectedRoot: { device: '101', inode: '202' },
          relativePath: 'index.html',
          deniedIdentities: [
            { device: '303', inode: '404' },
            { device: '505', inode: '606' },
          ],
          maxBytes: 8 * 1024 * 1024,
        },
      ],
      [
        {
          root: '/private/static-security-fixture/public',
          expectedRoot: { device: '101', inode: '202' },
          relativePath: 'safe.txt',
          deniedIdentities: [
            { device: '303', inode: '404' },
            { device: '505', inode: '606' },
          ],
          maxBytes: 16 * 1024 * 1024,
        },
      ],
    ]);
    const deniedIdentities = native.secureReadBeneath.mock.calls.map(
      ([input]) =>
        (
          input as {
            readonly deniedIdentities: readonly {
              readonly device: string;
              readonly inode: string;
            }[];
          }
        ).deniedIdentities,
    );
    expect(deniedIdentities[0]).toBe(deniedIdentities[1]);
    expect(deniedIdentities[1]).toBe(deniedIdentities[2]);
    expect(Object.isFrozen(deniedIdentities[0])).toBe(true);
    expect(deniedIdentities[0]!.every(Object.isFrozen)).toBe(true);
    expect(credentialBuffer.every((byte) => byte === 0)).toBe(true);
    expect(templateBuffer.every((byte) => byte === 0)).toBe(true);
    expect(servedHtmlTemplate.every((byte) => byte === 0)).toBe(true);
    expect(servedAsset.every((byte) => byte === 0)).toBe(true);
  });
  it('requires a complete trusted project snapshot and binds its selected root before native work', async () => {
    const descriptor = descriptorWithAuthorities(0);
    await expect(
      startStaticRuntime({
        descriptor,
        configuredProjects: [{ projectId: 'alpha' }, { projectId: 'beta' }],
        projectRoot: '/private/static-security-fixture',
      }),
    ).rejects.toMatchObject({ code: 'SCG_STATIC_DESCRIPTOR_INVALID' });

    await expect(
      startStaticRuntime({
        descriptor,
        configuredProjects: trustedConfiguredProjects('/private/other-project-root'),
        projectRoot: '/private/static-security-fixture',
      }),
    ).rejects.toThrow('static runtime project root is not authorized');

    expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
    expect(native.secureReadCredential).not.toHaveBeenCalled();
    expect(native.secureReadBeneath).not.toHaveBeenCalled();
  });
  it('rejects independent valid-shape trusted-authority mismatches before native work', async () => {
    const cases = [
      {
        label: 'canonical root',
        expectedMessage: 'static runtime project root is not authorized',
        mutate: (
          _descriptor: {
            approvedRootIdentity: { device: string; inode: string };
            credentialAuthorities: Array<{ path: string; device: string; inode: string }>;
          },
          _configuredProjects: ReturnType<typeof trustedConfiguredProjects>,
        ): string => {
          void _descriptor;
          void _configuredProjects;
          return '/private/different-static-security-fixture';
        },
      },
      {
        label: 'public root identity',
        expectedMessage: 'descriptor approved root identity is not configured',
        mutate: (
          descriptor: {
            approvedRootIdentity: { device: string; inode: string };
            credentialAuthorities: Array<{ path: string; device: string; inode: string }>;
          },
          _configuredProjects: ReturnType<typeof trustedConfiguredProjects>,
        ): string | undefined => {
          void _configuredProjects;
          descriptor.approvedRootIdentity = { device: '101', inode: '999' };
          return undefined;
        },
      },
      {
        label: 'credential path',
        expectedMessage: 'descriptor credential authority is not configured',
        mutate: (
          _descriptor: {
            approvedRootIdentity: { device: string; inode: string };
            credentialAuthorities: Array<{ path: string; device: string; inode: string }>;
          },
          configuredProjects: ReturnType<typeof trustedConfiguredProjects>,
        ): string | undefined => {
          configuredProjects.projects[0]!.credentialAuthority.path = '/private/other-alpha.env';
          return undefined;
        },
      },
      {
        label: 'credential device',
        expectedMessage: 'descriptor credential authority is not configured',
        mutate: (
          _descriptor: {
            approvedRootIdentity: { device: string; inode: string };
            credentialAuthorities: Array<{ path: string; device: string; inode: string }>;
          },
          configuredProjects: ReturnType<typeof trustedConfiguredProjects>,
        ): string | undefined => {
          configuredProjects.projects[0]!.credentialAuthority.device = '999';
          return undefined;
        },
      },
      {
        label: 'credential inode',
        expectedMessage: 'descriptor credential authority is not configured',
        mutate: (
          _descriptor: {
            approvedRootIdentity: { device: string; inode: string };
            credentialAuthorities: Array<{ path: string; device: string; inode: string }>;
          },
          configuredProjects: ReturnType<typeof trustedConfiguredProjects>,
        ): string | undefined => {
          configuredProjects.projects[0]!.credentialAuthority.inode = '999';
          return undefined;
        },
      },
    ] as const;

    for (const testCase of cases) {
      const base = descriptorWithAuthorities(0);
      const descriptor = {
        ...base,
        approvedRootIdentity: { ...base.approvedRootIdentity },
        credentialAuthorities: base.credentialAuthorities.map((authority) => ({ ...authority })),
      };
      const configuredProjects = trustedConfiguredProjects();
      const projectRoot =
        testCase.mutate(descriptor, configuredProjects) ?? '/private/static-security-fixture';
      const startup = startStaticRuntime({ descriptor, configuredProjects, projectRoot });

      const expectedFailure =
        testCase.label === 'canonical root'
          ? { message: testCase.expectedMessage }
          : {
              code: 'SCG_STATIC_DESCRIPTOR_INVALID',
              message: testCase.expectedMessage,
            };
      await expect(startup).rejects.toMatchObject(expectedFailure);
      expectNoNativeStartupCalls();
    }
  });
  it('fails fast once the static handler budget is full', async () => {
    let releaseBlockedReads!: () => void;
    const blockedReads = new Promise<void>((resolve) => {
      releaseBlockedReads = resolve;
    });
    native.verifyCredentialAuthoritySet.mockReturnValue(credentialCapability());
    native.secureReadCredential.mockReturnValue(
      Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
    );
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      if (input.relativePath === 'index.html') {
        return { bytes: Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8') };
      }
      if (input.relativePath === 'held.css') {
        return blockedReads.then(() => ({ bytes: Buffer.from('held', 'utf8') }));
      }
      throw nativeReadDenied();
    });

    const runtime = await startStaticRuntime({
      descriptor: descriptorWithAuthorities(0),
      configuredProjects: trustedConfiguredProjects(),
      projectRoot: '/private/static-security-fixture',
    });
    runtimes.add(runtime);
    const heldSockets: Socket[] = [];
    try {
      for (let index = 0; index < 32; index += 1) {
        heldSockets.push(
          await openRawRequest(
            runtime,
            `GET /held.css HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}\r\nConnection: keep-alive\r\n\r\n`,
          ),
        );
      }
      await waitForCallCount(() => native.secureReadBeneath.mock.calls.length, 33);

      const overflow = await fetch(urlFor(runtime, '/held.css'));
      expect(overflow.status).toBe(500);
      await expectInternalServerError(overflow);
      expect(native.secureReadBeneath).toHaveBeenCalledTimes(33);
    } finally {
      releaseBlockedReads();
      for (const socket of heldSockets) {
        socket.destroy();
      }
    }
  });
  it('caps idle pre-handler connections before they consume unbounded descriptors', async () => {
    const runtime = await startFixture(fixtureFiles());
    const partialSockets: Socket[] = [];
    let overflow: Socket | undefined;
    try {
      for (let index = 0; index < 64; index += 1) {
        partialSockets.push(
          await openRawRequest(
            runtime,
            `GET /idle-${index}.css HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}`,
          ),
        );
      }
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 0);
      });

      overflow = createConnection({ host: runtime.host, port: runtime.port });
      overflow.on('error', () => undefined);
      await waitForSocketClose(overflow);
      expect(native.secureReadBeneath).toHaveBeenCalledTimes(1);
    } finally {
      overflow?.destroy();
      for (const socket of partialSockets) {
        socket.destroy();
      }
    }
  });
  it('rejects malformed, ambiguous, and foreign Host authorities before any secure read', async () => {
    const files = fixtureFiles();
    native.verifyCredentialAuthoritySet.mockReturnValue(credentialCapability());
    native.secureReadCredential.mockReturnValue(
      Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
    );
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      const file = files.get(input.relativePath);
      if (file === undefined) {
        throw nativeReadDenied();
      }
      return { bytes: Buffer.from(file) };
    });
    const runtime = await startStaticRuntime({
      descriptor: descriptorWithAuthorities(0),
      configuredProjects: trustedConfiguredProjects(),
      projectRoot: '/private/static-security-fixture',
    });
    runtimes.add(runtime);

    const expectedHost = `${runtime.host}:${runtime.port}`;
    const accepted = await rawRequest(
      runtime,
      `GET / HTTP/1.1\r\nHost: ${expectedHost}\r\nConnection: close\r\n\r\n`,
    );
    expect(accepted).toMatch(/^HTTP\/1\.1 200 /);

    const rejectedHosts: ReadonlyArray<readonly [string, readonly string[]]> = [
      ['missing', []],
      ['foreign host', [`Host: localhost:${runtime.port}`]],
      ['missing port', [`Host: ${runtime.host}`]],
      ['wrong port', [`Host: ${runtime.host}:${runtime.port + 1}`]],
      ['duplicate expected Host', [`Host: ${expectedHost}`, `Host: ${expectedHost}`]],
      [
        'duplicate expected then foreign Host',
        [`Host: ${expectedHost}`, `Host: attacker.invalid:80`],
      ],
      [
        'duplicate foreign then expected Host',
        [`Host: attacker.invalid:80`, `Host: ${expectedHost}`],
      ],
      ['comma-joined expected then foreign Host', [`Host: ${expectedHost}, attacker.invalid:80`]],
      ['comma-joined foreign then expected Host', [`Host: attacker.invalid:80, ${expectedHost}`]],
      ['userinfo authority', [`Host: user@${expectedHost}`]],
      ['path authority', [`Host: ${expectedHost}/assets`]],
      ['unclosed bracket authority', [`Host: [${runtime.host}:${runtime.port}`]],
      ['misplaced bracket authority', [`Host: ${runtime.host}]:${runtime.port}`]],
      ['invalid zero port', [`Host: ${runtime.host}:0`]],
      ['invalid negative port', [`Host: ${runtime.host}:-1`]],
      ['invalid overflow port', [`Host: ${runtime.host}:65536`]],
      ['invalid nonnumeric port', [`Host: ${runtime.host}:not-a-port`]],
    ];

    native.secureReadBeneath.mockClear();
    for (const [, headers] of rejectedHosts) {
      const response = await rawRequest(
        runtime,
        ['GET / HTTP/1.1', ...headers, 'Connection: close', '', ''].join('\r\n'),
      );
      expect(response).toMatch(/^HTTP\/1\.1 404 /);
      expect(response).not.toContain(TOKEN);
      expect(native.secureReadBeneath).not.toHaveBeenCalled();
    }
  });
  it('routes CONNECT through host validation with the canonical empty 405 response', async () => {
    const runtime = await startFixture(fixtureFiles());
    const expectedHost = `${runtime.host}:${runtime.port}`;
    native.secureReadBeneath.mockClear();

    const accepted = await rawRequest(
      runtime,
      `CONNECT tunnel.invalid:443 HTTP/1.1\r\nHost: ${expectedHost}\r\nConnection: close\r\n\r\n`,
    );
    expect(accepted).toBe(
      [
        'HTTP/1.1 405 Method Not Allowed',
        `Cache-Control: ${CACHE_CONTROL}`,
        'Content-Length: 0',
        'Pragma: no-cache',
        'Allow: GET, HEAD',
        'Connection: close',
        '',
        '',
      ].join('\r\n'),
    );
    expect(native.secureReadBeneath).not.toHaveBeenCalled();

    const rejected = await rawRequest(
      runtime,
      `CONNECT tunnel.invalid:443 HTTP/1.1\r\nHost: localhost:${runtime.port}\r\nConnection: close\r\n\r\n`,
    );
    expect(rejected).toBe(
      [
        'HTTP/1.1 404 Not Found',
        `Cache-Control: ${CACHE_CONTROL}`,
        'Content-Length: 0',
        'Pragma: no-cache',
        'Connection: close',
        '',
        '',
      ].join('\r\n'),
    );
    expect(native.secureReadBeneath).not.toHaveBeenCalled();
  });

  it('returns one indistinguishable 404 response for malformed paths, traversal, links, races, missing files, directories, and nested HTML', async () => {
    const files = new Map<string, Buffer>([
      ['index.html', Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8')],
      ['safe.css', Buffer.from('body{}', 'utf8')],
    ]);
    const runtime = await startFixture(files, (relativePath) => {
      if (relativePath === 'credential-hardlink.css' || relativePath === 'identity-race.css') {
        throw nativeReadDenied();
      }
    });

    for (const path of [
      '/%',
      '/%252e%252e%252fcredential',
      '/%2e%2e%2fcredential',
      '/asset%00.txt',
      '/safe%5casset.css',
      '/directory/',
      '/nested/page.html',
      '/missing.css',
      '/credential-hardlink.css',
      '/identity-race.css',
    ]) {
      const get = await fetch(urlFor(runtime, path));
      expect(get.status).toBe(404);
      await expectNotFound(get);
      const head = await fetch(urlFor(runtime, path), { method: 'HEAD' });
      expect(head.status).toBe(404);
      await expectNotFound(head);
    }
    const safe = await fetch(urlFor(runtime, '/safe.css'));
    expect(safe.status).toBe(200);
    expect(await safe.text()).toBe('body{}');
  });
  it.each([
    'SCG_NATIVE_PATH_DENIED',
    'SCG_NATIVE_IDENTITY_MISMATCH',
    'SCG_NATIVE_READ_LIMIT',
  ] as const)('returns the canonical 404 without warning for %s on GET and HEAD', async (code) => {
    const runtime = await startFixture(fixtureFiles(), (relativePath) => {
      if (relativePath === 'denied.css') {
        throw nativeReadFailure(code);
      }
    });
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    native.secureReadBeneath.mockClear();

    try {
      for (const method of ['GET', 'HEAD'] as const) {
        const response = await rawRequest(
          runtime,
          `${method} /denied.css HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}\r\nConnection: close\r\n\r\n`,
        );
        expect(response).toBe(canonicalNotFoundResponse());
      }

      expect(native.secureReadBeneath).toHaveBeenCalledTimes(2);
      expect(warning).not.toHaveBeenCalled();
    } finally {
      warning.mockRestore();
    }
  });
  it.each(['100-continue', 'unsupported-expectation'])(
    'keeps %s routing host-first without automatic interim or expectation responses',
    async (expectation) => {
      const runtime = await startFixture(fixtureFiles());
      const expectedHost = `${runtime.host}:${runtime.port}`;
      native.secureReadBeneath.mockClear();

      for (const [host, method, expected] of [
        [expectedHost, 'GET', canonicalNotFoundResponse()],
        [expectedHost, 'HEAD', canonicalNotFoundResponse()],
        [expectedHost, 'POST', canonicalMethodNotAllowedResponse()],
        [`localhost:${runtime.port}`, 'GET', canonicalNotFoundResponse()],
        [`localhost:${runtime.port}`, 'HEAD', canonicalNotFoundResponse()],
        [`localhost:${runtime.port}`, 'POST', canonicalNotFoundResponse()],
      ] as const) {
        const response = await rawRequest(
          runtime,
          `${method} /missing.css HTTP/1.1\r\nHost: ${host}\r\nExpect: ${expectation}\r\nConnection: close\r\n\r\n`,
        );
        expect(response).toBe(expected);
        expect(response).not.toContain('100 Continue');
        expect(response).not.toContain('417 Expectation Failed');
      }

      expect(native.secureReadBeneath).toHaveBeenCalledTimes(2);
    },
  );
  it('keeps unexpected read failures observable while returning a fully redacted deterministic 500', async () => {
    const runtime = await startFixture(fixtureFiles());
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const rootCanary = '/private/static-security-fixture';
    const pathCanary = '/private/alpha.env';
    const nestedCause = Object.assign(new Error(`nested failure at ${pathCanary}`), {
      cause: new Error(`root failure at ${rootCanary}`),
    });
    const failure = Object.assign(new Error(`unexpected read failure: ${TOKEN}`), {
      cause: nestedCause,
    });
    native.secureReadBeneath.mockImplementation(() => {
      throw failure;
    });

    try {
      const response = await fetch(urlFor(runtime, '/unexpected.css'));
      expect(response.status).toBe(500);
      await expectInternalServerError(response);
      expect(warning.mock.calls).toEqual([
        [
          'Unexpected static runtime request failure.',
          {
            code: 'SCG_STATIC_RUNTIME_UNEXPECTED',
            type: 'SceneGlassStaticRuntimeError',
          },
        ],
      ]);
      expectWarningArgumentsRedacted(warning.mock.calls, [TOKEN, rootCanary, pathCanary]);
      native.secureReadBeneath.mockReturnValue({ bytes: Buffer.from('body{}', 'utf8') });
      const recovery = await fetch(urlFor(runtime, '/safe.css'));
      expect(recovery.status).toBe(200);
      expect(await recovery.text()).toBe('body{}');
    } finally {
      warning.mockRestore();
    }
  });

  it('evaluates method policy before URL parsing and emits no representation metadata on 405', async () => {
    const runtime = await startFixture(fixtureFiles());

    for (const method of ['POST', 'PUT', 'OPTIONS', 'DELETE']) {
      const response = await fetch(urlFor(runtime, '/%'), { method });
      expect(response.status).toBe(405);
      expect(response.headers.get('content-length')).toBe('0');
      expect(response.headers.get('content-type')).toBeNull();
      expect(response.headers.get('allow')).toBe('GET, HEAD');
      expect(response.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(response.headers.get('pragma')).toBe('no-cache');
      expect(await response.text()).toBe('');
    }
  });

  it('rejects marker replacement, missing marker, and non-standalone marker before listen', async () => {
    for (const template of [
      `<head>\n${MARKER}\n${MARKER}\n</head>`,
      '<head>\n</head>',
      `<head>${MARKER}\n</head>`,
      `<head>\n${MARKER}\n</head></head>`,
    ]) {
      await expect(
        startFixture(fixtureFiles(Buffer.from(template, 'utf8')), undefined, false),
      ).rejects.toThrow();
    }
  });
  it.each([
    ['empty', Buffer.alloc(0)],
    ['unterminated', Buffer.from(`SCENE_GLASS_HOST_TOKEN=${TOKEN}`, 'ascii')],
    ['malformed', Buffer.from('SCENE_GLASS_HOST_TOKEN\n', 'ascii')],
    [
      'duplicate',
      Buffer.from(`SCENE_GLASS_HOST_TOKEN=${TOKEN}\nSCENE_GLASS_HOST_TOKEN=${TOKEN}\n`, 'ascii'),
    ],
    ['unsorted', Buffer.from(`Z_KEY=${TOKEN}\nSCENE_GLASS_HOST_TOKEN=${TOKEN}\n`, 'ascii')],
    [
      'non-ASCII',
      Buffer.concat([
        Buffer.from('SCENE_GLASS_HOST_TOKEN=', 'ascii'),
        Buffer.from([0x80]),
        Buffer.from('\n'),
      ]),
    ],
    ['noncanonical', Buffer.from(`SCENE_GLASS_HOST_TOKEN=!${TOKEN}\n`, 'ascii')],
    ['missing selected key', Buffer.from(`OTHER_KEY=${TOKEN}\n`, 'ascii')],
  ])(
    'rejects %s credentials before listen and zeroizes the source buffer before revocation',
    async (_, credential) => {
      const capability = credentialCapability();
      const operationOrder: string[] = [];
      native.verifyCredentialAuthoritySet.mockReturnValue(capability);
      native.secureReadCredential.mockImplementation(() => {
        operationOrder.push('read');
        return credential;
      });
      native.zeroizeBuffer.mockImplementation((bytes: Buffer) => {
        operationOrder.push('zeroize');
        bytes.fill(0);
        return bytes;
      });
      native.revokeCredentialReadCapability.mockImplementation(() => {
        operationOrder.push('revoke');
      });
      native.secureReadBeneath.mockImplementation(() => {
        throw new Error('template read must not occur for invalid credentials');
      });

      await expect(
        startStaticRuntime({
          descriptor: descriptorWithAuthorities(0),
          configuredProjects: trustedConfiguredProjects(),
          projectRoot: '/private/static-security-fixture',
        }),
      ).rejects.toThrow();
      expect(native.verifyCredentialAuthoritySet).toHaveBeenCalledTimes(1);
      expect(native.secureReadCredential).toHaveBeenCalledTimes(1);
      expect(native.secureReadBeneath).not.toHaveBeenCalled();
      expect(credential.every((byte) => byte === 0)).toBe(true);
      expect(native.zeroizeBuffer).toHaveBeenCalledTimes(1);
      expect(native.zeroizeBuffer).toHaveBeenCalledWith(credential);
      expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(1);
      expect(native.revokeCredentialReadCapability).toHaveBeenCalledWith(capability);
      expect(operationOrder).toEqual(['read', 'zeroize', 'revoke']);
    },
  );
  it.each([
    [
      'duplicate project',
      [
        { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
        { projectId: 'alpha', path: '/private/alpha-copy.env', device: '505', inode: '606' },
      ],
    ],
    [
      'duplicate path',
      [
        { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
        { projectId: 'beta', path: '/private/alpha.env', device: '505', inode: '606' },
      ],
    ],
    [
      'duplicate device and inode',
      [
        { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
        { projectId: 'beta', path: '/private/beta.env', device: '303', inode: '404' },
      ],
    ],
    [
      'extra authority',
      [
        { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
        { projectId: 'beta', path: '/private/beta.env', device: '505', inode: '606' },
        { projectId: 'gamma', path: '/private/gamma.env', device: '707', inode: '808' },
      ],
    ],
  ])(
    'rejects credential authority arrays with %s before native work',
    async (_, credentialAuthorities) => {
      await expect(
        startStaticRuntime({
          descriptor: { ...descriptorWithAuthorities(0), credentialAuthorities },
          configuredProjects: trustedConfiguredProjects(),
          projectRoot: '/private/static-security-fixture',
        }),
      ).rejects.toThrow();
      expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
      expect(native.secureReadCredential).not.toHaveBeenCalled();
      expect(native.secureReadBeneath).not.toHaveBeenCalled();
      expect(native.zeroizeBuffer).not.toHaveBeenCalled();
      expect(native.revokeCredentialReadCapability).not.toHaveBeenCalled();
    },
  );
  it('rejects authority-set failure before credential and template reads', async () => {
    native.verifyCredentialAuthoritySet.mockImplementation(() => {
      throw nativeReadDenied();
    });

    await expect(
      startStaticRuntime({
        descriptor: descriptorWithAuthorities(0),
        configuredProjects: trustedConfiguredProjects(),
        projectRoot: '/private/static-security-fixture',
      }),
    ).rejects.toMatchObject({ code: 'SCG_NATIVE_PATH_DENIED' });
    expect(native.secureReadCredential).not.toHaveBeenCalled();
    expect(native.secureReadBeneath).not.toHaveBeenCalled();
  });
  it('revokes an acquired credential capability exactly once after a read-limit failure', async () => {
    const capability = credentialCapability();
    const operationOrder: string[] = [];
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockImplementation(() => {
      operationOrder.push('read');
      throw Object.assign(new Error('credential limit exceeded'), {
        code: 'SCG_NATIVE_READ_LIMIT' as const,
      });
    });
    native.revokeCredentialReadCapability.mockImplementation(() => {
      operationOrder.push('revoke');
    });

    await expect(
      startStaticRuntime({
        descriptor: descriptorWithAuthorities(0),
        configuredProjects: trustedConfiguredProjects(),
        projectRoot: '/private/static-security-fixture',
      }),
    ).rejects.toMatchObject({ code: 'SCG_NATIVE_READ_LIMIT' });
    expect(native.secureReadBeneath).not.toHaveBeenCalled();
    expect(native.zeroizeBuffer).not.toHaveBeenCalled();
    expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(1);
    expect(native.revokeCredentialReadCapability).toHaveBeenCalledWith(capability);
    expect(operationOrder).toEqual(['read', 'revoke']);
  });
  it('retains an acquired credential capability after two failed revocations until retained cleanup succeeds', async () => {
    const capability = credentialCapability();
    let revocationAttempts = 0;
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(
      Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
    );
    native.revokeCredentialReadCapability.mockImplementation(() => {
      revocationAttempts += 1;
      if (revocationAttempts <= 2) {
        throw new Error('native credential revocation failed');
      }
    });

    try {
      await expect(
        startStaticRuntime({
          descriptor: descriptorWithAuthorities(0),
          configuredProjects: trustedConfiguredProjects(),
          projectRoot: '/private/static-security-fixture',
        }),
      ).rejects.toThrow('static runtime failed and cleanup also failed');

      expect(native.secureReadBeneath).not.toHaveBeenCalled();
      expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(2);
      expect(native.revokeCredentialReadCapability).toHaveBeenNthCalledWith(1, capability);
      expect(native.revokeCredentialReadCapability).toHaveBeenNthCalledWith(2, capability);

      await waitForCallCount(() => native.revokeCredentialReadCapability.mock.calls.length, 3);
      expect(native.revokeCredentialReadCapability).toHaveBeenNthCalledWith(3, capability);
      expect(warning).not.toHaveBeenCalled();
    } finally {
      warning.mockRestore();
    }
  });
  it('quarantines permanent retained cleanup failures after a bounded retry count with redacted diagnostics', async () => {
    const capability = credentialCapability();
    const canary = 'credential-cleanup-canary';
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(
      Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
    );
    native.revokeCredentialReadCapability.mockImplementation(() => {
      throw new Error(canary);
    });

    try {
      await expect(
        startStaticRuntime({
          descriptor: descriptorWithAuthorities(0),
          configuredProjects: trustedConfiguredProjects(),
          projectRoot: '/private/static-security-fixture',
        }),
      ).rejects.toThrow('static runtime failed and cleanup also failed');

      await waitForCallCount(() => native.revokeCredentialReadCapability.mock.calls.length, 4);
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 150);
      });

      expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(4);
      expect(warning.mock.calls).toEqual([
        [
          'Static runtime credential capability cleanup failed.',
          {
            code: 'SCG_STATIC_RUNTIME_CREDENTIAL_CLEANUP_FAILED',
            type: 'SceneGlassStaticRuntimeCleanupError',
            detail: 'operation=revokeCredentialReadCapability attempt=2',
          },
        ],
      ]);
      expectWarningArgumentsRedacted(warning.mock.calls, [canary]);
    } finally {
      warning.mockRestore();
    }
  });
  it('retries a late aborted credential revocation under its retained cleanup owner', async () => {
    const capability = credentialCapability();
    let resolveVerified!: (value: unknown) => void;
    let revocationAttempts = 0;
    credentialAuthority.override = () =>
      new Promise<unknown>((resolve) => {
        resolveVerified = resolve;
      });
    native.revokeCredentialReadCapability.mockImplementation(() => {
      revocationAttempts += 1;
      if (revocationAttempts === 1) {
        throw new Error('late native credential revocation failed');
      }
    });
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const controller = new AbortController();

    try {
      const startup = startStaticRuntime({
        descriptor: descriptorWithAuthorities(0),
        configuredProjects: trustedConfiguredProjects(),
        projectRoot: '/private/static-security-fixture',
        signal: controller.signal,
      });
      controller.abort();
      await expect(startup).rejects.toMatchObject({ name: 'AbortError' });

      resolveVerified(Object.freeze({ capability }));
      await waitForCallCount(() => native.revokeCredentialReadCapability.mock.calls.length, 2);

      expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(2);
      expect(native.revokeCredentialReadCapability).toHaveBeenNthCalledWith(1, capability);
      expect(native.revokeCredentialReadCapability).toHaveBeenNthCalledWith(2, capability);
      expect(warning).not.toHaveBeenCalled();
    } finally {
      warning.mockRestore();
    }
  });
  it('retries saturated late credential cleanup before allowing it to leave recovery', async () => {
    vi.resetModules();
    const { startStaticRuntime: startIsolatedStaticRuntime } =
      await import('../../packages/onboarding/src/static/runtime.js');
    const retainedOwnerCapacity = 32;
    const fillerCapabilities = Array.from({ length: retainedOwnerCapacity }, credentialCapability);
    const lateCapability = credentialCapability();
    const resolveVerified: Array<(value: unknown) => void> = [];
    const revocationAttempts = new Map<object, number>();
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    credentialAuthority.override = () =>
      new Promise<unknown>((resolve) => {
        resolveVerified.push(resolve);
      });
    native.revokeCredentialReadCapability.mockImplementation((capability: unknown) => {
      if (typeof capability !== 'object' || capability === null) {
        throw new Error('unexpected credential capability');
      }
      const attempts = (revocationAttempts.get(capability) ?? 0) + 1;
      revocationAttempts.set(capability, attempts);
      if (attempts === 1) {
        throw new Error('native credential revocation failed');
      }
    });

    try {
      const fillerStartups = fillerCapabilities.map(() => {
        const controller = new AbortController();
        const startup = startIsolatedStaticRuntime({
          descriptor: descriptorWithAuthorities(0),
          configuredProjects: trustedConfiguredProjects(),
          projectRoot: '/private/static-security-fixture',
          signal: controller.signal,
        });
        controller.abort();
        return startup;
      });
      await Promise.all(
        fillerStartups.map((startup) =>
          expect(startup).rejects.toMatchObject({ name: 'AbortError' }),
        ),
      );
      expect(resolveVerified).toHaveLength(retainedOwnerCapacity);

      for (const [index, capability] of fillerCapabilities.entries()) {
        resolveVerified[index]!(Object.freeze({ capability }));
      }
      await waitForCallCount(
        () => native.revokeCredentialReadCapability.mock.calls.length,
        retainedOwnerCapacity,
      );

      const controller = new AbortController();
      const lateStartup = startIsolatedStaticRuntime({
        descriptor: descriptorWithAuthorities(0),
        configuredProjects: trustedConfiguredProjects(),
        projectRoot: '/private/static-security-fixture',
        signal: controller.signal,
      });
      controller.abort();
      await expect(lateStartup).rejects.toMatchObject({ name: 'AbortError' });
      expect(resolveVerified).toHaveLength(retainedOwnerCapacity + 1);

      resolveVerified[retainedOwnerCapacity]!(Object.freeze({ capability: lateCapability }));
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();

      expect(revocationAttempts.get(lateCapability)).toBe(2);
      for (const capability of fillerCapabilities) {
        expect(revocationAttempts.get(capability)).toBe(1);
      }

      await waitForCallCount(
        () => native.revokeCredentialReadCapability.mock.calls.length,
        (retainedOwnerCapacity + 1) * 2,
      );
      for (const capability of [...fillerCapabilities, lateCapability]) {
        expect(revocationAttempts.get(capability)).toBe(2);
      }
      expect(warning).not.toHaveBeenCalled();
    } finally {
      warning.mockRestore();
    }
  });
  it('denies every selected and unselected credential identity for GET and HEAD', async () => {
    const descriptor = descriptorWithAuthorities(0);
    const configuredProjects = trustedConfiguredProjects();
    const deniedIdentities = configuredProjects.projects.map(({ credentialAuthority }) => ({
      device: credentialAuthority.device,
      inode: credentialAuthority.inode,
    }));
    const credentialRoutes = new Set(
      configuredProjects.projects.map(({ projectId }) => `${projectId}-credential.css`),
    );
    native.verifyCredentialAuthoritySet.mockReturnValue(credentialCapability());
    native.secureReadCredential.mockReturnValue(
      Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
    );
    native.secureReadBeneath.mockImplementation(
      (input: {
        readonly relativePath: string;
        readonly deniedIdentities: readonly { readonly device: string; readonly inode: string }[];
      }) => {
        if (input.relativePath === 'index.html') {
          return { bytes: Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8') };
        }
        expect(input.deniedIdentities).toEqual(deniedIdentities);
        if (credentialRoutes.has(input.relativePath)) {
          throw nativeReadDenied();
        }
        if (input.relativePath === 'safe.css') {
          return { bytes: Buffer.from('body{}', 'utf8') };
        }
        throw new Error('unexpected static asset route');
      },
    );

    const runtime = await startStaticRuntime({
      descriptor,
      configuredProjects,
      projectRoot: '/private/static-security-fixture',
    });
    runtimes.add(runtime);

    for (const { projectId } of configuredProjects.projects) {
      for (const method of ['GET', 'HEAD'] as const) {
        const response = await fetch(urlFor(runtime, `/${projectId}-credential.css`), {
          method,
        });
        expect(response.status).toBe(404);
        await expectNotFound(response);
      }
    }
    const safe = await fetch(urlFor(runtime, '/safe.css'));
    expect(safe.status).toBe(200);
    expect(await safe.text()).toBe('body{}');

    expect(
      native.secureReadBeneath.mock.calls.slice(1).map(([input]) => input.relativePath),
    ).toEqual([
      'alpha-credential.css',
      'alpha-credential.css',
      'beta-credential.css',
      'beta-credential.css',
      'safe.css',
    ]);
  });
  it('uses the production native boundary to serve safe root and nested assets before denying credentials, links, and root replacements', async () => {
    vi.doUnmock('../../packages/onboarding/src/native.js');
    vi.doUnmock('../../packages/onboarding/src/credential-authority.js');
    vi.resetModules();
    const { startStaticRuntime: startProductionStaticRuntime } =
      await import('../../packages/onboarding/src/static/runtime.js');
    const fixture = await createNativeStaticFixture();
    const root = fixture.root;
    let runtime: StaticRuntime | undefined;
    try {
      const publicRoot = join(root, 'public');
      const credentialRoot = join(root, 'credentials');
      const outsideRoot = join(root, 'outside');
      await Promise.all([
        mkdir(publicRoot, { mode: 0o700 }),
        mkdir(credentialRoot, { mode: 0o700 }),
        mkdir(outsideRoot, { mode: 0o700 }),
      ]);

      const nestedDirectory = join(publicRoot, 'nested');
      const peerRoot = join(publicRoot, 'peer-root');
      await Promise.all([
        mkdir(nestedDirectory, { mode: 0o700 }),
        mkdir(peerRoot, { mode: 0o700 }),
      ]);
      const template = join(publicRoot, 'index.html');
      const safeAsset = join(publicRoot, 'safe.css');
      const nestedAsset = join(nestedDirectory, 'safe.css');
      const alphaCredential = join(credentialRoot, 'alpha.env');
      const betaCredential = join(peerRoot, '.beta.env');
      const outsideAsset = join(outsideRoot, 'outside.css');
      const rootSafeCss = 'body{}';
      const nestedSafeCss = '.nested{}';
      await Promise.all([
        writeSecureFile(template, `<head>\n${MARKER}\n</head>`),
        writeSecureFile(safeAsset, rootSafeCss),
        writeSecureFile(nestedAsset, nestedSafeCss),
        writeSecureFile(alphaCredential, credentialEnvelope('alpha', TOKEN)),
        writeSecureFile(betaCredential, credentialEnvelope('beta', TOKEN)),
        writeSecureFile(outsideAsset, 'outside'),
      ]);

      const alphaAuthority = {
        projectId: 'alpha',
        path: alphaCredential,
        ...(await fileIdentity(alphaCredential)),
      };
      const betaAuthority = {
        projectId: 'beta',
        path: betaCredential,
        ...(await fileIdentity(betaCredential)),
      };
      const descriptor = {
        ...descriptorWithAuthorities(0),
        approvedRootIdentity: await fileIdentity(publicRoot),
        credentialAuthorities: [alphaAuthority],
      };
      const startedRuntime = await startProductionStaticRuntime({
        descriptor,
        configuredProjects: trustedConfiguredProjects(
          root,
          [alphaAuthority, betaAuthority],
          descriptor.approvedRootIdentity,
        ),
        projectRoot: root,
      });
      runtime = startedRuntime;
      const expectDeniedForGetAndHead = async (path: string): Promise<void> => {
        for (const method of ['GET', 'HEAD'] as const) {
          const response = await fetch(urlFor(startedRuntime, path), { method });
          expect(response.status).toBe(404);
          await expectNotFound(response);
        }
      };
      const expectServedForGetAndHead = async (
        path: string,
        expectedBody: string,
      ): Promise<void> => {
        const expectedContentLength = String(Buffer.byteLength(expectedBody, 'utf8'));
        const get = await fetch(urlFor(startedRuntime, path));
        expect(get.status).toBe(200);
        expect(get.headers.get('content-type')).toBe('text/css; charset=utf-8');
        expect(get.headers.get('content-length')).toBe(expectedContentLength);
        expect(get.headers.get('cache-control')).toBe(CACHE_CONTROL);
        expect(get.headers.get('pragma')).toBe('no-cache');
        expect(get.headers.get('allow')).toBeNull();
        expect(await get.text()).toBe(expectedBody);

        const head = await fetch(urlFor(startedRuntime, path), { method: 'HEAD' });
        expect(head.status).toBe(200);
        expect(head.headers.get('content-type')).toBe('text/css; charset=utf-8');
        expect(head.headers.get('content-length')).toBe(expectedContentLength);
        expect(head.headers.get('cache-control')).toBe(CACHE_CONTROL);
        expect(head.headers.get('pragma')).toBe('no-cache');
        expect(head.headers.get('allow')).toBeNull();
        expect(await head.text()).toBe('');
      };
      await expectServedForGetAndHead('/safe.css', rootSafeCss);
      await expectServedForGetAndHead('/nested/safe.css', nestedSafeCss);
      await symlink(outsideAsset, join(publicRoot, 'leaf-link.css'));
      await symlink(outsideRoot, join(publicRoot, 'intermediate-link'));

      await Promise.all([
        link(alphaCredential, join(publicRoot, 'selected-credential-hardlink.css')),
        link(betaCredential, join(publicRoot, 'unselected-credential-hardlink.css')),
      ]);
      for (const path of [
        '/leaf-link.css',
        '/intermediate-link/outside.css',
        '/selected-credential-hardlink.css',
        '/unselected-credential-hardlink.css',
        '/peer-root/.beta.env',
      ]) {
        await expectDeniedForGetAndHead(path);
      }

      await rename(safeAsset, join(publicRoot, 'safe.original.css'));
      await symlink(outsideAsset, safeAsset);
      await expectDeniedForGetAndHead('/safe.css');

      await rename(nestedDirectory, join(publicRoot, 'nested.original'));
      await symlink(outsideRoot, nestedDirectory);
      await expectDeniedForGetAndHead('/nested/outside.css');

      await rename(publicRoot, join(root, 'public.replaced'));
      await mkdir(publicRoot, { mode: 0o700 });
      await writeSecureFile(join(publicRoot, 'safe.css'), 'replacement');
      expect(await fileIdentity(publicRoot)).not.toEqual(descriptor.approvedRootIdentity);
      await expectDeniedForGetAndHead('/safe.css');

      await rename(publicRoot, join(root, 'public.replaced-by-symlink'));
      await symlink(outsideRoot, publicRoot);
      await expectDeniedForGetAndHead('/safe.css');
    } finally {
      try {
        await runtime?.stop();
      } finally {
        await fixture.cleanup();
      }
    }
  });
});

async function startFixture(
  files: Map<string, Buffer>,
  beforeRead?: (relativePath: string) => void,
  keep = true,
): Promise<StaticRuntime> {
  native.verifyCredentialAuthoritySet.mockReturnValue(credentialCapability());
  native.secureReadCredential.mockReturnValue(
    Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii'),
  );
  native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
    beforeRead?.(input.relativePath);
    const file = files.get(input.relativePath);
    if (file === undefined) {
      throw nativeReadDenied();
    }
    return { bytes: Buffer.from(file) };
  });

  const runtime = await startStaticRuntime({
    descriptor: descriptorWithAuthorities(0),
    configuredProjects: trustedConfiguredProjects(),
    projectRoot: '/private/static-security-fixture',
  });
  if (keep) {
    runtimes.add(runtime);
  }
  return runtime;
}

function fixtureFiles(template?: Buffer): Map<string, Buffer> {
  return new Map([['index.html', template ?? Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8')]]);
}

function descriptorWithAuthorities(port: number) {
  return {
    schemaVersion: 1,
    template: 'public/index.html',
    publicRoot: 'public',
    host: '127.0.0.1',
    port,
    projectId: 'alpha',
    loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
    credentialProjectId: 'alpha',
    credentialKey: 'SCENE_GLASS_HOST_TOKEN',
    navigation: 'document',
    readinessPath: '/__scene-glass/ready',
    approvedRootIdentity: { device: '101', inode: '202' },
    credentialAuthorities: [
      { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
    ],
  } as const;
}
type CredentialAuthorityFixture = {
  readonly projectId: string;
  readonly path: string;
  readonly device: string;
  readonly inode: string;
};

function trustedConfiguredProjects(
  projectRoot = '/private/static-security-fixture',
  authorities: readonly CredentialAuthorityFixture[] = trustedCredentialAuthorities(),
  publicRootIdentity: {
    readonly device: string;
    readonly inode: string;
  } = descriptorWithAuthorities(0).approvedRootIdentity,
) {
  return {
    projects: authorities.map((authority) => ({
      projectId: authority.projectId,
      canonicalRoot:
        authority.projectId === 'alpha' ? projectRoot : join(projectRoot, 'public', 'peer-root'),
      publicRootIdentity:
        authority.projectId === 'alpha'
          ? { ...publicRootIdentity }
          : { device: '102', inode: '203' },
      tokenEnv:
        authority.projectId === 'alpha' ? 'SCENE_GLASS_HOST_TOKEN' : 'SCENE_GLASS_HOST_TOKEN_BETA',
      credentialAuthority: {
        projectId: authority.projectId,
        path: authority.path,
        device: authority.device,
        inode: authority.inode,
      },
    })),
  };
}
function trustedCredentialAuthorities(): readonly CredentialAuthorityFixture[] {
  return [
    { projectId: 'alpha', path: '/private/alpha.env', device: '303', inode: '404' },
    { projectId: 'beta', path: '/private/beta.env', device: '505', inode: '606' },
  ];
}

async function createNativeStaticFixture(): Promise<{
  readonly root: string;
  cleanup(): Promise<void>;
}> {
  const root = await mkdtemp(join(nativeHomeHierarchy(), '.scene-glass-static-serving-'));
  try {
    await chmod(root, 0o700);
  } catch (error: unknown) {
    await rm(root, { force: true, recursive: true });
    throw error;
  }
  return Object.freeze({
    root,
    cleanup: () => rm(root, { force: true, recursive: true }),
  });
}
async function expectNotFound(response: Response): Promise<void> {
  expect(response.headers.get('content-length')).toBe('0');
  expect(response.headers.get('content-type')).toBeNull();
  expect(response.headers.get('allow')).toBeNull();
  expect(response.headers.get('cache-control')).toBe(CACHE_CONTROL);
  expect(response.headers.get('pragma')).toBe('no-cache');
  expect(await response.text()).toBe('');
}
async function expectInternalServerError(response: Response): Promise<void> {
  expect(response.headers.get('content-length')).toBe('0');
  expect(response.headers.get('content-type')).toBeNull();
  expect(response.headers.get('allow')).toBeNull();
  expect(response.headers.get('cache-control')).toBe(CACHE_CONTROL);
  expect(response.headers.get('pragma')).toBe('no-cache');
  expect(await response.text()).toBe('');
}
async function writeSecureFile(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function fileIdentity(
  path: string,
): Promise<{ readonly device: string; readonly inode: string }> {
  const information = await stat(path, { bigint: true });
  return { device: information.dev.toString(), inode: information.ino.toString() };
}

type ExpectedNativeReadDenialCode =
  'SCG_NATIVE_PATH_DENIED' | 'SCG_NATIVE_IDENTITY_MISMATCH' | 'SCG_NATIVE_READ_LIMIT';

function nativeReadDenied(): Error & { readonly code: 'SCG_NATIVE_PATH_DENIED' } {
  return nativeReadFailure('SCG_NATIVE_PATH_DENIED');
}

function nativeReadFailure<T extends ExpectedNativeReadDenialCode>(
  code: T,
): Error & { readonly code: T } {
  return Object.assign(new Error('secure native denial'), { code });
}

function canonicalNotFoundResponse(): string {
  return [
    'HTTP/1.1 404 Not Found',
    `Cache-Control: ${CACHE_CONTROL}`,
    'Content-Length: 0',
    'Pragma: no-cache',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
}

function canonicalMethodNotAllowedResponse(): string {
  return [
    'HTTP/1.1 405 Method Not Allowed',
    `Cache-Control: ${CACHE_CONTROL}`,
    'Content-Length: 0',
    'Pragma: no-cache',
    'Allow: GET, HEAD',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
}
async function rawRequest(runtime: StaticRuntime, request: string): Promise<string> {
  if (Buffer.byteLength(request, 'ascii') > MAX_RAW_SOCKET_REQUEST_BYTES) {
    throw new Error('raw socket request exceeds its byte budget');
  }
  const socket = createConnection({ host: runtime.host, port: runtime.port });
  const chunks: Buffer[] = [];
  let responseBytes = 0;
  socket.on('error', () => undefined);
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      socket.off('connect', onConnect);
      socket.off('data', onData);
      socket.off('end', complete);
      socket.off('close', onClose);
      socket.off('error', fail);
      clearTimeout(timer);
    };
    const complete = (): void => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve();
      }
    };
    const fail = (error: Error): void => {
      if (!settled) {
        settled = true;
        cleanup();
        socket.destroy();
        reject(error);
      }
    };
    const onConnect = (): void => {
      try {
        socket.end(request, 'ascii');
      } catch {
        fail(new Error('raw socket request write failed'));
      }
    };
    const onData = (chunk: Buffer): void => {
      responseBytes += chunk.byteLength;
      if (responseBytes > MAX_RAW_SOCKET_RESPONSE_BYTES) {
        fail(new Error('raw socket response exceeds its byte budget'));
        return;
      }
      chunks.push(chunk);
    };
    const onClose = (): void => {
      fail(new Error('raw socket closed before its response completed'));
    };

    const timer = setTimeout(() => {
      fail(new Error('raw socket request timed out'));
    }, RAW_SOCKET_TIMEOUT_MS);
    socket.once('connect', onConnect);
    socket.on('data', onData);
    socket.once('end', complete);
    socket.once('close', onClose);
    socket.once('error', fail);
  });
  return Buffer.concat(chunks).toString('latin1');
}

async function openRawRequest(runtime: StaticRuntime, request: string): Promise<Socket> {
  if (Buffer.byteLength(request, 'ascii') > MAX_RAW_SOCKET_REQUEST_BYTES) {
    throw new Error('raw socket request exceeds its byte budget');
  }
  const socket = createConnection({ host: runtime.host, port: runtime.port });
  socket.on('error', () => undefined);
  await new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      socket.off('connect', onConnect);
      socket.off('error', fail);
      clearTimeout(timer);
    };
    const fail = (error: Error): void => {
      cleanup();
      socket.destroy();
      reject(error);
    };
    const onConnect = (): void => {
      try {
        socket.write(request, 'ascii');
        cleanup();
        resolve();
      } catch {
        fail(new Error('raw socket request write failed'));
      }
    };

    const timer = setTimeout(() => {
      fail(new Error('raw socket connection timed out'));
    }, RAW_SOCKET_TIMEOUT_MS);
    socket.once('connect', onConnect);
    socket.once('error', fail);
  });
  return socket;
}
async function waitForSocketClose(socket: Socket): Promise<void> {
  if (socket.destroyed) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      socket.off('close', complete);
      socket.off('error', complete);
      clearTimeout(timer);
    };
    const complete = (): void => {
      cleanup();
      resolve();
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('pre-handler socket was not closed at the connection limit'));
    }, RAW_SOCKET_TIMEOUT_MS);
    socket.once('close', complete);
    socket.once('error', complete);
  });
}

async function waitForCallCount(callCount: () => number, expected: number): Promise<void> {
  const deadline = Date.now() + RAW_SOCKET_TIMEOUT_MS;
  while (callCount() < expected) {
    if (Date.now() >= deadline) {
      throw new Error('static handler budget test did not reach the expected concurrency');
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 5);
    });
  }
}
function expectNoNativeStartupCalls(): void {
  expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
  expect(native.secureReadCredential).not.toHaveBeenCalled();
  expect(native.secureReadBeneath).not.toHaveBeenCalled();
  expect(native.zeroizeBuffer).not.toHaveBeenCalled();
  expect(native.revokeCredentialReadCapability).not.toHaveBeenCalled();
}

function urlFor(runtime: StaticRuntime, path: string): string {
  return `http://${runtime.host}:${runtime.port}${path}`;
}

function credentialCapability(): object {
  return Object.freeze(Object.create(null));
}

function expectWarningArgumentsRedacted(
  calls: readonly (readonly unknown[])[],
  canaries: readonly string[],
): void {
  for (const arguments_ of calls) {
    for (const argument of arguments_) {
      expectValueRedacted(argument, canaries, new Set<object>());
    }
  }
}

function expectValueRedacted(value: unknown, canaries: readonly string[], seen: Set<object>): void {
  if (typeof value === 'string') {
    for (const canary of canaries) {
      expect(value).not.toContain(canary);
    }
    return;
  }
  if (typeof value !== 'object' || value === null || seen.has(value)) {
    return;
  }
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && 'value' in descriptor) {
      expectValueRedacted(descriptor.value, canaries, seen);
    }
  }
}

function nativeHomeHierarchy(): string {
  const home = homedir();
  if (process.platform === 'darwin' && home.startsWith('/Users/')) {
    return home;
  }
  if (process.platform === 'linux' && home.startsWith('/home/')) {
    return home;
  }
  throw new Error(
    'production native static-serving coverage requires a macOS or Linux user home directory',
  );
}
