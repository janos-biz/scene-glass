import { Buffer } from 'node:buffer';
import { createServer, Server, ServerResponse } from 'node:http';
import { createConnection } from 'node:net';
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

import {
  startStaticRuntime,
  type StaticRuntime,
} from '../../packages/onboarding/src/static/runtime.js';

const TOKEN = Buffer.alloc(32, 7).toString('base64url');
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;
const MARKER = '<!-- scene-glass:static-loader:v1 -->';
const CACHE_CONTROL = 'no-store, private, max-age=0';
const RAW_SOCKET_TIMEOUT_MS = 2_000;
const MAX_RAW_SOCKET_REQUEST_BYTES = 8 * 1024;
const MAX_RAW_SOCKET_RESPONSE_BYTES = 64 * 1024;
type RawHttpResponse = {
  readonly statusLine: string;
  readonly headers: ReadonlyMap<string, string>;
  readonly bytesAfterHeaderTerminator: Buffer;
};
const runtimes = new Set<StaticRuntime>();
const FIXTURE_PROJECT_ROOT = '/private/static-runtime-fixture';
const FIXTURE_TRUSTED_PROJECTS = Object.freeze({
  projects: Object.freeze([
    Object.freeze({
      projectId: 'alpha',
      canonicalRoot: FIXTURE_PROJECT_ROOT,
      publicRootIdentity: Object.freeze({ device: '101', inode: '202' }),
      tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      credentialAuthority: Object.freeze({
        projectId: 'alpha',
        path: '/private/alpha.env',
        device: '303',
        inode: '404',
      }),
    }),
  ]),
});

afterEach(async () => {
  await Promise.all([...runtimes].map((runtime) => runtime.stop()));
  runtimes.clear();
  vi.clearAllMocks();
});

describe('canonical static runtime', () => {
  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
  ])(
    'renders one canonical loader line from a %s template and preserves GET/HEAD bytes',
    async (_, newline) => {
      const files = new Map<string, Buffer>([
        [
          'index.html',
          Buffer.from(
            `<html><head>${newline}${MARKER}${newline}</HEAD><body>static</body></html>${newline}`,
            'utf8',
          ),
        ],
      ]);
      const runtime = await startFixture(files);

      const expected = [
        `<html><head>${newline}`,
        `<script async src="http://127.0.0.1:4175/scene-glass-loader.js" data-scg-project="alpha" data-scg-token="${TOKEN}" data-scg-navigation="document"></script>${newline}`,
        `</HEAD><body>static</body></html>${newline}`,
      ].join('');
      const get = await fetch(urlFor(runtime, '/'));
      expect(get.status).toBe(200);
      expect(await get.text()).toBe(expected);
      expect(get.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(get.headers.get('content-length')).toBe(String(Buffer.byteLength(expected)));
      expect(get.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(get.headers.get('pragma')).toBe('no-cache');
      expect(get.headers.get('allow')).toBeNull();

      const head = await fetch(urlFor(runtime, '/index.html'), { method: 'HEAD' });
      expect(head.status).toBe(200);
      expect(head.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(head.headers.get('content-length')).toBe(String(Buffer.byteLength(expected)));
      expect(head.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(head.headers.get('pragma')).toBe('no-cache');
      expect(head.headers.get('allow')).toBeNull();
      expect(await head.text()).toBe('');

      expect(files.get('index.html')!.toString('utf8')).toContain(MARKER);
      expect(files.get('index.html')!.toString('utf8')).not.toContain(TOKEN);
    },
  );

  it('preserves closing-head indentation while replacing the standalone loader marker', async () => {
    const files = fixtureFiles(Buffer.from(`<head>\n${MARKER}\n  </head>`, 'utf8'));
    const runtime = await startFixture(files);
    const response = await fetch(urlFor(runtime, '/'));

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe(
      `<head>\n<script async src="http://127.0.0.1:4175/scene-glass-loader.js" data-scg-project="alpha" data-scg-token="${TOKEN}" data-scg-navigation="document"></script>\n  </head>`,
    );
    expect(files.get('index.html')?.toString('utf8')).toBe(`<head>\n${MARKER}\n  </head>`);
  });

  it('serves readiness and every admitted asset MIME with GET/HEAD parity', async () => {
    const mimeCases = [
      ['asset.css', 'text/css; charset=utf-8'],
      ['asset.js', 'text/javascript; charset=utf-8'],
      ['asset.mjs', 'text/javascript; charset=utf-8'],
      ['asset.json', 'application/json; charset=utf-8'],
      ['asset.svg', 'image/svg+xml'],
      ['asset.png', 'image/png'],
      ['asset.jpg', 'image/jpeg'],
      ['asset.jpeg', 'image/jpeg'],
      ['asset.gif', 'image/gif'],
      ['asset.webp', 'image/webp'],
      ['asset.ico', 'image/x-icon'],
      ['asset.woff', 'font/woff'],
      ['asset.woff2', 'font/woff2'],
      ['asset.txt', 'text/plain; charset=utf-8'],
      ['asset.unknown', 'application/octet-stream'],
    ] as const;
    const files = fixtureFiles();
    for (const [path] of mimeCases) {
      files.set(path, Buffer.from(`bytes:${path}`, 'utf8'));
    }
    const runtime = await startFixture(files);

    const ready = await fetch(urlFor(runtime, '/__scene-glass/ready'));
    const readyBody = '{"ready":true,"projectId":"alpha"}\n';
    expect(ready.status).toBe(200);
    expect(await ready.text()).toBe(readyBody);
    expect(ready.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(ready.headers.get('content-length')).toBe(String(Buffer.byteLength(readyBody)));
    expect(ready.headers.get('cache-control')).toBe(CACHE_CONTROL);
    expect(ready.headers.get('pragma')).toBe('no-cache');
    expect(ready.headers.get('allow')).toBeNull();

    const readyHead = await fetch(urlFor(runtime, '/__scene-glass/ready'), { method: 'HEAD' });
    expect(readyHead.status).toBe(200);
    expect(readyHead.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(readyHead.headers.get('content-length')).toBe(String(Buffer.byteLength(readyBody)));
    expect(readyHead.headers.get('cache-control')).toBe(CACHE_CONTROL);
    expect(readyHead.headers.get('pragma')).toBe('no-cache');
    expect(readyHead.headers.get('allow')).toBeNull();
    expect(await readyHead.text()).toBe('');

    for (const [path, contentType] of mimeCases) {
      const expected = files.get(path)!;
      const get = await fetch(urlFor(runtime, `/${path}`));
      expect(get.status).toBe(200);
      expect(Buffer.from(await get.arrayBuffer())).toEqual(expected);
      expect(get.headers.get('content-type')).toBe(contentType);
      expect(get.headers.get('content-length')).toBe(String(expected.byteLength));
      expect(get.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(get.headers.get('pragma')).toBe('no-cache');
      expect(get.headers.get('allow')).toBeNull();

      const head = await fetch(urlFor(runtime, `/${path}`), { method: 'HEAD' });
      expect(head.status).toBe(200);
      expect(head.headers.get('content-type')).toBe(contentType);
      expect(head.headers.get('content-length')).toBe(String(expected.byteLength));
      expect(head.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(head.headers.get('pragma')).toBe('no-cache');
      expect(head.headers.get('allow')).toBeNull();
      expect(await head.text()).toBe('');
    }
  });
  it('emits no raw body bytes for successful HTML, readiness, and asset HEAD responses', async () => {
    const files = fixtureFiles();
    files.set('head-asset.css', Buffer.from('body { color: green; }\n', 'utf8'));
    const runtime = await startFixture(files);
    const cases = [
      { label: 'HTML', path: '/', contentType: 'text/html; charset=utf-8' },
      {
        label: 'readiness',
        path: '/__scene-glass/ready',
        contentType: 'application/json; charset=utf-8',
      },
      {
        label: 'asset',
        path: '/head-asset.css',
        contentType: 'text/css; charset=utf-8',
      },
    ];

    for (const testCase of cases) {
      const get = parseRawHttpResponse(
        await rawRequest(runtime, rawHttpRequest(runtime, 'GET', testCase.path)),
      );
      const head = parseRawHttpResponse(
        await rawRequest(runtime, rawHttpRequest(runtime, 'HEAD', testCase.path)),
      );

      expect(get.statusLine).toBe('HTTP/1.1 200 OK');
      expect(head.statusLine).toBe(get.statusLine);
      expect(get.headers.get('content-type')).toBe(testCase.contentType);
      expect(head.headers.get('content-type')).toBe(get.headers.get('content-type'));
      expect(get.headers.get('content-length')).toBe(
        String(get.bytesAfterHeaderTerminator.byteLength),
      );
      expect(head.headers.get('content-length')).toBe(get.headers.get('content-length'));
      expect(get.headers.get('cache-control')).toBe(CACHE_CONTROL);
      expect(head.headers.get('cache-control')).toBe(get.headers.get('cache-control'));
      expect(get.headers.get('pragma')).toBe('no-cache');
      expect(head.headers.get('pragma')).toBe(get.headers.get('pragma'));
      expect(get.bytesAfterHeaderTerminator.byteLength).toBeGreaterThan(0);
      expect(head.bytesAfterHeaderTerminator).toEqual(Buffer.alloc(0));
    }
  });
  it('warns, wipes a retained asset body, and drains when a response cannot be sent', async () => {
    const files = fixtureFiles();
    const retainedAsset = Buffer.from('retained native asset body', 'utf8');
    files.set('retained.css', retainedAsset);
    const runtime = await startFixture(files);
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      if (input.relativePath === 'retained.css') {
        return { bytes: retainedAsset };
      }
      const file = files.get(input.relativePath);
      if (file === undefined) {
        throw new Error('not found');
      }
      return { bytes: Buffer.from(file) };
    });
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const writeHead = vi.spyOn(ServerResponse.prototype, 'writeHead').mockImplementation(() => {
      throw new Error(`response send failed for ${TOKEN}`);
    });
    let stopped = false;
    try {
      expect(retainedAsset.byteLength).toBeGreaterThan(0);
      await expect(fetch(urlFor(runtime, '/retained.css'))).rejects.toThrow();
      await expect(runtime.stop()).resolves.toBeUndefined();
      stopped = true;
      runtimes.delete(runtime);
      expect(retainedAsset).toEqual(Buffer.alloc(retainedAsset.byteLength));
      expect(warning.mock.calls).toEqual([
        [
          'Unexpected static runtime request failure.',
          {
            code: 'SCG_STATIC_RUNTIME_UNEXPECTED',
            type: 'SceneGlassStaticRuntimeError',
          },
        ],
      ]);
    } finally {
      writeHead.mockRestore();
      warning.mockRestore();
      if (!stopped) {
        runtimes.delete(runtime);
        await runtime.stop();
      }
    }
  });

  it('rejects ambiguous templates before binding a listener', async () => {
    const files = fixtureFiles(Buffer.from(`<head>\n${MARKER}\n${MARKER}\n</head>`, 'utf8'));
    const listen = vi.spyOn(Server.prototype, 'listen');
    let started: StaticRuntime | undefined;
    try {
      await expect(
        startFixture(files, { keep: false }).then((runtime) => {
          started = runtime;
          return runtime;
        }),
      ).rejects.toThrow('static HTML loader marker is ambiguous');
      expect(listen).not.toHaveBeenCalled();
    } finally {
      try {
        await started?.stop();
      } finally {
        listen.mockRestore();
      }
    }
  });

  it('validates descriptor replacement and authority cardinality before reads or listen', async () => {
    const descriptor = fixtureDescriptor(0);
    const replacement = {
      ...descriptor,
      credentialProjectId: 'beta',
    };
    const listen = vi.spyOn(Server.prototype, 'listen');
    let started: StaticRuntime | undefined;

    try {
      await expect(
        startStaticRuntime({
          descriptor: replacement,
          configuredProjects: FIXTURE_TRUSTED_PROJECTS,
          projectRoot: FIXTURE_PROJECT_ROOT,
        }).then((runtime) => {
          started = runtime;
          return runtime;
        }),
      ).rejects.toThrow();
      expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
      expect(native.secureReadCredential).not.toHaveBeenCalled();
      expect(native.secureReadBeneath).not.toHaveBeenCalled();
      expect(listen).not.toHaveBeenCalled();
    } finally {
      try {
        await started?.stop();
      } finally {
        listen.mockRestore();
      }
    }
  });

  it('does not issue credentials or capabilities for a pre-aborted startup', async () => {
    const controller = new AbortController();
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const capability = credentialCapability();
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    controller.abort();

    await expect(
      startStaticRuntime({
        descriptor: fixtureDescriptor(0),
        configuredProjects: FIXTURE_TRUSTED_PROJECTS,
        projectRoot: FIXTURE_PROJECT_ROOT,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      name: 'AbortError',
    });

    expect(native.verifyCredentialAuthoritySet).not.toHaveBeenCalled();
    expect(native.secureReadCredential).not.toHaveBeenCalled();
    expect(native.secureReadBeneath).not.toHaveBeenCalled();
    expect(native.zeroizeBuffer).not.toHaveBeenCalled();
    expect(native.revokeCredentialReadCapability).not.toHaveBeenCalled();
    expect(credential.includes(TOKEN, 0, 'ascii')).toBe(true);
  });
  it('aborts an active listener after releasing its credential capability exactly once', async () => {
    const controller = new AbortController();
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const capability = credentialCapability();
    const files = fixtureFiles();
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      const file = files.get(input.relativePath);
      if (file === undefined) {
        throw new Error('not found');
      }
      return { bytes: Buffer.from(file) };
    });

    const runtime = await startStaticRuntime({
      descriptor: fixtureDescriptor(0),
      configuredProjects: FIXTURE_TRUSTED_PROJECTS,
      projectRoot: FIXTURE_PROJECT_ROOT,
      signal: controller.signal,
    });
    runtimes.add(runtime);
    controller.abort();
    await expect(waitForPortToClose(runtime.port)).resolves.toBeUndefined();
    await runtime.stop();
    await runtime.stop();

    expectCredentialCapabilityReleased(credential, capability);
  });
  it('rejects abort before a deferred template read settles and zeroizes its late buffer', async () => {
    const controller = new AbortController();
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const capability = credentialCapability();
    const template = Buffer.from(`<head>\n${MARKER}\n</head>`, 'utf8');
    const deferredTemplate = deferred<{ readonly bytes: Buffer }>();
    const templateReadStarted = deferred<void>();
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    native.secureReadBeneath.mockImplementation(() => {
      templateReadStarted.resolve();
      return deferredTemplate.promise;
    });

    const start = startStaticRuntime({
      descriptor: fixtureDescriptor(0),
      configuredProjects: FIXTURE_TRUSTED_PROJECTS,
      projectRoot: FIXTURE_PROJECT_ROOT,
      signal: controller.signal,
    });
    const startupRejected = deferred<void>();
    let startupResolved = false;
    void start.then(
      () => {
        startupResolved = true;
      },
      () => {
        startupRejected.resolve();
      },
    );
    await templateReadStarted.promise;
    expectCredentialCapabilityReleased(credential, capability);
    controller.abort();
    await startupRejected.promise;
    expect(startupResolved).toBe(false);
    expect(template.includes(MARKER, 0, 'utf8')).toBe(true);
    deferredTemplate.resolve({ bytes: template });
    await new Promise<void>((resolve) => setImmediate(resolve));
    await expect(start).rejects.toMatchObject({ name: 'AbortError' });
    expect(template.every((byte) => byte === 0)).toBe(true);
    expectCredentialCapabilityReleased(credential, capability);
  });
  it.each([
    ['stop then abort', true],
    ['abort then stop', false],
  ])('releases its credential capability exactly once when %s races', async (_, stopFirst) => {
    const controller = new AbortController();
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const capability = credentialCapability();
    const files = fixtureFiles();
    native.verifyCredentialAuthoritySet.mockReturnValue(capability);
    native.secureReadCredential.mockReturnValue(credential);
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      const file = files.get(input.relativePath);
      if (file === undefined) {
        throw new Error('not found');
      }
      return { bytes: Buffer.from(file) };
    });

    const runtime = await startStaticRuntime({
      descriptor: fixtureDescriptor(0),
      configuredProjects: FIXTURE_TRUSTED_PROJECTS,
      projectRoot: FIXTURE_PROJECT_ROOT,
      signal: controller.signal,
    });
    runtimes.add(runtime);

    const stopping = stopFirst ? runtime.stop() : undefined;
    controller.abort();
    await Promise.all([stopping ?? runtime.stop(), runtime.stop()]);
    await expect(waitForPortToClose(runtime.port)).resolves.toBeUndefined();

    expectCredentialCapabilityReleased(credential, capability);
  });

  it('waits for a disconnected handler to wipe late HTML before shutdown resolves', async () => {
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const initialTemplate = fixtureFiles().get('index.html')!;
    const lateTemplate = Buffer.from(initialTemplate);
    const read = deferred<{ readonly bytes: Buffer }>();
    const readStarted = deferred<void>();
    native.verifyCredentialAuthoritySet.mockReturnValue(Object.freeze(Object.create(null)));
    native.secureReadCredential.mockReturnValue(credential);
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      if (input.relativePath === 'index.html' && native.secureReadBeneath.mock.calls.length > 1) {
        readStarted.resolve();
        return read.promise;
      }
      return { bytes: Buffer.from(initialTemplate) };
    });

    const runtime = await startStaticRuntime({
      descriptor: fixtureDescriptor(0),
      configuredProjects: FIXTURE_TRUSTED_PROJECTS,
      projectRoot: FIXTURE_PROJECT_ROOT,
    });
    runtimes.add(runtime);

    const socket = createConnection({ host: runtime.host, port: runtime.port });
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    socket.end(
      `GET / HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}\r\nConnection: close\r\n\r\n`,
    );
    await readStarted.promise;
    socket.destroy();

    const stopping = runtime.stop();
    let stopped = false;
    void stopping.then(() => {
      stopped = true;
    });
    await Promise.resolve();
    expect(stopped).toBe(false);

    read.resolve({ bytes: lateTemplate });
    await stopping;
    expect(lateTemplate.every((byte) => byte === 0)).toBe(true);
    runtimes.delete(runtime);
  });
  it('force-closes a live socket and reports a deterministic handler timeout while a native read remains pending', async () => {
    const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
    const initialTemplate = fixtureFiles().get('index.html')!;
    const lateAsset = Buffer.from('late asset', 'utf8');
    const read = deferred<{ readonly bytes: Buffer }>();
    const readStarted = deferred<void>();
    let readResolved = false;
    native.verifyCredentialAuthoritySet.mockReturnValue(Object.freeze(Object.create(null)));
    native.secureReadCredential.mockReturnValue(credential);
    native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
      if (input.relativePath === 'late.css') {
        readStarted.resolve();
        return read.promise;
      }
      return { bytes: Buffer.from(initialTemplate) };
    });

    const runtime = await startStaticRuntime({
      descriptor: fixtureDescriptor(0),
      configuredProjects: FIXTURE_TRUSTED_PROJECTS,
      projectRoot: FIXTURE_PROJECT_ROOT,
    });
    runtimes.add(runtime);
    const socket = createConnection({ host: runtime.host, port: runtime.port });
    let stopSettled = false;
    let stopped = false;
    let forceClosed = false;
    let socketCloseHadError: boolean | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });
      socket.write(`GET /late.css HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}\r\n\r\n`);
      await readStarted.promise;

      const socketClosed = new Promise<void>((resolve, reject) => {
        socket.once('close', (hadError) => {
          forceClosed = true;
          socketCloseHadError = hadError;
          resolve();
        });
        socket.once('error', reject);
      });
      vi.useFakeTimers();
      const stopping = runtime.stop();
      void stopping.then(
        () => {
          stopSettled = true;
        },
        () => {
          stopSettled = true;
        },
      );

      await Promise.resolve();
      expect(forceClosed).toBe(false);
      expect(stopSettled).toBe(false);
      await vi.advanceTimersByTimeAsync(2_000);
      await socketClosed;
      expect(forceClosed).toBe(true);
      expect(socketCloseHadError).toBe(false);
      expect(readResolved).toBe(false);
      expect(stopSettled).toBe(false);

      await vi.advanceTimersByTimeAsync(4_000);
      await expect(stopping).rejects.toStrictEqual(
        new Error('static runtime request handlers did not settle during shutdown'),
      );
      stopped = true;
    } finally {
      if (!readResolved) {
        readResolved = true;
        read.resolve({ bytes: lateAsset });
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      }
      expect(lateAsset.every((byte) => byte === 0)).toBe(true);
      socket.destroy();
      vi.useRealTimers();
      runtimes.delete(runtime);
      if (!stopped) {
        await runtime.stop();
      }
    }
  });
});

async function startFixture(
  files: Map<string, Buffer>,
  options: { readonly keep?: boolean; readonly signal?: AbortSignal } = {},
): Promise<StaticRuntime> {
  const credential = Buffer.from(credentialEnvelope('alpha', TOKEN), 'ascii');
  native.verifyCredentialAuthoritySet.mockReturnValue(Object.freeze(Object.create(null)));
  native.secureReadCredential.mockReturnValue(credential);
  native.secureReadBeneath.mockImplementation((input: { readonly relativePath: string }) => {
    const file = files.get(input.relativePath);
    if (file === undefined) {
      throw new Error('not found');
    }
    return { bytes: Buffer.from(file) };
  });

  const runtime = await startStaticRuntime({
    descriptor: fixtureDescriptor(0),
    configuredProjects: FIXTURE_TRUSTED_PROJECTS,
    projectRoot: FIXTURE_PROJECT_ROOT,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (options.keep !== false) {
    runtimes.add(runtime);
  }
  return runtime;
}

function fixtureFiles(template?: Buffer): Map<string, Buffer> {
  return new Map([
    [
      'index.html',
      template ??
        Buffer.from(`<html><head>\n${MARKER}\n</head><body>fixture</body></html>\n`, 'utf8'),
    ],
  ]);
}

function fixtureDescriptor(port: number) {
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

function deferred<T>(): {
  readonly promise: Promise<T>;
  resolve(value: T): void;
} {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((nextResolve) => {
    resolve = nextResolve;
  });
  return { promise, resolve };
}

async function waitForPortToClose(port: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const probe = createServer();
    const closed = await new Promise<boolean>((resolve) => {
      probe.once('error', () => resolve(false));
      probe.listen({ host: '127.0.0.1', port }, () => resolve(true));
    });
    if (closed) {
      await new Promise<void>((resolve, reject) => {
        probe.close((error) => (error === undefined ? resolve() : reject(error)));
      });
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
  throw new Error('static runtime listener remained bound after abort');
}
function rawHttpRequest(runtime: StaticRuntime, method: 'GET' | 'HEAD', path: string): string {
  return `${method} ${path} HTTP/1.1\r\nHost: ${runtime.host}:${runtime.port}\r\nConnection: close\r\n\r\n`;
}

async function rawRequest(runtime: StaticRuntime, request: string): Promise<Buffer> {
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
  return Buffer.concat(chunks);
}

function parseRawHttpResponse(response: Buffer): RawHttpResponse {
  const headerTerminator = Buffer.from('\r\n\r\n', 'ascii');
  const headerTerminatorIndex = response.indexOf(headerTerminator);
  if (headerTerminatorIndex < 0) {
    throw new Error('raw socket response is missing its header terminator');
  }

  const [statusLine, ...headerLines] = response
    .subarray(0, headerTerminatorIndex)
    .toString('ascii')
    .split('\r\n');
  if (statusLine === undefined || !statusLine.startsWith('HTTP/1.1 ')) {
    throw new Error('raw socket response has an invalid status line');
  }

  const headers = new Map<string, string>();
  for (const headerLine of headerLines) {
    const separator = headerLine.indexOf(':');
    if (separator <= 0) {
      throw new Error('raw socket response has an invalid header');
    }
    headers.set(
      headerLine.slice(0, separator).toLowerCase(),
      headerLine.slice(separator + 1).trim(),
    );
  }

  return {
    statusLine,
    headers,
    bytesAfterHeaderTerminator: response.subarray(
      headerTerminatorIndex + headerTerminator.byteLength,
    ),
  };
}
function urlFor(runtime: StaticRuntime, path: string): string {
  return `http://${runtime.host}:${runtime.port}${path}`;
}

function credentialCapability(): object {
  return Object.freeze(Object.create(null));
}

function expectCredentialCapabilityReleased(credential: Buffer, capability: object): void {
  expect(credential.every((byte) => byte === 0)).toBe(true);
  expect(native.zeroizeBuffer).toHaveBeenCalledTimes(1);
  expect(native.zeroizeBuffer).toHaveBeenCalledWith(credential);
  expect(native.revokeCredentialReadCapability).toHaveBeenCalledTimes(1);
  expect(native.revokeCredentialReadCapability).toHaveBeenCalledWith(capability);
}
