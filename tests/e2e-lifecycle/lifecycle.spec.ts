import { createHash, randomUUID } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { cp, lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { expect, test } from '@playwright/test';

const checkoutRoot = resolve(import.meta.dirname, '../..');
const browserCache = join(homedir(), 'Library/Caches/ms-playwright');
const protocolVersion = '2025-11-25';
const loaderTag =
  '<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>';
const activeProcesses = new Set<ChildProcess>();
const outputs = new WeakMap<ChildProcess, () => string>();

test.describe.configure({ mode: 'serial' });

for (const lane of [
  { name: 'Vue', fixture: 'vue3-ordinary', port: 5173, app: 'src/App.vue', text: 'Vue + Vite' },
  {
    name: 'React',
    fixture: 'react-ordinary',
    port: 5174,
    app: 'src/App.tsx',
    text: 'React + Vite mutable text',
  },
] as const) {
  test(`${lane.name}: live-dev lifecycle uses the host Vite and HMR`, async ({ page }) => {
    const state = await stageFixture(lane.fixture);
    const indexPath = join(state.root, 'index.html');
    const packagePath = join(state.root, 'package.json');
    const lockfilePath = join(state.root, 'pnpm-lock.yaml');
    const appPath = join(state.root, lane.app);
    const indexPreimage = await readFile(indexPath);
    const packagePreimage = await readFile(packagePath);
    const lockfilePreimage = await readFile(lockfilePath);
    const appPreimage = await readFile(appPath, 'utf8');

    try {
      const setup = await runLifecycle(state, 'setup', 'yes\n', true);
      expect(setup.code, setup.output).toBe(0);
      expect(setup.output).toContain('SCG_LIFECYCLE_ACTIVE');
      await expectLiveDevInstall(
        state,
        indexPreimage,
        packagePreimage,
        lockfilePreimage,
        setup.output,
      );

      const host = spawnHostVite(state);
      const hostBase = await waitForHost(state.port, host);
      const hostPid = host.pid;
      expect(hostPid).toBeTruthy();
      const vitePid = await listeningProcessPid(state.port);
      expect(processAlive(vitePid)).toBe(true);
      await expectPortFree(4175, 'before starting MCP');
      const failOpenPage = await page.context().newPage();
      try {
        await failOpenPage.goto(`${hostBase}/`);
        await expect(failOpenPage.getByRole('heading', { name: lane.text })).toBeVisible();
        await failOpenPage.evaluate(() => {
          window.history.pushState({}, '', '/scg-fail-open-navigation');
          window.dispatchEvent(new PopStateEvent('popstate'));
        });
        await expect
          .poll(() => failOpenPage.evaluate(() => window.location.pathname))
          .toBe('/scg-fail-open-navigation');
        await expect(failOpenPage.getByRole('heading', { name: lane.text })).toBeVisible();
      } finally {
        await failOpenPage.close();
      }

      const start = await runLifecycle(state, 'start');
      const token = await readToken(state.root);
      await waitForMcp(state, token, start.process);
      await expectMcpAuthAndAnnotation(state, token);

      await page.goto(`${hostBase}/`);
      await expect(
        page.locator('script[src="http://127.0.0.1:4175/scene-glass-loader.js"]'),
      ).toHaveCount(1);
      await expect.poll(() => page.evaluate(() => window.SceneGlass?.state)).toBe('ready');
      await expect(page.locator('.scg-ui-overlay[aria-label="Scene Glass 메모 제어"]')).toHaveCount(
        1,
      );
      await page.evaluate(() => {
        window.history.pushState({}, '', '/scg-live-dev-navigation');
        window.dispatchEvent(new PopStateEvent('popstate'));
      });
      await expect(page.locator('.scg-ui-overlay[aria-label="Scene Glass 메모 제어"]')).toHaveCount(
        1,
      );

      await page.evaluate(() => {
        (window as Window & { __scgHmrSentinel?: string }).__scgHmrSentinel = 'survives-hmr';
      });
      const edited = appPreimage.replace(lane.text, `${lane.text} HMR`);
      expect(edited).not.toBe(appPreimage);
      await writeFile(appPath, edited);
      await expect(page.getByText(`${lane.text} HMR`, { exact: false })).toBeVisible();
      await expect
        .poll(() =>
          page.evaluate(() => (window as Window & { __scgHmrSentinel?: string }).__scgHmrSentinel),
        )
        .toBe('survives-hmr');
      expect(await listeningProcessPid(state.port)).toBe(vitePid);
      expect(processAlive(vitePid)).toBe(true);
      expect(host.pid).toBe(hostPid);
      expect(processAlive(hostPid!)).toBe(true);
      await writeFile(appPath, appPreimage);

      const stoppedStart = await stopProcess(start.process);
      expect(stoppedStart).toContain('SCG_LIFECYCLE_START_EXITED');
      await expectPortFree(4175, 'after stopping MCP');
      expect(processAlive(hostPid!)).toBe(true);
      expect(processAlive(vitePid)).toBe(true);
      expect((await fetch(`${hostBase}/`)).status).toBe(200);

      const annotations = await snapshotTree(join(state.root, '.scg/annotations'));
      expect(annotations.size).toBeGreaterThan(0);
      const uninstall = await runLifecycle(state, 'uninstall', 'yes\n', true);
      expect(uninstall.code, uninstall.output).toBe(0);
      expect(uninstall.output).toContain('SCG_LIFECYCLE_UNINSTALLED');
      expect(await readFile(indexPath)).toEqual(indexPreimage);
      expect(await readFile(packagePath)).toEqual(packagePreimage);
      expect(await readFile(lockfilePath)).toEqual(lockfilePreimage);
      await expectMissing(join(state.root, '.env.development.local'));
      await expectMissing(join(state.root, '.scg/runtime'));
      expect(await snapshotTree(join(state.root, '.scg/annotations'))).toEqual(annotations);

      const secondUninstall = await runLifecycle(state, 'uninstall', 'yes\n', true);
      expect(secondUninstall.code, secondUninstall.output).toBe(0);
      expect(secondUninstall.output).toContain('SCG_LIFECYCLE_ALREADY_UNINSTALLED');
    } finally {
      await writeFile(appPath, appPreimage).catch(() => undefined);
      await cleanup(state);
    }
  });
}
test('one MCP listener serves two registered Vite projects after literal port drift', async () => {
  const sharedHome = join(homedir(), `.scene-glass-live-dev-home-${randomUUID()}`);
  const alphaSetup = await stageFixture('vue3-ordinary', sharedHome);
  const beta = await stageFixture('react-ordinary', sharedHome);
  let alpha = alphaSetup;

  try {
    const setupAlpha = await runLifecycle(alpha, 'setup', 'yes\n', true);
    expect(setupAlpha.code, setupAlpha.output).toBe(0);
    const alphaDescriptorPath = join(alpha.root, '.scg/runtime/host-descriptor.v1.json');
    const alphaDescriptor = await readFile(alphaDescriptorPath);

    const setupBeta = await runLifecycle(beta, 'setup', 'yes\n', true);
    expect(setupBeta.code, setupBeta.output).toBe(0);
    expect(await readFile(alphaDescriptorPath)).toEqual(alphaDescriptor);

    const persisted = JSON.parse(await readFile(join(sharedHome, '.scg/config.json'), 'utf8')) as {
      readonly projects: readonly {
        readonly projectId: string;
        readonly tokenEnv: string;
      }[];
    };
    expect(persisted.projects.map((project) => project.projectId).sort()).toEqual(
      [alpha.projectId, beta.projectId].sort(),
    );
    expect(new Set(persisted.projects.map((project) => project.tokenEnv)).size).toBe(2);
    const durablePaths = [
      join(sharedHome, '.scg/config.json'),
      join(sharedHome, '.scg/credential-authorities.v1.json'),
      alphaDescriptorPath,
      join(alpha.root, '.scg/onboarding/manifest.v1.json'),
      join(alpha.root, '.env.development.local'),
      join(beta.root, '.scg/runtime/host-descriptor.v1.json'),
      join(beta.root, '.scg/onboarding/manifest.v1.json'),
      join(beta.root, '.env.development.local'),
    ];
    const durableBefore = await Promise.all(durablePaths.map((path) => readFile(path)));

    alpha = await rewriteDeclaredVitePort(alpha, 5273);
    const alphaHost = spawnHostVite(alpha);
    const betaHost = spawnHostVite(beta);
    await Promise.all([waitForHost(alpha.port, alphaHost), waitForHost(beta.port, betaHost)]);

    await expectPortFree(4175, 'before multi-project MCP');
    const start = await runLifecycle(alpha, 'start');
    const [alphaToken, betaToken] = await Promise.all([
      readToken(alpha.root),
      readToken(beta.root),
    ]);
    await Promise.all([
      waitForMcp(alpha, alphaToken, start.process),
      waitForMcp(beta, betaToken, start.process),
    ]);
    await expectMcpAuthAndAnnotation(alpha, alphaToken);
    await expectMcpAuthAndAnnotation(beta, betaToken);
    expect(
      (await mcpRequest({ ...alpha, port: 5173 }, alphaToken, initializeMessage())).status,
    ).toBe(403);

    expect((await mcpRequest(beta, alphaToken, initializeMessage())).status).toBe(403);
    expect(
      (await mcpRequest({ ...beta, port: alpha.port }, betaToken, initializeMessage())).status,
    ).toBe(403);

    expect(alphaHost.exitCode, outputs.get(alphaHost)?.()).toBeNull();
    expect(betaHost.exitCode, outputs.get(betaHost)?.()).toBeNull();
    const listenerPid = await listeningProcessPid(4175);
    const refused = await runLifecycle(beta, 'start', undefined, true);
    expect(refused.code, refused.output).not.toBe(0);
    expect(await listeningProcessPid(4175)).toBe(listenerPid);
    expect(alphaHost.exitCode, outputs.get(alphaHost)?.()).toBeNull();
    expect(betaHost.exitCode, outputs.get(betaHost)?.()).toBeNull();

    const stopped = await stopProcess(start.process);
    expect(stopped).toContain('SCG_LIFECYCLE_START_EXITED');
    await expectPortFree(4175, 'after multi-project MCP');
    expect(alphaHost.exitCode, outputs.get(alphaHost)?.()).toBeNull();
    expect(betaHost.exitCode, outputs.get(betaHost)?.()).toBeNull();
    const betaSelectedStart = await runLifecycle(beta, 'start');
    await Promise.all([
      waitForMcp(alpha, alphaToken, betaSelectedStart.process),
      waitForMcp(beta, betaToken, betaSelectedStart.process),
    ]);
    const stoppedBetaSelected = await stopProcess(betaSelectedStart.process);
    expect(stoppedBetaSelected).toContain('SCG_LIFECYCLE_START_EXITED');
    await expectPortFree(4175, 'after beta-selected MCP');
    // strictPort 는 요구하지 않는다. 없거나 false 여도 기동은 그대로 되어야 한다 — 포트가
    // 밀리면 로더가 붙지 않을 뿐이고, 그 정도로 전체를 막지 않는 것이 지금의 계약이다.
    const alphaViteConfigPath = join(alpha.root, 'vite.config.ts');
    const strictConfig = await readFile(alphaViteConfigPath, 'utf8');
    expect(strictConfig).toContain('strictPort: true');
    await writeFile(
      alphaViteConfigPath,
      strictConfig.replace('strictPort: true', 'strictPort: false'),
    );
    const nonStrict = await runLifecycle(alpha, 'start');
    const stoppedNonStrict = await stopProcess(nonStrict.process);
    expect(stoppedNonStrict).toContain('SCG_LIFECYCLE_START_EXITED');
    await expectPortFree(4175, 'after non-strict start');
    const durableAfter = await Promise.all(durablePaths.map((path) => readFile(path)));
    expect(durableAfter).toEqual(durableBefore);
  } finally {
    await cleanup(alpha);
    await cleanup(beta);
  }
});

type FixtureState = {
  readonly root: string;
  readonly home: string;
  readonly port: number;
  readonly projectId: string;
};

async function stageFixture(projectId: string, sharedHome?: string): Promise<FixtureState> {
  const root = join(homedir(), `.scene-glass-live-dev-${projectId}-${randomUUID()}`);
  const home = sharedHome ?? join(homedir(), `.scene-glass-live-dev-home-${randomUUID()}`);
  const source = join(checkoutRoot, 'fixtures', projectId);
  const port = projectId === 'vue3-ordinary' ? 5173 : 5174;
  await rm(root, { recursive: true, force: true });
  await mkdir(home, { recursive: true, mode: 0o700 });
  await cp(source, root, {
    recursive: true,
    filter: (path) => {
      const top = relative(source, path).split(/[\\/]/u)[0];
      return (
        !['.scg', '.scene-glass', 'node_modules'].includes(top ?? '') && !top?.startsWith('.env')
      );
    },
  });
  const install = spawn(
    join(dirname(process.execPath), 'corepack'),
    ['pnpm', 'install', '--prefer-offline', '--ignore-scripts'],
    { cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const output = capture(install);
  expect(await waitForExit(install), output()).toBe(0);
  return { root, home, port, projectId };
}
async function rewriteDeclaredVitePort(state: FixtureState, port: number): Promise<FixtureState> {
  const packagePath = join(state.root, 'package.json');
  const configPath = join(state.root, 'vite.config.ts');
  const packageText = await readFile(packagePath, 'utf8');
  const configText = await readFile(configPath, 'utf8');
  const packagePort = `--port ${state.port}`;
  const configPort = `port: ${state.port}`;
  expect(packageText).toContain(packagePort);
  expect(configText).toContain(configPort);
  await Promise.all([
    writeFile(packagePath, packageText.replace(packagePort, `--port ${port}`)),
    writeFile(configPath, configText.replace(configPort, `port: ${port}`)),
  ]);
  return { ...state, port };
}

function spawnHostVite(state: FixtureState): ChildProcess {
  const host = spawn(join(dirname(process.execPath), 'corepack'), ['pnpm', 'run', 'dev'], {
    cwd: state.root,
    detached: true,
    env: lifecycleEnvironment(state.home),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  capture(host);
  activeProcesses.add(host);
  return host;
}

async function runLifecycle(
  state: FixtureState,
  command: 'setup' | 'start' | 'uninstall',
  input?: string,
  wait = false,
): Promise<{
  readonly process: ChildProcess;
  readonly code?: number | null;
  readonly output: string;
}> {
  const child = spawn(join(checkoutRoot, 'scripts', command), [], {
    cwd: state.root,
    detached: true,
    env: lifecycleEnvironment(state.home),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const output = capture(child);
  activeProcesses.add(child);
  if (input !== undefined) child.stdin?.end(input);
  if (!wait) return { process: child, output: output() };
  const code = await waitForExit(child);
  return { process: child, code, output: output() };
}

function lifecycleEnvironment(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    PLAYWRIGHT_BROWSERS_PATH: browserCache,
  };
  for (const key of Object.keys(env)) {
    if (key.startsWith('VITE_SCENE_GLASS_') || key === 'SCENE_GLASS_HOST_TOKEN') delete env[key];
  }
  return env;
}

async function expectLiveDevInstall(
  state: FixtureState,
  indexPreimage: Buffer,
  packagePreimage: Buffer,
  lockfilePreimage: Buffer,
  setupOutput: string,
): Promise<void> {
  const index = await readFile(join(state.root, 'index.html'), 'utf8');
  expect(index, setupOutput).toContain(loaderTag);
  expect(index.split(loaderTag)).toHaveLength(2);
  expect(index).toContain('</head>');
  expect(index).not.toContain('SCENE_GLASS_HOST_TOKEN=');
  expect(await readFile(join(state.root, 'package.json'))).toEqual(packagePreimage);
  expect(await readFile(join(state.root, 'pnpm-lock.yaml'))).toEqual(lockfilePreimage);
  expect(index).not.toEqual(indexPreimage.toString('utf8'));
  const env = await readFile(join(state.root, '.env.development.local'), 'utf8');
  const token = await readToken(state.root);
  expect(env.split('\n').filter(Boolean)).toEqual([
    'VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js',
    `VITE_SCENE_GLASS_PROJECT_ID=${state.projectId}`,
    `VITE_SCENE_GLASS_PROJECT_TOKEN=${token}`,
    `SCENE_GLASS_HOST_TOKEN=${token}`,
  ]);
  const config = await readFile(join(state.home, '.scg/config.json'));
  expect(config.includes(Buffer.from(token))).toBe(false);
}

async function waitForHost(port: number, child: ChildProcess): Promise<string> {
  // Vite's default host may bind ::1 only, so the page is served from either
  // loopback spelling; both origins are authorized by setup.
  const bases = [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
  let base: string | undefined;
  await poll(`host Vite on ${port}`, async () => {
    if (child.exitCode !== null)
      throw new Error(`SCG_LIFECYCLE_E2E_HOST_EXITED:\n${outputs.get(child)?.()}`);
    for (const candidate of bases) {
      if ((await fetch(`${candidate}/`).catch(() => undefined))?.status === 200) {
        base = candidate;
        return true;
      }
    }
    return false;
  });
  if (base === undefined) throw new Error(`SCG_LIFECYCLE_E2E_HOST_UNREACHABLE: ${port}`);
  return base;
}

async function waitForMcp(state: FixtureState, token: string, child: ChildProcess): Promise<void> {
  await poll('MCP readiness', async () => {
    if (child.exitCode !== null)
      throw new Error(`SCG_LIFECYCLE_E2E_MCP_EXITED:\n${outputs.get(child)?.()}`);
    return (
      (await mcpRequest(state, token, initializeMessage()).catch(() => undefined))?.status === 200
    );
  });
}

async function expectMcpAuthAndAnnotation(state: FixtureState, token: string): Promise<void> {
  expect((await mcpRequest(state, 'wrong-token', initializeMessage())).status).toBe(401);
  expect((await mcpRequest(state, undefined, initializeMessage())).status).toBe(401);
  const initialized = await mcpRequest(state, token, initializeMessage());
  expect(initialized.status).toBe(200);
  const session = initialized.headers.get('mcp-session-id');
  expect(session).toBeTruthy();
  expect((await mcpRequest(state, token, notificationMessage(), session!)).status).toBe(202);
  const created = await mcpRequest(
    state,
    token,
    toolsCall('annotations.create', {
      page: pageIdentity('/'),
      expectedRevision: 0,
      operationId: randomUUID(),
      locator: { dataScgId: 'live-dev-host-heading' },
      memo: 'Live dev annotation',
      surroundingText: 'live dev lifecycle',
      domOrder: 0,
      resolution: { status: 'resolved', reason: null },
    }),
    session!,
  );
  expect(created.status).toBe(200);
  const listed = await mcpRequest(
    state,
    token,
    toolsCall('annotations.list', { page: pageIdentity('/') }),
    session!,
  );
  expect(listed.status).toBe(200);
  expect((await listed.json()) as { result?: unknown }).toHaveProperty('result');
}

function initializeMessage(): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: randomUUID(),
    method: 'initialize',
    params: {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: 'live-dev-e2e', version: '1.0.0' },
    },
  };
}

function notificationMessage(): Record<string, unknown> {
  return { jsonrpc: '2.0', method: 'notifications/initialized', params: {} };
}

function toolsCall(name: string, argumentsValue: Record<string, unknown>): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: randomUUID(),
    method: 'tools/call',
    params: { name, arguments: argumentsValue },
  };
}

function pageIdentity(route: string): Record<string, unknown> {
  return {
    policyVersion: 1,
    canonicalIdentity: route,
    route,
    pageId: `p_${createHash('sha256').update(route).digest('hex')}`,
  };
}

async function mcpRequest(
  state: FixtureState,
  token: string | undefined,
  message: Record<string, unknown>,
  session?: string,
): Promise<Response> {
  return fetch(`http://127.0.0.1:4175/mcp/v1/projects/${state.projectId}`, {
    method: 'POST',
    headers: {
      origin: `http://127.0.0.1:${state.port}`,
      'content-type': 'application/json',
      'mcp-protocol-version': protocolVersion,
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
      ...(session === undefined ? {} : { 'mcp-session-id': session }),
    },
    body: JSON.stringify(message),
  });
}

async function readToken(root: string): Promise<string> {
  const env = await readFile(join(root, '.env.development.local'), 'utf8');
  const token = /^SCENE_GLASS_HOST_TOKEN=(.+)$/m.exec(env)?.[1];
  if (token === undefined) throw new Error('SCG_LIFECYCLE_E2E_TOKEN_MISSING');
  return token;
}

function capture(child: ChildProcess): () => string {
  let output = '';
  child.stdout?.on('data', (chunk: Buffer) => (output += chunk));
  child.stderr?.on('data', (chunk: Buffer) => (output += chunk));
  const value = () => output;
  outputs.set(child, value);
  return value;
}

async function stopProcess(child: ChildProcess): Promise<string> {
  if (child.pid === undefined) throw new Error('SCG_LIFECYCLE_E2E_PID_MISSING');
  process.kill(-child.pid, 'SIGTERM');
  await waitForExit(child);
  activeProcesses.delete(child);
  return outputs.get(child)?.() ?? '';
}

async function waitForExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolveExit, rejectExit) => {
    const timeout = setTimeout(
      () => rejectExit(new Error(`SCG_LIFECYCLE_E2E_PROCESS_TIMEOUT:\n${outputs.get(child)?.()}`)),
      60_000,
    );
    child.once('error', (error) => {
      clearTimeout(timeout);
      rejectExit(error);
    });
    child.once('close', (code) => {
      clearTimeout(timeout);
      activeProcesses.delete(child);
      resolveExit(code);
    });
  });
}

async function cleanup(state: FixtureState): Promise<void> {
  for (const child of activeProcesses) {
    if (child.pid !== undefined) {
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        /* already stopped */
      }
    }
  }
  await Promise.all([...activeProcesses].map((child) => waitForExit(child).catch(() => undefined)));
  activeProcesses.clear();
  await rm(join(checkoutRoot, '.scg'), { recursive: true, force: true });
  await rm(join(checkoutRoot, 'packages/onboarding/dist/.scene-glass-verified-runtime-cli.mjs'), {
    force: true,
  });
  await rm(state.root, { recursive: true, force: true });
  await rm(state.home, { recursive: true, force: true });
}

async function listeningProcessPid(port: number): Promise<number> {
  let pid: number | undefined;
  await poll(`Vite process on ${port}`, async () => {
    const lsof = spawn('lsof', ['-nP', `-tiTCP:${port}`, '-sTCP:LISTEN'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const output = capture(lsof);
    const code = await waitForExit(lsof);
    if (code !== 0) return false;
    const pids = [...new Set(output().trim().split(/\s+/u).map(Number).filter(Number.isInteger))];
    if (pids.length !== 1) return false;
    pid = pids[0];
    return true;
  });
  if (pid === undefined) throw new Error(`SCG_LIFECYCLE_E2E_VITE_PID_MISSING: ${port}`);
  return pid;
}
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function expectPortFree(port: number, phase: string): Promise<void> {
  if (await portOpen(port)) throw new Error(`SCG_LIFECYCLE_E2E_PORT_BUSY: ${port} ${phase}`);
}

async function portOpen(port: number): Promise<boolean> {
  return new Promise((resolveOpen) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.once('connect', () => {
      socket.destroy();
      resolveOpen(true);
    });
    socket.once('error', () => {
      socket.destroy();
      resolveOpen(false);
    });
  });
}

async function poll(name: string, predicate: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  throw new Error(`SCG_LIFECYCLE_E2E_READY_TIMEOUT: ${name}`);
}

async function snapshotTree(root: string): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (entry.isFile())
      files.set(
        join(entry.parentPath, entry.name).slice(root.length + 1),
        await readFile(join(entry.parentPath, entry.name)),
      );
  }
  return files;
}

async function expectMissing(path: string): Promise<void> {
  await lstat(path)
    .then(() => {
      throw new Error(`SCG_LIFECYCLE_E2E_RESIDUE: ${path}`);
    })
    .catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    });
}
