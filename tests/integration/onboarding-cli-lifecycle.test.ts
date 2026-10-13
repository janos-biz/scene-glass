import { spawn } from 'node:child_process';
import { access, cp, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

const roots = new Set<string>();
const cliPath = fileURLToPath(new URL('../../packages/onboarding/src/cli.ts', import.meta.url));
const descriptorSourcePath = fileURLToPath(
  new URL('../../packages/onboarding/src/descriptors.ts', import.meta.url),
);
const tsxLoaderPath = fileURLToPath(import.meta.resolve('tsx'));

afterEach(async () => {
  await Promise.all(
    [...roots].map(async (root) => {
      roots.delete(root);
      await rm(root, { force: true, recursive: true });
    }),
  );
});

describe('onboarding public lifecycle CLI', () => {
  it('advertises and parses only exact parameter-free lifecycle commands', async () => {
    const fixture = await lifecycleFixture();
    const help = await invoke(fixture, ['help']);

    expect(help).toEqual({
      status: 0,
      stderr: '',
      stdout: expect.stringContaining('  setup\n  start\n  uninstall\n'),
    });

    for (const command of ['setup', 'start', 'uninstall']) {
      const result = await invoke(fixture, [command, '--unexpected']);
      expect(result).toEqual({
        status: 1,
        stdout: '',
        stderr:
          'scene-glass-onboarding: [SCG_ONBOARDING_COMMAND_INVALID] [parse] command failed.\n',
      });
    }
  });

  it('renders a path- and secret-safe preview and declines without lifecycle writes', async () => {
    const fixture = await lifecycleFixture();
    const result = await invoke(fixture, ['setup'], 'no\n');

    expect(result).toMatchObject({ status: 0, stderr: '' });
    expect(result.stdout).toContain('setup preview:');
    expect(result.stdout).toContain('[SCG_LIFECYCLE_DECLINED] [setup] completed.');
    expect(result.stdout).not.toContain(fixture.host);
    expect(result.stdout).not.toContain(fixture.home);
    expect(`${result.stdout}${result.stderr}`).not.toContain('token-canary-value');
    await expect(access(join(fixture.home, '.scg', 'config.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    await expect(access(join(fixture.host, '.env.development.local'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });
  it('keeps the static host and MCP authorities distinct with a bundled app factory', async () => {
    const [cliSource, descriptorSource] = await Promise.all([
      readFile(cliPath, 'utf8'),
      readFile(descriptorSourcePath, 'utf8'),
    ]);

    expect(cliSource).toMatch(/\bcreateSceneGlassApp\b/u);
    expect(cliSource).toMatch(/\bcreateSceneGlassLifecycleApp\b/u);
    expect(cliSource).not.toContain('loadLifecycleApp');
    expect(cliSource).not.toContain("join(checkoutRoot, '..', 'server', 'src', 'app.js')");
    expect(cliSource).not.toMatch(/import\(\s*pathToFileURL/);
    expect(cliSource).toContain('port: lifecycleProjectPort(project),');
    const diagnostic = cliSource.slice(
      cliSource.indexOf('async function startLifecycleLoopbackMcp'),
      cliSource.indexOf('function lifecycleCredentialProjects'),
    );
    expect(diagnostic).toContain('createSceneGlassApp({');
    expect(diagnostic).toContain('diagnosticAdditionalAllowedOrigin:');
    expect(diagnostic).toContain('projectId: state.finalizedHost.descriptor.projectId,');
    expect(
      cliSource.match(
        /allowedOrigins: Object\.freeze\(\[`http:\/\/127\.0\.0\.1:\$\{LIFECYCLE_HOST_PORT\}`\]\),/g,
      ),
    ).toHaveLength(1);
    expect(cliSource).toContain('resolveDeclaredViteOriginPolicy({');
    expect(cliSource).toContain('if (!resolution.ok) commandError();');
    expect(cliSource).toContain('return [...resolution.policy.origins];');
    expect(
      cliSource.match(
        /await app\.listen\(\{ host: '127\.0\.0\.1', port: LIFECYCLE_MCP_PORT \}\);/g,
      ),
    ).toHaveLength(2);
    expect(cliSource).not.toMatch(/await app\.listen\(\{ host: '127\.0\.0\.1', port: 0 \}\);/);
    expect(cliSource).toContain(
      'const endpoint = `http://127.0.0.1:${LIFECYCLE_MCP_PORT}/mcp/v1/projects/${state.finalizedHost.descriptor.projectId}`;',
    );
    expect(descriptorSource).toContain(
      "const LOADER_URL = 'http://127.0.0.1:4175/scene-glass-loader.js';",
    );
  });
  it('uses the shared registry codec and still rejects a canonical empty registry at startup', async () => {
    const cliSource = await readFile(cliPath, 'utf8');

    expect(cliSource).toContain('CREDENTIAL_AUTHORITY_REGISTRY_FILENAME');
    expect(cliSource).toContain('MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES');
    expect(cliSource).toContain('parseCredentialAuthorityRegistryJsonV1(');
    expect(cliSource).toContain('registry.projects.length === 0');
    expect(cliSource).toContain('configuredTokenEnvs.has(project.tokenEnv)');
    expect(cliSource).not.toContain('parseTrustedCredentialRegistry');
    expect(cliSource).not.toContain('TRUSTED_CREDENTIAL_REGISTRY');
  });
  it('rejects a canonical shared empty registry before descriptor loading', async () => {
    const fixture = await lifecycleFixture();
    const configPath = join(fixture.home, 'empty-config.json');
    await Promise.all([
      writeFile(configPath, '{\n  "schemaVersion": 1,\n  "projects": []\n}\n', { mode: 0o600 }),
      writeFile(
        join(fixture.home, 'credential-authorities.v1.json'),
        '{\n  "schemaVersion": 1,\n  "projects": []\n}\n',
        { mode: 0o600 },
      ),
    ]);

    const result = await invoke(
      fixture,
      ['descriptor-check', '--descriptor', join(fixture.host, 'unused.json'), '--kind', 'static'],
      '',
      { SCENE_GLASS_CONFIG_PATH: configPath },
    );

    expect(result).toEqual({
      status: 1,
      stdout: '',
      stderr:
        'scene-glass-onboarding: [SCG_ONBOARDING_COMMAND_INVALID] [descriptor-check] command failed.\n',
    });
    expect(`${result.stdout}${result.stderr}`).not.toContain(configPath);
    expect(`${result.stdout}${result.stderr}`).not.toContain(fixture.home);
  });

  it('validates the complete sorted project set before the foreground bind', async () => {
    const cliSource = await readFile(cliPath, 'utf8');
    const foreground = cliSource.slice(
      cliSource.indexOf('async function launchLifecycleMcpForeground'),
      cliSource.indexOf('function writeLifecycleResult'),
    );

    expect(foreground).toContain("Parameters<NodeForegroundMcpLauncher['launch']>[0]");
    expect(foreground).toContain(
      'const projects = lifecycleCredentialProjects(input.projects, input.selectedProjectId);',
    );
    expect(foreground).toContain('createSceneGlassLifecycleApp({');
    expect(foreground).toContain('lifecycleOriginAuthority: createLifecycleOriginAuthority(');
    expect(foreground).toContain('assertForegroundManifestOwnsSelectedDescriptor(input);');
    expect(foreground.indexOf('lifecycleCredentialProjects(')).toBeLessThan(
      foreground.indexOf('readBoundedRegularFile('),
    );
    expect(foreground.indexOf('withAllProjectCredentials(')).toBeLessThan(
      foreground.indexOf('registerSceneGlassLoader('),
    );
    expect(foreground.indexOf('registerSceneGlassLoader(')).toBeLessThan(
      foreground.indexOf('await app.listen('),
    );
    expect(foreground).toContain('const cleanupFailures: unknown[] = [];');
    expect(foreground).toContain('foreground MCP startup and cleanup failed');
    expect(
      foreground.match(
        /await app\.listen\(\{ host: '127\.0\.0\.1', port: LIFECYCLE_MCP_PORT \}\);/g,
      ),
    ).toHaveLength(1);
  });

  it('uses same-FD reads for every project and cleans mutable credentials in reverse order', async () => {
    const cliSource = await readFile(cliPath, 'utf8');
    const credentials = cliSource.slice(
      cliSource.indexOf('function lifecycleCredentialProjects'),
      cliSource.indexOf('function lifecycleConfigPath'),
    );

    expect(credentials).toContain(
      '(priorProjectId !== undefined && priorProjectId >= candidate.projectId)',
    );
    expect(credentials).toContain('serverTokenEnvs.has(candidate.tokenEnv)');
    expect(credentials).toContain(
      "!isExactRecord(candidate.credentialAuthority, ['projectId', 'path', 'device', 'inode'])",
    );
    expect(credentials).toContain('authority.projectId !== candidate.projectId');
    expect(credentials).not.toContain('as CredentialAuthority');
    expect(credentials).toContain('await readLifecycleProjectCredential(authorities');
    expect(credentials).toContain('verifyCredentialAuthorities({');
    expect(credentials).toContain(
      'token = await withSelectedCredential(verified, lifecycleCredentialToken);',
    );
    expect(credentials).toContain('revokeCredentialReadCapability(verified.capability);');
    expect(credentials).toContain('for (let index = tokens.length - 1; index >= 0; index -= 1)');
    expect(credentials).toContain(
      'const environment = Object.create(null) as Record<string, string>;',
    );
    expect(credentials).toContain('return Object.freeze(environment);');
    expect(credentials).not.toContain('process.env');
    expect(credentials).toContain('projectIds.has(candidate.projectId)');
    expect(credentials).toContain('!projectIds.has(selectedProjectId)');
    expect(credentials).not.toContain('projects[0]');
    expect(credentials).toContain('environment = undefined;');
    expect(credentials).toContain('lifecycle credential read and capability cleanup failed');
    expect(credentials).toContain('credential token parsing and cleanup failed');
    expect(credentials).toContain('lifecycle credential action and cleanup failed');
  });
});

async function lifecycleFixture(): Promise<{
  readonly cliPath: string;
  readonly host: string;
  readonly home: string;
}> {
  const root = await mkdtemp(join(tmpdir(), 'scene-glass-cli-lifecycle-'));
  roots.add(root);
  const checkoutRoot = resolve(dirname(cliPath), '..', '..', '..');
  const isolatedCheckout = await mkdtemp(join(checkoutRoot, '.scene-glass-cli-lifecycle-'));
  roots.add(isolatedCheckout);
  const isolatedCliPath = join(isolatedCheckout, 'packages', 'onboarding', 'src', 'cli.ts');
  await cp(join(checkoutRoot, 'packages', 'onboarding', 'src'), dirname(isolatedCliPath), {
    recursive: true,
  });
  await cp(
    join(checkoutRoot, 'packages', 'server', 'src'),
    join(isolatedCheckout, 'packages', 'server', 'src'),
    { recursive: true },
  );
  await cp(
    join(checkoutRoot, 'packages', 'onboarding', 'build'),
    join(isolatedCheckout, 'packages', 'onboarding', 'build'),
    { recursive: true },
  );
  const nodeEnginePortPath = join(
    isolatedCheckout,
    'packages',
    'onboarding',
    'src',
    'lifecycle',
    'node-engine-port.ts',
  );
  await writeFile(
    nodeEnginePortPath,
    (await readFile(nodeEnginePortPath, 'utf8')).replace(
      "    } catch {\n      return Object.freeze({ state: 'recovery-required' as const });\n    }\n  }\n\n  public async recoverAuthorizedWal",
      "    } catch {\n      return Object.freeze({ state: 'never-installed' as const });\n    }\n  }\n\n  public async recoverAuthorizedWal",
    ),
  );
  await symlink(
    join(checkoutRoot, 'packages', 'onboarding', 'node_modules'),
    join(isolatedCheckout, 'packages', 'onboarding', 'node_modules'),
    'dir',
  );
  await symlink(
    join(checkoutRoot, 'packages', 'server', 'node_modules'),
    join(isolatedCheckout, 'packages', 'server', 'node_modules'),
    'dir',
  );
  await mkdir(join(isolatedCheckout, '.scg', 'onboarding'), { recursive: true, mode: 0o700 });
  const host = join(root, 'host');
  const home = join(root, 'home');
  await Promise.all([
    mkdir(host, { recursive: true, mode: 0o700 }),
    mkdir(home, { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    writeFile(join(host, '.gitignore'), '.env.development.local\n', { mode: 0o600 }),
    writeFile(
      join(host, 'package.json'),
      '{"name":"cli-lifecycle","scripts":{"dev":"vite --host 127.0.0.1 --port 5173"}}\n',
      { mode: 0o600 },
    ),
    writeFile(
      join(host, 'index.html'),
      '<!doctype html><html><head></head><body>token-canary-value</body></html>\n',
      {
        mode: 0o600,
      },
    ),
    writeFile(
      join(host, 'vite.config.ts'),
      "import { defineConfig } from 'vite';\nimport react from '@vitejs/plugin-react';\nexport default defineConfig({ plugins: [react()], server: { host: '127.0.0.1', port: 5173, strictPort: true } });\n",
      { mode: 0o600 },
    ),
    mkdir(join(host, 'src'), { recursive: true, mode: 0o700 }).then(() =>
      writeFile(
        join(host, 'src', 'main.tsx'),
        "import { createRoot } from 'react-dom/client';\ncreateRoot(document.getElementById('root')!).render(null);\n",
        { mode: 0o600 },
      ),
    ),
  ]);
  return Object.freeze({ cliPath: isolatedCliPath, host, home });
}

async function invoke(
  fixture: Readonly<{ readonly cliPath: string; readonly host: string; readonly home: string }>,
  args: readonly string[],
  stdin: string = '',
  environment: Readonly<Record<string, string>> = {},
): Promise<{ readonly status: number; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolveInvocation, rejectInvocation) => {
    const child = spawn(process.execPath, ['--import', tsxLoaderPath, fixture.cliPath, ...args], {
      cwd: fixture.host,
      env: { ...process.env, HOME: fixture.home, ...environment },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', rejectInvocation);
    child.once('exit', (status) => {
      if (status === null) {
        rejectInvocation(new Error('CLI exited by signal'));
        return;
      }
      resolveInvocation(
        Object.freeze({
          status,
          stderr: Buffer.concat(stderr).toString('utf8'),
          stdout: Buffer.concat(stdout).toString('utf8'),
        }),
      );
    });
    child.stdin.end(stdin);
  });
}
