import { createHash } from 'node:crypto';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import {
  access,
  chmod,
  copyFile,
  lstat,
  link,
  mkdtemp,
  mkdir,
  open,
  readFile,
  rename,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
type BootstrapVerifierModule = Readonly<{
  readonly BOOTSTRAP_TIMELINE: readonly string[];
  readonly verifyBootstrap: (input?: { readonly root?: string }) => Promise<unknown>;
  readonly verifyBootstrapFixture: (input?: {
    readonly root?: string;
    readonly expectedLockHash?: string;
  }) => Promise<unknown>;
}>;
type RuntimeBuildModule = Readonly<{
  readonly auditMetafile: (metafile: unknown) => void;
  readonly RuntimeBuildError: ErrorConstructor;
}>;
type ArtifactVerifierModule = Readonly<{
  readonly ArtifactVerificationError: ErrorConstructor;
  readonly createPlainNodeCliTestOnlyPorts: (testOnly: unknown) => unknown;
  readonly formatArtifactVerifierFailure: (error: unknown) => string;
  readonly publishRuntimeBuildManifest: (auditedCli: unknown) => Promise<void>;
  readonly verifyArtifacts: (input: unknown) => Promise<unknown>;
  readonly verifyPlainNodeCli: (input: unknown) => Promise<void>;
}>;

function moduleRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

function assertBootstrapVerifierModule(value: unknown): asserts value is BootstrapVerifierModule {
  if (
    !moduleRecord(value) ||
    !Array.isArray(value.BOOTSTRAP_TIMELINE) ||
    !value.BOOTSTRAP_TIMELINE.every((entry) => typeof entry === 'string') ||
    typeof value.verifyBootstrap !== 'function' ||
    typeof value.verifyBootstrapFixture !== 'function'
  ) {
    throw new TypeError('bootstrap verifier module has an invalid export surface');
  }
}

function assertRuntimeBuildModule(value: unknown): asserts value is RuntimeBuildModule {
  if (
    !moduleRecord(value) ||
    typeof value.auditMetafile !== 'function' ||
    typeof value.RuntimeBuildError !== 'function'
  ) {
    throw new TypeError('runtime build module has an invalid export surface');
  }
}

function assertArtifactVerifierModule(value: unknown): asserts value is ArtifactVerifierModule {
  if (
    !moduleRecord(value) ||
    typeof value.ArtifactVerificationError !== 'function' ||
    typeof value.createPlainNodeCliTestOnlyPorts !== 'function' ||
    typeof value.formatArtifactVerifierFailure !== 'function' ||
    typeof value.publishRuntimeBuildManifest !== 'function' ||
    typeof value.verifyArtifacts !== 'function' ||
    typeof value.verifyPlainNodeCli !== 'function'
  ) {
    throw new TypeError('artifact verifier module has an invalid export surface');
  }
}

const bootstrapVerifierSpecifier = new URL('../../scripts/verify-bootstrap.mjs', import.meta.url)
  .href;
const bootstrapVerifierModule: unknown = await import(bootstrapVerifierSpecifier);
assertBootstrapVerifierModule(bootstrapVerifierModule);
const {
  BOOTSTRAP_TIMELINE,
  verifyBootstrap,
  verifyBootstrapFixture: verifyBootstrapFixtureAt,
} = bootstrapVerifierModule;

const runtimeBuildSpecifier = new URL(
  '../../packages/onboarding/scripts/build-runtime.mjs',
  import.meta.url,
).href;
const runtimeBuildModule: unknown = await import(runtimeBuildSpecifier);
assertRuntimeBuildModule(runtimeBuildModule);
const { auditMetafile, RuntimeBuildError } = runtimeBuildModule;

const artifactVerifierSpecifier = new URL(
  '../../packages/onboarding/scripts/verify-artifacts.mjs',
  import.meta.url,
).href;
const artifactVerifierModule: unknown = await import(artifactVerifierSpecifier);
assertArtifactVerifierModule(artifactVerifierModule);
const {
  ArtifactVerificationError,
  createPlainNodeCliTestOnlyPorts,
  formatArtifactVerifierFailure,
  publishRuntimeBuildManifest,
  verifyArtifacts,
  verifyPlainNodeCli,
} = artifactVerifierModule;

const temporaryRoots = new Set<string>();
const ESBUILD_0_25_5_INTEGRITY =
  'sha512-P8OtKZRv/5J5hhz0cUAdu/cLuPIKXpQl1R9pZtvmHWQvrAUVd0UNIPT4IB4W3rNOqVO0rlqHmCIbSwxh/c9yUQ==';
const ESBUILD_0_28_1_INTEGRITY =
  'sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==';
const FS_EXT_INTEGRITY =
  'sha512-/TrISPOFhCkbgIRWK9lzscRzwPCu0PqtCcvMc9jsHKBgZGoqA0VzhspVht5Zu8lxaXjIYIBWILHpRotYkCCcQA==';
const ONBOARDING_EXTERNAL_DEPENDENCIES = Object.freeze({
  ajv: '8.20.0',
  esbuild: '0.25.5',
  'fs-ext': '2.1.1',
  fastify: '5.10.0',
  'node-addon-api': '8.5.0',
  'node-gyp': '11.2.0',
});
const ONBOARDING_WORKSPACE_DEPENDENCIES = Object.freeze({
  '@scene-glass/contracts': 'link:../contracts',
  '@scene-glass/core': 'link:../core',
  '@scene-glass/server': 'link:../server',
});
const CANONICAL_NATIVE_BUILD_SCRIPT =
  'node ../../node_modules/.pnpm/node-gyp@11.2.0/node_modules/node-gyp/bin/node-gyp.js rebuild --directory .';
function canonicalNodeGypRebuildShimSource(): string {
  return [
    '#!/bin/sh',
    'basedir=$(dirname "$(echo "$0" | sed -e \'s,\\\\,/,g\')")',
    '',
    'case `uname` in',
    '    *CYGWIN*|*MINGW*|*MSYS*)',
    '        if command -v cygpath > /dev/null 2>&1; then',
    '            basedir=`cygpath -w "$basedir"`',
    '        fi',
    '    ;;',
    'esac',
    '',
    'if [ -x "$basedir/node" ]; then',
    '  exec "$basedir/node"  "$basedir/../node-gyp/bin/node-gyp.js" "$@"',
    'else',
    '  exec node  "$basedir/../node-gyp/bin/node-gyp.js" "$@"',
    'fi',
    '',
  ].join('\n');
}
const execFileAsync = promisify(execFile);
const bootstrapVerifierPath = fileURLToPath(
  new URL('../../scripts/verify-bootstrap.mjs', import.meta.url),
);
const artifactVerifierSourcePath = fileURLToPath(
  new URL('../../packages/onboarding/scripts/verify-artifacts.mjs', import.meta.url),
);
const onboardingCliSourcePath = fileURLToPath(
  new URL('../../packages/onboarding/src/cli.ts', import.meta.url),
);
const tsxLoaderPath = fileURLToPath(
  new URL('../../node_modules/tsx/dist/loader.mjs', import.meta.url),
);
const ARTIFACT_VERIFIER_DEADLINE_MS = 5_000;
const ARTIFACT_VERIFIER_CLEANUP_DEADLINE_MS = 1_000;
const ARTIFACT_CHILD_GROUP_CLEANUP_DEADLINE_MS = 1_000;

afterEach(async () => {
  await Promise.all(
    [...temporaryRoots].map(async (root) => {
      temporaryRoots.delete(root);
      await rm(root, { force: true, recursive: true });
    }),
  );
});
async function verifyBootstrapFixture({ root }: { root: string }): Promise<unknown> {
  const expectedLockHash = createHash('sha256')
    .update(await readFile(join(root, 'pnpm-lock.yaml')))
    .digest('hex');
  return verifyBootstrapFixtureAt({ root, expectedLockHash });
}
type ChildExit = {
  signal: NodeJS.Signals | null;
  status: number | null;
};

type ArtifactInvocationState = {
  invocationLog: 'missing' | 'present' | 'unreadable';
  invocations: Array<{ command: string; pid?: number }>;
};

const delay = (milliseconds: number) =>
  new Promise<void>((resolveDelay) => {
    setTimeout(resolveDelay, milliseconds);
  });
async function waitForFileText(path: string, expected: string): Promise<string> {
  const deadline = Date.now() + ARTIFACT_VERIFIER_DEADLINE_MS;
  let contents = '';
  while (Date.now() < deadline) {
    try {
      contents = await readFile(path, 'utf8');
      if (contents.includes(expected)) {
        return contents;
      }
    } catch (error) {
      if (!hasErrorCode(error, 'ENOENT')) {
        throw error;
      }
    }
    await delay(25);
  }
  throw new Error(`timed out waiting for ${expected} in ${path}: ${contents}`);
}

function hasErrorCode(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === code;
}

function isMissingProcess(error: unknown): boolean {
  return hasErrorCode(error, 'ESRCH');
}
function isMissingOrForeignProcessGroup(error: unknown): boolean {
  // Verifier children inherit our uid; EPERM therefore means the numeric pgid was reused.
  return isMissingProcess(error) || hasErrorCode(error, 'EPERM');
}
async function writeTrustedCliConfig(
  root: string,
  projectId: string,
  framework: 'html' | 'react',
  credentialAuthority?: {
    readonly path: string;
    readonly device: string;
    readonly inode: string;
  },
): Promise<string> {
  const configPath = join(root, 'scene-glass.config.json');
  if (framework === 'html') {
    await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
  }
  const canonicalRoot = await realpath(root);
  const authority = credentialAuthority ?? {
    path: join(canonicalRoot, 'configured-credential-authority'),
    device: '1',
    inode: '2',
  };
  await Promise.all([
    writeFile(
      configPath,
      `${JSON.stringify(
        {
          schemaVersion: 1,
          projects: [
            {
              projectId,
              root,
              allowedOrigins: ['http://127.0.0.1:4175'],
              tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
              framework,
            },
          ],
        },
        null,
        2,
      )}\n`,
    ),
    writeFile(
      join(root, 'credential-authorities.v1.json'),
      `${JSON.stringify(
        {
          schemaVersion: 1,
          projects: [
            {
              projectId,
              tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
              canonicalRoot,
              credentialPath: authority.path,
              device: authority.device,
              inode: authority.inode,
            },
          ],
        },
        null,
        2,
      )}\n`,
    ),
  ]);
  return configPath;
}

async function createSelfAuthorizingDescriptorFixture(): Promise<{
  readonly configPath: string;
  readonly descriptorPath: string;
  readonly root: string;
}> {
  const root = await mkdtemp(join(tmpdir(), 'scene-glass-self-authorizing-descriptor-'));
  temporaryRoots.add(root);

  const configPath = await writeTrustedCliConfig(root, 'trusted-project', 'html');
  const descriptorPath = join(root, 'static-descriptor.json');
  await writeFile(
    descriptorPath,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        template: 'public/index.html',
        publicRoot: 'public',
        host: '127.0.0.1',
        port: 4174,
        projectId: 'self-authorized-project',
        loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
        credentialProjectId: 'self-authorized-project',
        credentialKey: 'SCENE_GLASS_HOST_TOKEN',
        navigation: 'document',
        readinessPath: '/__scene-glass/ready',
        approvedRootIdentity: { device: '1', inode: '2' },
        credentialAuthorities: [
          {
            projectId: 'self-authorized-project',
            path: join(root, 'credential-authority'),
            device: '1',
            inode: '3',
          },
        ],
      },
      null,
      2,
    )}\n`,
  );

  return { configPath, descriptorPath, root };
}

function observeChildExit(child: ChildProcess): Promise<ChildExit> {
  return new Promise((resolveExit, rejectExit) => {
    child.once('error', () => {
      rejectExit(new Error('artifact verifier process could not start'));
    });
    child.once('close', (status, signal) => {
      resolveExit({ status, signal });
    });
  });
}

function isArtifactInvocationRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function observedArtifactInvocationState(root: string): Promise<ArtifactInvocationState> {
  let contents: string;
  try {
    contents = await readFile(join(root, 'cli-invocations.ndjson'), 'utf8');
  } catch (error) {
    return {
      invocationLog: hasErrorCode(error, 'ENOENT') ? 'missing' : 'unreadable',
      invocations: [],
    };
  }

  const invocations = contents
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => {
      try {
        const entry: unknown = JSON.parse(line);
        if (!isArtifactInvocationRecord(entry)) {
          return { command: '<malformed>' };
        }
        const { command, pid } = entry;
        return {
          command: typeof command === 'string' ? command : '<malformed>',
          ...(typeof pid === 'number' && Number.isSafeInteger(pid) ? { pid } : {}),
        };
      } catch {
        return { command: '<malformed>' };
      }
    });
  return { invocationLog: 'present', invocations };
}

function observedArtifactVerifierState(
  verifier: ChildProcess,
  invocationState: ArtifactInvocationState,
): string {
  return JSON.stringify({
    invocationLog: invocationState.invocationLog,
    invocations: invocationState.invocations,
    verifier: {
      exitCode: verifier.exitCode,
      killed: verifier.killed,
      signalCode: verifier.signalCode,
    },
  });
}
function staticFixtureServerPid(invocationState: ArtifactInvocationState): number | undefined {
  const staticPreview = invocationState.invocations.find(
    (invocation) =>
      invocation.command === 'static-preview' && invocation.pid !== undefined && invocation.pid > 0,
  );
  return staticPreview?.pid;
}

async function waitForStaticFixtureServerPid(
  root: string,
  verifier: ChildProcess,
): Promise<number> {
  const deadline = Date.now() + ARTIFACT_VERIFIER_DEADLINE_MS;
  let invocationState = await observedArtifactInvocationState(root);

  while (Date.now() < deadline) {
    const staticPreviewPid = staticFixtureServerPid(invocationState);
    if (staticPreviewPid !== undefined) {
      return staticPreviewPid;
    }
    if (verifier.exitCode !== null || verifier.signalCode !== null) {
      throw new Error(
        `artifact verifier exited before static fixture startup: ${observedArtifactVerifierState(
          verifier,
          invocationState,
        )}`,
      );
    }

    await delay(25);
    invocationState = await observedArtifactInvocationState(root);
  }

  throw new Error(
    `artifact verifier did not record a static fixture server PID within ${ARTIFACT_VERIFIER_DEADLINE_MS}ms: ${observedArtifactVerifierState(
      verifier,
      invocationState,
    )}`,
  );
}

async function waitForArtifactVerifierExit(
  exit: Promise<ChildExit>,
  root: string,
  verifier: ChildProcess,
): Promise<ChildExit> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      exit,
      new Promise<never>((_, rejectExit) => {
        timeout = setTimeout(() => {
          void observedArtifactInvocationState(root).then((invocationState) => {
            rejectExit(
              new Error(
                `artifact verifier did not terminate within ${ARTIFACT_VERIFIER_DEADLINE_MS}ms: ${observedArtifactVerifierState(
                  verifier,
                  invocationState,
                )}`,
              ),
            );
          });
        }, ARTIFACT_VERIFIER_DEADLINE_MS);
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

function processGroupExists(processGroup: number): boolean {
  try {
    process.kill(-processGroup, 0);
    return true;
  } catch (error) {
    if (isMissingOrForeignProcessGroup(error)) {
      return false;
    }
    throw new Error('could not inspect static fixture process group');
  }
}
async function waitForOwnedArtifactChildProcessGroupExit(processGroup: number): Promise<boolean> {
  const deadline = Date.now() + ARTIFACT_CHILD_GROUP_CLEANUP_DEADLINE_MS;
  while (processGroupExists(processGroup)) {
    if (Date.now() >= deadline) {
      return false;
    }
    await delay(25);
  }
  return true;
}

async function drainOwnedArtifactChildProcessGroup(processGroup: number): Promise<void> {
  if (!processGroupExists(processGroup)) {
    return;
  }
  try {
    process.kill(-processGroup, 'SIGTERM');
  } catch (error) {
    if (!isMissingOrForeignProcessGroup(error)) {
      throw new Error('could not terminate owned artifact child process group');
    }
  }
  if (await waitForOwnedArtifactChildProcessGroupExit(processGroup)) {
    return;
  }
  try {
    process.kill(-processGroup, 'SIGKILL');
  } catch (error) {
    if (!isMissingOrForeignProcessGroup(error)) {
      throw new Error('could not force-kill owned artifact child process group');
    }
  }
  if (!(await waitForOwnedArtifactChildProcessGroupExit(processGroup))) {
    throw new Error('owned artifact child process group survived bounded cleanup');
  }
}

async function waitForProcessGroupExit(
  processGroup: number,
  root: string,
  verifier: ChildProcess,
): Promise<void> {
  const deadline = Date.now() + ARTIFACT_VERIFIER_DEADLINE_MS;
  while (processGroupExists(processGroup)) {
    if (Date.now() >= deadline) {
      const invocationState = await observedArtifactInvocationState(root);
      throw new Error(
        `static fixture process group survived verifier termination: ${observedArtifactVerifierState(
          verifier,
          invocationState,
        )}`,
      );
    }
    await delay(25);
  }
}

function killStaticFixtureProcessGroup(processGroup: number): void {
  try {
    process.kill(-processGroup, 'SIGKILL');
  } catch (error) {
    if (!isMissingOrForeignProcessGroup(error)) {
      throw new Error('could not kill static fixture process group');
    }
  }
}

function killArtifactVerifier(verifier: ChildProcess): void {
  if (verifier.exitCode !== null || verifier.signalCode !== null) {
    return;
  }
  try {
    verifier.kill('SIGKILL');
  } catch {
    // The verifier already exited between its observed state and the kill attempt.
  }
}

async function waitForArtifactVerifierCleanup(exit: Promise<ChildExit>): Promise<void> {
  await Promise.race([exit.catch(() => undefined), delay(ARTIFACT_VERIFIER_CLEANUP_DEADLINE_MS)]);
}

describe('onboarding no-script bootstrap', () => {
  it('enforces the reviewed policy and exact bootstrap timeline', async () => {
    const root = await bootstrapFixture();

    await expect(verifyBootstrapFixture({ root })).resolves.toMatchObject({
      manifestLifecyclePackages: ['esbuild@0.25.5', 'esbuild@0.28.1', 'fs-ext@2.1.1'],
      manifestUnreviewedLifecyclePackages: [],
      reviewedPackages: ['esbuild@0.25.5', 'esbuild@0.28.1', 'fs-ext@2.1.1'],
    });
    expect(BOOTSTRAP_TIMELINE).toEqual([
      'corepack pnpm install --frozen-lockfile --ignore-scripts',
      'node scripts/verify-bootstrap.mjs',
      'corepack pnpm rebuild fs-ext esbuild',
      'corepack pnpm --filter @scene-glass/onboarding run build:native',
      'node packages/onboarding/scripts/build-runtime.mjs',
      'node packages/onboarding/scripts/verify-artifacts.mjs',
    ]);
  });
  it('does not expose a tautological ignored-build policy result', async () => {
    const root = await bootstrapFixture();

    await expect(verifyBootstrapFixture({ root })).resolves.not.toHaveProperty('ignoredBuilds');
  });
  it('rejects oversized bootstrap documents and virtual-store entry floods before parsing', async () => {
    const oversizedManifestRoot = await bootstrapFixture();
    await writeFile(
      join(oversizedManifestRoot, 'package.json'),
      Buffer.alloc(512 * 1024 + 1, 0x20),
    );
    await expect(verifyBootstrapFixture({ root: oversizedManifestRoot })).rejects.toThrow(
      'package.json exceeds the document size limit',
    );

    const oversizedLockRoot = await bootstrapFixture();
    await writeFile(join(oversizedLockRoot, 'pnpm-lock.yaml'), Buffer.alloc(2 * 1024 * 1024 + 1));
    await expect(verifyBootstrapFixture({ root: oversizedLockRoot })).rejects.toThrow(
      'pnpm-lock.yaml exceeds the document size limit',
    );

    const floodRoot = await bootstrapFixture();
    const structuralDirectory = join(floodRoot, 'node_modules', '.pnpm', 'node_modules');
    for (let index = 0; index < 1_024; index += 1) {
      await writeFile(join(structuralDirectory, `entry-flood-${index}`), '');
    }
    await expect(verifyBootstrapFixture({ root: floodRoot })).rejects.toThrow(
      'pnpm virtual store structural node_modules directory exceeds the entry limit',
    );
  });
  it('binds production verification to the reviewed lock SHA-256', async () => {
    const root = await bootstrapFixture();

    await expect(verifyBootstrap({ root })).rejects.toThrow('pnpm-lock.yaml SHA-256');
    await expect(
      verifyBootstrapFixtureAt({ root, expectedLockHash: '0'.repeat(64) }),
    ).rejects.toThrow('pnpm-lock.yaml SHA-256');
    await expect(verifyBootstrapFixtureAt({ root })).rejects.toThrow(
      'verifyBootstrapFixture requires a lowercase SHA-256 expectedLockHash',
    );
  });
  it('requires the exact canonical workspace source', async () => {
    const root = await bootstrapFixture();
    const workspacePath = join(root, 'pnpm-workspace.yaml');
    const workspace = await readFile(workspacePath, 'utf8');
    await writeFile(workspacePath, workspace.replace("'apps/*'", "'examples/*'"));

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'pnpm-workspace.yaml source must be exactly',
    );
  });

  it('rejects malformed and duplicate allowBuilds entries', async () => {
    const malformedRoot = await bootstrapFixture();
    const malformedPath = join(malformedRoot, 'pnpm-workspace.yaml');
    const malformed = await readFile(malformedPath, 'utf8');
    await writeFile(malformedPath, malformed.replace('  esbuild: true', '  esbuild: yes'));

    await expect(verifyBootstrapFixture({ root: malformedRoot })).rejects.toThrow(
      'invalid allowBuilds entry:   esbuild: yes',
    );

    const duplicateRoot = await bootstrapFixture();
    const duplicatePath = join(duplicateRoot, 'pnpm-workspace.yaml');
    const duplicate = await readFile(duplicatePath, 'utf8');
    await writeFile(
      duplicatePath,
      duplicate.replace('  fs-ext: true', '  esbuild: true\n  fs-ext: true'),
    );

    await expect(verifyBootstrapFixture({ root: duplicateRoot })).rejects.toThrow(
      'repeats allowBuilds entry esbuild',
    );
  });
  it('rejects YAML aliases and merge keys in workspace build policy', async () => {
    const aliasRoot = await bootstrapFixture();
    const aliasWorkspacePath = join(aliasRoot, 'pnpm-workspace.yaml');
    const aliasWorkspace = await readFile(aliasWorkspacePath, 'utf8');
    await writeFile(
      aliasWorkspacePath,
      aliasWorkspace.replace(
        'allowBuilds:\n  esbuild: true\n  fs-ext: true',
        'allowBuilds: *approvedBuilds',
      ),
    );

    await expect(verifyBootstrapFixture({ root: aliasRoot })).rejects.toThrow(
      'pnpm-workspace.yaml must not use YAML aliases or anchors',
    );

    const mergeRoot = await bootstrapFixture();
    const mergeWorkspacePath = join(mergeRoot, 'pnpm-workspace.yaml');
    const mergeWorkspace = await readFile(mergeWorkspacePath, 'utf8');
    await writeFile(
      mergeWorkspacePath,
      mergeWorkspace.replace(
        'allowBuilds:\n  esbuild: true\n  fs-ext: true',
        'allowBuilds:\n  <<: { esbuild: true, fs-ext: true }',
      ),
    );

    await expect(verifyBootstrapFixture({ root: mergeRoot })).rejects.toThrow(
      'pnpm-workspace.yaml must not use YAML merge keys',
    );

    const punctuationAnchorRoot = await bootstrapFixture();
    const punctuationAnchorPath = join(punctuationAnchorRoot, 'pnpm-workspace.yaml');
    const punctuationAnchorWorkspace = await readFile(punctuationAnchorPath, 'utf8');
    await writeFile(
      punctuationAnchorPath,
      punctuationAnchorWorkspace.replace(
        'allowBuilds:\n  esbuild: true\n  fs-ext: true',
        'allowBuilds: &.정책\n  esbuild: true\n  fs-ext: true',
      ),
    );

    await expect(verifyBootstrapFixture({ root: punctuationAnchorRoot })).rejects.toThrow(
      'pnpm-workspace.yaml must not use YAML aliases or anchors',
    );

    const taggedMergeRoot = await bootstrapFixture();
    const taggedMergePath = join(taggedMergeRoot, 'pnpm-workspace.yaml');
    const taggedMergeWorkspace = await readFile(taggedMergePath, 'utf8');
    await writeFile(
      taggedMergePath,
      taggedMergeWorkspace.replace(
        'allowBuilds:\n  esbuild: true\n  fs-ext: true',
        "allowBuilds:\n  esbuild: true\n  fs-ext: true\n!!merge '<<': { dangerousBuilds: true }",
      ),
    );

    await expect(verifyBootstrapFixture({ root: taggedMergeRoot })).rejects.toThrow(
      'pnpm-workspace.yaml must not use YAML merge keys',
    );
  });
  it('rejects every alternate and duplicate workspace build policy authority', async () => {
    for (const policy of [
      'onlyBuiltDependencies',
      'ignoredBuiltDependencies',
      'neverBuiltDependencies',
      'dangerouslyAllowAllBuilds',
    ]) {
      const root = await bootstrapFixture();
      const workspacePath = join(root, 'pnpm-workspace.yaml');
      const workspace = await readFile(workspacePath, 'utf8');
      await writeFile(
        workspacePath,
        workspace.replace('strictDepBuilds: true', `${policy}: true\nstrictDepBuilds: true`),
      );

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
        `pnpm-workspace.yaml must not declare alternate build policy ${policy}`,
      );
    }
    const quotedPolicyRoot = await bootstrapFixture();
    const quotedPolicyPath = join(quotedPolicyRoot, 'pnpm-workspace.yaml');
    const quotedPolicyWorkspace = await readFile(quotedPolicyPath, 'utf8');
    await writeFile(
      quotedPolicyPath,
      quotedPolicyWorkspace.replace(
        'strictDepBuilds: true',
        '"dangerouslyAllowAllBuilds": false\nstrictDepBuilds: true',
      ),
    );
    await expect(verifyBootstrapFixture({ root: quotedPolicyRoot })).rejects.toThrow(
      'pnpm-workspace.yaml must not declare alternate build policy dangerouslyAllowAllBuilds',
    );

    for (const [policy, expected] of [
      ['allowBuilds', 'pnpm-workspace.yaml must declare exactly one allowBuilds policy'],
      ['strictDepBuilds', 'pnpm-workspace.yaml must declare exactly one strictDepBuilds policy'],
    ] as const) {
      const root = await bootstrapFixture();
      const workspacePath = join(root, 'pnpm-workspace.yaml');
      const workspace = await readFile(workspacePath, 'utf8');
      await writeFile(
        workspacePath,
        workspace.replace('strictDepBuilds: true', `strictDepBuilds: true\n${policy}: true`),
      );

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(expected);
    }
  });

  it('rejects alternate build policy authorities in root manifest fields', async () => {
    for (const policy of [
      'onlyBuiltDependencies',
      'ignoredBuiltDependencies',
      'neverBuiltDependencies',
      'dangerouslyAllowAllBuilds',
    ]) {
      const root = await bootstrapFixture();
      const packagePath = join(root, 'package.json');
      const rootPackage = JSON.parse(await readFile(packagePath, 'utf8'));
      rootPackage[policy] = true;
      await writeFile(packagePath, `${JSON.stringify(rootPackage, null, 2)}\n`);

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
        `package.json must not declare build policy ${policy}`,
      );

      const pnpmRoot = await bootstrapFixture();
      const pnpmPackagePath = join(pnpmRoot, 'package.json');
      const pnpmPackage = JSON.parse(await readFile(pnpmPackagePath, 'utf8'));
      pnpmPackage.pnpm = { [policy]: true };
      await writeFile(pnpmPackagePath, `${JSON.stringify(pnpmPackage, null, 2)}\n`);

      await expect(verifyBootstrapFixture({ root: pnpmRoot })).rejects.toThrow(
        'package.json must not declare a pnpm policy object',
      );
    }
    const pnpmObjectRoot = await bootstrapFixture();
    const pnpmObjectPath = join(pnpmObjectRoot, 'package.json');
    const pnpmObject = JSON.parse(await readFile(pnpmObjectPath, 'utf8'));
    pnpmObject.pnpm = { resolutionMode: 'highest' };
    await writeFile(pnpmObjectPath, `${JSON.stringify(pnpmObject, null, 2)}\n`);

    await expect(verifyBootstrapFixture({ root: pnpmObjectRoot })).rejects.toThrow(
      'package.json must not declare a pnpm policy object',
    );
  });
  it('requires the supported Corepack-bearing Node 24 engine line', async () => {
    const root = await bootstrapFixture();
    const packagePath = join(root, 'package.json');
    const manifest = await readFile(packagePath, 'utf8');
    await writeFile(packagePath, manifest.replace('">=24 <25"', '">=24"'));

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'package.json engines.node must be exactly ">=24 <25"',
    );
  });
  it('accepts only a balanced pnpm peer context after exact importer and snapshot bases', async () => {
    const peerContextRoot = await bootstrapFixture();
    const peerContextPath = join(peerContextRoot, 'pnpm-lock.yaml');
    const peerContextLock = await readFile(peerContextPath, 'utf8');
    const peerContext = peerContextLock
      .replace(
        '      fastify:\n        specifier: 5.10.0\n        version: 5.10.0',
        '      fastify:\n        specifier: 5.10.0\n        version: 5.10.0(@types/node@24.13.3)(tsx@4.23.1(esbuild@0.28.1))',
      )
      .replace(
        '  fastify@5.10.0: {}',
        '  fastify@5.10.0(@types/node@24.13.3)(tsx@4.23.1(esbuild@0.28.1)): {}',
      );
    await writeFile(peerContextPath, peerContext);
    const peerStoreEntry = 'fastify@5.10.0_@types+node@24.13.3_tsx@4.23.1_esbuild@0.28.1_';
    await rename(
      join(peerContextRoot, 'node_modules', '.pnpm', 'fastify@5.10.0'),
      join(peerContextRoot, 'node_modules', '.pnpm', peerStoreEntry),
    );
    const importerFastify = join(
      peerContextRoot,
      'packages',
      'onboarding',
      'node_modules',
      'fastify',
    );
    await rm(importerFastify);
    await symlink(
      `../../../node_modules/.pnpm/${peerStoreEntry}/node_modules/fastify`,
      importerFastify,
    );

    await expect(verifyBootstrapFixture({ root: peerContextRoot })).resolves.toBeDefined();

    const invalidSuffixRoot = await bootstrapFixture();
    const invalidSuffixPath = join(invalidSuffixRoot, 'pnpm-lock.yaml');
    const invalidSuffixLock = await readFile(invalidSuffixPath, 'utf8');
    await writeFile(
      invalidSuffixPath,
      invalidSuffixLock.replace(
        '      fastify:\n        specifier: 5.10.0\n        version: 5.10.0',
        '      fastify:\n        specifier: 5.10.0\n        version: 5.10.0-invalid',
      ),
    );

    await expect(verifyBootstrapFixture({ root: invalidSuffixRoot })).rejects.toThrow(
      'fastify version must be "5.10.0" with only pnpm peer suffixes',
    );
    for (const [malformedSuffix, expectedMessage] of [
      [
        '5.10.0(@types/node@24.13.3)(tsx@4.23.1(esbuild@0.28.1)',
        'fastify version has an invalid pnpm peer suffix',
      ],
      [
        '5.10.0(@types/node@24.13.3))(tsx@4.23.1(esbuild@0.28.1))',
        'fastify version must be "5.10.0" with only pnpm peer suffixes',
      ],
    ] as const) {
      const malformedNestedRoot = await bootstrapFixture();
      const malformedNestedPath = join(malformedNestedRoot, 'pnpm-lock.yaml');
      const malformedNestedLock = await readFile(malformedNestedPath, 'utf8');
      await writeFile(
        malformedNestedPath,
        malformedNestedLock.replace(
          '      fastify:\n        specifier: 5.10.0\n        version: 5.10.0',
          `      fastify:\n        specifier: 5.10.0\n        version: ${malformedSuffix}`,
        ),
      );
      await expect(verifyBootstrapFixture({ root: malformedNestedRoot })).rejects.toThrow(
        expectedMessage,
      );
    }

    const nearPrefixRoot = await bootstrapFixture();
    const nearPrefixPath = join(nearPrefixRoot, 'pnpm-lock.yaml');
    const nearPrefixLock = await readFile(nearPrefixPath, 'utf8');
    await writeFile(nearPrefixPath, nearPrefixLock.replace('  tsx@4.23.1:', '  tsx@4.23.10:'));

    await expect(verifyBootstrapFixture({ root: nearPrefixRoot })).rejects.toThrow(
      'tsx snapshot must be "4.23.1" with only pnpm peer suffixes',
    );
  });
  it('parses the complete onboarding importer without duplicate or unknown workspace records', async () => {
    const flowRecordRoot = await bootstrapFixture();
    const flowRecordPath = join(flowRecordRoot, 'pnpm-lock.yaml');
    const flowRecordLock = await readFile(flowRecordPath, 'utf8');
    await writeFile(
      flowRecordPath,
      flowRecordLock.replace(
        '      esbuild:\n        specifier: 0.25.5\n        version: 0.25.5',
        '      esbuild: {specifier: 0.25.5, version: 0.25.5}',
      ),
    );
    await expect(verifyBootstrapFixture({ root: flowRecordRoot })).resolves.toBeDefined();

    const duplicateDependencyRoot = await bootstrapFixture();
    const duplicateDependencyPath = join(duplicateDependencyRoot, 'pnpm-lock.yaml');
    const duplicateDependencyLock = await readFile(duplicateDependencyPath, 'utf8');
    const esbuildRecord = '      esbuild:\n        specifier: 0.25.5\n        version: 0.25.5';
    await writeFile(
      duplicateDependencyPath,
      duplicateDependencyLock.replace(esbuildRecord, `${esbuildRecord}\n${esbuildRecord}`),
    );
    await expect(verifyBootstrapFixture({ root: duplicateDependencyRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer dependencies repeats esbuild',
    );

    const duplicateSectionRoot = await bootstrapFixture();
    const duplicateSectionPath = join(duplicateSectionRoot, 'pnpm-lock.yaml');
    const duplicateSectionLock = await readFile(duplicateSectionPath, 'utf8');
    await writeFile(
      duplicateSectionPath,
      duplicateSectionLock.replace('    dependencies:\n', '    dependencies:\n    dependencies:\n'),
    );
    await expect(verifyBootstrapFixture({ root: duplicateSectionRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer repeats dependencies',
    );

    const quotedDuplicateRoot = await bootstrapFixture();
    const quotedDuplicatePath = join(quotedDuplicateRoot, 'pnpm-lock.yaml');
    const quotedDuplicateLock = await readFile(quotedDuplicatePath, 'utf8');
    await writeFile(
      quotedDuplicatePath,
      quotedDuplicateLock.replace(
        esbuildRecord,
        `${esbuildRecord}\n      "esbuild":\n        specifier: 0.25.5\n        version: 0.25.5`,
      ),
    );
    await expect(verifyBootstrapFixture({ root: quotedDuplicateRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer dependencies repeats esbuild',
    );

    const unknownWorkspaceRoot = await bootstrapFixture();
    const unknownWorkspacePath = join(unknownWorkspaceRoot, 'pnpm-lock.yaml');
    const unknownWorkspaceLock = await readFile(unknownWorkspacePath, 'utf8');
    await writeFile(
      unknownWorkspacePath,
      unknownWorkspaceLock.replace(
        '    dependencies:\n',
        '    dependencies:\n      @scene-glass/unreviewed:\n        specifier: workspace:*\n        version: link:../unreviewed\n',
      ),
    );
    await expect(verifyBootstrapFixture({ root: unknownWorkspaceRoot })).rejects.toThrow(
      'pnpm-lock.yaml onboarding importer references an unknown workspace package',
    );

    const unknownResolutionRoot = await bootstrapFixture();
    const unknownResolutionPath = join(unknownResolutionRoot, 'pnpm-lock.yaml');
    const unknownResolutionLock = await readFile(unknownResolutionPath, 'utf8');
    await writeFile(
      unknownResolutionPath,
      unknownResolutionLock.replace(
        '      @scene-glass/contracts:\n        specifier: workspace:*\n        version: link:../contracts',
        '      @scene-glass/contracts:\n        specifier: workspace:*\n        version: link:../unreviewed',
      ),
    );
    await expect(verifyBootstrapFixture({ root: unknownResolutionRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding @scene-glass/contracts version must be exactly "link:../contracts"',
    );

    const missingWorkspaceRoot = await bootstrapFixture();
    const missingWorkspacePath = join(missingWorkspaceRoot, 'pnpm-lock.yaml');
    const missingWorkspaceLock = await readFile(missingWorkspacePath, 'utf8');
    await writeFile(
      missingWorkspacePath,
      missingWorkspaceLock.replace(
        '      @scene-glass/core:\n        specifier: workspace:*\n        version: link:../core\n',
        '',
      ),
    );
    await expect(verifyBootstrapFixture({ root: missingWorkspaceRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer dependencies do not match the reviewed map',
    );
  });
  it('rejects missing importer links and missing reviewed snapshot edges', async () => {
    const missingImporterLinkRoot = await bootstrapFixture();
    await rm(join(missingImporterLinkRoot, 'packages', 'onboarding', 'node_modules', 'fastify'));
    await expect(verifyBootstrapFixture({ root: missingImporterLinkRoot })).rejects.toThrow(
      'onboarding importer realized dependency links do not exactly match the reviewed lock importer',
    );

    const missingSnapshotEdgeRoot = await bootstrapFixture();
    await rm(
      join(
        missingSnapshotEdgeRoot,
        'node_modules',
        '.pnpm',
        'tsx@4.23.1',
        'node_modules',
        'esbuild',
      ),
    );
    await expect(verifyBootstrapFixture({ root: missingSnapshotEdgeRoot })).rejects.toThrow(
      'pnpm virtual store realized dependency links do not exactly match its reviewed snapshot edges',
    );
  });

  it('ignores unrelated prepare scripts but rejects every bootstrap lifecycle script', async () => {
    const root = await bootstrapFixture();
    await writeExtractedManifest(root, 'strip-ansi@6.0.1', 'strip-ansi', {
      name: 'strip-ansi',
      version: '6.0.1',
      scripts: { prepare: 'node package-for-publication.js' },
    });

    await expect(verifyBootstrapFixture({ root })).resolves.toBeDefined();

    for (const lifecycle of [
      'preinstall',
      'install',
      'postinstall',
      'prebuild:native',
      'postbuild:native',
    ]) {
      await writeExtractedManifest(root, 'strip-ansi@6.0.1', 'strip-ansi', {
        name: 'strip-ansi',
        version: '6.0.1',
        scripts: { [lifecycle]: 'node exfiltrate.js' },
      });

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
        'unreviewed lifecycle scripts',
      );
    }
  });
  it('requires the canonical node-gyp entry and rebuild shim authority', async () => {
    const shimRoot = await bootstrapFixture();
    const shimPath = join(shimRoot, 'node_modules', '.pnpm', 'node_modules', '.bin', 'node-gyp');
    await writeFile(shimPath, '#!/bin/sh\nexec node ./unreviewed.js\n', { mode: 0o755 });

    await expect(verifyBootstrapFixture({ root: shimRoot })).rejects.toThrow(
      'canonical node-gyp rebuild shim source',
    );
    const basedirNodeRoot = await bootstrapFixture();
    const basedirNodePath = join(
      basedirNodeRoot,
      'node_modules',
      '.pnpm',
      'node_modules',
      '.bin',
      'node',
    );
    await writeFile(basedirNodePath, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await expect(verifyBootstrapFixture({ root: basedirNodeRoot })).rejects.toThrow(
      'unexpected canonical node-gyp rebuild shim $basedir/node',
    );

    const packageShimRoot = await bootstrapFixture();
    const packageShimPath = join(
      packageShimRoot,
      'node_modules',
      '.pnpm',
      'fs-ext@2.1.1',
      'node_modules',
      'fs-ext',
      'node_modules',
      '.bin',
      'node-gyp',
    );
    await mkdir(dirname(packageShimPath), { recursive: true });
    await writeFile(packageShimPath, '#!/bin/sh\nexec node ./unreviewed.js\n', { mode: 0o755 });
    await expect(verifyBootstrapFixture({ root: packageShimRoot })).rejects.toThrow(
      'unexpected package-local node-gyp rebuild shim',
    );

    const unqualifiedRoot = await bootstrapFixture();
    const onboardingPath = join(unqualifiedRoot, 'packages', 'onboarding', 'package.json');
    const onboarding = JSON.parse(await readFile(onboardingPath, 'utf8'));
    onboarding.scripts['build:native'] = 'node-gyp rebuild --directory .';
    await writeFile(onboardingPath, `${JSON.stringify(onboarding, null, 2)}\n`);

    await expect(verifyBootstrapFixture({ root: unqualifiedRoot })).rejects.toThrow(
      'packages/onboarding/package.json scripts.build:native must be exactly',
    );

    for (const hook of ['prebuild:native', 'postbuild:native']) {
      const hookRoot = await bootstrapFixture();
      const hookManifestPath = join(hookRoot, 'packages', 'onboarding', 'package.json');
      const hookManifest = JSON.parse(await readFile(hookManifestPath, 'utf8'));
      hookManifest.scripts[hook] = 'node exfiltrate.js';
      await writeFile(hookManifestPath, `${JSON.stringify(hookManifest, null, 2)}\n`);

      await expect(verifyBootstrapFixture({ root: hookRoot })).rejects.toThrow(
        `packages/onboarding/package.json scripts.${hook} must be exactly undefined`,
      );
    }

    const manifestRoot = await bootstrapFixture();
    const nodeGypManifestPath = join(
      manifestRoot,
      'node_modules',
      '.pnpm',
      'node-gyp@11.2.0',
      'node_modules',
      'node-gyp',
      'package.json',
    );
    const nodeGypManifest = JSON.parse(await readFile(nodeGypManifestPath, 'utf8'));
    nodeGypManifest.bin = './bin/shadow.js';
    await writeFile(nodeGypManifestPath, `${JSON.stringify(nodeGypManifest, null, 2)}\n`);

    await expect(verifyBootstrapFixture({ root: manifestRoot })).rejects.toThrow(
      'canonical node-gyp manifest bin must be exactly "./bin/node-gyp.js"',
    );

    const entryRoot = await bootstrapFixture();
    const entryPath = join(
      entryRoot,
      'node_modules',
      '.pnpm',
      'node-gyp@11.2.0',
      'node_modules',
      'node-gyp',
      'bin',
      'node-gyp.js',
    );
    await rm(entryPath);
    await symlink('../package.json', entryPath);

    await expect(verifyBootstrapFixture({ root: entryRoot })).rejects.toThrow(
      'canonical node-gyp entry must be a regular non-symlink file',
    );
  });
  it('inventories implicit node-gyp install hooks from binding.gyp', async () => {
    const reviewedRoot = await bootstrapFixture();
    const reviewedPackageRoot = join(
      reviewedRoot,
      'node_modules',
      '.pnpm',
      'esbuild@0.25.5',
      'node_modules',
      'esbuild',
    );
    await writeFile(join(reviewedPackageRoot, 'binding.gyp'), '{}\n');

    await expect(verifyBootstrapFixture({ root: reviewedRoot })).rejects.toThrow(
      'lifecycle scripts for esbuild@0.25.5 do not match the reviewed scripts',
    );

    const unreviewedRoot = await bootstrapFixture();
    await writeExtractedManifest(unreviewedRoot, 'strip-ansi@6.0.1', 'strip-ansi', {
      name: 'strip-ansi',
      version: '6.0.1',
    });
    const unreviewedPackageRoot = join(
      unreviewedRoot,
      'node_modules',
      '.pnpm',
      'strip-ansi@6.0.1',
      'node_modules',
      'strip-ansi',
    );
    await writeFile(join(unreviewedPackageRoot, 'binding.gyp'), '{}\n');

    await expect(verifyBootstrapFixture({ root: unreviewedRoot })).rejects.toThrow(
      'declares unreviewed lifecycle scripts for strip-ansi@6.0.1',
    );

    const symlinkRoot = await bootstrapFixture();
    const symlinkPackageRoot = join(
      symlinkRoot,
      'node_modules',
      '.pnpm',
      'esbuild@0.25.5',
      'node_modules',
      'esbuild',
    );
    await symlink('package.json', join(symlinkPackageRoot, 'binding.gyp'));

    await expect(verifyBootstrapFixture({ root: symlinkRoot })).rejects.toThrow(
      'binding.gyp must be a regular non-symlink file',
    );
  });

  it('rejects an extracted reviewed name with an unreviewed version or script', async () => {
    const root = await bootstrapFixture();
    await writeExtractedManifest(root, 'fs-ext@2.1.1', 'fs-ext', {
      name: 'fs-ext',
      version: '2.1.2',
      scripts: { install: 'node-gyp configure build' },
    });

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'unreviewed fs-ext version 2.1.2',
    );

    await writeExtractedManifest(root, 'fs-ext@2.1.1', 'fs-ext', {
      name: 'fs-ext',
      version: '2.1.1',
      scripts: { install: 'node-gyp rebuild' },
    });
    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'do not match the reviewed scripts',
    );
  });

  it('accepts a canonical multiline flow mapping for reviewed lock integrity', async () => {
    const root = await bootstrapFixture();
    const lockPath = join(root, 'pnpm-lock.yaml');
    const lock = await readFile(lockPath, 'utf8');
    await writeFile(
      lockPath,
      lock.replace(
        `    resolution: {integrity: ${ESBUILD_0_25_5_INTEGRITY}}`,
        `    resolution:
      {
        integrity: ${ESBUILD_0_25_5_INTEGRITY},
      }`,
      ),
    );

    await expect(verifyBootstrapFixture({ root })).resolves.toMatchObject({
      reviewedPackages: ['esbuild@0.25.5', 'esbuild@0.28.1', 'fs-ext@2.1.1'],
    });
  });
  it('rejects each reviewed package integrity and misplaced integrity keys', async () => {
    for (const [packageKey, integrity] of [
      ['esbuild@0.25.5', ESBUILD_0_25_5_INTEGRITY],
      ['esbuild@0.28.1', ESBUILD_0_28_1_INTEGRITY],
      ['fs-ext@2.1.1', FS_EXT_INTEGRITY],
    ] as const) {
      const root = await bootstrapFixture();
      const lockPath = join(root, 'pnpm-lock.yaml');
      const lock = await readFile(lockPath, 'utf8');
      await writeFile(lockPath, lock.replace(integrity, 'sha512-not-the-reviewed-integrity'));

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(packageKey);
    }

    const root = await bootstrapFixture();
    const lockPath = join(root, 'pnpm-lock.yaml');
    const lock = await readFile(lockPath, 'utf8');
    await writeFile(
      lockPath,
      lock.replace(
        `    resolution: {integrity: ${ESBUILD_0_25_5_INTEGRITY}}`,
        `    resolution:\n      metadata:\n        integrity: ${ESBUILD_0_25_5_INTEGRITY}`,
      ),
    );

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'esbuild@0.25.5 record resolution must be a flow mapping',
    );
  });
  it('preserves the exact dual audited esbuild policy', async () => {
    const onboardingBundlerRoot = await bootstrapFixture();
    const onboardingBundlerPath = join(onboardingBundlerRoot, 'pnpm-lock.yaml');
    const onboardingBundlerLock = await readFile(onboardingBundlerPath, 'utf8');
    await writeFile(
      onboardingBundlerPath,
      onboardingBundlerLock.replace(
        '      esbuild:\n        specifier: 0.25.5\n        version: 0.25.5',
        '      esbuild:\n        specifier: 0.28.1\n        version: 0.28.1',
      ),
    );
    await expect(verifyBootstrapFixture({ root: onboardingBundlerRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding esbuild specifier must be exactly "0.25.5"',
    );

    for (const [consumer, version] of [['tsx', '4.23.1']] as const) {
      const root = await bootstrapFixture();
      const lockPath = join(root, 'pnpm-lock.yaml');
      const lock = await readFile(lockPath, 'utf8');
      await writeFile(
        lockPath,
        lock.replace(
          `  ${consumer}@${version}:\n    dependencies:\n      esbuild: 0.28.1`,
          `  ${consumer}@${version}:\n    dependencies:\n      esbuild: 0.25.5`,
        ),
      );

      await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
        `pnpm-lock.yaml ${consumer}@${version} esbuild must be exactly "0.28.1"`,
      );
    }

    const extraInventoryRoot = await bootstrapFixture();
    const extraInventoryPath = join(extraInventoryRoot, 'pnpm-lock.yaml');
    const extraInventoryLock = await readFile(extraInventoryPath, 'utf8');
    await writeFile(
      extraInventoryPath,
      extraInventoryLock.replace(
        `  esbuild@0.28.1:\n    resolution: {integrity: ${ESBUILD_0_28_1_INTEGRITY}`,
        `  esbuild@0.25.6:\n    resolution: {integrity: ${ESBUILD_0_25_5_INTEGRITY}}\n  esbuild@0.28.1:\n    resolution: {integrity: ${ESBUILD_0_28_1_INTEGRITY}`,
      ),
    );
    await expect(verifyBootstrapFixture({ root: extraInventoryRoot })).rejects.toThrow(
      'pnpm-lock.yaml must contain exactly esbuild@0.25.5',
    );
  });
  it('checks every external onboarding pin and resolved base version', async () => {
    for (const [name, version] of Object.entries(ONBOARDING_EXTERNAL_DEPENDENCIES)) {
      const dependencyRecord = `      ${name}:\n        specifier: ${version}\n        version: ${version}`;

      const specifierRoot = await bootstrapFixture();
      const specifierPath = join(specifierRoot, 'pnpm-lock.yaml');
      const specifierLock = await readFile(specifierPath, 'utf8');
      await writeFile(
        specifierPath,
        specifierLock.replace(
          dependencyRecord,
          dependencyRecord.replace(`specifier: ${version}`, `specifier: ${version}.0`),
        ),
      );
      await expect(verifyBootstrapFixture({ root: specifierRoot })).rejects.toThrow(
        `${name} specifier must be exactly`,
      );

      const resolutionRoot = await bootstrapFixture();
      const resolutionPath = join(resolutionRoot, 'pnpm-lock.yaml');
      const resolutionLock = await readFile(resolutionPath, 'utf8');
      await writeFile(
        resolutionPath,
        resolutionLock.replace(
          dependencyRecord,
          dependencyRecord.replace(`version: ${version}`, `version: ${version}.0`),
        ),
      );
      await expect(verifyBootstrapFixture({ root: resolutionRoot })).rejects.toThrow(
        `${name} version must be "${version}" with only pnpm peer suffixes`,
      );
    }

    const extraRoot = await bootstrapFixture();
    const extraPath = join(extraRoot, 'pnpm-lock.yaml');
    const extraLock = await readFile(extraPath, 'utf8');
    await writeFile(
      extraPath,
      extraLock.replace(
        '    dependencies:\n',
        '    dependencies:\n      unexpected-build-tool:\n        specifier: 1.0.0\n        version: 1.0.0\n',
      ),
    );
    await expect(verifyBootstrapFixture({ root: extraRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer dependencies do not match the reviewed map',
    );

    const missingRoot = await bootstrapFixture();
    const missingPath = join(missingRoot, 'pnpm-lock.yaml');
    const missingLock = await readFile(missingPath, 'utf8');
    await writeFile(missingPath, missingLock.replace('      node-gyp:', '      node-gyp-removed:'));
    await expect(verifyBootstrapFixture({ root: missingRoot })).rejects.toThrow(
      'pnpm-lock.yaml packages/onboarding importer dependencies do not match the reviewed map',
    );
  });

  it('rejects incomplete virtual-store manifests', async () => {
    const missingDirectoryRoot = await bootstrapFixture();
    await mkdir(join(missingDirectoryRoot, 'node_modules', '.pnpm', 'incomplete@1.0.0'), {
      recursive: true,
    });
    await expect(verifyBootstrapFixture({ root: missingDirectoryRoot })).rejects.toThrow(
      'missing package node_modules directory',
    );

    const missingManifestRoot = await bootstrapFixture();
    await mkdir(
      join(
        missingManifestRoot,
        'node_modules',
        '.pnpm',
        'missing@1.0.0',
        'node_modules',
        'missing',
      ),
      { recursive: true },
    );
    await expect(verifyBootstrapFixture({ root: missingManifestRoot })).rejects.toThrow(
      'pnpm virtual store is missing an own package manifest',
    );
  });
  it('rejects orphan virtual-store records without dependency edges', async () => {
    const root = await bootstrapFixture();
    await writeExtractedManifest(root, 'orphan@1.0.0', 'orphan', {
      name: 'orphan',
      version: '1.0.0',
    });

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'pnpm virtual store package entry does not resolve to a reviewed lock snapshot',
    );
  });
  it('rejects malformed virtual-store package entries and accepts internal dependency links', async () => {
    const emptyEntryRoot = await bootstrapFixture();
    await mkdir(join(emptyEntryRoot, 'node_modules', '.pnpm', 'empty@1.0.0', 'node_modules'), {
      recursive: true,
    });
    await expect(verifyBootstrapFixture({ root: emptyEntryRoot })).rejects.toThrow(
      'pnpm virtual store package entry must contain exactly one own package manifest',
    );

    const symlinkOnlyRoot = await bootstrapFixture();
    await writeVirtualStoreDependencySymlink(
      symlinkOnlyRoot,
      'symlink-only@1.0.0',
      'esbuild',
      '../../esbuild@0.25.5/node_modules/esbuild',
    );
    await expect(verifyBootstrapFixture({ root: symlinkOnlyRoot })).rejects.toThrow(
      'pnpm virtual store package entry must contain exactly one own package manifest',
    );

    const escapingLinkRoot = await bootstrapFixture();
    await writeExtractedManifest(escapingLinkRoot, 'escaping@1.0.0', 'escaping', {
      name: 'escaping',
      version: '1.0.0',
      dependencies: { outside: '1.0.0' },
    });
    await mkdir(join(escapingLinkRoot, 'outside'), { recursive: true });
    await writeVirtualStoreDependencySymlink(
      escapingLinkRoot,
      'escaping@1.0.0',
      'outside',
      '../../../../outside',
    );
    await expect(verifyBootstrapFixture({ root: escapingLinkRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink resolves outside the virtual store',
    );

    const internalLinkRoot = await bootstrapFixture();
    await writeExtractedManifest(internalLinkRoot, 'consumer-esbuild@1.0.0', 'consumer-esbuild', {
      name: 'consumer-esbuild',
      version: '1.0.0',
      dependencies: { esbuild: '0.25.5' },
    });
    await writeVirtualStoreDependencySymlink(
      internalLinkRoot,
      'consumer-esbuild@1.0.0',
      'esbuild',
      '../../esbuild@0.25.5/node_modules/esbuild',
    );
    await expect(verifyBootstrapFixture({ root: internalLinkRoot })).resolves.toBeDefined();
  });
  it('accepts declared npm aliases only when the target identity matches', async () => {
    const aliasRoot = await bootstrapFixture();
    await writeExtractedManifest(aliasRoot, 'alias-consumer@1.0.0', 'alias-consumer', {
      name: 'alias-consumer',
      version: '1.0.0',
      dependencies: { 'esbuild-alias': 'npm:esbuild@0.25.5' },
    });
    await writeVirtualStoreDependencySymlink(
      aliasRoot,
      'alias-consumer@1.0.0',
      'esbuild-alias',
      '../../esbuild@0.25.5/node_modules/esbuild',
    );

    await expect(verifyBootstrapFixture({ root: aliasRoot })).resolves.toBeDefined();

    const mismatchedAliasRoot = await bootstrapFixture();
    await writeExtractedManifest(mismatchedAliasRoot, 'alias-consumer@1.0.0', 'alias-consumer', {
      name: 'alias-consumer',
      version: '1.0.0',
      dependencies: { 'esbuild-alias': 'npm:esbuild@0.25.5' },
    });
    await writeVirtualStoreDependencySymlink(
      mismatchedAliasRoot,
      'alias-consumer@1.0.0',
      'esbuild-alias',
      '../../fs-ext@2.1.1/node_modules/fs-ext',
    );

    await expect(verifyBootstrapFixture({ root: mismatchedAliasRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink target manifest name does not match the dependency name',
    );
    const wrongVersionAliasRoot = await bootstrapFixture();
    await writeExtractedManifest(wrongVersionAliasRoot, 'alias-consumer@1.0.0', 'alias-consumer', {
      name: 'alias-consumer',
      version: '1.0.0',
      dependencies: { 'esbuild-alias': 'npm:esbuild@0.25.5' },
    });
    await writeVirtualStoreDependencySymlink(
      wrongVersionAliasRoot,
      'alias-consumer@1.0.0',
      'esbuild-alias',
      '../../esbuild@0.28.1/node_modules/esbuild',
    );

    await expect(verifyBootstrapFixture({ root: wrongVersionAliasRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink does not match its reviewed snapshot target',
    );
  });

  it('accepts only the reviewed structural package aliases', async () => {
    const root = await bootstrapFixture();
    await writeExtractedManifest(root, 'strip-ansi@6.0.1', 'strip-ansi', {
      name: 'strip-ansi',
      version: '6.0.1',
    });
    const structuralDirectory = join(root, 'node_modules', '.pnpm', 'node_modules');
    await mkdir(structuralDirectory, { recursive: true });
    await symlink(
      '../strip-ansi@6.0.1/node_modules/strip-ansi',
      join(structuralDirectory, 'strip-ansi-cjs'),
    );

    await expect(verifyBootstrapFixture({ root })).resolves.toBeDefined();
  });
  it('accepts only exact reviewed workspace dependency targets', async () => {
    const workspaceLinkRoot = await bootstrapFixture();
    const browserClientRoot = join(workspaceLinkRoot, 'packages', 'browser-client');
    await mkdir(browserClientRoot, { recursive: true });
    await writeFile(
      join(browserClientRoot, 'package.json'),
      `${JSON.stringify({ name: '@scene-glass/browser-client', version: '0.1.0' }, null, 2)}\n`,
    );
    await writeExtractedManifest(
      workspaceLinkRoot,
      'consumer-workspace@1.0.0',
      'consumer-workspace',
      {
        name: 'consumer-workspace',
        version: '1.0.0',
        dependencies: { '@scene-glass/browser-client': 'workspace:*' },
      },
    );
    await writeVirtualStoreDependencySymlink(
      workspaceLinkRoot,
      'consumer-workspace@1.0.0',
      '@scene-glass/browser-client',
      browserClientRoot,
    );

    await expect(verifyBootstrapFixture({ root: workspaceLinkRoot })).resolves.toBeDefined();

    const substitutedRoot = await bootstrapFixture();
    const expectedPackageRoot = join(substitutedRoot, 'packages', 'browser-client');
    const substitutedPackageRoot = join(substitutedRoot, 'packages', 'browser-client-copy');
    await Promise.all([
      mkdir(expectedPackageRoot, { recursive: true }),
      mkdir(substitutedPackageRoot, { recursive: true }),
    ]);
    const browserClientManifest = `${JSON.stringify(
      { name: '@scene-glass/browser-client', version: '0.1.0' },
      null,
      2,
    )}\n`;
    await Promise.all([
      writeFile(join(expectedPackageRoot, 'package.json'), browserClientManifest),
      writeFile(join(substitutedPackageRoot, 'package.json'), browserClientManifest),
    ]);
    await writeExtractedManifest(
      substitutedRoot,
      'consumer-workspace@1.0.0',
      'consumer-workspace',
      {
        name: 'consumer-workspace',
        version: '1.0.0',
        dependencies: { '@scene-glass/browser-client': 'workspace:*' },
      },
    );
    await writeVirtualStoreDependencySymlink(
      substitutedRoot,
      'consumer-workspace@1.0.0',
      '@scene-glass/browser-client',
      substitutedPackageRoot,
    );

    await expect(verifyBootstrapFixture({ root: substitutedRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink does not resolve to its reviewed workspace root',
    );
  });
  it('rejects an intermediate virtual-store node_modules symlink escape', async () => {
    const root = await bootstrapFixture();
    const outside = await mkdtemp(join(tmpdir(), 'scene-glass-bootstrap-escape-'));
    temporaryRoots.add(outside);

    await rm(join(root, 'node_modules', '.pnpm', 'node_modules'), {
      force: true,
      recursive: true,
    });
    await symlink(outside, join(root, 'node_modules', '.pnpm', 'node_modules'));

    await expect(verifyBootstrapFixture({ root })).rejects.toThrow(
      'pnpm virtual store structural entry must be a real directory',
    );
  });

  it('rejects structural dependency symlinks with mismatched target identities', async () => {
    const nameMismatchRoot = await bootstrapFixture();
    const structuralDirectory = join(nameMismatchRoot, 'node_modules', '.pnpm', 'node_modules');
    await mkdir(structuralDirectory, { recursive: true });
    await symlink('../fs-ext@2.1.1/node_modules/fs-ext', join(structuralDirectory, 'esbuild'));

    await expect(verifyBootstrapFixture({ root: nameMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink target manifest name does not match the dependency name',
    );
    const unreviewedTargetRoot = await bootstrapFixture();
    await writeExtractedManifest(
      unreviewedTargetRoot,
      'structural-surprise@1.0.0',
      'structural-surprise',
      { name: 'structural-surprise', version: '1.0.0' },
    );
    const unreviewedStructuralDirectory = join(
      unreviewedTargetRoot,
      'node_modules',
      '.pnpm',
      'node_modules',
    );
    await mkdir(unreviewedStructuralDirectory, { recursive: true });
    await symlink(
      '../structural-surprise@1.0.0/node_modules/structural-surprise',
      join(unreviewedStructuralDirectory, 'structural-surprise'),
    );

    await expect(verifyBootstrapFixture({ root: unreviewedTargetRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink does not resolve to a reviewed lock snapshot',
    );

    const shapeMismatchRoot = await bootstrapFixture();
    const nestedTarget = join(
      shapeMismatchRoot,
      'node_modules',
      '.pnpm',
      'esbuild@0.25.5',
      'node_modules',
      'esbuild',
      'not-a-store-entry',
    );
    await mkdir(nestedTarget, { recursive: true });
    await writeFile(
      join(nestedTarget, 'package.json'),
      `${JSON.stringify({ name: 'esbuild', version: '0.25.5' }, null, 2)}\n`,
    );
    const shapeStructuralDirectory = join(
      shapeMismatchRoot,
      'node_modules',
      '.pnpm',
      'node_modules',
    );
    await mkdir(shapeStructuralDirectory, { recursive: true });
    await symlink(
      '../esbuild@0.25.5/node_modules/esbuild/not-a-store-entry',
      join(shapeStructuralDirectory, 'esbuild'),
    );

    await expect(verifyBootstrapFixture({ root: shapeMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink must resolve to a canonical store package entry',
    );
  });

  it('rejects package-local dependency symlinks with mismatched target identities', async () => {
    const nameMismatchRoot = await bootstrapFixture();
    await writeExtractedManifest(nameMismatchRoot, 'consumer-esbuild@1.0.0', 'consumer-esbuild', {
      name: 'consumer-esbuild',
      version: '1.0.0',
      dependencies: { esbuild: '0.25.5' },
    });
    await writeVirtualStoreDependencySymlink(
      nameMismatchRoot,
      'consumer-esbuild@1.0.0',
      'esbuild',
      '../../fs-ext@2.1.1/node_modules/fs-ext',
    );

    await expect(verifyBootstrapFixture({ root: nameMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink target manifest name does not match the dependency name',
    );
    const versionMismatchRoot = await bootstrapFixture();
    await writeExtractedManifest(
      versionMismatchRoot,
      'consumer-esbuild@1.0.0',
      'consumer-esbuild',
      {
        name: 'consumer-esbuild',
        version: '1.0.0',
        dependencies: { esbuild: '0.25.5' },
      },
    );
    await writeVirtualStoreDependencySymlink(
      versionMismatchRoot,
      'consumer-esbuild@1.0.0',
      'esbuild',
      '../../esbuild@0.28.1/node_modules/esbuild',
    );

    await expect(verifyBootstrapFixture({ root: versionMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink does not match its reviewed snapshot target',
    );

    const peerMismatchRoot = await bootstrapFixture();
    await Promise.all([
      writeExtractedManifest(peerMismatchRoot, 'peer-consumer@1.0.0', 'peer-consumer', {
        name: 'peer-consumer',
        version: '1.0.0',
        dependencies: { 'peer-target': '1.0.0' },
      }),
      writeExtractedManifest(peerMismatchRoot, 'peer-target@1.0.0_peer-a@1.0.0', 'peer-target', {
        name: 'peer-target',
        version: '1.0.0',
      }),
      writeExtractedManifest(peerMismatchRoot, 'peer-target@1.0.0_peer-b@1.0.0', 'peer-target', {
        name: 'peer-target',
        version: '1.0.0',
      }),
    ]);
    await writeVirtualStoreDependencySymlink(
      peerMismatchRoot,
      'peer-consumer@1.0.0',
      'peer-target',
      '../../peer-target@1.0.0_peer-b@1.0.0/node_modules/peer-target',
    );

    await expect(verifyBootstrapFixture({ root: peerMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink does not match its reviewed snapshot target',
    );

    const shapeMismatchRoot = await bootstrapFixture();
    await writeExtractedManifest(shapeMismatchRoot, 'consumer-esbuild@1.0.0', 'consumer-esbuild', {
      name: 'consumer-esbuild',
      version: '1.0.0',
      dependencies: { esbuild: '0.25.5' },
    });
    const nestedTarget = join(
      shapeMismatchRoot,
      'node_modules',
      '.pnpm',
      'esbuild@0.25.5',
      'node_modules',
      'esbuild',
      'not-a-store-entry',
    );
    await mkdir(nestedTarget, { recursive: true });
    await writeFile(
      join(nestedTarget, 'package.json'),
      `${JSON.stringify({ name: 'esbuild', version: '0.25.5' }, null, 2)}\n`,
    );
    await writeVirtualStoreDependencySymlink(
      shapeMismatchRoot,
      'consumer-esbuild@1.0.0',
      'esbuild',
      '../../esbuild@0.25.5/node_modules/esbuild/not-a-store-entry',
    );

    await expect(verifyBootstrapFixture({ root: shapeMismatchRoot })).rejects.toThrow(
      'pnpm virtual store dependency symlink must resolve to a canonical store package entry',
    );
  });

  it('accepts only closed bootstrap CLI grammar', async () => {
    const timeline = await execFileAsync(
      process.execPath,
      [bootstrapVerifierPath, '--print-timeline'],
      { encoding: 'utf8' },
    );
    expect(timeline.stdout).toBe(`${BOOTSTRAP_TIMELINE.join('\n')}\n`);

    const invalidArguments: ReadonlyArray<readonly [string[], string]> = [
      [['--root', 'first', '--root', 'second'], 'duplicate option: --root'],
      [
        ['--print-timeline', '--root', 'fixture'],
        '--print-timeline cannot be combined with other arguments',
      ],
      [['--unknown'], 'unknown argument: --unknown'],
      [['mistyped-root'], 'unexpected positional argument: mistyped-root'],
      [['--print-timeline', '--print-timeline'], 'duplicate option: --print-timeline'],
    ];
    for (const [args, message] of invalidArguments) {
      await expect(
        execFileAsync(process.execPath, [bootstrapVerifierPath, ...args], { encoding: 'utf8' }),
      ).rejects.toMatchObject({ stderr: expect.stringContaining(message) });
    }
  });
  it('rejects self-authorizing descriptors against the trusted CLI registry', async () => {
    const fixture = await createSelfAuthorizingDescriptorFixture();

    await expect(
      execFileAsync(
        process.execPath,
        [
          '--import',
          tsxLoaderPath,
          onboardingCliSourcePath,
          'descriptor-check',
          '--descriptor',
          fixture.descriptorPath,
          '--kind',
          'static',
        ],
        {
          cwd: fixture.root,
          encoding: 'utf8',
          env: { ...process.env, SCENE_GLASS_CONFIG_PATH: fixture.configPath },
        },
      ),
    ).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining(
        '[SCG_STATIC_DESCRIPTOR_INVALID] [descriptor-check] command failed.',
      ),
    });
  });

  it('emits the exact Revision-9 manifest and verifies live framework probes and teardown', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);

    const cliHash = createHash('sha256')
      .update(await readFile(join(root, 'dist', 'cli.js')))
      .digest('hex');
    const addonHash = createHash('sha256')
      .update(await readFile(join(root, 'build', 'Release', 'secure_read.node')))
      .digest('hex');
    const expected = {
      schemaVersion: 1,
      platform: process.platform,
      arch: process.arch,
      nodeMajor: 24,
      napi: 9,
      addonSha256: addonHash,
      cliSha256: cliHash,
    };
    const manifestPath = join(root, 'dist', 'build-manifest.json');
    const canonicalManifest = `${JSON.stringify(expected, null, 2)}\n`;
    const verifierModule = artifactVerifierModule;
    expect('createBuildManifest' in verifierModule).toBe(false);
    await expect(writeFixtureBuildManifest(root)).resolves.toEqual(expected);
    expect(await readFile(manifestPath, 'utf8')).toBe(canonicalManifest);
    expect((await lstat(manifestPath)).mode & 0o777).toBe(0o644);
    await expect(verifyArtifacts({ root })).resolves.toEqual(expected);

    const invocations = (await readFile(join(root, 'cli-invocations.ndjson'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(invocations).toHaveLength(6);
    expect(invocations[0]).toEqual({ command: 'help', args: [] });
    expect(invocations[1].command).toBe('descriptor-check');
    expect(invocations[1].args).toEqual(['--descriptor', expect.any(String), '--kind', 'static']);
    expect(invocations[2].args).toEqual(['--descriptor', invocations[1].args[1]]);
    expect(JSON.stringify(invocations)).not.toContain('--help');
    expect(invocations.map((invocation) => invocation.command)).toEqual([
      'help',
      'descriptor-check',
      'static-preview',
      'static-loopback-probe',
      'static-loopback-probe',
      'static-preview-teardown',
    ]);
    expect(
      invocations
        .filter((invocation) => invocation.command === 'static-loopback-probe')
        .map((invocation) => invocation.path),
    ).toEqual(['/', '/__scene-glass/ready']);
    expect(invocations[5]).toEqual({ command: 'static-preview-teardown', signal: 'SIGTERM' });
    expect(JSON.stringify(invocations)).not.toContain('--dry-read');

    const descriptorPath = invocations[1].args[1] as string;
    const descriptor = JSON.parse(invocations[1].descriptor);
    expect(Object.keys(descriptor)).toEqual([
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
    ]);
    expect(descriptor).toMatchObject({
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port: expect.any(Number),
      projectId: 'artifact-verifier',
      loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
      credentialProjectId: 'artifact-verifier',
      credentialKey: 'SCENE_GLASS_HOST_TOKEN',
      navigation: 'document',
      readinessPath: '/__scene-glass/ready',
    });
    expect(descriptor.credentialAuthorities).toHaveLength(1);
    expect(Object.keys(descriptor.credentialAuthorities[0])).toEqual([
      'projectId',
      'path',
      'device',
      'inode',
    ]);
    expect(descriptor.credentialAuthorities[0]).toMatchObject({
      projectId: 'artifact-verifier',
      path: join(dirname(descriptorPath), 'credential-authority'),
      device: invocations[1].credentialIdentity.device,
      inode: invocations[1].credentialIdentity.inode,
    });
    expect(descriptor.approvedRootIdentity).toEqual(invocations[1].approvedRootIdentity);
    expect(invocations[1].approvedRootPath).toBe(join(dirname(descriptorPath), 'public'));
    expect(invocations[1].descriptor).toBe(`${JSON.stringify(descriptor, null, 2)}\n`);
    await expect(access(dirname(descriptorPath))).rejects.toMatchObject({ code: 'ENOENT' });
    for (const descriptorInvocation of invocations.filter(
      (invocation) =>
        invocation.command === 'static-preview' || invocation.command === 'managed-vite-preflight',
    )) {
      await expect(access(dirname(descriptorInvocation.args[1] as string))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    }
    expect(JSON.parse(await readFile(manifestPath, 'utf8'))).toEqual(expected);

    await writeFile(join(root, 'dist', 'cli.js'), '\n// tampered\n', { flag: 'a' });
    await expect(verifyArtifacts({ root })).rejects.toThrow(ArtifactVerificationError);

    await createArtifacts(root);
    await writeFile(join(root, 'build', 'Release', 'secure_read.node'), '\n// tampered\n', {
      flag: 'a',
    });
    await expect(verifyArtifacts({ root })).rejects.toThrow(ArtifactVerificationError);

    await createArtifacts(root);
    await rm(manifestPath);
    await expect(writeFixtureBuildManifest(root)).resolves.toEqual(expected);

    const cliPath = join(root, 'dist', 'cli.js');
    await rm(cliPath);
    await symlink(join(root, 'build', 'Release', 'secure_read.node'), cliPath);
    await expect(verifyArtifacts({ root })).rejects.toThrow(ArtifactVerificationError);

    await rm(cliPath);
    await createArtifacts(root);
    const extraLink = join(root, 'dist', 'cli-extra-link.js');
    await link(cliPath, extraLink);
    await expect(verifyArtifacts({ root })).rejects.toThrow(ArtifactVerificationError);

    await rm(extraLink);
    await chmod(cliPath, 0o644);
    await expect(verifyArtifacts({ root })).rejects.toThrow(ArtifactVerificationError);

    await createArtifacts(root);
    await writeFile(join(root, 'binding.gyp'), '{"targets":[{"defines":["NAPI_VERSION=8"]}]}\n');
    await expect(verifyArtifacts({ root })).rejects.toThrow(
      'native addon must declare exact Node-API 9',
    );

    await createArtifacts(root);
    await writeFile(
      manifestPath,
      `${JSON.stringify({ ...expected, schemaVersion: 2 }, null, 2)}\n`,
    );
    await expect(verifyArtifacts({ root })).rejects.toThrow('does not match this platform');

    await writeFile(manifestPath, `${JSON.stringify({ ...expected, napi: 10 }, null, 2)}\n`);
    await expect(verifyArtifacts({ root })).rejects.toThrow('does not match this platform');

    await writeFile(manifestPath, canonicalManifest);
    await chmod(manifestPath, 0o600);
    await expect(verifyArtifacts({ root })).rejects.toThrow('regular mode 0644 canonical manifest');
  });
  it('kills detached plain-Node CLI process groups before honoring verifier SIGTERM', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    await writeFixtureBuildManifest(root);

    const verifierPath = join(root, 'scripts', 'verify-artifacts.mjs');
    await mkdir(dirname(verifierPath), { recursive: true });
    await copyFile(artifactVerifierSourcePath, verifierPath);

    const verifier = spawn(process.execPath, [verifierPath], {
      cwd: root,
      stdio: 'ignore',
    });
    const verifierExit = observeChildExit(verifier);
    let staticFixtureProcessGroup: number | undefined;
    let staticFixtureCleanupComplete = false;

    try {
      staticFixtureProcessGroup = await waitForStaticFixtureServerPid(root, verifier);
      expect(verifier.kill('SIGTERM')).toBe(true);

      const exit = await waitForArtifactVerifierExit(verifierExit, root, verifier);
      expect(exit).toEqual({ status: null, signal: 'SIGTERM' });

      await waitForProcessGroupExit(staticFixtureProcessGroup, root, verifier);
      expect(processGroupExists(staticFixtureProcessGroup)).toBe(false);
      const staticPreviewInvocation = (await readFile(join(root, 'cli-invocations.ndjson'), 'utf8'))
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as { command?: unknown; args?: unknown })
        .find(
          (invocation) =>
            invocation.command === 'static-preview' &&
            Array.isArray(invocation.args) &&
            typeof invocation.args[1] === 'string',
        );
      if (
        staticPreviewInvocation === undefined ||
        !Array.isArray(staticPreviewInvocation.args) ||
        typeof staticPreviewInvocation.args[1] !== 'string'
      ) {
        throw new Error('static preview invocation did not expose a descriptor path');
      }
      await expect(access(dirname(staticPreviewInvocation.args[1]))).rejects.toMatchObject({
        code: 'ENOENT',
      });
      staticFixtureCleanupComplete = true;
    } finally {
      killArtifactVerifier(verifier);
      try {
        if (!staticFixtureCleanupComplete) {
          if (staticFixtureProcessGroup === undefined) {
            staticFixtureProcessGroup = staticFixtureServerPid(
              await observedArtifactInvocationState(root),
            );
          }
          if (staticFixtureProcessGroup !== undefined) {
            killStaticFixtureProcessGroup(staticFixtureProcessGroup);
          }
        }
      } finally {
        await waitForArtifactVerifierCleanup(verifierExit);
      }
    }
  });
  it('quiesces owned handle and tree finalizers and rejects late lifecycle work for both signals', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const cliPath = join(root, 'dist', 'cli.js');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');
    const verifierPath = join(root, 'scripts', 'verify-artifacts.mjs');
    await mkdir(dirname(verifierPath), { recursive: true });
    await copyFile(artifactVerifierSourcePath, verifierPath);

    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      const eventsPath = join(root, `signal-quiescence-${signal}.ndjson`);
      const runnerPath = join(root, `signal-quiescence-${signal}.mjs`);
      const ownedTreePath = join(root, `signal-owned-tree-${signal}`);
      const lateTreePath = join(root, `signal-late-tree-${signal}`);
      await writeFile(eventsPath, '');
      await writeFile(
        runnerPath,
        [
          "import { appendFile, mkdir, rm } from 'node:fs/promises';",
          "import { spawn } from 'node:child_process';",
          'import {',
          '  createArtifactVerifierSignalTestHarness,',
          '  createPlainNodeCliTestOnlyPorts,',
          '  verifyPlainNodeCli,',
          "} from './scripts/verify-artifacts.mjs';",
          '',
          'const [root, cli, expectedCliHash, eventsPath, ownedTreePath, lateTreePath] = process.argv.slice(2);',
          'const record = (event) => appendFile(eventsPath, `${event}\\n`);',
          'let releaseBarrier;',
          'const barrier = new Promise((resolve) => { releaseBarrier = resolve; });',
          'setInterval(() => {}, 1_000);',
          'let releaseTreeFinalizer;',
          'const treeFinalizerBarrier = new Promise((resolve) => { releaseTreeFinalizer = resolve; });',
          'const signalHarness = createArtifactVerifierSignalTestHarness({',
          '  onSignalShutdownStarted: (signal) => {',
          '    void record(`shutdown:${signal}`).then(releaseBarrier);',
          '  },',
          '});',
          'await mkdir(ownedTreePath);',
          'await mkdir(lateTreePath);',
          'signalHarness.registerTreeAuthority(async () => {',
          '  await treeFinalizerBarrier;',
          '  await rm(ownedTreePath, { force: true, recursive: true });',
          "  await record('tree-finalized');",
          '});',
          'const testOnly = createPlainNodeCliTestOnlyPorts({',
          '  afterFileHandleClose: async ({ phase }) => {',
          "    if (phase === 'pinned-cli-close') await record('handle-finalized');",
          '  },',
          '});',
          'await verifyPlainNodeCli({',
          '  root,',
          '  cli,',
          '  expectedCliHash,',
          '  testOnly,',
          '  beforePinnedExecution: async () => {',
          "    await record('barrier-ready');",
          '    await barrier;',
          "    await record('barrier-released');",
          '    try {',
          '      signalHarness.registerTreeAuthority(async () => {',
          '        await rm(lateTreePath, { force: true, recursive: true });',
          "        await record('late-tree-finalized');",
          '      });',
          '    } catch {',
          "      await record('late-tree-rejected');",
          '    }',
          "    const lateChild = spawn(process.execPath, ['--eval', 'setInterval(() => {}, 1_000)'], {",
          "      detached: true, stdio: 'ignore',",
          '    });',
          '    if (lateChild.pid === undefined) throw new Error("late child did not expose a process group");',
          '    lateChild.unref();',
          '    try {',
          '      signalHarness.registerProcessGroup(lateChild.pid);',
          '    } catch {',
          '      await record(`late-group-rejected:${lateChild.pid}`);',
          '    }',
          '    releaseTreeFinalizer();',
          '    await new Promise(() => {});',
          '  },',
          '});',
          '',
        ].join('\n'),
      );

      const verifier = spawn(
        process.execPath,
        [runnerPath, root, cliPath, expectedCliHash, eventsPath, ownedTreePath, lateTreePath],
        { cwd: root, stdio: 'ignore' },
      );
      const verifierExit = observeChildExit(verifier);
      let lateProcessGroup: number | undefined;
      try {
        await waitForFileText(eventsPath, 'barrier-ready');
        expect(verifier.kill(signal)).toBe(true);
        expect(await waitForArtifactVerifierExit(verifierExit, root, verifier)).toEqual({
          status: null,
          signal,
        });

        const events = await readFile(eventsPath, 'utf8');
        expect(events).toContain(`shutdown:${signal}\n`);
        expect(events).toContain('barrier-released\n');
        expect(events).toContain('late-tree-rejected\n');
        expect(events).toContain('late-tree-finalized\n');
        expect(events).toContain('tree-finalized\n');
        expect(events).toContain('handle-finalized\n');
        const lateGroup = events.match(/late-group-rejected:([1-9][0-9]*)/);
        if (lateGroup?.[1] === undefined) {
          throw new Error('late process-group registration was not rejected');
        }
        lateProcessGroup = Number(lateGroup[1]);
        expect(await waitForOwnedArtifactChildProcessGroupExit(lateProcessGroup)).toBe(true);
        await expect(access(ownedTreePath)).rejects.toMatchObject({ code: 'ENOENT' });
        await expect(access(lateTreePath)).rejects.toMatchObject({ code: 'ENOENT' });
      } finally {
        killArtifactVerifier(verifier);
        if (lateProcessGroup !== undefined) {
          await drainOwnedArtifactChildProcessGroup(lateProcessGroup);
        }
        await waitForArtifactVerifierCleanup(verifierExit);
      }
    }
  });
  it('rejects direct manifest creation outside the audited runtime build', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);

    const verifierPath = join(root, 'scripts', 'verify-artifacts.mjs');
    await mkdir(dirname(verifierPath), { recursive: true });
    await copyFile(artifactVerifierSourcePath, verifierPath);

    await expect(
      execFileAsync(process.execPath, [verifierPath, '--create-manifest'], {
        cwd: root,
        encoding: 'utf8',
      }),
    ).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('verify-artifacts.mjs accepts no arguments'),
    });
    await expect(access(join(root, 'dist', 'build-manifest.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });
  it('redacts canonical fixture credential paths from verifier failure stderr', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const canonicalRoot = await realpath(root);
    const canonicalCredentialPath = join(canonicalRoot, 'credential-authority');
    await writeFile(canonicalCredentialPath, 'SCENE_GLASS_HOST_TOKEN=fixture-token\n', {
      mode: 0o600,
    });
    const cliPath = join(root, 'dist', 'cli.js');
    const cliSource = await readFile(cliPath, 'utf8');
    await writeFile(
      cliPath,
      cliSource.replace(
        "if (command === 'help' && args.length === 0) {",
        [
          "if (command === 'help' && args.length === 0) {",
          `  process.stderr.write(${JSON.stringify(`${canonicalCredentialPath}\n`)});`,
          '  process.exitCode = 1;',
        ].join('\n'),
      ),
    );
    await chmod(cliPath, 0o600);
    await writeFixtureBuildManifest(root);

    const verifierPath = join(root, 'scripts', 'verify-artifacts.mjs');
    await mkdir(dirname(verifierPath), { recursive: true });
    await copyFile(artifactVerifierSourcePath, verifierPath);
    const failure = await execFileAsync(process.execPath, [verifierPath], {
      cwd: root,
      encoding: 'utf8',
    }).then(
      () => undefined,
      (error) => error as { readonly code?: number; readonly stderr?: string },
    );

    expect(failure).toMatchObject({ code: 1 });
    expect(failure?.stderr).toContain(
      'ArtifactVerificationError: plain-Node CLI help emitted a credential or absolute fixture root',
    );
    expect(failure?.stderr).not.toContain(canonicalRoot);
    expect(failure?.stderr).not.toContain(canonicalCredentialPath);
  });
  it('emits a fixed redacted diagnostic for malformed manifest bytes', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const canonicalRoot = await realpath(root);
    const manifestToken = 'manifest-private-token';
    const manifestPath = join(root, 'dist', 'build-manifest.json');
    await writeFile(
      manifestPath,
      `{"source":${JSON.stringify(join(canonicalRoot, 'sensitive-manifest-path'))},"token":"${manifestToken}"\n`,
      { mode: 0o644 },
    );
    await chmod(manifestPath, 0o644);

    const verifierPath = join(root, 'scripts', 'verify-artifacts.mjs');
    await mkdir(dirname(verifierPath), { recursive: true });
    await copyFile(artifactVerifierSourcePath, verifierPath);
    const failure = await execFileAsync(process.execPath, [verifierPath], {
      cwd: root,
      encoding: 'utf8',
    }).then(
      () => undefined,
      (error) => error as { readonly code?: number; readonly stderr?: string },
    );

    expect(failure).toMatchObject({ code: 1 });
    expect(failure?.stderr).toBe(
      'ArtifactVerificationError: dist/build-manifest.json is not valid JSON\n',
    );
    expect(failure?.stderr).not.toContain(canonicalRoot);
    expect(failure?.stderr).not.toContain(manifestToken);
  });
  it('preserves primary lifecycle failures, completes cleanup, and redacts public diagnostics', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const canonicalRoot = await realpath(root);
    const canonicalCredentialPath = join(canonicalRoot, 'credential-authority');
    const lifecycleToken = 'lifecycle-private-token';
    const cliPath = join(root, 'dist', 'cli.js');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');
    const captureFailure = async (promise: Promise<unknown>): Promise<unknown> =>
      promise.then(
        () => {
          throw new Error('expected lifecycle verification to fail');
        },
        (error) => error,
      );

    const setupPrimary = new Error(
      `hook setup failure at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
    );
    const pinnedCloseFailure = new Error(
      `pinned close failure at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
    );
    let pinnedCloseAttempts = 0;
    const setupFailure = await captureFailure(
      verifyPlainNodeCli({
        root,
        cli: cliPath,
        expectedCliHash,
        beforePinnedExecution: async () => {
          throw setupPrimary;
        },
        lifecycle: {
          beforePinnedCliClose: async () => {
            pinnedCloseAttempts += 1;
            throw pinnedCloseFailure;
          },
        },
      }),
    );
    expect(pinnedCloseAttempts).toBe(1);
    expect(setupFailure).toBeInstanceOf(AggregateError);
    expect((setupFailure as AggregateError).errors).toEqual([setupPrimary, pinnedCloseFailure]);
    const setupDiagnostic = formatArtifactVerifierFailure(setupFailure);
    expect(setupDiagnostic).toBe(
      'ArtifactVerificationError: artifact verification failed; cleanup phases failed: pinned-cli-close\n',
    );
    expect(setupDiagnostic).not.toContain(canonicalRoot);
    expect(setupDiagnostic).not.toContain(canonicalCredentialPath);
    expect(setupDiagnostic).not.toContain(lifecycleToken);
    for (const hostileError of [
      new ArtifactVerificationError(
        `hostile verifier error at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
      ),
      Object.assign(
        new (class HostileArtifactVerificationError extends ArtifactVerificationError {})(),
        {
          message: `hostile verifier subclass at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
        },
      ),
      Object.assign(new ArtifactVerificationError('safe'), {
        message: `mutated verifier error at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
      }),
    ]) {
      const hostileFailure = await captureFailure(
        verifyPlainNodeCli({
          root,
          cli: cliPath,
          expectedCliHash,
          beforePinnedExecution: async () => {
            throw hostileError;
          },
        }),
      );
      expect(hostileFailure).toBe(hostileError);
      expect(formatArtifactVerifierFailure(hostileFailure)).toBe(
        'ArtifactVerificationError: artifact verification failed\n',
      );
    }

    const primitiveCleanupFailure = await captureFailure(
      verifyPlainNodeCli({
        root,
        cli: cliPath,
        expectedCliHash,
        lifecycle: {
          beforePinnedCliClose: async () => {
            throw 'primitive pinned cleanup failure';
          },
        },
      }),
    );
    expect(primitiveCleanupFailure).toBeInstanceOf(AggregateError);
    expect((primitiveCleanupFailure as AggregateError).errors).toEqual([
      'primitive pinned cleanup failure',
    ]);
    expect(formatArtifactVerifierFailure(primitiveCleanupFailure)).toBe(
      'ArtifactVerificationError: artifact verification failed; cleanup phases failed: pinned-cli-close\n',
    );

    const runPrimary = new Error(
      `static verification failure at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
    );
    const restoreFailure = new Error(
      `restore failure at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
    );
    const staticTreeFailure = new Error(
      `static tree cleanup failure at ${canonicalRoot} using ${canonicalCredentialPath} with ${lifecycleToken}`,
    );
    let restoreAttempts = 0;
    let staticFixtureDirectory: string | undefined;
    const staticFailure = await captureFailure(
      verifyPlainNodeCli({
        root,
        cli: cliPath,
        expectedCliHash,
        beforePinnedExecution: async () => async () => {
          restoreAttempts += 1;
          throw restoreFailure;
        },
        lifecycle: {
          beforeStaticFixtureVerification: async () => {
            throw runPrimary;
          },
          beforeStaticFixtureTreeCleanup: async ({ directory }: { readonly directory: string }) => {
            staticFixtureDirectory = directory;
            throw staticTreeFailure;
          },
        },
      }),
    );
    expect(restoreAttempts).toBe(1);
    expect(staticFailure).toBeInstanceOf(AggregateError);
    expect((staticFailure as AggregateError).errors).toEqual([
      runPrimary,
      staticTreeFailure,
      restoreFailure,
    ]);
    if (staticFixtureDirectory === undefined) {
      throw new Error('static fixture cleanup hook did not run');
    }
    await expect(access(staticFixtureDirectory)).rejects.toMatchObject({ code: 'ENOENT' });
    const staticDiagnostic = formatArtifactVerifierFailure(staticFailure);
    expect(staticDiagnostic).toBe(
      'ArtifactVerificationError: artifact verification failed; cleanup phases failed: static-fixture-tree-cleanup, pinned-execution-restore\n',
    );
    expect(staticDiagnostic).not.toContain(canonicalRoot);
    expect(staticDiagnostic).not.toContain(canonicalCredentialPath);
    expect(staticDiagnostic).not.toContain(lifecycleToken);
  });
  it('waits for every started static setup mutation before cleanup', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const cliPath = join(root, 'dist', 'cli.js');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');
    let setupFailure: unknown;
    let setupDirectory: string | undefined;
    let delayedMutationCompleted = false;
    const testOnly = createPlainNodeCliTestOnlyPorts({
      afterSetupMutations: ({
        directory,
        phase,
      }: {
        readonly directory: string;
        readonly phase: string;
      }) => {
        expect(phase).toBe('static-fixture-setup');
        setupDirectory = directory;
        const failingMutation = (async () => {
          await delay(5);
          try {
            await mkdir(directory);
            throw new Error('expected delayed setup mkdir to fail');
          } catch (error) {
            setupFailure = error;
            throw error;
          }
        })();
        const delayedMutation = (async () => {
          await delay(20);
          await writeFile(join(directory, 'late-setup-mutation'), 'settled\n');
          delayedMutationCompleted = true;
        })();
        return [failingMutation, delayedMutation];
      },
    });
    const failure = await verifyPlainNodeCli({
      root,
      cli: cliPath,
      expectedCliHash,
      testOnly,
    }).then(
      () => {
        throw new Error('expected delayed setup failure');
      },
      (error: unknown) => error,
    );

    expect(failure).toBe(setupFailure);
    expect(failure).toMatchObject({ code: 'EEXIST' });
    expect(delayedMutationCompleted).toBe(true);
    if (setupDirectory === undefined) {
      throw new Error('static setup test port did not receive the fixture directory');
    }
    await expect(access(setupDirectory)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('preserves real child, nested public cleanup, tree-finalization, and FD-close failure order', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const cliPath = join(root, 'dist', 'cli.js');
    const childFailureSource = (await readFile(cliPath, 'utf8')).replace(
      "  process.stdout.write('descriptor check passed\\n');",
      "  process.stderr.write('production child failure\\n');\n  process.exitCode = 1;",
    );
    await writeFile(cliPath, childFailureSource, { mode: 0o600 });
    await chmod(cliPath, 0o600);
    const expectedCliHash = createHash('sha256').update(childFailureSource).digest('hex');
    const directoryCloseFailure = new Error('directory close finalizer failed');
    const treeFinalizationFailure = new Error('tree finalizer failed');
    const pinnedCloseFailure = new Error('pinned FileHandle close finalizer failed');
    let staticFixtureDirectory: string | undefined;
    let laterStaticSiblingRemoved = false;
    let closedPinnedHandle:
      { readonly stat: (options?: { readonly bigint?: boolean }) => Promise<unknown> } | undefined;
    const testOnly = createPlainNodeCliTestOnlyPorts({
      afterDirectoryClose: async ({
        label,
        path,
      }: {
        readonly label: string;
        readonly path: string;
      }) => {
        if (label === 'static artifact fixture') {
          if (path.endsWith('/public')) {
            throw directoryCloseFailure;
          }
          staticFixtureDirectory = path;
        }
      },
      afterArtifactTreeRemoval: async ({
        label,
        path,
      }: {
        readonly label: string;
        readonly path: string;
      }) => {
        if (label === 'static artifact fixture' && path.endsWith('/static-descriptor.json')) {
          laterStaticSiblingRemoved = true;
        }
        if (label === 'static artifact fixture' && path === staticFixtureDirectory) {
          throw treeFinalizationFailure;
        }
      },
      afterFileHandleClose: async ({
        handle,
        phase,
      }: {
        readonly handle: {
          readonly stat: (options?: { readonly bigint?: boolean }) => Promise<unknown>;
        };
        readonly phase: string;
      }) => {
        if (phase === 'pinned-cli-close') {
          closedPinnedHandle = handle;
          throw pinnedCloseFailure;
        }
      },
    });
    const failure = await verifyPlainNodeCli({
      root,
      cli: cliPath,
      expectedCliHash,
      testOnly,
    }).then(
      () => {
        throw new Error('expected production lifecycle failure');
      },
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(AggregateError);
    const errors = (failure as AggregateError).errors;
    expect(errors).toHaveLength(4);
    expect(errors[0]).toBeInstanceOf(ArtifactVerificationError);
    expect(errors.slice(1)).toEqual([
      directoryCloseFailure,
      treeFinalizationFailure,
      pinnedCloseFailure,
    ]);
    expect(formatArtifactVerifierFailure(failure)).toBe(
      'ArtifactVerificationError: plain-Node CLI descriptor-check failed with exit 1; no classified CLI failure; cleanup phases failed: static-fixture-tree-cleanup, artifact-tree-child-cleanup, artifact-tree-directory-close, artifact-tree-removal-finalization, pinned-cli-close\n',
    );
    expect(laterStaticSiblingRemoved).toBe(true);
    if (staticFixtureDirectory === undefined || closedPinnedHandle === undefined) {
      throw new Error('production finalizer test port did not observe its target');
    }
    await expect(access(staticFixtureDirectory)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(closedPinnedHandle.stat({ bigint: true })).rejects.toMatchObject({
      code: 'EBADF',
    });
    expect(
      (await observedArtifactInvocationState(root)).invocations.map(({ command }) => command),
    ).toEqual(['help', 'descriptor-check']);
  });
  it('preserves native restore, FileHandle-close, and tree-finalization failure order', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    const cliPath = join(root, 'dist', 'cli.js');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');
    const restoreFailure = new Error('native authority restore failed');
    const nativeCloseFailure = new Error('native FileHandle close finalizer failed');
    const nativeTreeFailure = new Error('native tree finalizer failed');
    let nativeRoot: string | undefined;
    let closedNativeHandle:
      { readonly stat: (options?: { readonly bigint?: boolean }) => Promise<unknown> } | undefined;
    const testOnly = createPlainNodeCliTestOnlyPorts({
      afterArtifactTreeRemoval: async ({
        label,
        path,
      }: {
        readonly label: string;
        readonly path: string;
      }) => {
        if (label === 'private native-self-test authority' && path === nativeRoot) {
          throw nativeTreeFailure;
        }
      },
      afterFileHandleClose: async ({
        handle,
        phase,
      }: {
        readonly handle: {
          readonly stat: (options?: { readonly bigint?: boolean }) => Promise<unknown>;
        };
        readonly phase: string;
      }) => {
        if (phase === 'native-authority-close') {
          closedNativeHandle = handle;
          throw nativeCloseFailure;
        }
      },
    });
    const failure = await verifyPlainNodeCli({
      root,
      cli: cliPath,
      expectedCliHash,
      testOnly,
      afterNativeAuthorityCreated: async ({ root: authorityRoot }: { readonly root: string }) => {
        nativeRoot = authorityRoot;
        return async () => {
          throw restoreFailure;
        };
      },
    }).then(
      () => {
        throw new Error('expected native finalization failure');
      },
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors).toEqual([
      restoreFailure,
      nativeCloseFailure,
      nativeTreeFailure,
    ]);
    expect(formatArtifactVerifierFailure(failure)).toBe(
      'ArtifactVerificationError: artifact verification failed; cleanup phases failed: native-authority-restore, native-authority-close, native-authority-tree-cleanup, artifact-tree-removal-finalization\n',
    );
    if (nativeRoot === undefined || closedNativeHandle === undefined) {
      throw new Error('native finalizer test port did not observe its target');
    }
    await expect(access(nativeRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(closedNativeHandle.stat({ bigint: true })).rejects.toMatchObject({
      code: 'EBADF',
    });
  });
  it('rejects a forged audited CLI authority even when its FD and hash match', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);

    const cliPath = join(root, 'dist', 'cli.js');
    const auditedContents = await readFile(cliPath);
    const auditedHandle = await open(cliPath, 'r');
    try {
      const facts = await auditedHandle.stat({ bigint: true });
      await expect(
        publishRuntimeBuildManifest({
          contents: auditedContents,
          facts,
          handle: auditedHandle,
          hash: createHash('sha256').update(auditedContents).digest('hex'),
          path: cliPath,
        }),
      ).rejects.toThrow('build manifest publication requires module-issued audited CLI authority');
      await expect(access(join(root, 'dist', 'build-manifest.json'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    } finally {
      await auditedHandle.close();
    }
  });
  it('executes the pinned verified CLI when its pathname is replaced before execution', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);

    const cliPath = join(root, 'dist', 'cli.js');
    const originalCliPath = join(root, 'dist', 'original-cli.js');
    const replacementPath = join(root, 'dist', 'replacement-cli.js');
    const replacementExecutedPath = join(root, 'replacement-executed');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');
    await writeFile(
      replacementPath,
      [
        "import { writeFile } from 'node:fs/promises';",
        `await writeFile(${JSON.stringify(replacementExecutedPath)}, 'replacement executed\\n');`,
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    await chmod(replacementPath, 0o600);

    await expect(
      verifyPlainNodeCli({
        root,
        cli: cliPath,
        expectedCliHash,
        beforePinnedExecution: async () => {
          await rename(cliPath, originalCliPath);
          await rename(replacementPath, cliPath);
          return async () => {
            await rename(originalCliPath, cliPath);
          };
        },
      }),
    ).resolves.toBeUndefined();

    await expect(access(replacementExecutedPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await readFile(join(root, 'cli-invocations.ndjson'), 'utf8')).toContain(
      '{"command":"help","args":[]}',
    );
  });
  it('executes the pinned entry when its ancestor is retargeted to a malicious symlink tree', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);

    const distPath = join(root, 'dist');
    const originalDistPath = join(root, 'pinned-dist');
    const replacementDistPath = join(root, 'replacement-dist');
    const replacementExecutedPath = join(root, 'ancestor-replacement-executed');
    const cliPath = join(distPath, 'cli.js');
    const expectedCliHash = createHash('sha256')
      .update(await readFile(cliPath))
      .digest('hex');

    await expect(
      verifyPlainNodeCli({
        root,
        cli: cliPath,
        expectedCliHash,
        beforePinnedExecution: async () => {
          await rename(distPath, originalDistPath);
          await mkdir(replacementDistPath);
          await Promise.all([
            writeFile(
              join(replacementDistPath, 'cli.js'),
              [
                "import { writeFile } from 'node:fs/promises';",
                `await writeFile(${JSON.stringify(replacementExecutedPath)}, 'replacement executed\\n');`,
                '',
              ].join('\n'),
              { mode: 0o600 },
            ),
            symlink(
              join(originalDistPath, 'managed-vite-fixture.mjs'),
              join(replacementDistPath, 'managed-vite-fixture.mjs'),
            ),
          ]);
          await symlink(replacementDistPath, distPath, 'dir');
          return async () => {
            await rm(distPath, { force: true });
            await rename(originalDistPath, distPath);
            await rm(replacementDistPath, { force: true, recursive: true });
          };
        },
      }),
    ).resolves.toBeUndefined();

    await expect(access(replacementExecutedPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('rejects an isolated symlink replacement of the build manifest', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    await writeFixtureBuildManifest(root);

    const manifestPath = join(root, 'dist', 'build-manifest.json');
    await rm(manifestPath);
    await symlink(join(root, 'dist', 'cli.js'), manifestPath);

    await expect(verifyArtifacts({ root })).rejects.toThrow('regular mode 0644 canonical manifest');
  });

  it('rejects an isolated oversized build manifest before allocation', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    await writeFixtureBuildManifest(root);

    await writeFile(join(root, 'dist', 'build-manifest.json'), Buffer.alloc(4 * 1024 + 1));

    await expect(verifyArtifacts({ root })).rejects.toThrow('regular mode 0644 canonical manifest');
  });

  it('rejects an isolated hardlinked build manifest', async () => {
    const root = await bootstrapFixture();
    await createArtifacts(root);
    await writeFixtureBuildManifest(root);

    const manifestPath = join(root, 'dist', 'build-manifest.json');
    await link(manifestPath, join(root, 'dist', 'build-manifest-extra-link.json'));

    await expect(verifyArtifacts({ root })).rejects.toThrow('regular mode 0644 canonical manifest');
  });

  it('rejects noncanonical credential, secret, test, .gjc, and source-map metafile inputs before bundling', () => {
    for (const input of [
      'src/credential-authority-copy.ts',
      'src/secret.ts',
      'tests/runtime-helper.ts',
      '.gjc/generated.ts',
      'src/runtime.js.map',
    ]) {
      expect(() =>
        auditMetafile({
          inputs: { [input]: { imports: [] } },
          outputs: { 'dist/cli.js': { imports: [] } },
        }),
      ).toThrow(RuntimeBuildError);
    }
  });
  it('externalizes only the exact reviewed runtime package roots', () => {
    expect(() =>
      auditMetafile({
        inputs: {
          'src/cli.ts': {
            imports: [
              { path: 'node:fs/promises', external: true },
              { path: 'fs-ext', external: true },
              { path: 'fastify', external: true },
              { path: 'ajv', external: true },
            ],
          },
        },
        outputs: {
          'dist/cli.js': {
            imports: [{ path: 'fs-ext/lib', external: true }],
          },
        },
      }),
    ).not.toThrow();

    for (const specifier of [
      'fastify/lib/plugin',
      'ajv/dist/2020',
      'vite',
      '@vitejs/plugin-vue',
      '@vitejs/plugin-react',
      'vue',
      'react',
      'react-dom',
    ]) {
      expect(() =>
        auditMetafile({
          inputs: {
            'src/cli.ts': {
              imports: [{ path: specifier, external: true }],
            },
          },
          outputs: { 'dist/cli.js': { imports: [] } },
        }),
      ).toThrow(`runtime bundle leaves unapproved import external: ${specifier}`);
    }

    expect(() =>
      auditMetafile({
        inputs: {
          'src/cli.ts': {
            imports: [{ path: 'lightningcss', external: true }],
          },
        },
        outputs: { 'dist/cli.js': { imports: [] } },
      }),
    ).toThrow('runtime bundle leaves unapproved import external: lightningcss');

    expect(() =>
      auditMetafile({
        inputs: { 'src/cli.ts': { imports: [] } },
        outputs: {
          'dist/cli.js': {
            imports: [{ path: 'fsevents', external: true }],
          },
        },
      }),
    ).toThrow('runtime bundle leaves unapproved import external: fsevents');
  });
});

async function bootstrapFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'scene-glass-bootstrap-'));
  temporaryRoots.add(root);
  await Promise.all([
    writeFile(
      join(root, 'package.json'),
      `${JSON.stringify(
        {
          name: 'bootstrap-fixture',
          private: true,
          type: 'module',
          packageManager: 'pnpm@10.34.5',
          engines: { node: '>=24 <25' },
        },
        null,
        2,
      )}\n`,
    ),
    writeFile(
      join(root, 'pnpm-workspace.yaml'),
      [
        'packages:',
        "  - 'apps/*'",
        "  - 'packages/*'",
        "  - 'fixtures/*'",
        'allowBuilds:',
        '  esbuild: true',
        '  fs-ext: true',
        'strictDepBuilds: true',
        '',
      ].join('\n'),
    ),
    writeFile(join(root, 'pnpm-lock.yaml'), lockfile()),
  ]);
  await writeOnboardingManifest(root);
  await Promise.all([
    writeExtractedManifest(root, 'esbuild@0.25.5', 'esbuild', {
      name: 'esbuild',
      version: '0.25.5',
      scripts: { postinstall: 'node install.js' },
    }),
    writeExtractedManifest(root, 'esbuild@0.28.1', 'esbuild', {
      name: 'esbuild',
      version: '0.28.1',
      scripts: { postinstall: 'node install.js' },
    }),
    writeExtractedManifest(root, 'tsx@4.23.1', 'tsx', {
      name: 'tsx',
      version: '4.23.1',
      dependencies: { esbuild: '0.28.1' },
    }),
    writeExtractedManifest(root, 'fs-ext@2.1.1', 'fs-ext', {
      name: 'fs-ext',
      version: '2.1.1',
      scripts: { install: 'node-gyp configure build' },
    }),
    writeExtractedManifest(root, 'node-gyp@11.2.0', 'node-gyp', {
      name: 'node-gyp',
      version: '11.2.0',
      bin: './bin/node-gyp.js',
    }),
  ]);
  await writeOnboardingImporterTopology(root);
  const canonicalNodeGypEntry = join(
    root,
    'node_modules',
    '.pnpm',
    'node-gyp@11.2.0',
    'node_modules',
    'node-gyp',
    'bin',
    'node-gyp.js',
  );
  await mkdir(dirname(canonicalNodeGypEntry), { recursive: true });
  await writeFile(canonicalNodeGypEntry, 'process.exitCode = 0;\n');
  const structuralNodeGyp = join(root, 'node_modules', '.pnpm', 'node_modules', 'node-gyp');
  await mkdir(dirname(structuralNodeGyp), { recursive: true });
  await symlink(join('..', 'node-gyp@11.2.0', 'node_modules', 'node-gyp'), structuralNodeGyp);
  const rebuildShim = join(root, 'node_modules', '.pnpm', 'node_modules', '.bin', 'node-gyp');
  await mkdir(dirname(rebuildShim), { recursive: true });
  await writeFile(rebuildShim, canonicalNodeGypRebuildShimSource(), { mode: 0o755 });
  return root;
}
async function writeOnboardingManifest(root: string): Promise<void> {
  const path = join(root, 'packages', 'onboarding', 'package.json');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    `${JSON.stringify(
      {
        name: '@scene-glass/onboarding',
        scripts: { 'build:native': CANONICAL_NATIVE_BUILD_SCRIPT },
      },
      null,
      2,
    )}\n`,
  );
}

async function writeExtractedManifest(
  root: string,
  storeName: string,
  packageName: string,
  manifest: Record<string, unknown>,
): Promise<void> {
  const path = join(
    root,
    'node_modules',
    '.pnpm',
    storeName,
    'node_modules',
    packageName,
    'package.json',
  );
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
}
async function writeVirtualStoreDependencySymlink(
  root: string,
  storeName: string,
  dependencyName: string,
  target: string,
): Promise<void> {
  const nodeModulesDirectory = join(root, 'node_modules', '.pnpm', storeName, 'node_modules');
  const dependencyPath = join(nodeModulesDirectory, ...dependencyName.split('/'));
  await mkdir(dirname(dependencyPath), { recursive: true });
  await symlink(target, dependencyPath);
}
function importerStoreEntry(packageName: string, version: string): string {
  return `${packageName.replace('/', '+')}@${version}`;
}

async function writeOnboardingImporterTopology(root: string): Promise<void> {
  const externalDependencies = Object.entries(ONBOARDING_EXTERNAL_DEPENDENCIES).filter(
    ([packageName]) =>
      packageName !== 'esbuild' && packageName !== 'fs-ext' && packageName !== 'node-gyp',
  );
  await Promise.all([
    ...externalDependencies.map(async ([packageName, version]) => {
      await writeExtractedManifest(root, importerStoreEntry(packageName, version), packageName, {
        name: packageName,
        version,
      });
    }),
    ...Object.entries(ONBOARDING_WORKSPACE_DEPENDENCIES).map(async ([packageName]) => {
      const packageDirectory = join(root, 'packages', packageName.slice('@scene-glass/'.length));
      await mkdir(packageDirectory, { recursive: true });
      await writeFile(
        join(packageDirectory, 'package.json'),
        `${JSON.stringify({ name: packageName, version: '1.0.0' }, null, 2)}\n`,
      );
    }),
  ]);

  const onboardingNodeModules = join(root, 'packages', 'onboarding', 'node_modules');
  for (const [packageName, version] of Object.entries(ONBOARDING_EXTERNAL_DEPENDENCIES)) {
    const link = join(onboardingNodeModules, ...packageName.split('/'));
    const store = importerStoreEntry(packageName, version);
    const target = join(
      root,
      'node_modules',
      '.pnpm',
      store,
      'node_modules',
      ...packageName.split('/'),
    );
    await mkdir(dirname(link), { recursive: true });
    await symlink(target, link);
  }
  for (const [packageName, resolution] of Object.entries(ONBOARDING_WORKSPACE_DEPENDENCIES)) {
    const link = join(onboardingNodeModules, ...packageName.split('/'));
    const target = join(root, 'packages', resolution.slice('link:../'.length));
    await mkdir(dirname(link), { recursive: true });
    await symlink(target, link);
  }

  await writeVirtualStoreDependencySymlink(
    root,
    'tsx@4.23.1',
    'esbuild',
    join(root, 'node_modules', '.pnpm', 'esbuild@0.28.1', 'node_modules', 'esbuild'),
  );
}

const MANAGED_VITE_ARTIFACT_FIXTURE = String.raw`
import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream, fstatSync, readSync } from 'node:fs';
import { appendFile, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const RESULT_KIND = 'managed-vite-cache-result';
const RECEIPT_MAX_BYTES = 512;
const RUNTIME_CLI_MAX_BYTES = 16 * 1024 * 1024;
const SNAPSHOT_AUTHORITY_MAX_BYTES = 1024;
const SNAPSHOT_AUTHORITY_KEYS = ['syntheticRoot', 'rootIdentity', 'commitmentDigest'];
const SNAPSHOT_AUTHORITY_IDENTITY_KEYS = ['device', 'inode'];
const TEARDOWN_TIMEOUT_MS = 250;
const mode = process.env.SCG_ARTIFACT_MANAGED_VITE_MODE ?? 'accepted';

const record = (entry) => appendFile('cli-invocations.ndjson', JSON.stringify(entry) + '\n');

const receipt = () =>
  JSON.stringify({ version: 1, kind: RESULT_KIND, status: 'clean', reason: 'clean' }) + '\n';

const readBounded = (stream, maximum) =>
  new Promise((resolveRead, rejectRead) => {
    const chunks = [];
    let size = 0;
    let ended = false;
    const fail = (error) => rejectRead(error);
    stream.on('data', (chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (size + bytes.length > maximum) {
        stream.destroy();
        fail(new Error('bounded transport exceeded'));
        return;
      }
      chunks.push(bytes);
      size += bytes.length;
    });
    stream.once('end', () => {
      ended = true;
      resolveRead(Buffer.concat(chunks, size));
    });
    stream.once('error', fail);
    stream.once('close', () => {
      if (!ended) {
        fail(new Error('transport closed early'));
      }
    });
  });
const hasExactKeys = (value, keys) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  Object.keys(value).every((key, index) => key === keys[index]);

const expectedSnapshotRoot = (descriptorPath, descriptor) =>
  join(dirname(descriptorPath), '.scg', 'runtime', 'vite-root', String(descriptor.installId));

export const readSnapshotAuthority = async (descriptorPath, descriptor) => {
  const bytes = await readBounded(
    createReadStream('', { fd: 5, autoClose: true }),
    SNAPSHOT_AUTHORITY_MAX_BYTES,
  );
  const serialized = bytes.toString('utf8');
  let authority;
  try {
    authority = JSON.parse(serialized);
  } catch {
    throw new Error('managed Vite snapshot authority transport was invalid');
  }
  if (
    bytes.length === 0 ||
    !hasExactKeys(authority, SNAPSHOT_AUTHORITY_KEYS) ||
    authority.syntheticRoot !== expectedSnapshotRoot(descriptorPath, descriptor) ||
    !hasExactKeys(authority.rootIdentity, SNAPSHOT_AUTHORITY_IDENTITY_KEYS) ||
    typeof authority.rootIdentity.device !== 'string' ||
    typeof authority.rootIdentity.inode !== 'string' ||
    authority.rootIdentity.device.length > 20 ||
    authority.rootIdentity.inode.length > 20 ||
    !/^(?:0|[1-9][0-9]*)$/.test(authority.rootIdentity.device) ||
    !/^(?:0|[1-9][0-9]*)$/.test(authority.rootIdentity.inode) ||
    typeof authority.commitmentDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(authority.commitmentDigest) ||
    JSON.stringify(authority, null, 2) + '\n' !== serialized
  ) {
    throw new Error('managed Vite snapshot authority transport was invalid');
  }
  return { authority, bytes };
};

const writeExact = (stream, bytes) =>
  new Promise((resolveWrite, rejectWrite) => {
    stream.once('error', rejectWrite);
    stream.end(bytes, resolveWrite);
  });

const writeChildResult = async (bytes) => {
  const transport = createWriteStream('', { fd: 4, autoClose: true });
  await writeExact(transport, bytes);
};

const closeChildResult = async () => {
  const transport = createWriteStream('', { fd: 4, autoClose: true });
  await new Promise((resolveClose, rejectClose) => {
    transport.once('error', rejectClose);
    transport.end(resolveClose);
  });
};

const waitForExit = (child) =>
  new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit);
    child.once('close', (status, signal) => resolveExit({ status, signal }));
  });

const isCanonicalReceipt = (bytes) => bytes.toString('utf8') === receipt();

const processGroupExists = (pid) => {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (error && error.code === 'ESRCH') {
      return false;
    }
    throw error;
  }
};

const waitForProcessGroupExit = async (pid) => {
  const deadline = Date.now() + TEARDOWN_TIMEOUT_MS;
  while (processGroupExists(pid)) {
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  return true;
};

const terminateProcessGroup = (pid, signal) => {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (!error || error.code !== 'ESRCH') {
      throw error;
    }
  }
};

const childProvenance = async (descriptorPath, descriptor) => {
  if (typeof descriptor.provenanceSerialized === 'string') {
    return descriptor.provenanceSerialized;
  }
  return readFile(
    join(
      dirname(descriptorPath),
      '.scg',
      'runtime',
      'vite-cache',
      String(descriptor.installId) + '.provenance.v1.json',
    ),
    'utf8',
  );
};
const hasVerifiedRuntimeCliFacts = (facts) =>
  facts.isFile() &&
  Number.isSafeInteger(facts.size) &&
  facts.size > 0 &&
  facts.size <= RUNTIME_CLI_MAX_BYTES;
const hasInheritedRuntimeCli = () => {
  try {
    return hasVerifiedRuntimeCliFacts(fstatSync(7));
  } catch {
    return false;
  }
};
const pinnedCliChildBootstrap = (descriptorPath) => {
  const virtualCliPath = process.argv[1];
  const virtualCliUrl = pathToFileURL(virtualCliPath).href;
  const facts = fstatSync(7);
  if (!hasVerifiedRuntimeCliFacts(facts)) {
    throw new Error('inherited runtime CLI descriptor has invalid bounds');
  }
  const bytes = Buffer.allocUnsafe(facts.size);
  let offset = 0;
  while (offset < bytes.length) {
    const bytesRead = readSync(7, bytes, offset, bytes.length - offset, offset);
    if (bytesRead === 0) {
      throw new Error('inherited runtime CLI ended unexpectedly');
    }
    offset += bytesRead;
  }
  const source = bytes.toString('base64');
  const loader =
    "import { Buffer } from 'node:buffer';" +
    ' const virtual = ' + JSON.stringify(virtualCliUrl) + ';' +
    ' const source = ' + JSON.stringify(source) + ';' +
    " export async function resolve(specifier, context, nextResolve) {" +
    ' if (specifier === virtual) return { url: virtual, shortCircuit: true };' +
    ' return nextResolve(specifier, context); }' +
    " export async function load(url, context, nextLoad) {" +
    " if (url === virtual) return { format: 'module', source: Buffer.from(source, 'base64'), shortCircuit: true };" +
    ' return nextLoad(url, context); }';
  return [
    "import { register } from 'node:module';",
    'const virtualCliPath = ' + JSON.stringify(virtualCliPath) + ';',
    'const virtualCliUrl = ' + JSON.stringify(virtualCliUrl) + ';',
    'const loader = ' + JSON.stringify(loader) + ';',
    "register('data:text/javascript,' + encodeURIComponent(loader), import.meta.url);",
    'process.argv = [process.execPath, virtualCliPath, "managed-vite-child", "--descriptor", ' +
      JSON.stringify(descriptorPath) +
      '];',
    'await import(virtualCliUrl);',
  ].join('\n');
};

export const runManagedViteDevFixture = async ({ descriptorPath }) => {
  const descriptor = JSON.parse(await readFile(descriptorPath, 'utf8'));
  const framework = descriptor.framework;
  const snapshotAuthority = await readSnapshotAuthority(descriptorPath, descriptor);
  const provenance = await childProvenance(descriptorPath, descriptor);
  const inheritedRuntimeCli = hasInheritedRuntimeCli();
  const child = spawn(
    process.execPath,
    inheritedRuntimeCli
      ? ['--input-type=module', '--eval', pinnedCliChildBootstrap(descriptorPath)]
      : [process.argv[1], 'managed-vite-child', '--descriptor', descriptorPath],
    {
      detached: mode === 'orphan-descendant',
      stdio: inheritedRuntimeCli
        ? ['ignore', 'inherit', 'inherit', 'pipe', 'pipe', 'pipe', 'ignore', 7]
        : ['ignore', 'inherit', 'inherit', 'pipe', 'pipe', 'pipe'],
    },
  );
  const provenancePipe = child.stdio[3];
  const receiptPipe = child.stdio[4];
  const snapshotAuthorityPipe = child.stdio[5];
  if (
    provenancePipe === null ||
    receiptPipe === null ||
    snapshotAuthorityPipe === null
  ) {
    throw new Error('managed-vite-child did not expose fd 3/4/5');
  }
  const receiptRead = readBounded(receiptPipe, RECEIPT_MAX_BYTES).catch(() => undefined);
  const provenanceWrite = writeExact(provenancePipe, Buffer.from(provenance, 'utf8')).then(
    () => 'fulfilled',
    () => 'rejected',
  );
  const snapshotAuthorityWrite = writeExact(snapshotAuthorityPipe, snapshotAuthority.bytes).then(
    () => 'fulfilled',
    () => 'rejected',
  );
  const childExit = waitForExit(child);
  let forwardedSignal;
  let forced = false;
  let teardownTimer;
  const requestChildTermination = (signal) => {
    forwardedSignal ??= signal;
    child.kill(signal);
    if (teardownTimer === undefined) {
      teardownTimer = setTimeout(() => {
        forced = true;
        if (mode === 'orphan-descendant') {
          terminateProcessGroup(child.pid, 'SIGKILL');
        } else {
          child.kill('SIGKILL');
        }
      }, TEARDOWN_TIMEOUT_MS);
    }
  };
  const onInterrupt = () => requestChildTermination('SIGINT');
  const onTerminate = () => requestChildTermination('SIGTERM');
  process.once('SIGINT', onInterrupt);
  process.once('SIGTERM', onTerminate);
  if (mode === 'teardown-timeout') {
    receiptPipe.once('data', () => requestChildTermination('SIGTERM'));
  }
  if (mode === 'orphan-descendant') {
    receiptPipe.once('data', () => {
      forwardedSignal ??= 'SIGTERM';
      child.kill('SIGTERM');
    });
  }

  try {
    const [exit, receiptBytes, provenanceStatus, snapshotAuthorityStatus] = await Promise.all([
      childExit,
      receiptRead,
      provenanceWrite,
      snapshotAuthorityWrite,
    ]);
    if (teardownTimer !== undefined) {
      clearTimeout(teardownTimer);
    }
    if (mode === 'orphan-descendant' && processGroupExists(child.pid)) {
      terminateProcessGroup(child.pid, 'SIGTERM');
      if (!(await waitForProcessGroupExit(child.pid))) {
        terminateProcessGroup(child.pid, 'SIGKILL');
      }
      const cleaned = await waitForProcessGroupExit(child.pid);
      await record({
        command: 'managed-vite-emergency-cleanup',
        mode,
        orphanDescendant: true,
        cleaned,
      });
      throw new Error('managed Vite orphan descendant required emergency cleanup');
    }
    if (forced) {
      await record({
        command: 'managed-vite-emergency-cleanup',
        mode,
        teardownTimeout: true,
        childSignal: exit.signal,
      });
      throw new Error('managed Vite teardown timed out');
    }
    if (
      provenanceStatus !== 'fulfilled' ||
      snapshotAuthorityStatus !== 'fulfilled' ||
      receiptBytes === undefined ||
      !isCanonicalReceipt(receiptBytes) ||
      exit.status !== 0 ||
      exit.signal !== null
    ) {
      const reason =
        provenanceStatus !== 'fulfilled'
          ? 'provenance-write'
          : snapshotAuthorityStatus !== 'fulfilled'
            ? 'snapshot-authority-write'
            : mode === 'oversized-receipt' && receiptBytes === undefined
              ? 'oversized-receipt'
              : mode === 'missing-receipt' &&
                  (receiptBytes === undefined || receiptBytes.length === 0)
                ? 'missing-receipt'
                : exit.status !== 0 || exit.signal !== null
                  ? 'early-exit'
                  : !isCanonicalReceipt(receiptBytes)
                    ? 'malformed-receipt'
                    : 'early-exit';
      await record({
        command: 'managed-vite-protocol-failure',
        mode,
        reason,
        childStatus: exit.status,
        childSignal: exit.signal,
      });
      throw new Error('managed Vite child protocol failed');
    }
    await record({
      command: 'managed-vite-protocol',
      framework,
      provenanceFd: 3,
      receiptFd: 4,
      snapshotAuthorityFd: 5,
      provenanceBytes: Buffer.byteLength(provenance, 'utf8'),
      snapshotAuthorityBytes: snapshotAuthority.bytes.length,
      receiptBytes: receiptBytes.length,
      childStatus: exit.status,
      emergencyCleanup: false,
    });
    if (forwardedSignal !== undefined) {
      process.kill(process.pid, forwardedSignal);
    }
  } finally {
    if (teardownTimer !== undefined) {
      clearTimeout(teardownTimer);
    }
    provenancePipe.destroy();
    receiptPipe.destroy();
    snapshotAuthorityPipe.destroy();
    process.removeListener('SIGINT', onInterrupt);
    process.removeListener('SIGTERM', onTerminate);
  }
};

export const runManagedViteChildFixture = async ({ descriptorPath }) => {
  const descriptor = JSON.parse(await readFile(descriptorPath, 'utf8'));
  const framework = descriptor.framework;
  const snapshotAuthority = await readSnapshotAuthority(descriptorPath, descriptor);
  const provenance = await readBounded(
    createReadStream('', { fd: 3, autoClose: true }),
    16 * 1024,
  );
  const serializedProvenance = provenance.toString('utf8');
  if (
    serializedProvenance.length === 0 ||
    JSON.stringify(JSON.parse(serializedProvenance), null, 2) + '\n' !== serializedProvenance
  ) {
    throw new Error('managed Vite provenance transport was not canonical');
  }
  await record({
    command: 'managed-vite-child',
    framework,
    provenanceFd: 3,
    receiptFd: 4,
    snapshotAuthorityFd: 5,
    provenanceBytes: provenance.length,
    snapshotAuthorityBytes: snapshotAuthority.bytes.length,
    mode,
  });

  if (mode === 'early-exit') {
    process.exitCode = 1;
    return;
  }
  if (mode === 'missing-receipt') {
    await closeChildResult();
    return;
  }
  if (mode === 'malformed-receipt') {
    await writeChildResult(Buffer.from('{"unexpected":true}\n', 'utf8'));
    return;
  }
  if (mode === 'oversized-receipt') {
    await writeChildResult(Buffer.alloc(RECEIPT_MAX_BYTES + 1, 0x61));
    return;
  }
  if (mode === 'orphan-descendant') {
    const descendant = spawn(
      process.execPath,
      [
        '-e',
        "process.once('SIGTERM', () => undefined); process.stdout.write('ready'); setInterval(() => undefined, 1000);",
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    await new Promise((resolveReady, rejectReady) => {
      descendant.once('error', rejectReady);
      descendant.stdout.once('data', resolveReady);
    });
    descendant.stdout.destroy();
    descendant.unref();
    await writeChildResult(Buffer.from(receipt(), 'utf8'));
    await new Promise(() => {
      setInterval(() => undefined, 1_000);
    });
    return;
  }
  if (mode === 'teardown-timeout') {
    process.once('SIGTERM', () => undefined);
    await writeChildResult(Buffer.from('managed Vite started\n', 'utf8'));
    await new Promise(() => {
      setInterval(() => undefined, 1_000);
    });
    return;
  }

  const entry = framework === 'vue3' ? 'main.ts' : 'main.tsx';
  const server = createServer(async (request, response) => {
    await record({ command: 'loopback-probe', framework, path: request.url });
    const page = '<script type="module" src="/src/' + entry + '"></script>';
    const vueEntry = "import App from '/src/App.vue';";
    const vueComponent = "const frameworkLabel = 'vue-artifact';";
    const reactEntry = "import RefreshRuntime from '/@react-refresh'; jsxDEV();";
    const body = request.url === '/'
      ? page
      : framework === 'vue3' && request.url === '/src/main.ts'
        ? vueEntry
        : framework === 'vue3' && request.url === '/src/App.vue'
          ? vueComponent
          : framework === 'react' && request.url === '/src/main.tsx'
            ? reactEntry
            : undefined;
    if (body === undefined) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/javascript' });
    response.end(body);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen({ host: '127.0.0.1', port: descriptor.port }, resolveListen);
  });
  let stopping = false;
  const stop = (signal) => {
    if (stopping) {
      return;
    }
    stopping = true;
    server.close(() => {
      void record({ command: 'managed-vite-teardown', framework, signal }).then(() =>
        writeChildResult(Buffer.from(receipt(), 'utf8')),
      );
    });
  };
  process.once('SIGTERM', () => stop('SIGTERM'));
  process.once('SIGINT', () => stop('SIGINT'));
  process.stdout.write('managed Vite started\n');
};
`;
async function createArtifacts(root: string): Promise<void> {
  const dist = join(root, 'dist');
  const release = join(root, 'build', 'Release');
  await Promise.all([mkdir(dist, { recursive: true }), mkdir(release, { recursive: true })]);
  await Promise.all([
    writeFile(
      join(dist, 'cli.js'),
      [
        "import { appendFile, lstat, readFile } from 'node:fs/promises';",
        "import { createServer } from 'node:http';",
        "import { dirname, join } from 'node:path';",
        '',
        '',
        'const command = process.argv[2];',
        'const args = process.argv.slice(3);',
        "const record = (entry) => appendFile('cli-invocations.ndjson', JSON.stringify(entry) + '\\n');",
        '',
        "if (command === 'help' && args.length === 0) {",
        '  await record({ command, args });',
        '  process.stdout.write([',
        "    'usage: scene-glass-onboarding <command>',",
        "    '',",
        "    'commands:',",
        "    '  help',",
        "    '  setup',",
        "    '  start',",
        "    '  uninstall',",
        "    '  descriptor-check --descriptor <absolute-path> --kind static',",
        "    '  native-self-test --root <absolute-path>',",
        "    '  static-preview --descriptor <absolute-path>',",
        "    '',",
        "  ].join('\\n'));",
        '} else if (',
        "  command === 'descriptor-check'",
        '  && args.length === 4',
        "  && args[0] === '--descriptor'",
        "  && args[2] === '--kind'",
        "  && args[3] === 'static'",
        ') {',
        "  const descriptor = await readFile(args[1], 'utf8');",
        '  const parsed = JSON.parse(descriptor);',
        '  const approvedRootPath = join(dirname(args[1]), parsed.publicRoot);',
        '  const [approvedRoot, credential] = await Promise.all([',
        '    lstat(approvedRootPath, { bigint: true }),',
        '    lstat(parsed.credentialAuthorities[0].path, { bigint: true }),',
        '  ]);',
        '  await record({',
        '    command,',
        '    args,',
        '    descriptor,',
        '    approvedRootPath,',
        '    approvedRootIdentity: { device: approvedRoot.dev.toString(), inode: approvedRoot.ino.toString() },',
        '    credentialIdentity: { device: credential.dev.toString(), inode: credential.ino.toString() },',
        '  });',
        "  process.stdout.write('descriptor check passed\\n');",
        "} else if (command === 'static-preview' && args.length === 2 && args[0] === '--descriptor') {",
        "  const descriptor = JSON.parse(await readFile(args[1], 'utf8'));",
        "  const credential = await readFile(descriptor.credentialAuthorities[0].path, 'utf8');",
        "  const token = credential.split('\\n').find((line) => line.startsWith('SCENE_GLASS_HOST_TOKEN='))?.slice('SCENE_GLASS_HOST_TOKEN='.length);",
        "  if (token === undefined) throw new Error('static preview credential did not contain the host token');",
        '  const server = createServer(async (request, response) => {',
        "    await record({ command: 'static-loopback-probe', path: request.url });",
        "    const body = request.url === '/'",
        "      ? '<!doctype html>\\n<html><head>\\n' +",
        '        \'<script async src="http://127.0.0.1:4175/scene-glass-loader.js" \' +',
        '        `data-scg-project="${descriptor.projectId}" data-scg-token="${token}" data-scg-navigation="document"></script>\\n` +',
        "        '</head><body><p>static artifact page</p></body></html>\\n'",
        '      : request.url === descriptor.readinessPath',
        '        ? `{"ready":true,"projectId":"${descriptor.projectId}"}\\n`',
        '        : undefined;',
        '    if (body === undefined) {',
        '      response.writeHead(404);',
        '      response.end();',
        '      return;',
        '    }',
        "    response.writeHead(200, { 'content-type': request.url === '/' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8' });",
        '    response.end(body);',
        '  });',
        '  await new Promise((resolve, reject) => {',
        "    server.once('error', reject);",
        "    server.listen({ host: '127.0.0.1', port: descriptor.port }, resolve);",
        '  });',
        '  await record({ command, args, pid: process.pid });',
        '  let stopping = false;',
        '  const stop = (signal) => {',
        '    if (stopping) {',
        '      return;',
        '    }',
        '    stopping = true;',
        "    server.close(() => { void record({ command: 'static-preview-teardown', signal }); });",
        '  };',
        "  process.once('SIGTERM', () => stop('SIGTERM'));",
        "  process.once('SIGINT', () => stop('SIGINT'));",
        "} else if (command === 'native-self-test' && args.length === 2 && args[0] === '--root') {",
        '  await record({ command, args });',
        "  process.stdout.write('native self-test passed\\n');",
        "} else if (command === 'managed-vite-preflight' && args.length === 2 && args[0] === '--descriptor') {",
        "  const descriptor = JSON.parse(await readFile(args[1], 'utf8'));",
        "  const { readSnapshotAuthority } = await import('./managed-vite-fixture.mjs');",
        '  const snapshotAuthority = await readSnapshotAuthority(args[1], descriptor);',
        '  await record({',
        '    command,',
        '    args,',
        '    framework: descriptor.framework,',
        '    snapshotAuthorityFd: 5,',
        '    snapshotAuthorityBytes: snapshotAuthority.bytes.length,',
        '  });',
        "  process.stdout.write('managed Vite preflight passed\\n');",
        "} else if (command === 'managed-vite-dev' && args.length === 2 && args[0] === '--descriptor') {",
        "  process.stdout.write('managed Vite preflight passed\\n');",
        "  const { runManagedViteDevFixture } = await import('./managed-vite-fixture.mjs');",
        '  await runManagedViteDevFixture({ descriptorPath: args[1] });',
        "} else if (command === 'managed-vite-child' && args.length === 2 && args[0] === '--descriptor') {",
        "  const { runManagedViteChildFixture } = await import('./managed-vite-fixture.mjs');",
        '  await runManagedViteChildFixture({ descriptorPath: args[1] });',
        "} else if ((command === 'setup' || command === 'start' || command === 'uninstall') && args.length !== 0) {",
        "  process.stderr.write('scene-glass-onboarding: [SCG_ONBOARDING_COMMAND_INVALID] [parse] command failed.\\n');",
        '  process.exitCode = 1;',
        '} else {',
        '  process.exitCode = 1;',
        '}',
        '',
      ].join('\n'),
    ),
    writeFile(join(dist, 'managed-vite-fixture.mjs'), MANAGED_VITE_ARTIFACT_FIXTURE),
    writeFile(join(release, 'secure_read.node'), Buffer.from('native-addon')),
    writeFile(
      join(root, 'binding.gyp'),
      '{"targets":[{"target_name":"secure_read","defines":["NAPI_VERSION=9"]}]}\n',
    ),
  ]);
  await Promise.all([
    chmod(join(dist, 'cli.js'), 0o600),
    chmod(join(release, 'secure_read.node'), 0o755),
  ]);
}
async function writeFixtureBuildManifest(root: string): Promise<{
  readonly addonSha256: string;
  readonly arch: string;
  readonly cliSha256: string;
  readonly napi: 9;
  readonly nodeMajor: 24;
  readonly platform: string;
  readonly schemaVersion: 1;
}> {
  const [cli, addon] = await Promise.all([
    readFile(join(root, 'dist', 'cli.js')),
    readFile(join(root, 'build', 'Release', 'secure_read.node')),
  ]);
  const manifest = {
    schemaVersion: 1 as const,
    platform: process.platform,
    arch: process.arch,
    nodeMajor: 24 as const,
    napi: 9 as const,
    addonSha256: createHash('sha256').update(addon).digest('hex'),
    cliSha256: createHash('sha256').update(cli).digest('hex'),
  };
  const manifestPath = join(root, 'dist', 'build-manifest.json');
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
  await chmod(manifestPath, 0o644);
  return manifest;
}

function lockfile(): string {
  const importerDependencies = [
    ...Object.entries(ONBOARDING_WORKSPACE_DEPENDENCIES).flatMap(([name, resolution]) => [
      `      ${name}:`,
      '        specifier: workspace:*',
      `        version: ${resolution}`,
    ]),
    ...Object.entries(ONBOARDING_EXTERNAL_DEPENDENCIES).flatMap(([name, version]) => [
      `      ${name}:`,
      `        specifier: ${version}`,
      `        version: ${version}`,
    ]),
  ];
  const importerSnapshots = Object.entries(ONBOARDING_EXTERNAL_DEPENDENCIES)
    .filter(
      ([packageName]) =>
        packageName !== 'esbuild' && packageName !== 'fs-ext' && packageName !== 'node-gyp',
    )
    .map(([packageName, version]) => `  ${packageName}@${version}: {}`);

  return [
    "lockfileVersion: '9.0'",
    '',
    'importers:',
    '  packages/onboarding:',
    '    dependencies:',
    ...importerDependencies,
    '',
    'packages:',
    '  esbuild@0.25.5:',
    '    resolution: {integrity: ' + ESBUILD_0_25_5_INTEGRITY + '}',
    '  esbuild@0.28.1:',
    '    resolution: {integrity: ' + ESBUILD_0_28_1_INTEGRITY + '}',
    '  fs-ext@2.1.1:',
    '    resolution: {integrity: ' + FS_EXT_INTEGRITY + '}',
    '',
    'snapshots:',
    '  alias-consumer@1.0.0:',
    '    dependencies:',
    '      esbuild-alias: esbuild@0.25.5',
    '  consumer-esbuild@1.0.0:',
    '    dependencies:',
    '      esbuild: 0.25.5',
    '  consumer-workspace@1.0.0:',
    '    dependencies:',
    '      "@scene-glass/browser-client": link:../browser-client',
    '  escaping@1.0.0:',
    '    dependencies:',
    '      outside: 1.0.0',
    '  outside@1.0.0: {}',
    '  esbuild@0.25.5: {}',
    '  esbuild@0.28.1: {}',
    '  fs-ext@2.1.1: {}',
    '  node-gyp@11.2.0: {}',
    ...importerSnapshots,
    '  peer-consumer@1.0.0:',
    '    dependencies:',
    '      peer-target: 1.0.0(peer-a@1.0.0)',
    '  peer-target@1.0.0(peer-a@1.0.0): {}',
    '  peer-target@1.0.0(peer-b@1.0.0): {}',
    '  strip-ansi@6.0.1: {}',
    '  tsx@4.23.1:',
    '    dependencies:',
    '      esbuild: 0.28.1',
    '',
  ].join('\n');
}
