import { execFile } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseServerConfigV1 } from '@scene-glass/contracts';
import { createSceneGlassApp, registerSceneGlassLoader } from '@scene-glass/server';
import {
  createLifecycleOriginAuthority,
  createSceneGlassLifecycleApp,
} from '../../server/src/app.js';
import {
  CREDENTIAL_AUTHORITY_REGISTRY_FILENAME,
  MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES,
  parseCredentialAuthorityRegistryJsonV1,
  verifyCredentialAuthorities,
  withSelectedCredential,
  type CredentialAuthorityRegistryEntry,
} from './credential-authority.js';
import {
  parseStaticHostDescriptorJsonV1,
  type TrustedDescriptorProject,
  type TrustedDescriptorProjectSet,
} from './descriptors.js';
import {
  assertSecureReadNativeAvailable,
  secureReadBeneath,
  zeroizeBuffer,
  revokeCredentialReadCapability,
} from './native.js';
import { startStaticRuntime, type StaticRuntime } from './static/index.js';
import type { CredentialAuthority, FileIdentity, StaticHostDescriptorV1 } from './types.js';
import {
  LifecycleEngine,
  type LifecycleEngineOperation,
  type LifecycleResult,
} from './lifecycle/engine.js';
import {
  managedVitePluginFromConfig,
  resolveDeclaredViteOriginPolicy,
} from './lifecycle/host-plan.js';
import type { SetupProjectSeed } from './lifecycle/config.js';
import {
  createNodeLifecycleEnginePort,
  type NodeForegroundMcpLauncher,
} from './lifecycle/node-engine-port.js';
import {
  createNodeLifecycleVerificationPorts,
  nodeVerificationAuthorityState,
} from './lifecycle/node-verification-port.js';
import { parseSetupManifestJsonV1 } from './lifecycle/provenance.js';
import type {
  NodeBootstrapProfile,
  NodeBrowserProfile,
} from './lifecycle/node-verification-port.js';

const MAX_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_PACKAGE_MANIFEST_BYTES = 64 * 1024;
const NATIVE_SELF_TEST_MAX_BYTES = 64 * 1024;
const CREDENTIAL_MAX_BYTES = 8 * 1024;
const CONFIG_PATH_ENV = 'SCENE_GLASS_CONFIG_PATH';

type Invocation =
  | { readonly command: 'help' }
  | { readonly command: 'setup' | 'start' | 'uninstall' }
  | {
      readonly command: 'descriptor-check';
      readonly descriptorPath: string;
      readonly kind: DescriptorKind;
    }
  | { readonly command: 'native-self-test'; readonly root: string }
  | { readonly command: 'static-preview'; readonly descriptorPath: string };

type CliPhase = Invocation['command'] | 'parse';
type DescriptorKind = 'static';

interface ParsedDescriptor<T> {
  readonly descriptor: T;
  readonly configuredProjects: TrustedDescriptorProjectSet;
  readonly projectRoot: string;
}

let activePhase: CliPhase = 'parse';

class CliError extends Error {
  public readonly code: string;
  public readonly phase: CliPhase;

  public constructor(
    code: string = 'SCG_ONBOARDING_COMMAND_INVALID',
    phase: CliPhase = activePhase,
  ) {
    super('scene-glass-onboarding command failed');
    this.name = 'CliError';
    this.code = code;
    this.phase = phase;
  }
}

function commandError(): never {
  throw new CliError();
}

function parseInvocation(argv: readonly string[]): Invocation {
  const [command, ...arguments_] = argv;
  if (command === 'help' && arguments_.length === 0) {
    return Object.freeze({ command });
  }
  if (
    (command === 'setup' || command === 'start' || command === 'uninstall') &&
    arguments_.length === 0
  ) {
    return Object.freeze({ command });
  }

  if (command === 'descriptor-check') {
    if (arguments_.length !== 4 || arguments_[0] !== '--descriptor' || arguments_[2] !== '--kind') {
      commandError();
    }
    const descriptorPath = parseAbsolutePath(arguments_[1]);
    const kind = arguments_[3];
    if (kind !== 'static') {
      commandError();
    }
    return Object.freeze({ command, descriptorPath, kind });
  }

  if (command === 'native-self-test') {
    if (arguments_.length !== 2 || arguments_[0] !== '--root') {
      commandError();
    }
    return Object.freeze({ command, root: parseAbsolutePath(arguments_[1]) });
  }

  if (command === 'static-preview') {
    if (arguments_.length !== 2 || arguments_[0] !== '--descriptor') {
      commandError();
    }
    return Object.freeze({ command, descriptorPath: parseAbsolutePath(arguments_[1]) });
  }

  commandError();
}

function parseAbsolutePath(value: string | undefined): string {
  if (typeof value !== 'string' || value.includes('\0') || !isAbsolute(value)) {
    commandError();
  }
  return resolve(value);
}

async function main(): Promise<void> {
  const invocation = parseInvocation(process.argv.slice(2));
  activePhase = invocation.command;
  switch (invocation.command) {
    case 'help':
      writeUsage();
      return;
    case 'setup':
    case 'start':
    case 'uninstall':
      await runLifecycleCommand(invocation.command);
      return;
    case 'descriptor-check':
      await descriptorCheck(invocation.descriptorPath);
      return;
    case 'native-self-test':
      await nativeSelfTest(invocation.root);
      return;
    case 'static-preview':
      await staticPreview(invocation.descriptorPath);
      return;
  }
}

function writeUsage(): void {
  process.stdout.write(
    'usage: scene-glass-onboarding <command>\n\n' +
      'commands:\n' +
      '  help\n' +
      '  setup\n' +
      '  start\n' +
      '  uninstall\n' +
      '  descriptor-check --descriptor <absolute-path> --kind static\n' +
      '  native-self-test --root <absolute-path>\n' +
      '  static-preview --descriptor <absolute-path>\n',
  );
}

type PublicLifecycleCommand = Extract<LifecycleEngineOperation, 'setup' | 'start' | 'uninstall'>;

const LIFECYCLE_HOST_PORT = 4174;
const LIFECYCLE_MCP_PORT = 4175;
const PUBLIC_CREDENTIAL_PATH = '.env.development.local';
const PREVIEW_OPERATION_LIMIT = 32;
const APPROVAL_INPUT_LIMIT = 64;

async function runLifecycleCommand(command: PublicLifecycleCommand): Promise<void> {
  const [checkoutRoot, hostRoot, homeDirectory] = await Promise.all([
    canonicalDirectory(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')),
    canonicalDirectory(process.cwd()),
    canonicalDirectory(homedir()),
  ]);
  const project =
    command === 'setup'
      ? await discoverLifecycleProject(hostRoot)
      : lifecyclePlaceholderProject(hostRoot);
  const verification = createCliLifecycleVerificationPorts(homeDirectory, checkoutRoot);
  const stateRootPath = await selectPublicLifecycleStateRoot(checkoutRoot, hostRoot);
  const port = createNodeLifecycleEnginePort({
    approval: (input) => requestLifecycleApproval(input, project.allowedOrigins.join(' + ')),
    checkoutRoot,
    cwd: checkoutRoot,
    environment: process.env,
    foregroundMcp: {
      launch: async (input) => launchLifecycleMcpForeground(input, checkoutRoot),
    },
    homeDirectory,
    stateRootPath,
    host: {
      credentialPath: join(hostRoot, PUBLIC_CREDENTIAL_PATH),
      port: lifecycleProjectPort(project),
      rootPath: hostRoot,
    },
    project,
    verification,
  });
  const engine = new LifecycleEngine(port);
  const result =
    command === 'setup'
      ? await engine.runSetup()
      : command === 'start'
        ? await engine.runStart()
        : await engine.runUninstall();
  writeLifecycleResult(result);
  if (result.status !== 'success') {
    throw new CliError(result.code, command);
  }
}

async function canonicalDirectory(path: string): Promise<string> {
  const canonical = await realpath(path);
  const facts = await lstat(canonical);
  if (!facts.isDirectory() || facts.isSymbolicLink()) {
    commandError();
  }
  return canonical;
}

async function discoverLifecycleProject(root: string): Promise<SetupProjectSeed> {
  const manifestPath = join(root, 'package.json');
  let manifestText: string;
  let manifest: unknown;
  try {
    manifestText = await readBoundedUtf8(manifestPath, MAX_PACKAGE_MANIFEST_BYTES);
    manifest = JSON.parse(manifestText);
  } catch {
    commandError();
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    Array.isArray(manifest) ||
    typeof (manifest as { readonly name?: unknown }).name !== 'string'
  ) {
    commandError();
  }

  const [publicTemplate, viteConfig] = await Promise.all([
    regularFileExists(join(root, 'public/index.html')),
    boundedOptionalUtf8(join(root, 'vite.config.ts'), MAX_DESCRIPTOR_BYTES),
  ]);
  const framework = detectLifecycleFramework(publicTemplate, viteConfig);
  const allowedOrigins =
    framework === 'html'
      ? [`http://127.0.0.1:${LIFECYCLE_HOST_PORT}`]
      : declaredViteAllowedOrigins(
          (manifest as { readonly name: string }).name,
          framework,
          manifestText!,
          viteConfig,
        );
  try {
    return Object.freeze({
      allowedOrigins: Object.freeze(allowedOrigins),
      framework,
      projectId: (manifest as { readonly name: string }).name,
      root,
    });
  } catch {
    commandError();
  }
}

function lifecyclePlaceholderProject(root: string): SetupProjectSeed {
  return Object.freeze({
    allowedOrigins: Object.freeze([`http://127.0.0.1:${LIFECYCLE_HOST_PORT}`]),
    framework: 'html',
    projectId: 'scene-glass-lifecycle',
    root,
  });
}

function detectLifecycleFramework(
  publicTemplate: boolean,
  viteConfig: string | undefined,
): 'html' | 'react' | 'vue3' {
  if (publicTemplate && viteConfig === undefined) {
    return 'html';
  }
  if (publicTemplate || viteConfig === undefined) {
    commandError();
  }
  const plugin = managedVitePluginFromConfig(viteConfig);
  if (plugin === undefined) {
    commandError();
  }
  return plugin === '@vitejs/plugin-vue' ? 'vue3' : 'react';
}

async function regularFileExists(path: string): Promise<boolean> {
  try {
    const facts = await lstat(path);
    if (facts.isSymbolicLink()) {
      commandError();
    }
    return facts.isFile();
  } catch (error) {
    if (isMissingFile(error)) {
      return false;
    }
    throw error;
  }
}

async function boundedOptionalUtf8(path: string, maximum: number): Promise<string | undefined> {
  if (!(await regularFileExists(path))) {
    return undefined;
  }
  return readBoundedUtf8(path, maximum);
}

function lifecycleProjectPort(project: SetupProjectSeed): number {
  const origin = project.allowedOrigins[0];
  if (origin === undefined) commandError();
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/u.exec(origin);
  if (match?.[1] === undefined) commandError();
  const port = Number(match[1]);
  if (!Number.isSafeInteger(port) || port > 65_535) commandError();
  return port;
}

/**
 * Authorizes both loopback origin spellings for a Vite host. Vite's default
 * host is 'localhost', which Node may resolve to ::1 only; the browser Origin
 * header then reads http://localhost:<port> while an IPv4 binding serves
 * http://127.0.0.1:<port>. Both are loopback-served on this machine and the
 * Origin header cannot be forged by web content, so both are authorized and
 * the host needs no explicit `server.host`.
 */
function declaredViteAllowedOrigins(
  projectId: string,
  framework: 'vue3' | 'react',
  packageJson: string,
  viteConfig: string | undefined,
): string[] {
  if (viteConfig === undefined) commandError();
  const resolution = resolveDeclaredViteOriginPolicy({
    framework,
    packageJson,
    projectId,
    viteConfig,
  });
  if (!resolution.ok) commandError();
  return [...resolution.policy.origins];
}
async function selectPublicLifecycleStateRoot(
  checkoutRoot: string,
  hostRoot: string,
): Promise<string> {
  const relativeStateRoot = '.scg/onboarding';
  const hostStateRoot = join(hostRoot, relativeStateRoot);
  if (await filesystemEntryExists(hostStateRoot)) return hostStateRoot;

  const legacyStateRoot = join(checkoutRoot, relativeStateRoot);
  const legacyManifestPath = join(legacyStateRoot, 'manifest.v1.json');
  const legacyManifest = await boundedOptionalUtf8(legacyManifestPath, MAX_DESCRIPTOR_BYTES);
  if (legacyManifest === undefined) {
    return (await filesystemEntryExists(join(legacyStateRoot, 'lifecycle.wal.v1.json')))
      ? legacyStateRoot
      : hostStateRoot;
  }
  try {
    const parsed = parseSetupManifestJsonV1(legacyManifest);
    const selectedDescriptors = parsed.artifacts.filter(
      (artifact) =>
        artifact.kind === 'file' &&
        artifact.hunks.some((hunk) => /^scg-(?:html|vue3|react)-descriptor$/u.test(hunk.subject)),
    );
    return selectedDescriptors.length === 1 &&
      selectedDescriptors[0]?.path === join(hostRoot, '.scg/runtime/host-descriptor.v1.json')
      ? legacyStateRoot
      : hostStateRoot;
  } catch {
    // Preserve fail-closed recovery for an existing unreadable legacy authority.
    return legacyStateRoot;
  }
}

async function filesystemEntryExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isMissingFile(error)) return false;
    throw error;
  }
}
function isMissingFile(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

async function requestLifecycleApproval(
  input: Readonly<{
    readonly preview: Readonly<{
      readonly operations: readonly Readonly<{
        readonly kind: string;
        readonly hunkCount: number;
      }>[];
    }>;
    readonly digest: Readonly<{
      readonly algorithm: 'sha256';
      readonly value: string;
      readonly operationCount: number;
    }>;
  }>,
  effectiveOrigin: string | undefined,
): Promise<boolean> {
  const operations = input.preview.operations
    .slice(0, PREVIEW_OPERATION_LIMIT)
    .map((operation) => `${operation.kind}:${operation.hunkCount}`)
    .join(', ');
  process.stdout.write(
    `setup preview: ${input.digest.operationCount} operation(s)${operations.length === 0 ? '' : ` [${operations}]`}${effectiveOrigin === undefined ? '' : ` origin=${effectiveOrigin}`}\n` +
      'Approve setup? [yes/no] ',
  );
  return readLifecycleApproval();
}

async function readLifecycleApproval(): Promise<boolean> {
  const input = await new Promise<Buffer>((resolveInput, rejectInput) => {
    let settled = false;
    const settle = (value: Buffer): void => {
      if (settled) {
        return;
      }
      settled = true;
      process.stdin.off('error', rejectInput);
      process.stdin.off('end', onEnd);
      process.stdin.pause();
      resolveInput(value.subarray(0, APPROVAL_INPUT_LIMIT));
    };
    const onData = (chunk: Buffer | string): void => settle(Buffer.from(chunk));
    const onEnd = (): void => settle(Buffer.alloc(0));
    process.stdin.once('data', onData);
    process.stdin.once('error', rejectInput);
    process.stdin.once('end', onEnd);
    process.stdin.resume();
  });
  try {
    return input.toString('utf8').trim().toLowerCase() === 'yes';
  } finally {
    input.fill(0);
  }
}

const LIFECYCLE_HTTP_MAX_BYTES = 64 * 1024;

function createCliLifecycleVerificationPorts(homeDirectory: string, checkoutRoot: string) {
  let syntheticDocument: LifecycleSyntheticDocument | undefined;
  return createNodeLifecycleVerificationPorts({
    loaderPort: LIFECYCLE_MCP_PORT,
    startBootstrapProfile: async () => startLifecycleBrowserProfile('bootstrap'),
    startBrowserProfile: async () => {
      if (syntheticDocument === undefined) {
        throw new Error('lifecycle synthetic document is unavailable');
      }
      return startLifecycleBrowserProfile('diagnostic', syntheticDocument);
    },
    startLoopbackMcp: async (input) => {
      const runtime = await startLifecycleLoopbackMcp(input.authority, homeDirectory, checkoutRoot);
      syntheticDocument = runtime.document;
      return runtime;
    },
  });
}

type LifecycleCredentialProject = Readonly<{
  readonly projectId: string;
  readonly serverTokenEnv: string;
  readonly credentialAuthority: CredentialAuthority;
}>;

type LifecycleCredentialEnvironment = Readonly<Record<string, string>>;

async function startLifecycleLoopbackMcp(
  authority: Parameters<typeof nodeVerificationAuthorityState>[0],
  homeDirectory: string,
  checkoutRoot: string,
) {
  const state = nodeVerificationAuthorityState(authority);
  const selectedProjectId = state.finalizedHost.descriptor.credentialProjectId;
  const projects = lifecycleCredentialProjects(state.configuredProjects, selectedProjectId);
  const configPath = lifecycleConfigPath(homeDirectory);
  const loaderSource = await readBoundedRegularFile(
    join(checkoutRoot, 'packages/browser-client/dist/scene-glass-loader.js'),
    MAX_DESCRIPTOR_BYTES,
  );
  let app: Awaited<ReturnType<typeof createSceneGlassApp>> | undefined;
  let syntheticDocument: LifecycleSyntheticDocument | undefined;
  let selectedToken: string | undefined;
  try {
    const started = await withAllProjectCredentials(
      projects,
      selectedProjectId,
      async (environment) => {
        const token =
          environment[
            projects.find((project) => project.projectId === selectedProjectId)?.serverTokenEnv ??
              ''
          ];
        if (typeof token !== 'string') {
          throw new Error('selected lifecycle credential is unavailable');
        }
        syntheticDocument = await startLifecycleSyntheticDocument({
          loaderUrl: state.finalizedHost.descriptor.loaderUrl,
          projectId: state.finalizedHost.descriptor.projectId,
          token,
        });
        return Object.freeze({
          app: await createSceneGlassApp({
            configPath,
            environment,
            diagnosticAdditionalAllowedOrigin: {
              origin: syntheticDocument.origin,
              projectId: state.finalizedHost.descriptor.projectId,
            },
          }),
          token,
        });
      },
    );
    app = started.app;
    selectedToken = started.token;
    registerSceneGlassLoader(app, loaderSource);
    await app.listen({ host: '127.0.0.1', port: LIFECYCLE_MCP_PORT });
  } catch (error) {
    const cleanupFailures: unknown[] = [];
    if (app !== undefined) {
      try {
        await app.close();
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    if (syntheticDocument !== undefined) {
      try {
        await syntheticDocument.close();
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    loaderSource.fill(0);
    selectedToken = undefined;
    if (cleanupFailures.length > 0) {
      throw new AggregateError(
        [error, ...cleanupFailures],
        'lifecycle MCP startup and cleanup failed',
        { cause: error },
      );
    }
    throw error;
  }
  if (app === undefined || selectedToken === undefined || syntheticDocument === undefined) {
    loaderSource.fill(0);
    throw new Error(
      'lifecycle MCP startup did not produce a synthetic document and selected credential',
    );
  }
  const activeApp = app;
  const activeSyntheticDocument = syntheticDocument;
  let requestToken: string | undefined = selectedToken;
  const endpoint = `http://127.0.0.1:${LIFECYCLE_MCP_PORT}/mcp/v1/projects/${state.finalizedHost.descriptor.projectId}`;
  // The diagnostic Origin must equal the project's configured allowed origin
  // (the resolved host dev origin, e.g. http://127.0.0.1:5173), not a fixed
  // managed-host port; the loopback MCP validates Origin against allowedOrigins.
  const diagnosticOrigin = `http://${state.finalizedHost.descriptor.host}:${state.finalizedHost.descriptor.port}`;
  let closed = false;
  const close = async (): Promise<void> => {
    if (!closed) {
      closed = true;
      try {
        await activeApp.close();
      } finally {
        try {
          await activeSyntheticDocument.close();
        } finally {
          loaderSource.fill(0);
          requestToken = undefined;
        }
      }
    }
  };
  return Object.freeze({
    document: activeSyntheticDocument,
    server: Object.freeze({
      loopback: true as const,
      persistent: false as const,
      async close() {
        await close();
        return Object.freeze({ phase: 'mcp-server' as const, records: Object.freeze([]) });
      },
    }),
    session: Object.freeze({
      async request(
        input: Readonly<{
          readonly body: Readonly<Record<string, unknown>>;
          readonly headers: Readonly<Record<string, string>>;
        }>,
        context: Readonly<{ readonly signal: AbortSignal; readonly deadline: number }>,
      ) {
        if (context.signal.aborted || Date.now() >= context.deadline) {
          throw new Error('lifecycle MCP request is no longer active');
        }
        if (requestToken === undefined) {
          throw new Error('lifecycle MCP session is closed');
        }
        const response = await fetch(endpoint, {
          body: JSON.stringify(input.body),
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${requestToken}`,
            'content-type': 'application/json',
            origin: diagnosticOrigin,
            ...input.headers,
          },
          method: 'POST',
          signal: context.signal,
        });
        const body = new Uint8Array(await response.arrayBuffer());
        if (body.byteLength > LIFECYCLE_HTTP_MAX_BYTES) {
          body.fill(0);
          throw new Error('lifecycle MCP response exceeds its byte limit');
        }
        return Object.freeze({
          body,
          headers: Object.freeze(Object.fromEntries(response.headers.entries())),
          status: response.status,
        });
      },
      async close() {
        await close();
        return Object.freeze({ phase: 'mcp-session' as const, records: Object.freeze([]) });
      },
    }),
  });
}

function lifecycleCredentialProjects(
  value: unknown,
  selectedProjectId: string,
): readonly LifecycleCredentialProject[] {
  const candidates = Array.isArray(value)
    ? value
    : isRecord(value) && Array.isArray(value.projects)
      ? value.projects
      : undefined;
  if (
    candidates === undefined ||
    candidates.length === 0 ||
    typeof selectedProjectId !== 'string'
  ) {
    throw new Error('lifecycle credential projects are invalid');
  }
  const projectIds = new Set<string>();
  const serverTokenEnvs = new Set<string>();
  const projects: LifecycleCredentialProject[] = [];
  let priorProjectId: string | undefined;
  for (const candidate of candidates) {
    // Required keys are strict; `canonicalRoot`/`publicRootIdentity` are the
    // only tolerated extras (present on descriptor-derived TrustedDescriptor
    // project sets, absent on manifest-derived foreground project sets).
    const candidateKeys =
      typeof candidate === 'object' && candidate !== null
        ? Reflect.ownKeys(candidate as Record<string, unknown>)
        : undefined;
    if (
      candidateKeys === undefined ||
      !candidateKeys.every(
        (key) =>
          typeof key === 'string' &&
          [
            'projectId',
            'canonicalRoot',
            'publicRootIdentity',
            'tokenEnv',
            'credentialAuthority',
          ].includes(key),
      ) ||
      !['projectId', 'tokenEnv', 'credentialAuthority'].every((key) =>
        candidateKeys.includes(key),
      ) ||
      typeof candidate.projectId !== 'string' ||
      candidate.projectId.length === 0 ||
      typeof candidate.tokenEnv !== 'string' ||
      candidate.tokenEnv.length === 0 ||
      !isExactRecord(candidate.credentialAuthority, ['projectId', 'path', 'device', 'inode'])
    ) {
      throw new Error('lifecycle credential projects are invalid');
    }
    const authority = candidate.credentialAuthority;
    if (
      authority.projectId !== candidate.projectId ||
      typeof authority.path !== 'string' ||
      !isAbsolute(authority.path) ||
      resolve(authority.path) !== authority.path ||
      typeof authority.device !== 'string' ||
      !/^(?:0|[1-9]\d*)$/.test(authority.device) ||
      typeof authority.inode !== 'string' ||
      !/^(?:0|[1-9]\d*)$/.test(authority.inode) ||
      (priorProjectId !== undefined && priorProjectId >= candidate.projectId) ||
      projectIds.has(candidate.projectId) ||
      serverTokenEnvs.has(candidate.tokenEnv)
    ) {
      throw new Error('lifecycle credential projects are invalid');
    }
    priorProjectId = candidate.projectId;
    projectIds.add(candidate.projectId);
    serverTokenEnvs.add(candidate.tokenEnv);
    projects.push(
      Object.freeze({
        projectId: candidate.projectId,
        serverTokenEnv: candidate.tokenEnv,
        credentialAuthority: Object.freeze({
          projectId: authority.projectId,
          path: authority.path,
          device: authority.device,
          inode: authority.inode,
        }),
      }),
    );
  }
  if (!projectIds.has(selectedProjectId)) {
    throw new Error('selected lifecycle credential project is unavailable');
  }
  return Object.freeze(projects);
}

async function withAllProjectCredentials<T>(
  projects: readonly LifecycleCredentialProject[],
  selectedProjectId: string,
  action: (environment: LifecycleCredentialEnvironment) => T | Promise<T>,
): Promise<T> {
  const authorities = Object.freeze(projects.map((project) => project.credentialAuthority));
  const tokens: Buffer[] = [];
  let environment: LifecycleCredentialEnvironment | undefined;
  let result!: T;
  let failed = false;
  let failure: unknown;
  try {
    for (const project of projects) {
      tokens.push(
        await readLifecycleProjectCredential(authorities, project.credentialAuthority.projectId),
      );
    }
    environment = lifecycleCredentialEnvironment(projects, tokens);
    result = await action(environment);
  } catch (error) {
    failed = true;
    failure = error;
  }

  const cleanupFailures: unknown[] = [];
  environment = undefined;
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    try {
      zeroizeBuffer(tokens[index]!);
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError);
    }
  }
  if (failed) {
    if (cleanupFailures.length > 0) {
      throw new AggregateError(
        [failure, ...cleanupFailures],
        'lifecycle credential action and cleanup failed',
        { cause: failure },
      );
    }
    throw failure;
  }
  if (cleanupFailures.length > 0) {
    throw new AggregateError(cleanupFailures, 'lifecycle credential cleanup failed');
  }
  return result;
}

async function readLifecycleProjectCredential(
  authorities: readonly CredentialAuthority[],
  selectedProjectId: string,
): Promise<Buffer> {
  const verified = verifyCredentialAuthorities({
    authorities,
    expectedOwnerUid: effectiveUserId(),
    maxBytes: CREDENTIAL_MAX_BYTES,
    selectedProjectId,
  });
  let token: Buffer | undefined;
  let failed = false;
  let failure: unknown;
  try {
    token = await withSelectedCredential(verified, lifecycleCredentialToken);
  } catch (error) {
    failed = true;
    failure = error;
  }

  let revokeFailure: unknown;
  try {
    revokeCredentialReadCapability(verified.capability);
  } catch (error) {
    revokeFailure = error;
  }
  if (failed) {
    if (revokeFailure !== undefined) {
      throw new AggregateError(
        [failure, revokeFailure],
        'lifecycle credential read and capability cleanup failed',
        { cause: failure },
      );
    }
    throw failure;
  }
  if (revokeFailure !== undefined) {
    if (token !== undefined) {
      try {
        zeroizeBuffer(token);
      } catch (cleanupError) {
        throw new AggregateError(
          [revokeFailure, cleanupError],
          'lifecycle credential capability and token cleanup failed',
          { cause: revokeFailure },
        );
      }
    }
    throw revokeFailure;
  }
  if (token === undefined) {
    throw new Error('lifecycle credential source is unavailable');
  }
  return token;
}

function lifecycleCredentialEnvironment(
  projects: readonly LifecycleCredentialProject[],
  tokens: readonly Buffer[],
): LifecycleCredentialEnvironment {
  if (projects.length !== tokens.length) {
    throw new Error('lifecycle credential environment is incomplete');
  }
  const environment = Object.create(null) as Record<string, string>;
  for (let index = 0; index < projects.length; index += 1) {
    const project = projects[index]!;
    const token = tokens[index];
    if (token === undefined) {
      throw new Error('lifecycle credential environment is incomplete');
    }
    if (Object.hasOwn(environment, project.serverTokenEnv)) {
      throw new Error('lifecycle credential environment aliases a server binding');
    }
    environment[project.serverTokenEnv] = token.toString('utf8');
  }
  return Object.freeze(environment);
}

const LIFECYCLE_CREDENTIAL_PREFIX = Buffer.from('SCENE_GLASS_HOST_TOKEN=', 'utf8');
const LIFECYCLE_CREDENTIAL_TOKEN_BYTES = 43;

/**
 * Finds the exactly-one `SCENE_GLASS_HOST_TOKEN=` assignment at a line boundary
 * (file start or immediately after a newline) within the canonical four-key
 * `.env.development.local` envelope. Returns -1 when it is absent or duplicated.
 */
function lifecycleHostTokenAssignmentStart(source: Buffer): number {
  let found = -1;
  let searchFrom = 0;
  while (searchFrom <= source.length - LIFECYCLE_CREDENTIAL_PREFIX.length) {
    const index = source.indexOf(LIFECYCLE_CREDENTIAL_PREFIX, searchFrom);
    if (index === -1) {
      break;
    }
    if (index === 0 || source[index - 1] === 0x0a) {
      if (found !== -1) {
        return -1;
      }
      found = index;
    }
    searchFrom = index + 1;
  }
  return found;
}

function lifecycleCredentialToken(source: Buffer): Buffer {
  const keyStart = lifecycleHostTokenAssignmentStart(source);
  if (keyStart === -1) {
    throw new Error('credential source is invalid');
  }
  const tokenStart = keyStart + LIFECYCLE_CREDENTIAL_PREFIX.length;
  const tokenEnd = tokenStart + LIFECYCLE_CREDENTIAL_TOKEN_BYTES;
  // 토큰은 줄 끝에서 끝나야 한다 — 뒤에 다른 글자가 붙으면 그 줄은 다른 값이라는 뜻이다.
  // 다만 파일의 마지막 줄이 줄바꿈 없이 끝나는 것은 흔한 정상 텍스트 파일이므로 받아들인다.
  // 편집기가 마지막 줄바꿈을 지웠다는 이유로 기동을 막을 일은 아니다.
  const terminator = source.length > tokenEnd ? source[tokenEnd] : 0x0a;
  if (source.length < tokenEnd || (terminator !== 0x0a && terminator !== 0x0d)) {
    throw new Error('credential source is invalid');
  }
  const token = Buffer.alloc(LIFECYCLE_CREDENTIAL_TOKEN_BYTES);
  source.copy(token, 0, tokenStart, tokenEnd);
  for (const byte of token) {
    if (!(
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x5f
    )) {
      const failure = new Error('credential source is invalid');
      try {
        zeroizeBuffer(token);
      } catch (cleanupError) {
        throw new AggregateError(
          [failure, cleanupError],
          'credential token parsing and cleanup failed',
          { cause: failure },
        );
      }
      throw failure;
    }
  }
  return token;
}

function lifecycleConfigPath(homeDirectory: string): string {
  const selected = process.env[CONFIG_PATH_ENV] ?? join(homeDirectory, '.scg/config.json');
  if (!isAbsolute(selected) || selected.includes('\0')) {
    commandError();
  }
  return resolve(selected);
}

interface LifecycleBrowserPage {
  evaluate<T>(expression: () => T | Promise<T>): Promise<T>;
  goto(
    url: string,
    options: Readonly<{ readonly timeout: number; readonly waitUntil: 'domcontentloaded' }>,
  ): Promise<unknown>;
  waitForFunction(
    expression: () => boolean | Promise<boolean>,
    arg: undefined,
    options: Readonly<{ readonly timeout: number }>,
  ): Promise<unknown>;
}

interface LifecycleSyntheticDocument {
  readonly origin: string;
  readonly url: string;
  close(): Promise<void>;
}

interface LifecycleBrowserContext {
  newPage(): Promise<LifecycleBrowserPage>;
  close(): Promise<void>;
}

interface LifecycleBrowser {
  newContext(): Promise<LifecycleBrowserContext>;
  close(): Promise<void>;
}

interface LifecyclePlaywright {
  readonly chromium: {
    launch(input: Readonly<{ readonly headless: true }>): Promise<LifecycleBrowser>;
  };
}

interface LifecycleBrowserState {
  readonly cacheStorageNames: readonly string[];
  readonly indexedDbNames: readonly string[];
  readonly localStorageKeys: readonly string[];
  readonly serviceWorkerRegistrations: readonly string[];
  readonly sessionStorageKeys: readonly string[];
}

function lifecyclePlaywright(): LifecyclePlaywright {
  return createRequire(import.meta.url)('@playwright/test') as LifecyclePlaywright;
}
async function startLifecycleSyntheticDocument(
  input: Readonly<{
    readonly loaderUrl: string;
    readonly projectId: string;
    readonly token: string;
  }>,
): Promise<LifecycleSyntheticDocument> {
  const body = Buffer.from(
    `<!doctype html><html><head><script async src="${escapeLifecycleHtmlAttribute(input.loaderUrl)}" data-scg-project="${escapeLifecycleHtmlAttribute(input.projectId)}" data-scg-token="${escapeLifecycleHtmlAttribute(input.token)}" data-scg-navigation="spa"></script></head><body><div id="app"></div></body></html>`,
    'utf8',
  );
  const server = createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/') {
      response.writeHead(404, { connection: 'close' }).end();
      return;
    }
    response.writeHead(200, {
      'cache-control': 'no-store',
      connection: 'close',
      'content-length': body.byteLength,
      'content-type': 'text/html; charset=utf-8',
    });
    response.end(body);
  });
  server.keepAliveTimeout = 1;
  try {
    await listenLifecycleSyntheticDocument(server);
    const address = server.address();
    if (address === null || typeof address === 'string' || address.port < 1) {
      throw new Error('lifecycle synthetic document did not bind a loopback port');
    }
    const origin = `http://127.0.0.1:${address.port}`;
    let closed = false;
    return Object.freeze({
      origin,
      url: `${origin}/`,
      async close() {
        if (!closed) {
          closed = true;
          try {
            await closeLifecycleSyntheticDocument(server);
          } finally {
            body.fill(0);
          }
        }
      },
    });
  } catch (error) {
    body.fill(0);
    await closeLifecycleSyntheticDocument(server);
    throw error;
  }
}

function escapeLifecycleHtmlAttribute(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
}

function listenLifecycleSyntheticDocument(server: Server): Promise<void> {
  return new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen({ host: '127.0.0.1', port: 0 }, () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });
}

function closeLifecycleSyntheticDocument(server: Server): Promise<void> {
  if (!server.listening) {
    return Promise.resolve();
  }
  return new Promise((resolveClose, rejectClose) => {
    server.close((error) => (error === undefined ? resolveClose() : rejectClose(error)));
  });
}

function startLifecycleBrowserProfile(kind: 'bootstrap'): Promise<NodeBootstrapProfile>;
function startLifecycleBrowserProfile(
  kind: 'diagnostic',
  syntheticDocument: LifecycleSyntheticDocument,
): Promise<NodeBrowserProfile>;
async function startLifecycleBrowserProfile(
  kind: 'bootstrap' | 'diagnostic',
  syntheticDocument?: LifecycleSyntheticDocument,
): Promise<NodeBootstrapProfile | NodeBrowserProfile> {
  const browser = await lifecyclePlaywright().chromium.launch({ headless: true });
  let context: LifecycleBrowserContext | undefined;
  let page: LifecycleBrowserPage | undefined;
  let closed = false;
  try {
    context = await browser.newContext();
    page = await context.newPage();
  } catch (error) {
    await browser.close();
    throw error;
  }
  if (context === undefined || page === undefined) {
    throw new Error('Chromium profile did not create a page');
  }
  const activeContext = context;
  const activePage = page;
  const closeProfile = async <T extends 'bootstrap-profile' | 'browser-profile'>(phase: T) => {
    if (closed) {
      return Object.freeze({
        browserState: emptyLifecycleBrowserState(),
        phase,
        records: Object.freeze([]),
      });
    }
    closed = true;
    let state = emptyLifecycleBrowserState();
    try {
      if (phase === 'browser-profile') {
        state = await clearAndInspectLifecycleBrowserState(activePage);
      }
    } finally {
      try {
        await activeContext.close();
      } finally {
        try {
          await browser.close();
        } finally {
          if (phase === 'browser-profile') {
            await syntheticDocument?.close();
          }
        }
      }
    }
    return Object.freeze({
      browserState: state,
      phase,
      records: Object.freeze([]),
    });
  };

  if (kind === 'bootstrap') {
    return Object.freeze({
      empty: true as const,
      workersEnabled: true as const,
      persistent: false as const,
      async smoke(
        contextInput: Readonly<{ readonly signal: AbortSignal; readonly deadline: number }>,
      ) {
        assertLifecycleDeadline(contextInput);
        const workersEnabled = await activePage.evaluate(() => typeof Worker === 'function');
        assertLifecycleDeadline(contextInput);
        if (workersEnabled !== true) {
          throw new Error('Chromium workers are unavailable');
        }
      },
      close: async () => closeProfile('bootstrap-profile'),
    });
  }

  if (syntheticDocument === undefined) {
    throw new Error('lifecycle synthetic document is unavailable');
  }

  return Object.freeze({
    persistent: false as const,
    async verifyHostPage(
      input: Readonly<{
        readonly host: Readonly<{
          load(
            path: '/scene-glass-loader.js',
            context: Readonly<{ readonly signal: AbortSignal; readonly deadline: number }>,
          ): Promise<{
            readonly body: Uint8Array;
          }>;
        }>;
        readonly loaderPath: '/scene-glass-loader.js';
        readonly context: Readonly<{ readonly signal: AbortSignal; readonly deadline: number }>;
      }>,
    ) {
      assertLifecycleDeadline(input.context);
      const loader = await input.host.load(input.loaderPath, input.context);
      loader.body.fill(0);
      assertLifecycleDeadline(input.context);
      const timeout = Math.max(1, input.context.deadline - Date.now());
      await activePage.goto(syntheticDocument.url, { timeout, waitUntil: 'domcontentloaded' });
      assertLifecycleDeadline(input.context);
      await activePage.waitForFunction(
        () =>
          (
            window as Window & {
              readonly SceneGlass?: Readonly<{ readonly state?: unknown }>;
            }
          ).SceneGlass?.state === 'ready',
        undefined,
        { timeout: Math.max(1, input.context.deadline - Date.now()) },
      );
      assertLifecycleDeadline(input.context);
      await activePage.waitForFunction(
        () => document.querySelector('.scg-ui-overlay') !== null,
        undefined,
        { timeout: Math.max(1, input.context.deadline - Date.now()) },
      );
      assertLifecycleDeadline(input.context);
      return Object.freeze({ loaderReady: true, panelReady: true, logs: Object.freeze([]) });
    },
    close: async () => closeProfile('browser-profile'),
  });
}

function assertLifecycleDeadline(
  context: Readonly<{ readonly signal: AbortSignal; readonly deadline: number }>,
): void {
  if (context.signal.aborted || Date.now() >= context.deadline) {
    throw new Error('lifecycle browser operation is no longer active');
  }
}

function emptyLifecycleBrowserState(): LifecycleBrowserState {
  return Object.freeze({
    cacheStorageNames: Object.freeze([]),
    indexedDbNames: Object.freeze([]),
    localStorageKeys: Object.freeze([]),
    serviceWorkerRegistrations: Object.freeze([]),
    sessionStorageKeys: Object.freeze([]),
  });
}

async function clearAndInspectLifecycleBrowserState(
  page: LifecycleBrowserPage,
): Promise<LifecycleBrowserState> {
  const state = await page.evaluate(async () => {
    localStorage.clear();
    sessionStorage.clear();
    const registrations =
      'serviceWorker' in navigator ? await navigator.serviceWorker.getRegistrations() : [];
    await Promise.all(registrations.map(async (registration) => registration.unregister()));
    if ('caches' in globalThis) {
      await Promise.all((await caches.keys()).map(async (name) => caches.delete(name)));
    }
    const names =
      typeof indexedDB.databases === 'function'
        ? (await indexedDB.databases())
            .map((database) => database.name)
            .filter((name): name is string => typeof name === 'string')
        : [];
    await Promise.all(
      names.map(async (name) => {
        await new Promise<void>((resolveDelete) => {
          const request = indexedDB.deleteDatabase(name);
          request.addEventListener('success', () => resolveDelete(), { once: true });
          request.addEventListener('error', () => resolveDelete(), { once: true });
          request.addEventListener('blocked', () => resolveDelete(), { once: true });
        });
      }),
    );
    return {
      cacheStorageNames: 'caches' in globalThis ? await caches.keys() : [],
      indexedDbNames:
        typeof indexedDB.databases === 'function'
          ? (await indexedDB.databases())
              .map((database) => database.name)
              .filter((name): name is string => typeof name === 'string')
          : [],
      localStorageKeys: Object.keys(localStorage),
      serviceWorkerRegistrations:
        'serviceWorker' in navigator
          ? (await navigator.serviceWorker.getRegistrations()).map(
              (registration) => registration.scope,
            )
          : [],
      sessionStorageKeys: Object.keys(sessionStorage),
    };
  });
  return Object.freeze({
    cacheStorageNames: Object.freeze([...state.cacheStorageNames]),
    indexedDbNames: Object.freeze([...state.indexedDbNames]),
    localStorageKeys: Object.freeze([...state.localStorageKeys]),
    serviceWorkerRegistrations: Object.freeze([...state.serviceWorkerRegistrations]),
    sessionStorageKeys: Object.freeze([...state.sessionStorageKeys]),
  });
}
/**
 * Recovers the compact snapshot authority for a committed install by reading
 * the setup-committed full commitment (bounded, identity-pinned) and
 * projecting its canonical authority fields. The commitment parser re-derives
 * the commitment digest from the unsigned content, so a tampered commitment
 * cannot mint a matching authority; the managed Vite runtime then re-verifies
 * every committed file against this authority before serving.
 */
async function launchLifecycleMcpForeground(
  input: Parameters<NodeForegroundMcpLauncher['launch']>[0],
  checkoutRoot: string,
) {
  const projects = lifecycleCredentialProjects(input.projects, input.selectedProjectId);
  assertForegroundManifestOwnsSelectedDescriptor(input);
  const loaderSource = await readBoundedRegularFile(
    join(checkoutRoot, 'packages/browser-client/dist/scene-glass-loader.js'),
    MAX_DESCRIPTOR_BYTES,
  );
  let app: Awaited<ReturnType<typeof createSceneGlassLifecycleApp>> | undefined;
  try {
    app = await withAllProjectCredentials(projects, input.selectedProjectId, async (environment) =>
      createSceneGlassLifecycleApp({
        configPath: input.configPath,
        environment,
        lifecycleOriginAuthority: createLifecycleOriginAuthority(
          input.lifecycleOrigin as Parameters<typeof createLifecycleOriginAuthority>[0],
        ),
      }),
    );
    registerSceneGlassLoader(app, loaderSource);
    await app.listen({ host: '127.0.0.1', port: LIFECYCLE_MCP_PORT });
    writeForegroundStartBanner(input);
    reportCheckoutUpdate(checkoutRoot);
  } catch (error) {
    const cleanupFailures: unknown[] = [];
    if (app !== undefined) {
      try {
        await app.close();
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    loaderSource.fill(0);
    if (cleanupFailures.length > 0) {
      throw new AggregateError(
        [error, ...cleanupFailures],
        'foreground MCP startup and cleanup failed',
        { cause: error },
      );
    }
    throw error;
  }
  if (app === undefined) {
    loaderSource.fill(0);
    throw new Error('foreground MCP startup did not create an application');
  }
  const activeApp = app;
  let settled = false;
  let cleaned = false;
  let resolveExit:
    | ((value: { readonly reason: 'signal' | 'exit'; readonly exitCode: number }) => void)
    | undefined;
  const exited = new Promise<{ readonly reason: 'signal' | 'exit'; readonly exitCode: number }>(
    (resolveExitPromise) => {
      resolveExit = resolveExitPromise;
    },
  );
  const stop = (): void => {
    if (!settled) {
      settled = true;
      resolveExit?.(Object.freeze({ reason: 'signal' as const, exitCode: 0 }));
    }
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  return Object.freeze({
    cleanup: async () => {
      if (cleaned) {
        return;
      }
      cleaned = true;
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
      try {
        await activeApp.close();
      } finally {
        loaderSource.fill(0);
      }
    },
    waitForExit: async () => exited,
  });
}

/**
 * A successful foreground start printed nothing at all, so a running service was
 * indistinguishable from a hung one. Report the bound address and every project
 * this process serves, with the exact loopback URLs re-derived for this startup.
 * Only project ids and already-public origins are printed — never a token
 * environment name, credential path, or authority.
 */
function writeForegroundStartBanner(
  input: Parameters<NodeForegroundMcpLauncher['launch']>[0],
): void {
  const origins = declaredStartOriginsByProject(input.lifecycleOrigin);
  const lines = [`scene-glass: listening on http://127.0.0.1:${LIFECYCLE_MCP_PORT}`];
  const projectIds = [...input.projects.map((project) => project.projectId)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  for (const projectId of projectIds) {
    const marker = projectId === input.selectedProjectId ? '*' : '-';
    const projectOrigins = origins.get(projectId);
    lines.push(
      `scene-glass:   ${marker} ${projectId}${
        projectOrigins === undefined || projectOrigins.length === 0
          ? ''
          : ` → ${projectOrigins.join('  ')}`
      }`,
    );
  }
  lines.push(
    `scene-glass: ${projectIds.length} project(s) served; * is this directory. Open a project URL and hard-refresh once.`,
    'scene-glass: ready. Press Ctrl+C to stop (your Vite dev servers keep running).',
  );
  process.stdout.write(`${lines.join('\n')}\n`);
}

/** Reads the per-project origins this startup re-derived, defensively. */
function declaredStartOriginsByProject(value: unknown): Map<string, readonly string[]> {
  const byProject = new Map<string, readonly string[]>();
  if (typeof value !== 'object' || value === null) {
    return byProject;
  }
  const replacements = (value as { readonly replacements?: unknown }).replacements;
  if (!Array.isArray(replacements)) {
    return byProject;
  }
  for (const entry of replacements) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const { projectId, origins } = entry as {
      readonly projectId?: unknown;
      readonly origins?: unknown;
    };
    if (typeof projectId !== 'string' || !Array.isArray(origins)) {
      continue;
    }
    byProject.set(
      projectId,
      Object.freeze(origins.filter((origin): origin is string => typeof origin === 'string')),
    );
  }
  return byProject;
}

/** git 확인에 매달려 기동이 늦어지지 않게 하는 상한. */
const CHECKOUT_UPDATE_TIMEOUT_MS = 4_000;

/** 읽기만 하는 git 질의를 짧게 돌린다. 실패는 값이 없는 것으로만 취급한다. */
async function readGit(checkoutRoot: string, args: readonly string[]): Promise<string | undefined> {
  return new Promise((resolveOutput) => {
    execFile(
      'git',
      ['-C', checkoutRoot, ...args],
      { timeout: CHECKOUT_UPDATE_TIMEOUT_MS, windowsHide: true },
      (error, stdout) => resolveOutput(error === null ? stdout.trim() : undefined),
    );
  });
}

/**
 * 이 체크아웃이 원격보다 뒤처져 있는지 본다. **가져오기만 하고 아무것도 바꾸지 않는다** —
 * 갱신은 quickstart 의 일이다. start 가 pull 하면 소스만 새것이 되고, 이미 메모리에 올라간
 * `cli.js` 와 기동 시 한 번 읽는 로더 번들은 옛것으로 남아 고친 것이 반영되지 않는다.
 * 빌드까지 떠안으면 툴체인이 없는 환경에서는 서비스를 띄우지도 못한다.
 *
 * 확인이 안 되는 경우(네트워크 없음, git 저장소가 아님, detached HEAD, 원격 없음)는 조용히
 * 넘어간다. 알려 주려던 편의가 기동을 막으면 안 된다.
 */
async function checkoutCommitsBehind(checkoutRoot: string): Promise<number | undefined> {
  const branch = await readGit(checkoutRoot, ['symbolic-ref', '--quiet', '--short', 'HEAD']);
  if (branch === undefined || branch === '') return undefined;
  const remote = await readGit(checkoutRoot, ['config', '--get', `branch.${branch}.remote`]);
  if (remote === undefined || remote === '') return undefined;
  if ((await readGit(checkoutRoot, ['fetch', '--quiet', remote, branch])) === undefined) {
    return undefined;
  }
  const behind = await readGit(checkoutRoot, ['rev-list', '--count', `HEAD..${remote}/${branch}`]);
  if (behind === undefined || !/^[0-9]+$/u.test(behind)) return undefined;
  const count = Number(behind);
  return Number.isSafeInteger(count) ? count : undefined;
}

/** 배너 뒤에 한 줄로 알린다. 기동을 막지도, 늦추지도 않는다. */
function reportCheckoutUpdate(checkoutRoot: string): void {
  void checkoutCommitsBehind(checkoutRoot)
    .then((behind) => {
      if (behind === undefined || behind === 0) return;
      process.stdout.write(
        `scene-glass: update available — this checkout is ${behind} commit(s) behind its remote; run scripts/quickstart to pull and rebuild.\n`,
      );
    })
    .catch(() => {
      // 확인 실패는 알리지 않는다. 오프라인에서 매번 경고를 띄울 이유가 없다.
    });
}

function assertForegroundManifestOwnsSelectedDescriptor(
  input: Parameters<NodeForegroundMcpLauncher['launch']>[0],
): void {
  const selectedDescriptors = input.manifest.artifacts.filter(
    (artifact) =>
      artifact.kind === 'file' &&
      artifact.hunks.some((hunk) => /^scg-(?:html|vue3|react)-descriptor$/u.test(hunk.subject)),
  );
  if (selectedDescriptors.length !== 1) {
    throw new Error('foreground MCP manifest does not own exactly one selected descriptor');
  }
}

function writeLifecycleResult(result: LifecycleResult): void {
  process.stdout.write(
    `scene-glass-onboarding: [${result.code}] [${result.operation}] completed.\n`,
  );
  if (result.failures.length > 0) {
    process.stdout.write(
      `scene-glass-onboarding: failure stages: ${result.failures.map((failure) => failure.stage).join(',')}.\n`,
    );
  }
  const diagnostic = result.startDiagnostic;
  if (diagnostic === undefined) return;
  const remediation: Record<typeof diagnostic.code, string> = {
    SCG_START_VITE_DECLARATION_INVALID:
      'use the supported literal Vite dev declaration, then restart Vite and rerun scripts/start.',
    SCG_START_VITE_PORT_DISALLOWED:
      'choose a literal port other than 80 or 4175, restart Vite, then rerun scripts/start.',
    SCG_START_VITE_ORIGIN_CONFLICT:
      'choose a unique declared Vite port, restart Vite, then rerun scripts/start.',
    SCG_START_VITE_INPUT_CHANGED: 'Vite inputs changed during startup; rerun scripts/start.',
    SCG_START_VITE_PERSISTED_BASELINE_INVALID:
      'reconcile Scene Glass provenance with uninstall/setup, then rerun scripts/start.',
  };
  process.stdout.write(
    `scene-glass-onboarding: [${diagnostic.code}] [start] project=${diagnostic.projectId}; ${remediation[diagnostic.code]}\n`,
  );
}
async function descriptorCheck(descriptorPath: string): Promise<void> {
  await loadStaticDescriptor(descriptorPath);
  process.stdout.write('descriptor check passed\n');
}

async function nativeSelfTest(root: string): Promise<void> {
  assertSecureReadNativeAvailable();
  const rootIdentity = await directoryIdentity(root);
  const options = Object.freeze({
    root,
    expectedRoot: rootIdentity,
    relativePath: 'package.json',
    deniedIdentities: [],
    maxBytes: NATIVE_SELF_TEST_MAX_BYTES,
  });
  const first = secureReadBeneath(options);
  let second: ReturnType<typeof secureReadBeneath> | undefined;
  try {
    second = secureReadBeneath(options);
    if (
      first.bytes.length === 0 ||
      !first.bytes.equals(second.bytes) ||
      !sameFileIdentity(first.identity, second.identity)
    ) {
      commandError();
    }
    assertNativeSelfTestFailure(
      () => secureReadBeneath({ ...options, deniedIdentities: [first.identity] }),
      'SCG_NATIVE_PATH_DENIED',
    );
    assertNativeSelfTestFailure(
      () => secureReadBeneath({ ...options, expectedRoot: differentIdentity(rootIdentity) }),
      'SCG_NATIVE_IDENTITY_MISMATCH',
    );
  } finally {
    zeroizeBuffer(first.bytes);
    if (second !== undefined) {
      zeroizeBuffer(second.bytes);
    }
  }
  process.stdout.write('native self-test passed\n');
}

function assertNativeSelfTestFailure(
  operation: () => unknown,
  expectedCode: 'SCG_NATIVE_PATH_DENIED' | 'SCG_NATIVE_IDENTITY_MISMATCH',
): void {
  try {
    operation();
  } catch (error: unknown) {
    if (hasSafeErrorCode(error) && error.code === expectedCode) {
      return;
    }
  }
  commandError();
}

function differentIdentity(identity: FileIdentity): FileIdentity {
  return Object.freeze({
    device: identity.device,
    inode: identity.inode === '0' ? '1' : '0',
  });
}
async function closeStaticRuntime(runtime: StaticRuntime): Promise<void> {
  await runtime.stop();
}

async function staticPreview(descriptorPath: string): Promise<void> {
  const parsed = await loadStaticDescriptor(descriptorPath);
  const controller = new AbortController();
  let runtime: StaticRuntime | undefined;
  let resolveStartSettled: (() => void) | undefined;
  const startSettled = new Promise<void>((resolveStartSettledPromise) => {
    resolveStartSettled = resolveStartSettledPromise;
  });
  let stopPromise: Promise<void> | undefined;
  let stopError: unknown;
  let stopped = false;
  let resolveStopped: (() => void) | undefined;

  const stop = (): Promise<void> => {
    controller.abort();
    stopPromise ??= startSettled.then(async () => {
      if (runtime !== undefined) {
        await closeStaticRuntime(runtime);
      }
    });
    void stopPromise.then(
      () => {
        stopped = true;
        resolveStopped?.();
      },
      (error: unknown) => {
        stopError = error;
        stopped = true;
        resolveStopped?.();
      },
    );
    return stopPromise;
  };
  const onSignal = (): void => {
    void stop();
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  let primaryFailure: unknown;
  let cleanupFailure: unknown;
  try {
    try {
      runtime = await startStaticRuntime({
        descriptor: parsed.descriptor,
        configuredProjects: parsed.configuredProjects,
        projectRoot: parsed.projectRoot,
        signal: controller.signal,
      });
    } catch (error: unknown) {
      if (!controller.signal.aborted || !isStaticStartCancellation(error)) {
        primaryFailure = error;
      }
    } finally {
      resolveStartSettled?.();
    }

    if (primaryFailure === undefined && runtime !== undefined && !controller.signal.aborted) {
      await new Promise<void>((resolveStoppedPromise) => {
        resolveStopped = resolveStoppedPromise;
        if (stopped) {
          resolveStoppedPromise();
        }
      });
      if (stopError !== undefined) {
        primaryFailure = stopError;
      }
    }
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    try {
      await stop();
    } catch (cleanupError: unknown) {
      cleanupFailure = cleanupError;
    }
  }

  if (cleanupFailure !== undefined) {
    if (primaryFailure !== undefined && cleanupFailure !== primaryFailure) {
      throw combineCliFailures(
        primaryFailure,
        cleanupFailure,
        'static preview failed and cleanup also failed',
      );
    }
    if (primaryFailure === undefined) {
      throw cleanupFailure;
    }
  }

  if (primaryFailure !== undefined) {
    throw primaryFailure;
  }
}

function isStaticStartCancellation(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.name === 'AbortError' &&
    error.message === 'static runtime start was aborted'
  );
}
function combineCliFailures(
  primaryError: unknown,
  cleanupError: unknown,
  message: string,
): AggregateError {
  const cleanupFailures =
    cleanupError instanceof AggregateError ? Array.from(cleanupError.errors) : [cleanupError];
  const combined = new AggregateError([primaryError, ...cleanupFailures], message);
  if (hasSafeErrorCode(primaryError)) {
    Object.defineProperty(combined, 'code', { value: primaryError.code });
  }
  return combined;
}

async function loadStaticDescriptor(
  descriptorPath: string,
): Promise<ParsedDescriptor<StaticHostDescriptorV1>> {
  const configuredProjects = await loadTrustedConfiguredProjects();
  const serialized = await readBoundedUtf8(descriptorPath, MAX_DESCRIPTOR_BYTES);
  const descriptor = parseStaticHostDescriptorJsonV1(serialized, configuredProjects);
  const projectRoot = await assertConfiguredDescriptorRoot(descriptor, configuredProjects);
  assertLiveConfiguredCredentialAuthorities(descriptor);
  return Object.freeze({ descriptor, configuredProjects, projectRoot });
}

async function assertConfiguredDescriptorRoot(
  descriptor: StaticHostDescriptorV1,
  configuredProjects: TrustedDescriptorProjectSet,
): Promise<string> {
  const configuredProject = configuredProjects.projects.find(
    (project) => project.projectId === descriptor.projectId,
  );
  if (configuredProject === undefined) {
    commandError();
  }
  const configuredRoot = configuredProject.canonicalRoot;
  const approvedRoot = join(configuredRoot, 'public');
  if (!isPathContainedBy(configuredRoot, approvedRoot)) {
    commandError();
  }
  const identity = await directoryIdentity(approvedRoot);
  if (
    !sameFileIdentity(identity, descriptor.approvedRootIdentity) ||
    !sameFileIdentity(identity, configuredProject.publicRootIdentity)
  ) {
    commandError();
  }
  return configuredRoot;
}

function assertLiveConfiguredCredentialAuthorities(descriptor: StaticHostDescriptorV1): void {
  const verified = verifyCredentialAuthorities({
    authorities: descriptor.credentialAuthorities,
    selectedProjectId: descriptor.credentialProjectId,
    expectedOwnerUid: effectiveUserId(),
    maxBytes: CREDENTIAL_MAX_BYTES,
  });
  revokeCredentialReadCapability(verified.capability);
}

async function loadTrustedConfiguredProjects(): Promise<TrustedDescriptorProjectSet> {
  const resolvedConfigPath = lifecycleConfigPath(homedir());
  const serialized = await readBoundedUtf8(resolvedConfigPath, MAX_DESCRIPTOR_BYTES);
  let config: ReturnType<typeof parseServerConfigV1>;
  try {
    config = parseServerConfigV1(JSON.parse(serialized));
  } catch {
    commandError();
  }

  const registryPath = join(dirname(resolvedConfigPath), CREDENTIAL_AUTHORITY_REGISTRY_FILENAME);
  let registry: ReturnType<typeof parseCredentialAuthorityRegistryJsonV1>;
  try {
    registry = parseCredentialAuthorityRegistryJsonV1(
      await readBoundedUtf8(registryPath, MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES),
    );
  } catch {
    commandError();
  }
  if (registry.projects.length === 0 || registry.projects.length !== config.projects.length) {
    commandError();
  }

  const registryProjects = new Map<string, CredentialAuthorityRegistryEntry>();
  for (const project of registry.projects) {
    registryProjects.set(project.projectId, project);
  }
  const configuredProjectIds = new Set<string>();
  const configuredTokenEnvs = new Set<string>();
  for (const project of config.projects) {
    if (
      configuredProjectIds.has(project.projectId) ||
      configuredTokenEnvs.has(project.tokenEnv) ||
      !registryProjects.has(project.projectId)
    ) {
      commandError();
    }
    configuredProjectIds.add(project.projectId);
    configuredTokenEnvs.add(project.tokenEnv);
  }
  if (registryProjects.size !== configuredProjectIds.size) {
    commandError();
  }

  const projects = await Promise.all(
    config.projects.map(async (project): Promise<TrustedDescriptorProject> => {
      if (!isAbsolute(project.root)) {
        commandError();
      }
      const canonicalRoot = await realpath(project.root);
      const rootIdentity = await directoryIdentity(canonicalRoot);
      const publicRootIdentity =
        project.framework === 'html'
          ? await directoryIdentity(join(canonicalRoot, 'public'))
          : rootIdentity;
      const registered = registryProjects.get(project.projectId);
      if (
        registered === undefined ||
        registered.tokenEnv !== project.tokenEnv ||
        registered.canonicalRoot !== canonicalRoot
      ) {
        commandError();
      }
      return Object.freeze({
        projectId: project.projectId,
        canonicalRoot,
        publicRootIdentity,
        tokenEnv: project.tokenEnv,
        credentialAuthority: Object.freeze({
          projectId: registered.projectId,
          path: registered.credentialPath,
          device: registered.device,
          inode: registered.inode,
        }),
      });
    }),
  );
  return Object.freeze({ projects: Object.freeze(projects) });
}

interface StableBigintFileFacts {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

function sameStableBigIntFileFacts(
  before: StableBigintFileFacts,
  after: StableBigintFileFacts,
): boolean {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.uid === after.uid &&
    before.gid === after.gid &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  );
}

function assertTrustedRegularFileFacts(facts: StableBigintFileFacts, maxBytes: number): void {
  if (
    !facts.isFile() ||
    facts.isSymbolicLink() ||
    facts.nlink < 1n ||
    facts.uid !== BigInt(effectiveUserId()) ||
    (facts.mode & 0o022n) !== 0n ||
    facts.size <= 0n ||
    facts.size > BigInt(maxBytes)
  ) {
    commandError();
  }
}

async function readBoundedRegularFile(path: string, maxBytes: number): Promise<Buffer> {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0 ||
    typeof constants.O_NOFOLLOW !== 'number' ||
    typeof constants.O_NONBLOCK !== 'number'
  ) {
    commandError();
  }

  let before: StableBigintFileFacts;
  let file: Awaited<ReturnType<typeof open>>;
  try {
    before = await lstat(path, { bigint: true });
    assertTrustedRegularFileFacts(before, maxBytes);
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    commandError();
  }

  try {
    const opened = await file.stat({ bigint: true });
    assertTrustedRegularFileFacts(opened, maxBytes);
    if (!sameStableBigIntFileFacts(before, opened)) {
      commandError();
    }

    const bytes = Buffer.allocUnsafe(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) {
        commandError();
      }
      offset += bytesRead;
    }

    const after = (await file.stat({ bigint: true })) as StableBigintFileFacts;
    let pathAfter: StableBigintFileFacts;
    try {
      pathAfter = await lstat(path, { bigint: true });
    } catch {
      commandError();
    }
    if (
      !sameStableBigIntFileFacts(opened, after) ||
      !sameStableBigIntFileFacts(before, pathAfter)
    ) {
      commandError();
    }
    return bytes;
  } finally {
    await file.close();
  }
}

async function readBoundedUtf8(path: string, maxBytes: number): Promise<string> {
  const bytes = await readBoundedRegularFile(path, maxBytes);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    commandError();
  }
}

async function directoryIdentity(path: string): Promise<FileIdentity> {
  const facts = await lstat(path, { bigint: true });
  if (!facts.isDirectory() || facts.isSymbolicLink()) {
    commandError();
  }
  return Object.freeze({ device: facts.dev.toString(), inode: facts.ino.toString() });
}
function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function isPathContainedBy(root: string, path: string): boolean {
  const relativePath = relative(root, path);
  return (
    relativePath !== '..' &&
    !relativePath.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
  );
}

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }
  const actualKeys = Object.keys(value);
  return actualKeys.length === keys.length && actualKeys.every((key, index) => key === keys[index]);
}

function effectiveUserId(): number {
  if (typeof process.geteuid !== 'function') {
    commandError();
  }
  return process.geteuid();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasSafeErrorCode(value: unknown): value is { readonly code: string } {
  return isRecord(value) && typeof value.code === 'string' && /^SCG_[A-Z0-9_]+$/.test(value.code);
}

function cliFailureDetails(error: unknown): { readonly code: string; readonly phase: CliPhase } {
  const code = hasSafeErrorCode(error) ? error.code : 'SCG_ONBOARDING_FAILURE';
  const phase = error instanceof CliError ? error.phase : activePhase;
  return Object.freeze({ code, phase });
}

const invokedPath = process.argv[1] === undefined ? null : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    const failure = cliFailureDetails(error);
    process.stderr.write(
      `scene-glass-onboarding: [${failure.code}] [${failure.phase}] command failed.\n`,
    );
    process.exitCode = 1;
  });
}
