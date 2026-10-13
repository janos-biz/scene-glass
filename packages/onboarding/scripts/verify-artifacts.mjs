import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  opendir,
  realpath,
  rmdir,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { request as requestLoopback } from 'node:http';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { clearTimeout, setTimeout } from 'node:timers';
import { TextDecoder } from 'node:util';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_SCHEMA_VERSION = 1;
const REQUIRED_NODE_MAJOR = 24;
const REQUIRED_ADDON_NAPI = 9;
const MANIFEST_MAX_BYTES = 4 * 1024;
const CLI_PATH = 'dist/cli.js';
const PACKAGE_MANIFEST_PATH = 'package.json';
const PACKAGE_MANIFEST_MAX_BYTES = 64 * 1024;
const PACKAGE_MANIFEST_MODE = 0o644n;
const ADDON_PATH = 'build/Release/secure_read.node';
const CLI_MAX_BYTES = 16 * 1024 * 1024;
const ADDON_MAX_BYTES = 32 * 1024 * 1024;
const CLI_ARTIFACT_MODE = 0o600n;
const ADDON_ARTIFACT_MODE = 0o755n;
const CLI_USAGE = [
  'usage: scene-glass-onboarding <command>',
  '',
  'commands:',
  '  help',
  '  setup',
  '  start',
  '  uninstall',
  '  descriptor-check --descriptor <absolute-path> --kind static',
  '  native-self-test --root <absolute-path>',
  '  static-preview --descriptor <absolute-path>',
  '',
].join('\n');
const STATIC_DESCRIPTOR_PROJECT_ID = 'artifact-verifier';
const STATIC_DESCRIPTOR_TEMPORARY_PREFIX = 'scene-glass-onboarding-descriptor-';
const CHILD_DEADLINE_MS = 20_000;
const CHILD_OUTPUT_LIMIT_BYTES = 64 * 1024;
// Must not be shorter than the managed Vite supervisor's child teardown grace.
const CHILD_TERMINATION_GRACE_MS = 10_000;
const STATIC_PREVIEW_PROBE_DEADLINE_MS = 5_000;
const ARTIFACT_TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ARTIFACT_TOKEN_SHA256 = createHash('sha256').update(ARTIFACT_TOKEN).digest('hex');
const BINDING_GYP_MAX_BYTES = 64 * 1024;
const VITE_SNAPSHOT_AUTHORITY_MAX_BYTES = 1024;
const ARTIFACT_READ_CHUNK_BYTES = 64 * 1024;
const ABSOLUTE_ROOT_OUTPUT_PATTERN = /(?:^|[\s"'`])\/(?:Users|home|private|tmp|var|opt)\//;
const LOOPBACK_PROBE_DEADLINE_MS = 5_000;
const VERIFIED_CLI_FD = 7;
const LOOPBACK_PROBE_LIMIT_BYTES = 64 * 1024;
const ARTIFACT_CLEANUP_MAX_ENTRIES = 4_096;
const ARTIFACT_CLEANUP_MAX_DEPTH = 8;
const ARTIFACT_CLEANUP_DEADLINE_MS = 5_000;
const ARTIFACT_SIGNAL_SHUTDOWN_DEADLINE_MS = 2_000;
const activeCliProcessGroups = new Set();
const activeOwnedCleanupAuthorities = new Set();
const HOSTILE_MANAGED_VITE_AMBIENT_VALUE = 'scene-glass-untrusted-ambient-authority';
let cliSignalHandlersInstalled = false;
let cliSignalShutdownStarted = false;
const signalTestHarnesses = new Set();

function isMissingProcess(error) {
  return typeof error === 'object' && error !== null && error.code === 'ESRCH';
}

function killCliProcessGroup(processGroup, signal) {
  try {
    process.kill(-processGroup, signal);
    return true;
  } catch (error) {
    return isMissingProcess(error);
  }
}
function activeCliProcessGroupExists(processGroup) {
  try {
    process.kill(-processGroup, 0);
    return true;
  } catch (error) {
    return !isMissingProcess(error);
  }
}

function hasActiveCliLifecycle() {
  return activeCliProcessGroups.size > 0 || activeOwnedCleanupAuthorities.size > 0;
}

function waitForSignalShutdown(milliseconds) {
  return new Promise((resolveShutdown) => {
    setTimeout(resolveShutdown, milliseconds);
  });
}

function abortCliProcessGroup(processGroup) {
  killCliProcessGroup(processGroup, 'SIGKILL');
}

function drainActiveCliProcessGroups() {
  for (const processGroup of activeCliProcessGroups) {
    abortCliProcessGroup(processGroup);
    if (!activeCliProcessGroupExists(processGroup)) {
      activeCliProcessGroups.delete(processGroup);
    }
  }
}

async function quiesceCliLifecycle(deadline) {
  while (hasActiveCliLifecycle() && Date.now() < deadline) {
    drainActiveCliProcessGroups();
    const authorities = [...activeOwnedCleanupAuthorities].sort((left, right) =>
      left.kind.localeCompare(right.kind),
    );
    if (authorities.length > 0) {
      const remaining = deadline - Date.now();
      await Promise.race([
        Promise.allSettled(
          authorities.map((authority) => finalizeOwnedCleanupAuthority(authority)),
        ),
        waitForSignalShutdown(Math.min(25, remaining)),
      ]);
    } else if (activeCliProcessGroups.size > 0) {
      await waitForSignalShutdown(Math.min(25, deadline - Date.now()));
    }
  }
}

function registerOwnedCleanupAuthority(attempt, kind = 'tree') {
  const authority = { attempt, completion: undefined, kind };
  activeOwnedCleanupAuthorities.add(authority);
  if (cliSignalShutdownStarted) {
    void finalizeOwnedCleanupAuthority(authority).catch(() => {});
    throw internalArtifactVerificationError('artifact verifier is quiescing after a signal');
  }
  installCliSignalHandlers();
  return authority;
}

async function finalizeOwnedCleanupAuthority(authority) {
  authority.completion ??= Promise.resolve()
    .then(authority.attempt)
    .finally(() => {
      activeOwnedCleanupAuthorities.delete(authority);
      if (!hasActiveCliLifecycle() && !cliSignalShutdownStarted) {
        removeCliSignalHandlers();
      }
    });
  return authority.completion;
}

function notifySignalShutdownStarted(signal) {
  for (const harness of signalTestHarnesses) {
    try {
      harness.onSignalShutdownStarted(signal);
    } catch {
      // Test instrumentation must not weaken signal shutdown.
    }
  }
}

async function terminateActiveCliProcessGroups(signal) {
  if (cliSignalShutdownStarted) {
    return;
  }
  cliSignalShutdownStarted = true;
  const deadline = Date.now() + ARTIFACT_SIGNAL_SHUTDOWN_DEADLINE_MS;
  notifySignalShutdownStarted(signal);
  try {
    await quiesceCliLifecycle(deadline);
  } finally {
    removeCliSignalHandlers();
    try {
      process.kill(process.pid, signal);
    } catch {
      process.exit(1);
    }
  }
}

function onVerifierInterrupt() {
  void terminateActiveCliProcessGroups('SIGINT');
}

function onVerifierTerminate() {
  void terminateActiveCliProcessGroups('SIGTERM');
}

function installCliSignalHandlers() {
  if (cliSignalHandlersInstalled) {
    return;
  }
  cliSignalHandlersInstalled = true;
  process.on('SIGINT', onVerifierInterrupt);
  process.on('SIGTERM', onVerifierTerminate);
}

function removeCliSignalHandlers() {
  if (!cliSignalHandlersInstalled) {
    return;
  }
  cliSignalHandlersInstalled = false;
  process.removeListener('SIGINT', onVerifierInterrupt);
  process.removeListener('SIGTERM', onVerifierTerminate);
}

function registerCliProcessGroup(processGroup) {
  if (cliSignalShutdownStarted) {
    abortCliProcessGroup(processGroup);
    throw internalArtifactVerificationError('artifact verifier is quiescing after a signal');
  }
  activeCliProcessGroups.add(processGroup);
  installCliSignalHandlers();
}

function unregisterCliProcessGroup(processGroup) {
  activeCliProcessGroups.delete(processGroup);
  if (!hasActiveCliLifecycle() && !cliSignalShutdownStarted) {
    removeCliSignalHandlers();
  }
}

export class ArtifactVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ArtifactVerificationError';
  }
}

const internalArtifactVerificationErrors = new WeakSet();

function internalArtifactVerificationError(message) {
  const error = new ArtifactVerificationError(message);
  internalArtifactVerificationErrors.add(error);
  return error;
}

function fail(message) {
  throw internalArtifactVerificationError(message);
}
const lifecycleFailureMetadata = new WeakMap();

function createArtifactCleanupBudget() {
  return { deadline: Date.now() + ARTIFACT_CLEANUP_DEADLINE_MS, entries: 0 };
}

function consumeArtifactCleanupBudget(budget) {
  budget.entries += 1;
  if (budget.entries > ARTIFACT_CLEANUP_MAX_ENTRIES || Date.now() > budget.deadline) {
    fail('artifact cleanup exceeded its global entry or deadline bound');
  }
}

function lifecycleMetadataFor(error) {
  if ((typeof error !== 'object' && typeof error !== 'function') || error === null) {
    return undefined;
  }
  return lifecycleFailureMetadata.get(error);
}

function recordLifecycleFailureMetadata(error, metadata) {
  if (
    (typeof error === 'object' || typeof error === 'function') &&
    error !== null &&
    !lifecycleFailureMetadata.has(error)
  ) {
    lifecycleFailureMetadata.set(error, metadata);
  }
}

function lifecycleFailureLeaves(error) {
  const metadata = lifecycleMetadataFor(error);
  if (metadata === undefined) {
    return { errors: [error], cleanupPhases: [] };
  }
  return {
    errors: [metadata.primary, ...metadata.cleanupErrors],
    cleanupPhases: [...metadata.cleanupPhases],
  };
}

function successfulOutcome(value) {
  return { failed: false, value };
}

function failedOutcome(error) {
  return { failed: true, error };
}

function cleanupAttempt(phase, attempt) {
  return { phase, attempt };
}

async function collectCleanupFailures(attempts) {
  const failures = [];
  for (const { phase, attempt } of attempts) {
    try {
      await attempt();
    } catch (error) {
      failures.push({ error, phase });
    }
  }
  return failures;
}

async function settleSetupMutations(mutations) {
  let primaryFailure;
  let hasPrimaryFailure = false;
  await Promise.allSettled(
    mutations.map(async (mutation) => {
      try {
        await mutation;
      } catch (error) {
        if (!hasPrimaryFailure) {
          hasPrimaryFailure = true;
          primaryFailure = error;
        }
      }
    }),
  );
  if (hasPrimaryFailure) {
    throw primaryFailure;
  }
}

function throwLifecycleFailures(primaryOutcome, cleanupFailures, message) {
  if (!primaryOutcome.failed && cleanupFailures.length === 0) {
    return;
  }

  if (primaryOutcome.failed && cleanupFailures.length === 0) {
    throw primaryOutcome.error;
  }

  const primaryLeaves = primaryOutcome.failed
    ? lifecycleFailureLeaves(primaryOutcome.error)
    : { errors: [], cleanupPhases: [] };
  const cleanupLeaves = cleanupFailures.map(({ error, phase }) => ({
    ...lifecycleFailureLeaves(error),
    phase,
  }));
  const errors = [
    ...primaryLeaves.errors,
    ...cleanupLeaves.flatMap(({ errors: leaves }) => leaves),
  ];
  const cleanupPhases = [
    ...primaryLeaves.cleanupPhases,
    ...cleanupLeaves.flatMap(({ phase, cleanupPhases: nestedPhases }) => [phase, ...nestedPhases]),
  ];
  const [primary, ...cleanupErrors] = errors;

  if (
    !primaryOutcome.failed &&
    errors.length === 1 &&
    (typeof primary === 'object' || typeof primary === 'function') &&
    primary !== null &&
    lifecycleMetadataFor(primary) === undefined
  ) {
    recordLifecycleFailureMetadata(primary, {
      cleanupErrors: [],
      cleanupPhases,
      primary,
    });
    throw primary;
  }

  const aggregate = new AggregateError(errors, message);
  recordLifecycleFailureMetadata(aggregate, {
    cleanupErrors,
    cleanupPhases,
    primary,
  });
  throw aggregate;
}

function sameArtifactDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function closeFileHandle(handle, phase, testOnly) {
  await handle.close();
  await testOnly?.afterFileHandleClose?.(Object.freeze({ handle, phase }));
}

async function closeFileHandleWithLifecycle(handle, primaryOutcome, phase, message, testOnly) {
  const closeFailures = await collectCleanupFailures([
    cleanupAttempt(phase, () => closeFileHandle(handle, phase, testOnly)),
  ]);
  throwLifecycleFailures(primaryOutcome, closeFailures, message);
  return primaryOutcome.value;
}

async function closeArtifactDirectory(directory, label, path, testOnly) {
  await directory.close();
  await testOnly?.afterDirectoryClose?.(Object.freeze({ directory, label, path }));
}

async function removeArtifactTree(
  path,
  label,
  budget = createArtifactCleanupBudget(),
  depth = 0,
  testOnly,
) {
  consumeArtifactCleanupBudget(budget);
  if (depth > ARTIFACT_CLEANUP_MAX_DEPTH) {
    fail(`${label} exceeds the cleanup depth limit`);
  }

  let facts;
  try {
    facts = await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return;
    }
    throw error;
  }
  if (!facts.isDirectory() || facts.isSymbolicLink()) {
    await unlink(path);
    await testOnly?.afterArtifactTreeRemoval?.(Object.freeze({ label, path }));
    return;
  }

  let directory;
  const names = [];
  const cleanupFailures = [];
  try {
    directory = await opendir(path, { bufferSize: 32 });
    for (;;) {
      consumeArtifactCleanupBudget(budget);
      const entry = await directory.read();
      if (entry === null) {
        break;
      }
      if (
        names.length >= ARTIFACT_CLEANUP_MAX_ENTRIES ||
        entry.name.length === 0 ||
        entry.name === '.' ||
        entry.name === '..' ||
        entry.name.includes('/') ||
        entry.name.includes('\\')
      ) {
        fail(`${label} has an unsafe cleanup entry`);
      }
      names.push(entry.name);
    }
  } catch (error) {
    cleanupFailures.push({ error, phase: 'artifact-tree-directory-read' });
  }

  names.sort((left, right) => left.localeCompare(right));
  for (const name of names) {
    cleanupFailures.push(
      ...(await collectCleanupFailures([
        cleanupAttempt('artifact-tree-child-cleanup', () =>
          removeArtifactTree(join(path, name), label, budget, depth + 1, testOnly),
        ),
      ])),
    );
  }

  cleanupFailures.push(
    ...(await collectCleanupFailures(
      directory === undefined
        ? []
        : [
            cleanupAttempt('artifact-tree-directory-close', () =>
              closeArtifactDirectory(directory, label, path, testOnly),
            ),
          ],
    )),
  );
  cleanupFailures.push(
    ...(await collectCleanupFailures([
      cleanupAttempt('artifact-tree-removal-finalization', async () => {
        const after = await lstat(path, { bigint: true });
        if (
          !after.isDirectory() ||
          after.isSymbolicLink() ||
          !sameArtifactDirectoryIdentity(facts, after)
        ) {
          fail(`${label} changed during cleanup`);
        }
        await rmdir(path);
        await testOnly?.afterArtifactTreeRemoval?.(Object.freeze({ label, path }));
      }),
    ])),
  );
  throwLifecycleFailures(
    successfulOutcome(),
    cleanupFailures,
    `${label} tree cleanup and finalization failed`,
  );
}

function artifactTreeCleanupAttempts({
  directory,
  label,
  lifecycle,
  hook,
  phase,
  testOnly,
  cleanupAuthority,
}) {
  return [
    ...(lifecycle?.[hook] === undefined
      ? []
      : [cleanupAttempt(phase, () => lifecycle[hook](Object.freeze({ directory, label, phase })))]),
    cleanupAttempt(phase, () =>
      cleanupAuthority === undefined
        ? removeArtifactTree(directory, label, undefined, undefined, testOnly)
        : finalizeOwnedCleanupAuthority(cleanupAuthority),
    ),
  ];
}

async function cleanupAfterFailure(
  error,
  { directory, label, lifecycle, hook, phase, testOnly, cleanupAuthority },
) {
  const cleanupFailures = await collectCleanupFailures(
    artifactTreeCleanupAttempts({
      directory,
      label,
      lifecycle,
      hook,
      phase,
      testOnly,
      cleanupAuthority,
    }),
  );
  throwLifecycleFailures(
    failedOutcome(error),
    cleanupFailures,
    `${label} setup and cleanup failed`,
  );
}
const PLAIN_NODE_CLI_LIFECYCLE_HOOKS = new Set([
  'beforeManagedFixtureTreeCleanup',
  'beforeManagedFixtureVerification',
  'beforeNativeAuthorityClose',
  'beforeNativeAuthorityTreeCleanup',
  'beforePinnedCliClose',
  'beforeStaticFixtureTreeCleanup',
  'beforeStaticFixtureVerification',
]);
const PLAIN_NODE_CLI_TEST_ONLY_PORTS = new WeakSet();
const VERIFIED_ARTIFACT_SNAPSHOTS = new WeakSet();
const PLAIN_NODE_CLI_TEST_ONLY_HOOKS = new Set([
  'afterArtifactSnapshotVerified',
  'afterArtifactTreeRemoval',
  'afterDirectoryClose',
  'afterFileHandleClose',
  'afterSetupMutations',
]);

export function createPlainNodeCliTestOnlyPorts(testOnly) {
  if (typeof testOnly !== 'object' || testOnly === null || Array.isArray(testOnly)) {
    fail('plain-Node CLI test-only port is invalid');
  }
  for (const [name, hook] of Object.entries(testOnly)) {
    if (!PLAIN_NODE_CLI_TEST_ONLY_HOOKS.has(name) || typeof hook !== 'function') {
      fail('plain-Node CLI test-only port is invalid');
    }
  }
  const ports = Object.freeze({ ...testOnly });
  PLAIN_NODE_CLI_TEST_ONLY_PORTS.add(ports);
  return ports;
}

function normalizePlainNodeCliTestOnlyPorts(testOnly) {
  if (testOnly === undefined) {
    return undefined;
  }
  if (
    (typeof testOnly !== 'object' && typeof testOnly !== 'function') ||
    testOnly === null ||
    !PLAIN_NODE_CLI_TEST_ONLY_PORTS.has(testOnly)
  ) {
    fail('plain-Node CLI test-only port is invalid');
  }
  return testOnly;
}
export function createArtifactVerifierSignalTestHarness({ onSignalShutdownStarted } = {}) {
  if (typeof onSignalShutdownStarted !== 'function') {
    fail('artifact verifier signal test harness is invalid');
  }
  const harness = {
    onSignalShutdownStarted,
    registerProcessGroup(processGroup) {
      if (!Number.isSafeInteger(processGroup) || processGroup <= 0) {
        fail('artifact verifier signal test process group is invalid');
      }
      registerCliProcessGroup(processGroup);
    },
    registerTreeAuthority(attempt) {
      if (typeof attempt !== 'function') {
        fail('artifact verifier signal test authority is invalid');
      }
      return registerOwnedCleanupAuthority(attempt, 'tree');
    },
    dispose() {
      signalTestHarnesses.delete(harness);
    },
  };
  signalTestHarnesses.add(harness);
  return Object.freeze(harness);
}

function normalizePlainNodeCliLifecycle(lifecycle) {
  if (lifecycle === undefined) {
    return Object.freeze({});
  }
  if (typeof lifecycle !== 'object' || lifecycle === null || Array.isArray(lifecycle)) {
    fail('plain-Node CLI lifecycle port is invalid');
  }
  for (const [name, hook] of Object.entries(lifecycle)) {
    if (!PLAIN_NODE_CLI_LIFECYCLE_HOOKS.has(name) || typeof hook !== 'function') {
      fail('plain-Node CLI lifecycle port is invalid');
    }
  }
  return Object.freeze({ ...lifecycle });
}

function artifactPaths(root) {
  const absoluteRoot = resolve(root);
  return {
    addon: join(absoluteRoot, ADDON_PATH),
    cli: join(absoluteRoot, CLI_PATH),
    manifest: join(absoluteRoot, 'dist', 'build-manifest.json'),
    packageManifest: join(absoluteRoot, PACKAGE_MANIFEST_PATH),
    root: absoluteRoot,
  };
}

function runtimeNodeContract() {
  const nodeVersion = process.versions.node;
  const [majorText, minorText, patchText] = nodeVersion.split('.');
  const nodeMajor = Number(majorText);
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(majorText ?? '') ||
    !/^(?:0|[1-9][0-9]*)$/.test(minorText ?? '') ||
    !/^(?:0|[1-9][0-9]*)$/.test(patchText ?? '') ||
    nodeMajor !== REQUIRED_NODE_MAJOR
  ) {
    fail(`artifact verification requires Node ${REQUIRED_NODE_MAJOR}`);
  }

  const runtimeNapi = Number(process.versions.napi);
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(process.versions.napi ?? '') ||
    !Number.isSafeInteger(runtimeNapi) ||
    runtimeNapi < REQUIRED_ADDON_NAPI
  ) {
    fail(`artifact verification requires Node-API ${REQUIRED_ADDON_NAPI} support`);
  }

  return { nodeMajor, runtimeNapi };
}

function assertArtifactFacts(facts, label, mode, maxBytes) {
  if (
    !facts.isFile() ||
    facts.isSymbolicLink() ||
    facts.nlink !== 1n ||
    (facts.mode & 0o7777n) !== mode ||
    facts.size <= 0n ||
    facts.size > BigInt(maxBytes)
  ) {
    fail(`${label} must be a single-link regular file with its approved mode and bounded size`);
  }
}

function sameArtifactFacts(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  );
}
function samePinnedArtifactFacts(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    (before.nlink === after.nlink || (before.nlink === 1n && after.nlink === 0n))
  );
}
function assertPinnedCliFacts(facts) {
  if (
    !facts.isFile() ||
    facts.isSymbolicLink() ||
    (facts.nlink !== 1n && facts.nlink !== 0n) ||
    (facts.mode & 0o7777n) !== CLI_ARTIFACT_MODE ||
    facts.size <= 0n ||
    facts.size > BigInt(CLI_MAX_BYTES)
  ) {
    fail(`${CLI_PATH} changed after it was verified`);
  }
}

async function readVerifiedArtifactSnapshot(path, label, mode, maxBytes) {
  if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number') {
    fail('artifact verification requires no-follow nonblocking file descriptors');
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ELOOP') {
      fail(`required artifact is missing or unsafe: ${label}`);
    }
    throw internalArtifactVerificationError(`required artifact cannot be opened: ${label}`);
  }

  let readOutcome;
  try {
    const before = await handle.stat({ bigint: true });
    assertArtifactFacts(before, label, mode, maxBytes);
    const size = Number(before.size);
    const contents = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(contents, offset, size - offset, offset);
      if (bytesRead === 0) {
        fail(`${label} changed while it was being read`);
      }
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameArtifactFacts(before, after)) {
      fail(`${label} changed while it was being read`);
    }
    readOutcome = successfulOutcome(
      Object.freeze({
        contents,
        facts: before,
        hash: createHash('sha256').update(contents).digest('hex'),
      }),
    );
  } catch (error) {
    readOutcome = failedOutcome(error);
  }
  return closeFileHandleWithLifecycle(
    handle,
    readOutcome,
    'artifact-read-close',
    `${label} read and close failed`,
  );
}

async function readVerifiedArtifact(path, label, mode, maxBytes) {
  return (await readVerifiedArtifactSnapshot(path, label, mode, maxBytes)).contents;
}
async function readBoundedRegularFile(path, label, maxBytes) {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0 ||
    typeof constants.O_NOFOLLOW !== 'number' ||
    typeof constants.O_NONBLOCK !== 'number'
  ) {
    fail('artifact verification requires bounded no-follow file descriptors');
  }

  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ELOOP') {
      fail(`${label} must be a regular non-symlink file`);
    }
    throw error;
  }

  let readOutcome;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(maxBytes)) {
      fail(`${label} exceeds the file size limit`);
    }

    const chunks = [];
    const chunk = Buffer.allocUnsafe(Math.min(ARTIFACT_READ_CHUNK_BYTES, maxBytes));
    let size = 0;
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, size);
      if (bytesRead === 0) {
        break;
      }
      if (size + bytesRead > maxBytes) {
        fail(`${label} exceeds the file size limit`);
      }
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
      size += bytesRead;
    }

    const after = await handle.stat({ bigint: true });
    if (!sameArtifactFacts(before, after) || size !== Number(before.size)) {
      fail(`${label} changed while it was being read`);
    }
    readOutcome = successfulOutcome(Buffer.concat(chunks, size));
  } catch (error) {
    readOutcome = failedOutcome(error);
  }
  return closeFileHandleWithLifecycle(
    handle,
    readOutcome,
    'bounded-file-read-close',
    `${label} read and close failed`,
  );
}

async function readBoundedRegularUtf8(path, label, maxBytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(
      await readBoundedRegularFile(path, label, maxBytes),
    );
  } catch (error) {
    if (error instanceof ArtifactVerificationError || lifecycleMetadataFor(error) !== undefined) {
      throw error;
    }
    fail(`${label} is not valid UTF-8`);
  }
}
async function openPinnedVerifiedCli(path, expectedHash) {
  if (typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedHash)) {
    fail('verified CLI hash is invalid');
  }
  if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number') {
    fail('artifact verification requires no-follow nonblocking file descriptors');
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ELOOP') {
      fail(`required artifact is missing or unsafe: ${CLI_PATH}`);
    }
    throw internalArtifactVerificationError(`required artifact cannot be opened: ${CLI_PATH}`);
  }

  let pinOutcome;
  try {
    const facts = await handle.stat({ bigint: true });
    assertArtifactFacts(facts, CLI_PATH, CLI_ARTIFACT_MODE, CLI_MAX_BYTES);
    const pinned = { handle, facts, hash: expectedHash, path };
    await revalidatePinnedCli(pinned);
    pinOutcome = successfulOutcome(pinned);
  } catch (error) {
    pinOutcome = failedOutcome(error);
  }
  if (pinOutcome.failed) {
    return closeFileHandleWithLifecycle(
      handle,
      pinOutcome,
      'pinned-cli-open-close',
      'pinned CLI opening and close failed',
    );
  }
  return pinOutcome.value;
}

async function revalidatePinnedCli(pinned) {
  assertArtifactFacts(pinned.facts, CLI_PATH, CLI_ARTIFACT_MODE, CLI_MAX_BYTES);
  const before = await pinned.handle.stat({ bigint: true });
  assertPinnedCliFacts(before);
  if (!samePinnedArtifactFacts(pinned.facts, before)) {
    fail(`${CLI_PATH} changed after it was verified`);
  }
  const size = Number(before.size);
  const contents = Buffer.allocUnsafe(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await pinned.handle.read(contents, offset, size - offset, offset);
    if (bytesRead === 0) {
      fail(`${CLI_PATH} changed while it was being read`);
    }
    offset += bytesRead;
  }
  const after = await pinned.handle.stat({ bigint: true });
  assertPinnedCliFacts(after);
  if (
    !samePinnedArtifactFacts(before, after) ||
    createHash('sha256').update(contents).digest('hex') !== pinned.hash
  ) {
    fail(`${CLI_PATH} changed after it was verified`);
  }
  return contents;
}

function pinnedCliBootstrap(cli, args, virtualCliPath) {
  return [
    "import { createHash } from 'node:crypto';",
    "import { fstatSync, readSync } from 'node:fs';",
    "import { register } from 'node:module';",
    "import { pathToFileURL } from 'node:url';",
    `const verifiedCliFd = ${VERIFIED_CLI_FD};`,
    `const virtualCliPath = ${JSON.stringify(virtualCliPath)};`,
    `const commandArguments = ${JSON.stringify(args)};`,
    `const verifiedCliHash = ${JSON.stringify(cli.hash)};`,
    'const verifiedCliFacts = fstatSync(verifiedCliFd);',
    'if (',
    '  !verifiedCliFacts.isFile() ||',
    '  !Number.isSafeInteger(verifiedCliFacts.size) ||',
    '  verifiedCliFacts.size <= 0 ||',
    `  verifiedCliFacts.size > ${CLI_MAX_BYTES}`,
    ') {',
    "  throw new Error('verified CLI descriptor has invalid bounds');",
    '}',
    'const verifiedCliSource = Buffer.allocUnsafe(verifiedCliFacts.size);',
    'let verifiedCliOffset = 0;',
    'while (verifiedCliOffset < verifiedCliSource.byteLength) {',
    '  const bytesRead = readSync(',
    '    verifiedCliFd,',
    '    verifiedCliSource,',
    '    verifiedCliOffset,',
    '    verifiedCliSource.byteLength - verifiedCliOffset,',
    '    verifiedCliOffset,',
    '  );',
    "  if (bytesRead === 0) throw new Error('verified CLI descriptor ended unexpectedly');",
    '  verifiedCliOffset += bytesRead;',
    '}',
    "if (createHash('sha256').update(verifiedCliSource).digest('hex') !== verifiedCliHash) {",
    "  throw new Error('verified CLI descriptor failed integrity validation');",
    '}',
    'const virtualCliUrl = pathToFileURL(virtualCliPath).href;',
    'const loader =',
    '  "import { Buffer } from \'node:buffer\';" +',
    '  ` const virtual = ${JSON.stringify(virtualCliUrl)};` +',
    '  " const source = " + JSON.stringify(verifiedCliSource.toString("base64")) + ";" +',
    '  " export async function resolve(specifier, context, nextResolve) {" +',
    '  " if (specifier === virtual) return { url: virtual, shortCircuit: true };" +',
    '  " return nextResolve(specifier, context); }" +',
    '  " export async function load(url, context, nextLoad) {" +',
    '  " if (url === virtual) {" +',
    "  \"   return { format: 'module', source: Buffer.from(source, 'base64'), shortCircuit: true };\" +",
    '  " } return nextLoad(url, context); }";',
    'register(`data:text/javascript,${encodeURIComponent(loader)}`, import.meta.url);',
    'process.argv = [process.execPath, virtualCliPath, ...commandArguments];',
    'await import(virtualCliUrl);',
  ].join('\n');
}

function buildManifest({ cliHash, addonHash, nodeMajor, napi }) {
  return {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    platform: process.platform,
    arch: process.arch,
    nodeMajor,
    napi,
    addonSha256: addonHash,
    cliSha256: cliHash,
  };
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}
function assertNoArtifactTokenOrDigest(contents, label) {
  const text = Buffer.isBuffer(contents) ? contents.toString('utf8') : contents;
  if (text.includes(ARTIFACT_TOKEN) || text.includes(ARTIFACT_TOKEN_SHA256)) {
    fail(`${label} contains ARTIFACT_TOKEN or its SHA-256 digest`);
  }
}

function assertSecretless(contents, label) {
  const text = Buffer.isBuffer(contents) ? contents.toString('utf8') : contents;
  if (/sourceMappingURL|sourceURL=|synthetic-token-canary/i.test(text)) {
    fail(`${label} contains a source-map reference or test credential canary`);
  }
  if (
    /authorization\s*:\s*bearer\s+[^\s"'`]+|(?:access[_-]?token|secret|password)\s*[:=]\s*["'`][^"'`]+/i.test(
      text,
    )
  ) {
    fail(`${label} contains a credential-like literal`);
  }
}

async function resolvePublishedCliAuthority(auditedCli) {
  const { resolveAuditedCliPublication } = await import('./build-runtime.mjs');
  return resolveAuditedCliPublication(auditedCli);
}
async function publishedCliPathFacts(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch {
    fail('audited CLI changed after publication');
  }
}

async function readAuditedPublishedCli(auditedCli, expectedPath) {
  const publication = await resolvePublishedCliAuthority(auditedCli);
  if (publication === undefined || publication.path !== expectedPath) {
    fail('audited CLI publication authority is invalid');
  }
  const beforePathFacts = await publishedCliPathFacts(publication.path);
  if (!samePinnedArtifactFacts(publication.facts, beforePathFacts)) {
    fail('audited CLI changed after publication');
  }
  assertArtifactFacts(beforePathFacts, CLI_PATH, CLI_ARTIFACT_MODE, CLI_MAX_BYTES);

  const pinnedContents = await revalidatePinnedCli(publication);
  const pathFacts = await publishedCliPathFacts(publication.path);
  if (
    !pathFacts.isFile() ||
    pathFacts.isSymbolicLink() ||
    !samePinnedArtifactFacts(publication.facts, pathFacts)
  ) {
    fail('audited CLI changed after publication');
  }
  if (!pinnedContents.equals(publication.contents)) {
    fail('audited CLI changed after publication');
  }
  return pinnedContents;
}

async function readVerifiedArtifacts(paths, { auditedCli } = {}) {
  const [cli, addon] = await Promise.all([
    auditedCli === undefined
      ? readVerifiedArtifact(paths.cli, CLI_PATH, CLI_ARTIFACT_MODE, CLI_MAX_BYTES)
      : readAuditedPublishedCli(auditedCli, paths.cli),
    readVerifiedArtifact(paths.addon, ADDON_PATH, ADDON_ARTIFACT_MODE, ADDON_MAX_BYTES),
  ]);
  assertSecretless(cli, CLI_PATH);
  assertSecretless(addon, ADDON_PATH);
  assertNoArtifactTokenOrDigest(cli, CLI_PATH);
  assertNoArtifactTokenOrDigest(addon, ADDON_PATH);
  return {
    addonHash: createHash('sha256').update(addon).digest('hex'),
    cliHash: createHash('sha256').update(cli).digest('hex'),
  };
}
async function createVerifiedArtifactSnapshot(paths, { expectedCliHash } = {}) {
  const [cliSource, addon, packageManifest] = await Promise.all([
    readVerifiedArtifactSnapshot(paths.cli, CLI_PATH, CLI_ARTIFACT_MODE, CLI_MAX_BYTES),
    readVerifiedArtifactSnapshot(paths.addon, ADDON_PATH, ADDON_ARTIFACT_MODE, ADDON_MAX_BYTES),
    readVerifiedArtifactSnapshot(
      paths.packageManifest,
      PACKAGE_MANIFEST_PATH,
      PACKAGE_MANIFEST_MODE,
      PACKAGE_MANIFEST_MAX_BYTES,
    ),
  ]);
  assertSecretless(cliSource.contents, CLI_PATH);
  assertSecretless(addon.contents, ADDON_PATH);
  assertNoArtifactTokenOrDigest(cliSource.contents, CLI_PATH);
  assertNoArtifactTokenOrDigest(addon.contents, ADDON_PATH);

  let cli;
  try {
    cli = await openPinnedVerifiedCli(paths.cli, expectedCliHash ?? cliSource.hash);
    const pinnedContents = await revalidatePinnedCli(cli);
    if (
      !sameArtifactFacts(cliSource.facts, cli.facts) ||
      !pinnedContents.equals(cliSource.contents)
    ) {
      fail('verified artifact snapshot changed before CLI authority creation');
    }
    const snapshot = Object.freeze({
      addon,
      cli,
      cliContents: cliSource.contents,
      packageManifest,
      root: paths.root,
    });
    VERIFIED_ARTIFACT_SNAPSHOTS.add(snapshot);
    return snapshot;
  } catch (error) {
    if (cli === undefined) {
      throw error;
    }
    return closeFileHandleWithLifecycle(
      cli.handle,
      failedOutcome(error),
      'verified-artifact-snapshot-cli-close',
      'verified artifact snapshot creation and CLI close failed',
    );
  }
}

function normalizeVerifiedArtifactSnapshot(
  snapshot,
  { root, cliPath, expectedAddonHash, expectedCliHash },
) {
  if (snapshot === undefined) {
    return undefined;
  }
  if (
    (typeof snapshot !== 'object' && typeof snapshot !== 'function') ||
    snapshot === null ||
    !VERIFIED_ARTIFACT_SNAPSHOTS.has(snapshot) ||
    snapshot.root !== root ||
    snapshot.cli?.path !== cliPath ||
    snapshot.cli?.hash !== expectedCliHash ||
    (expectedAddonHash !== undefined && snapshot.addon?.hash !== expectedAddonHash) ||
    !Buffer.isBuffer(snapshot.cliContents) ||
    !Buffer.isBuffer(snapshot.addon?.contents) ||
    !Buffer.isBuffer(snapshot.packageManifest?.contents)
  ) {
    fail('verified artifact snapshot authority is invalid');
  }
  return snapshot;
}

async function nativeAuthorityArtifactsFromSnapshot(paths, cli, snapshot) {
  try {
    const [pinnedCliContents, addon, packageManifest] = await Promise.all([
      revalidatePinnedCli(cli),
      readVerifiedArtifactSnapshot(paths.addon, ADDON_PATH, ADDON_ARTIFACT_MODE, ADDON_MAX_BYTES),
      readVerifiedArtifactSnapshot(
        paths.packageManifest,
        PACKAGE_MANIFEST_PATH,
        PACKAGE_MANIFEST_MODE,
        PACKAGE_MANIFEST_MAX_BYTES,
      ),
    ]);
    if (
      cli !== snapshot.cli ||
      !pinnedCliContents.equals(snapshot.cliContents) ||
      !sameArtifactFacts(snapshot.addon.facts, addon.facts) ||
      snapshot.addon.hash !== addon.hash ||
      !sameArtifactFacts(snapshot.packageManifest.facts, packageManifest.facts) ||
      snapshot.packageManifest.hash !== packageManifest.hash
    ) {
      fail('verified artifact snapshot changed before private authority creation');
    }
    return {
      addonContents: snapshot.addon.contents,
      cliContents: snapshot.cliContents,
      packageManifestContents: snapshot.packageManifest.contents,
    };
  } catch (error) {
    if (lifecycleMetadataFor(error) !== undefined) {
      throw error;
    }
    fail('verified artifact snapshot changed before private authority creation');
  }
}

async function createIsolatedCliEnvironment() {
  const directoryCandidate = await mkdtemp(join(tmpdir(), 'scene-glass-artifact-cli-'));
  let directory = directoryCandidate;
  let home;
  let temporary;
  const cleanupAuthority = registerOwnedCleanupAuthority(() =>
    removeArtifactTree(directory, 'isolated CLI environment'),
  );
  try {
    directory = await realpath(directoryCandidate);
    home = join(directory, 'home');
    temporary = join(directory, 'tmp');
    await settleSetupMutations([mkdir(home, { mode: 0o700 }), mkdir(temporary, { mode: 0o700 })]);
    return {
      directory,
      environment: {
        HOME: home,
        TEMP: temporary,
        TMP: temporary,
        TMPDIR: temporary,
        TZ: 'UTC',
        npm_config_ignore_scripts: 'true',
      },
      cleanupAuthority,
    };
  } catch (error) {
    await cleanupAfterFailure(error, {
      directory,
      label: 'isolated CLI environment',
      phase: 'isolated-cli-environment-tree-cleanup',
      cleanupAuthority,
    });
  }
}

async function runPlainNodeCli(root, cli, args, options = {}) {
  if (process.platform === 'win32') {
    fail('artifact verification requires POSIX process groups');
  }
  const verifiedCliSource = await revalidatePinnedCli(cli);

  const {
    afterReady,
    afterSpawn,
    configPath,
    readyMarker,
    sensitivePaths = [],
    snapshotAuthorityBytes,
    terminateAfterReady = false,
  } = options;
  if (
    snapshotAuthorityBytes !== undefined &&
    (!Buffer.isBuffer(snapshotAuthorityBytes) ||
      snapshotAuthorityBytes.byteLength === 0 ||
      snapshotAuthorityBytes.byteLength > VITE_SNAPSHOT_AUTHORITY_MAX_BYTES)
  ) {
    fail('plain-Node CLI snapshot authority transport is invalid');
  }
  if (configPath !== undefined && (typeof configPath !== 'string' || !isAbsolute(configPath))) {
    fail('plain-Node CLI trusted configuration path is invalid');
  }
  const runtimeCliSource = verifiedCliSource;
  const isolation = await createIsolatedCliEnvironment();
  const runtimeCliPath = join(isolation.directory, 'verified-runtime-cli-authority.mjs');
  let runtimeCli;
  try {
    await writeFile(runtimeCliPath, runtimeCliSource, { mode: Number(CLI_ARTIFACT_MODE) });
    await chmod(runtimeCliPath, Number(CLI_ARTIFACT_MODE));
    runtimeCli = await openPinnedVerifiedCli(
      runtimeCliPath,
      createHash('sha256').update(runtimeCliSource).digest('hex'),
    );
    if (!(await revalidatePinnedCli(runtimeCli)).equals(runtimeCliSource)) {
      fail('verified CLI bootstrap authority marker is invalid');
    }
  } catch (error) {
    if (runtimeCli !== undefined) {
      await closeFileHandle(runtimeCli.handle, 'runtime-cli-authority-close');
    }
    await cleanupAfterFailure(error, {
      cleanupAuthority: isolation.cleanupAuthority,
      directory: isolation.directory,
      label: 'isolated CLI environment',
      phase: 'isolated-cli-environment-tree-cleanup',
    });
  }
  const virtualCliPath = resolve(root, 'dist', '.scene-glass-verified-runtime-cli.mjs');
  const snapshotAuthorityOutputFragments = [];
  if (snapshotAuthorityBytes !== undefined) {
    const serialized = snapshotAuthorityBytes.toString('utf8');
    snapshotAuthorityOutputFragments.push(serialized);
    try {
      const authority = JSON.parse(serialized);
      if (typeof authority?.syntheticRoot === 'string') {
        snapshotAuthorityOutputFragments.push(authority.syntheticRoot);
      }
      if (typeof authority?.commitmentDigest === 'string') {
        snapshotAuthorityOutputFragments.push(authority.commitmentDigest);
      }
    } catch {
      // The production CLI must reject malformed transport; it remains redacted here.
    }
  }
  const allSensitivePaths = [...sensitivePaths, isolation.directory];
  return new Promise((resolveRun, rejectRun) => {
    const childEnvironment =
      configPath === undefined
        ? {
            ...isolation.environment,
            VITE_SCENE_GLASS_HOSTILE_AUTHORITY: HOSTILE_MANAGED_VITE_AMBIENT_VALUE,
          }
        : {
            ...isolation.environment,
            SCENE_GLASS_CONFIG_PATH: configPath,
            VITE_SCENE_GLASS_HOSTILE_AUTHORITY: HOSTILE_MANAGED_VITE_AMBIENT_VALUE,
          };
    assertNoArtifactTokenOrDigest(
      JSON.stringify([process.execPath, virtualCliPath, ...args]),
      'plain-Node CLI argv',
    );
    assertNoArtifactTokenOrDigest(JSON.stringify(childEnvironment), 'plain-Node CLI environment');
    const child = spawn(
      process.execPath,
      ['--input-type=module', '--eval', pinnedCliBootstrap(runtimeCli, args, virtualCliPath)],
      {
        cwd: root,
        detached: true,
        env: childEnvironment,
        stdio:
          snapshotAuthorityBytes === undefined
            ? [
                'ignore',
                'pipe',
                'pipe',
                'ignore',
                'ignore',
                'ignore',
                'ignore',
                runtimeCli.handle.fd,
              ]
            : [
                'ignore',
                'pipe',
                'pipe',
                'ignore',
                'ignore',
                'pipe',
                'ignore',
                runtimeCli.handle.fd,
              ],
      },
    );
    const processGroup = child.pid;
    let processGroupRegistered = false;
    if (processGroup !== undefined) {
      registerCliProcessGroup(processGroup);
      processGroupRegistered = true;
    }
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let deadlineExceeded = false;
    let outputExceeded = false;
    let forced = false;
    let requestedSignal = null;
    let termination = null;
    let groupTermination = null;
    let spawnError;
    let probeError;
    let deadlineTimer;
    let forceTimer;
    let completionTimer;
    let snapshotAuthorityPipe;
    let snapshotAuthorityWrite;
    let markerSeen = false;
    let readyAction;
    let finished = false;

    const cleanup = () => {
      if (deadlineTimer !== undefined) {
        clearTimeout(deadlineTimer);
      }
      if (forceTimer !== undefined) {
        clearTimeout(forceTimer);
      }
      if (completionTimer !== undefined) {
        clearTimeout(completionTimer);
      }
      snapshotAuthorityPipe?.destroy();
      if (processGroupRegistered) {
        processGroupRegistered = false;
        unregisterCliProcessGroup(processGroup);
      }
    };
    const groupExists = () => {
      if (processGroup === undefined) {
        return false;
      }
      try {
        process.kill(-processGroup, 0);
        return true;
      } catch (error) {
        if (isMissingProcess(error)) {
          return false;
        }
        throw internalArtifactVerificationError(
          'plain-Node CLI process group could not be inspected',
        );
      }
    };
    const signalGroup = (signal) => {
      if (processGroup === undefined) {
        return true;
      }
      if (killCliProcessGroup(processGroup, signal)) {
        return true;
      }
      probeError ??= internalArtifactVerificationError(
        'plain-Node CLI process group could not be signaled',
      );
      return false;
    };
    const terminateProcessGroup = (reason) => {
      if (groupTermination !== null) {
        return;
      }
      groupTermination = reason;
      termination ??= reason;
      snapshotAuthorityPipe?.destroy();
      signalGroup('SIGTERM');
      forceTimer = setTimeout(() => {
        forced = true;
        snapshotAuthorityPipe?.destroy();
        signalGroup('SIGKILL');
      }, CHILD_TERMINATION_GRACE_MS);
    };
    const requestWrapperTermination = () => {
      if (termination !== null) {
        return;
      }
      try {
        if (!child.kill('SIGTERM')) {
          probeError = internalArtifactVerificationError(
            'plain-Node CLI wrapper process could not receive SIGTERM',
          );
          termination = 'wrapper-signal-failure';
          return;
        }
      } catch {
        probeError = internalArtifactVerificationError(
          'plain-Node CLI wrapper process could not receive SIGTERM',
        );
        termination = 'wrapper-signal-failure';
        return;
      }
      requestedSignal = 'SIGTERM';
      termination = 'requested-signal';
    };
    if (snapshotAuthorityBytes !== undefined) {
      const transport = child.stdio[5];
      if (transport === null || transport === undefined) {
        probeError = internalArtifactVerificationError(
          'plain-Node CLI did not expose the snapshot authority transport',
        );
        terminateProcessGroup('snapshot-authority-transport');
      } else {
        snapshotAuthorityPipe = transport;
        snapshotAuthorityWrite = writeExactPipe(snapshotAuthorityPipe, snapshotAuthorityBytes).then(
          () => 'fulfilled',
          () => 'rejected',
        );
        void snapshotAuthorityWrite.then((status) => {
          if (status !== 'rejected') {
            return;
          }
          probeError ??= internalArtifactVerificationError(
            'plain-Node CLI snapshot authority transport could not be written',
          );
          terminateProcessGroup('snapshot-authority-transport');
        });
      }
    }
    const waitForGroupExit = async () => {
      const deadline = Date.now() + CHILD_TERMINATION_GRACE_MS + 1_000;
      while (groupExists()) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          return false;
        }
        await new Promise((resolveDelay) => {
          setTimeout(resolveDelay, Math.min(50, remaining));
        });
      }
      return true;
    };
    const capturedOutput = () => Buffer.concat([...stdout, ...stderr]).toString('utf8');
    const assertSafeChildOutput = (output) => {
      const unsafeCategory = ABSOLUTE_ROOT_OUTPUT_PATTERN.test(output)
        ? 'absolute-root-pattern'
        : output.includes(ARTIFACT_TOKEN)
          ? 'artifact-token'
          : /SCENE_GLASS_HOST_TOKEN\s*=/i.test(output)
            ? 'credential-assignment'
            : allSensitivePaths.some((path) => output.includes(path))
              ? 'sensitive-path'
              : snapshotAuthorityOutputFragments.some(
                    (fragment) => fragment.length > 0 && output.includes(fragment),
                  )
                ? 'snapshot-authority'
                : undefined;
      if (unsafeCategory !== undefined) {
        fail(
          `plain-Node CLI ${args[0] ?? 'unknown'} emitted a credential or absolute fixture root (${unsafeCategory})`,
        );
      }
    };
    const runAfterReady = (action = afterReady) => {
      readyAction ??= (async () => {
        try {
          if (action !== undefined) {
            await action();
          }
          if (terminateAfterReady && termination === null) {
            requestWrapperTermination();
          }
        } catch (error) {
          probeError =
            error instanceof ArtifactVerificationError
              ? error
              : internalArtifactVerificationError(
                  'plain-Node CLI loopback probes did not complete within their bounds',
                );
          terminateProcessGroup('loopback-probe-failure');
        }
      })();
    };
    const capture = (destination) => (chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = CHILD_OUTPUT_LIMIT_BYTES - outputBytes;
      if (remaining > 0) {
        const captured = bytes.subarray(0, remaining);
        destination.push(captured);
        outputBytes += captured.byteLength;
      }
      if (bytes.byteLength > remaining) {
        outputExceeded = true;
        terminateProcessGroup('output-limit');
      }
      if (readyMarker !== undefined && !markerSeen && capturedOutput().includes(readyMarker)) {
        markerSeen = true;
        runAfterReady(afterReady);
      }
    };
    const finish = async (status, signal) => {
      if (finished) {
        return;
      }
      finished = true;
      try {
        if (readyAction !== undefined) {
          await readyAction;
        }
        if (
          snapshotAuthorityWrite !== undefined &&
          (await snapshotAuthorityWrite) !== 'fulfilled'
        ) {
          probeError ??= internalArtifactVerificationError(
            'plain-Node CLI snapshot authority transport could not be written',
          );
        }
        if (groupExists()) {
          if (termination === null) {
            terminateProcessGroup('orphaned-descendant');
          }
          if (!(await waitForGroupExit())) {
            if (groupTermination === null) {
              terminateProcessGroup('orphaned-descendant');
            }
            if (!(await waitForGroupExit())) {
              fail('plain-Node CLI left a descendant process alive after process-group teardown');
            }
          }
        }
        const capturedStdout = Buffer.concat(stdout).toString('utf8');
        const capturedStderr = Buffer.concat(stderr).toString('utf8');
        assertNoArtifactTokenOrDigest(capturedStdout, 'plain-Node CLI stdout');
        assertNoArtifactTokenOrDigest(capturedStderr, 'plain-Node CLI stderr');
        const captured = `${capturedStdout}${capturedStderr}`;
        assertSafeChildOutput(captured);
        if (spawnError !== undefined) {
          rejectRun(internalArtifactVerificationError('plain-Node CLI could not start'));
          return;
        }
        if (probeError !== undefined) {
          rejectRun(probeError);
          return;
        }
        resolveRun({
          status,
          signal,
          stdout: capturedStdout,
          stderr: capturedStderr,
          deadlineExceeded,
          forced,
          markerSeen,
          outputExceeded,
          requestedSignal,
          termination,
          groupTermination,
          groupDrainedWithoutVerifierAssistance: groupTermination === null,
          descendantsTerminated: true,
        });
      } catch (error) {
        rejectRun(
          error instanceof ArtifactVerificationError
            ? error
            : internalArtifactVerificationError('plain-Node CLI verification could not complete'),
        );
      } finally {
        cleanup();
      }
    };

    if (child.stdout === null || child.stderr === null) {
      spawnError = internalArtifactVerificationError(
        'plain-Node CLI did not expose bounded output streams',
      );
    } else {
      const outputStreamFailure = () => {
        probeError ??= internalArtifactVerificationError('plain-Node CLI output stream failed');
        terminateProcessGroup('output-stream-failure');
      };
      child.stdout.on('data', capture(stdout));
      child.stdout.once('error', outputStreamFailure);
      child.stderr.on('data', capture(stderr));
      child.stderr.once('error', outputStreamFailure);
    }
    deadlineTimer = setTimeout(() => {
      deadlineExceeded = true;
      terminateProcessGroup('deadline');
    }, CHILD_DEADLINE_MS);
    completionTimer = setTimeout(
      () => {
        deadlineExceeded = true;
        terminateProcessGroup('close-deadline');
        void finish(null, null);
      },
      CHILD_DEADLINE_MS + CHILD_TERMINATION_GRACE_MS + 1_000,
    );
    child.once('error', () => {
      spawnError ??= internalArtifactVerificationError('plain-Node CLI could not start');
      void finish(null, null);
    });
    child.once('close', (status, signal) => {
      void finish(status, signal);
    });
    if (afterSpawn !== undefined) {
      runAfterReady(afterSpawn);
    }
  }).then(
    async (value) => {
      const cleanupFailures = await collectCleanupFailures([
        cleanupAttempt('runtime-cli-authority-close', () =>
          closeFileHandle(runtimeCli.handle, 'runtime-cli-authority-close'),
        ),
        cleanupAttempt('isolated-cli-environment-tree-cleanup', () =>
          finalizeOwnedCleanupAuthority(isolation.cleanupAuthority),
        ),
      ]);
      throwLifecycleFailures(
        successfulOutcome(value),
        cleanupFailures,
        'plain-Node CLI verification and isolated-environment cleanup failed',
      );
      return value;
    },
    async (error) => {
      const cleanupFailures = await collectCleanupFailures([
        cleanupAttempt('runtime-cli-authority-close', () =>
          closeFileHandle(runtimeCli.handle, 'runtime-cli-authority-close'),
        ),
        cleanupAttempt('isolated-cli-environment-tree-cleanup', () =>
          finalizeOwnedCleanupAuthority(isolation.cleanupAuthority),
        ),
      ]);
      throwLifecycleFailures(
        failedOutcome(error),
        cleanupFailures,
        'plain-Node CLI verification and isolated-environment cleanup failed',
      );
    },
  );
}
function writeExactPipe(pipe, bytes) {
  return new Promise((resolveWrite, rejectWrite) => {
    let settled = false;
    const fail = () => {
      if (!settled) {
        settled = true;
        rejectWrite(
          internalArtifactVerificationError('plain-Node CLI snapshot authority transport failed'),
        );
      }
    };
    const succeed = () => {
      if (!settled) {
        settled = true;
        resolveWrite();
      }
    };

    pipe.once('error', fail);
    try {
      pipe.end(bytes, succeed);
    } catch {
      fail();
    }
  });
}

function classifiedCliFailure(result) {
  return (
    `${result.stdout}${result.stderr}`.match(
      /scene-glass-onboarding: \[SCG_[A-Z0-9_]+\] \[[a-z-]+\] command failed\./,
    )?.[0] ?? 'no classified CLI failure'
  );
}

function assertCliResult(result, mode) {
  if (result.deadlineExceeded) {
    fail(`plain-Node CLI ${mode} exceeded its execution deadline`);
  }
  if (result.outputExceeded) {
    fail(`plain-Node CLI ${mode} exceeded its output limit`);
  }
  if (
    !result.descendantsTerminated ||
    !result.groupDrainedWithoutVerifierAssistance ||
    result.termination !== null ||
    result.forced
  ) {
    fail(`plain-Node CLI ${mode} required verifier-assisted process cleanup`);
  }
  if (result.signal !== null || result.status !== 0) {
    const outcome = result.signal === null ? `exit ${result.status}` : `signal ${result.signal}`;
    fail(`plain-Node CLI ${mode} failed with ${outcome}; ${classifiedCliFailure(result)}`);
  }
  return `${result.stdout}${result.stderr}`;
}
function assertCliParseRejection(result, command) {
  if (
    result.deadlineExceeded ||
    result.outputExceeded ||
    !result.descendantsTerminated ||
    !result.groupDrainedWithoutVerifierAssistance ||
    result.termination !== null ||
    result.forced ||
    result.signal !== null ||
    result.status !== 1 ||
    result.stdout !== '' ||
    result.stderr !==
      'scene-glass-onboarding: [SCG_ONBOARDING_COMMAND_INVALID] [parse] command failed.\n'
  ) {
    fail(`plain-Node CLI ${command} extra-argument rejection was not exact`);
  }
}

function assertCliShutdownOutput(result, mode) {
  const output = `${result.stdout}${result.stderr}`;
  if (
    result.stderr !== '' ||
    /\b(?:error|failed|recovery|recovering|recovered)\b|\[SCG_[A-Z0-9_]+\]/i.test(output)
  ) {
    fail(`plain-Node CLI ${mode} emitted recovery or error output during shutdown`);
  }
  return output;
}

function assertCliGracefulShutdownResult(result, mode) {
  if (
    result.deadlineExceeded ||
    result.outputExceeded ||
    !result.descendantsTerminated ||
    !result.groupDrainedWithoutVerifierAssistance ||
    result.requestedSignal !== 'SIGTERM' ||
    result.termination !== 'requested-signal' ||
    result.forced ||
    result.signal !== null ||
    result.status !== 0
  ) {
    fail(`plain-Node CLI ${mode} did not complete bounded graceful SIGTERM shutdown`);
  }
  return assertCliShutdownOutput(result, mode);
}
async function writeTrustedProjectConfigFixture(
  directory,
  projectId,
  framework,
  credentialAuthority,
) {
  const configPath = join(directory, 'scene-glass.config.json');
  const serialized = stableJson({
    schemaVersion: 1,
    projects: [
      {
        projectId,
        root: directory,
        allowedOrigins: ['http://127.0.0.1:4175'],
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        framework,
      },
    ],
  });
  const registry = stableJson({
    schemaVersion: 1,
    projects: [
      {
        projectId,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        canonicalRoot: directory,
        credentialPath: credentialAuthority.path,
        device: credentialAuthority.device,
        inode: credentialAuthority.inode,
      },
    ],
  });
  assertSecretless(serialized, 'temporary trusted project configuration');
  assertSecretless(registry, 'temporary trusted credential registry');
  assertNoArtifactTokenOrDigest(serialized, 'temporary trusted project configuration');
  assertNoArtifactTokenOrDigest(registry, 'temporary trusted credential registry');
  await settleSetupMutations([
    writeFile(configPath, serialized, { encoding: 'utf8', mode: 0o600 }),
    writeFile(join(directory, 'credential-authorities.v1.json'), registry, {
      encoding: 'utf8',
      mode: 0o600,
    }),
  ]);
  return configPath;
}

async function createStaticDescriptorFixture(lifecycle, testOnly) {
  const directoryCandidate = await mkdtemp(join(tmpdir(), STATIC_DESCRIPTOR_TEMPORARY_PREFIX));
  let directory = directoryCandidate;
  const cleanupAuthority = registerOwnedCleanupAuthority(() =>
    removeArtifactTree(directory, 'static artifact fixture', undefined, undefined, testOnly),
  );
  try {
    directory = await realpath(directoryCandidate);

    const publicRoot = join(directory, 'public');
    const credentialPath = join(directory, 'credential-authority');
    await mkdir(publicRoot, { mode: 0o700 });
    const setupMutations = [
      writeFile(
        credentialPath,
        `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${STATIC_DESCRIPTOR_PROJECT_ID}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${ARTIFACT_TOKEN}\nSCENE_GLASS_HOST_TOKEN=${ARTIFACT_TOKEN}\n`,
        {
          encoding: 'utf8',
          mode: 0o600,
        },
      ),
      writeFile(
        join(publicRoot, 'index.html'),
        '<!doctype html>\n<html><head>\n<!-- scene-glass:static-loader:v1 -->\n</head><body><p>static artifact page</p></body></html>\n',
        { encoding: 'utf8', mode: 0o600 },
      ),
    ];
    const testOnlySetupMutations = [];
    if (testOnly?.afterSetupMutations !== undefined) {
      try {
        const startedMutation = testOnly.afterSetupMutations(
          Object.freeze({ directory, phase: 'static-fixture-setup' }),
        );
        testOnlySetupMutations.push(
          ...(Array.isArray(startedMutation) ? startedMutation : [startedMutation]),
        );
      } catch (error) {
        testOnlySetupMutations.push(Promise.reject(error));
      }
    }
    await settleSetupMutations([...setupMutations, ...testOnlySetupMutations]);
    const [rootIdentity, credentialIdentity, port] = await Promise.all([
      lstat(publicRoot, { bigint: true }),
      lstat(credentialPath, { bigint: true }),
      reserveLoopbackPort(),
    ]);
    const descriptorPath = join(directory, 'static-descriptor.json');
    const serialized = stableJson({
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port,
      projectId: STATIC_DESCRIPTOR_PROJECT_ID,
      loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
      credentialProjectId: STATIC_DESCRIPTOR_PROJECT_ID,
      credentialKey: 'SCENE_GLASS_HOST_TOKEN',
      navigation: 'document',
      readinessPath: '/__scene-glass/ready',
      approvedRootIdentity: {
        device: rootIdentity.dev.toString(),
        inode: rootIdentity.ino.toString(),
      },
      credentialAuthorities: [
        {
          projectId: STATIC_DESCRIPTOR_PROJECT_ID,
          path: credentialPath,
          device: credentialIdentity.dev.toString(),
          inode: credentialIdentity.ino.toString(),
        },
      ],
    });
    assertSecretless(serialized, 'temporary static descriptor');
    await writeFile(descriptorPath, serialized, 'utf8');
    const configPath = await writeTrustedProjectConfigFixture(
      directory,
      STATIC_DESCRIPTOR_PROJECT_ID,
      'html',
      {
        path: credentialPath,
        device: credentialIdentity.dev.toString(),
        inode: credentialIdentity.ino.toString(),
      },
    );
    return { configPath, descriptorPath, directory, port, cleanupAuthority };
  } catch (error) {
    await cleanupAfterFailure(error, {
      directory,
      label: 'static artifact fixture',
      lifecycle,
      hook: 'beforeStaticFixtureTreeCleanup',
      phase: 'static-fixture-tree-cleanup',
      testOnly,
      cleanupAuthority,
    });
  }
}
async function reserveLoopbackPort() {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', rejectPort);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      const address = server.address();
      if (address === null || typeof address === 'string' || address.address !== '127.0.0.1') {
        server.close(() =>
          rejectPort(internalArtifactVerificationError('could not reserve a loopback port')),
        );
        return;
      }
      server.close((error) => {
        if (error !== undefined) {
          rejectPort(error);
          return;
        }
        resolvePort(address.port);
      });
    });
  });
}

function requestLoopbackText(port, pathname, expectedContentType) {
  return new Promise((resolveText, rejectText) => {
    let settled = false;
    let timer;
    const settle = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      callback(value);
    };
    const probe = requestLoopback(
      {
        agent: false,
        host: '127.0.0.1',
        method: 'GET',
        path: pathname,
        port,
      },
      (response) => {
        if (response.statusCode !== 200) {
          response.destroy();
          probe.destroy();
          settle(
            rejectText,
            internalArtifactVerificationError(
              `artifact loopback probe returned status ${response.statusCode} for ${pathname}`,
            ),
          );
          return;
        }
        if (
          expectedContentType !== undefined &&
          response.headers['content-type'] !== expectedContentType
        ) {
          response.destroy();
          probe.destroy();
          settle(
            rejectText,
            internalArtifactVerificationError(
              'artifact loopback probe returned an unexpected content type',
            ),
          );
          return;
        }
        const chunks = [];
        let bytes = 0;
        response.on('data', (chunk) => {
          const body = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytes += body.byteLength;
          if (bytes > LOOPBACK_PROBE_LIMIT_BYTES) {
            response.destroy();
            probe.destroy();
            settle(
              rejectText,
              internalArtifactVerificationError(
                'managed Vite loopback probe exceeded its output limit',
              ),
            );
            return;
          }
          chunks.push(body);
        });
        response.once('error', () => {
          settle(
            rejectText,
            internalArtifactVerificationError(
              'managed Vite loopback probe failed while reading a response',
            ),
          );
        });
        response.once('end', () => {
          settle(resolveText, Buffer.concat(chunks).toString('utf8'));
        });
      },
    );
    probe.once('error', () => {
      settle(
        rejectText,
        internalArtifactVerificationError(
          'managed Vite loopback probe could not reach the loopback server',
        ),
      );
    });
    timer = setTimeout(() => {
      probe.destroy();
      settle(
        rejectText,
        internalArtifactVerificationError(
          'managed Vite loopback probe exceeded its execution deadline',
        ),
      );
    }, LOOPBACK_PROBE_DEADLINE_MS);
    probe.end();
  });
}

async function waitForLoopbackText(port, pathname, expectedContentType) {
  const deadline = Date.now() + STATIC_PREVIEW_PROBE_DEADLINE_MS;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await requestLoopbackText(port, pathname, expectedContentType);
    } catch (error) {
      lastError = error;
      if (
        error instanceof ArtifactVerificationError &&
        error.message.startsWith('artifact loopback probe returned')
      ) {
        throw error;
      }
      await new Promise((resolveDelay) => {
        setTimeout(resolveDelay, 50);
      });
    }
  }
  throw (
    lastError ??
    internalArtifactVerificationError(
      'static preview loopback probe did not become ready within its bound',
    )
  );
}

async function probeStaticPreviewRuntime(port) {
  const page = await waitForLoopbackText(port, '/', 'text/html; charset=utf-8');
  const expectedPage =
    '<!doctype html>\n<html><head>\n' +
    '<script async src="http://127.0.0.1:4175/scene-glass-loader.js" ' +
    `data-scg-project="${STATIC_DESCRIPTOR_PROJECT_ID}" data-scg-token="${ARTIFACT_TOKEN}" ` +
    'data-scg-navigation="document"></script>\n' +
    '</head><body><p>static artifact page</p></body></html>\n';
  if (page !== expectedPage) {
    fail('static preview did not return the exact rendered document');
  }

  const readiness = await waitForLoopbackText(
    port,
    '/__scene-glass/ready',
    'application/json; charset=utf-8',
  );
  if (readiness !== `{"ready":true,"projectId":"${STATIC_DESCRIPTOR_PROJECT_ID}"}\n`) {
    fail('static preview did not return the exact readiness response');
  }
}

async function createVerifiedNativeExecutionAuthority(
  root,
  cli,
  artifactSnapshot,
  lifecycle,
  testOnly,
) {
  const paths = artifactPaths(root);
  const snapshotArtifacts = await nativeAuthorityArtifactsFromSnapshot(
    paths,
    cli,
    artifactSnapshot,
  );
  const privateRootCandidate = await mkdtemp(join(paths.root, '.artifact-native-execution-'));
  let privateRoot = privateRootCandidate;
  let privateCli;
  const treeCleanupAuthority = registerOwnedCleanupAuthority(() =>
    removeArtifactTree(
      privateRoot,
      'private native-self-test authority',
      undefined,
      undefined,
      testOnly,
    ),
  );
  let privateCliCleanupAuthority;
  try {
    privateRoot = await realpath(privateRootCandidate);
    const { addonContents, cliContents, packageManifestContents } = snapshotArtifacts;
    const virtualCliPath = join(privateRoot, 'dist', 'cli.js');
    const privateAddonPath = join(privateRoot, ADDON_PATH);
    const privatePackageManifestPath = join(privateRoot, PACKAGE_MANIFEST_PATH);
    await settleSetupMutations([
      mkdir(dirname(virtualCliPath), { recursive: true, mode: 0o700 }),
      mkdir(dirname(privateAddonPath), { recursive: true, mode: 0o700 }),
    ]);
    await settleSetupMutations([
      writeFile(virtualCliPath, cliContents, { mode: Number(CLI_ARTIFACT_MODE) }),
      writeFile(privateAddonPath, addonContents, { mode: Number(ADDON_ARTIFACT_MODE) }),
      writeFile(privatePackageManifestPath, packageManifestContents, {
        mode: Number(PACKAGE_MANIFEST_MODE),
      }),
    ]);
    await settleSetupMutations([
      chmod(virtualCliPath, Number(CLI_ARTIFACT_MODE)),
      chmod(privateAddonPath, Number(ADDON_ARTIFACT_MODE)),
      chmod(privatePackageManifestPath, Number(PACKAGE_MANIFEST_MODE)),
    ]);
    const [verifiedCli, verifiedAddon, verifiedPackageManifest] = await Promise.all([
      readVerifiedArtifact(
        virtualCliPath,
        'private native-self-test CLI',
        CLI_ARTIFACT_MODE,
        CLI_MAX_BYTES,
      ),
      readVerifiedArtifact(
        privateAddonPath,
        'private native-self-test addon',
        ADDON_ARTIFACT_MODE,
        ADDON_MAX_BYTES,
      ),
      readVerifiedArtifact(
        privatePackageManifestPath,
        'private native-self-test package manifest',
        PACKAGE_MANIFEST_MODE,
        PACKAGE_MANIFEST_MAX_BYTES,
      ),
    ]);
    if (
      !verifiedCli.equals(cliContents) ||
      !verifiedAddon.equals(addonContents) ||
      !verifiedPackageManifest.equals(packageManifestContents)
    ) {
      fail('private native-self-test authority changed before execution');
    }
    privateCli = await openPinnedVerifiedCli(virtualCliPath, cli.hash);
    privateCliCleanupAuthority = registerOwnedCleanupAuthority(
      () => closeFileHandle(privateCli.handle, 'native-authority-close', testOnly),
      'handle',
    );
    return Object.freeze({
      root: privateRoot,
      cli: privateCli,
      cleanupAuthority: treeCleanupAuthority,
      closeAuthority: privateCliCleanupAuthority,
    });
  } catch (error) {
    const cleanupFailures = await collectCleanupFailures([
      ...(privateCli === undefined || lifecycle.beforeNativeAuthorityClose === undefined
        ? []
        : [cleanupAttempt('native-authority-close', () => lifecycle.beforeNativeAuthorityClose())]),
      ...(privateCli === undefined
        ? []
        : [
            cleanupAttempt('native-authority-close', () =>
              finalizeOwnedCleanupAuthority(privateCliCleanupAuthority),
            ),
          ]),
      ...artifactTreeCleanupAttempts({
        directory: privateRoot,
        label: 'private native-self-test authority',
        lifecycle,
        hook: 'beforeNativeAuthorityTreeCleanup',
        phase: 'native-authority-tree-cleanup',
        testOnly,
        cleanupAuthority: treeCleanupAuthority,
      }),
    ]);
    throwLifecycleFailures(
      failedOutcome(error),
      cleanupFailures,
      'private native-self-test authority setup and cleanup failed',
    );
  }
}
export async function verifyPlainNodeCli({
  root = packageRoot,
  cli = join(packageRoot, CLI_PATH),
  expectedCliHash,
  expectedAddonHash,
  artifactSnapshot,
  beforePinnedExecution,
  afterNativeAuthorityCreated,
  lifecycle,
  testOnly,
} = {}) {
  if (beforePinnedExecution !== undefined && typeof beforePinnedExecution !== 'function') {
    fail('plain-Node CLI pin hook is invalid');
  }
  if (
    afterNativeAuthorityCreated !== undefined &&
    typeof afterNativeAuthorityCreated !== 'function'
  ) {
    fail('plain-Node CLI native authority hook is invalid');
  }
  if (typeof expectedCliHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedCliHash)) {
    fail('verified CLI hash is invalid');
  }
  const lifecyclePort = normalizePlainNodeCliLifecycle(lifecycle);
  const testOnlyPorts = normalizePlainNodeCliTestOnlyPorts(testOnly);
  const snapshotPaths = { ...artifactPaths(root), cli };
  const verifiedArtifactSnapshot = normalizeVerifiedArtifactSnapshot(
    artifactSnapshot ??
      (await createVerifiedArtifactSnapshot(snapshotPaths, {
        expectedCliHash,
      })),
    {
      root: resolve(root),
      cliPath: cli,
      expectedAddonHash,
      expectedCliHash,
    },
  );
  const pinnedCli = verifiedArtifactSnapshot.cli;
  const pinnedCliCleanupAuthority = registerOwnedCleanupAuthority(
    () => closeFileHandle(pinnedCli.handle, 'pinned-cli-close', testOnlyPorts),
    'handle',
  );
  let restore;
  let verificationOutcome = successfulOutcome();
  try {
    const pinnedExecutionRestore = await beforePinnedExecution?.();
    if (pinnedExecutionRestore !== undefined && typeof pinnedExecutionRestore !== 'function') {
      fail('plain-Node CLI pin hook must return a restore function');
    }
    restore = pinnedExecutionRestore;
    await verifyPinnedPlainNodeCli({
      root,
      cli: pinnedCli,
      artifactSnapshot: verifiedArtifactSnapshot,
      afterNativeAuthorityCreated,
      lifecycle: lifecyclePort,
      testOnly: testOnlyPorts,
    });
  } catch (error) {
    verificationOutcome = failedOutcome(error);
  }
  const cleanupFailures = await collectCleanupFailures([
    ...(restore === undefined ? [] : [cleanupAttempt('pinned-execution-restore', () => restore())]),
    ...(lifecyclePort.beforePinnedCliClose === undefined
      ? []
      : [cleanupAttempt('pinned-cli-close', () => lifecyclePort.beforePinnedCliClose())]),
    cleanupAttempt('pinned-cli-close', () =>
      finalizeOwnedCleanupAuthority(pinnedCliCleanupAuthority),
    ),
  ]);
  throwLifecycleFailures(
    verificationOutcome,
    cleanupFailures,
    'plain-Node CLI verification and finalization failed',
  );
}

async function verifyPinnedPlainNodeCli({
  root,
  cli,
  artifactSnapshot,
  afterNativeAuthorityCreated,
  lifecycle,
  testOnly,
}) {
  await nativeAuthorityArtifactsFromSnapshot(artifactPaths(root), cli, artifactSnapshot);
  const help = assertCliResult(
    await runPlainNodeCli(root, cli, ['help'], {
      sensitivePaths: [resolve(root)],
    }),
    'help',
  );
  if (help !== CLI_USAGE) {
    fail('plain-Node CLI help did not emit the exact command list');
  }
  for (const command of ['setup', 'start', 'uninstall']) {
    assertCliParseRejection(
      await runPlainNodeCli(root, cli, [command, '--invalid'], {
        sensitivePaths: [resolve(root)],
      }),
      command,
    );
  }

  const fixture = await createStaticDescriptorFixture(lifecycle, testOnly);
  let staticVerificationOutcome = successfulOutcome();
  try {
    await lifecycle.beforeStaticFixtureVerification?.();
    const descriptorCheck = assertCliResult(
      await runPlainNodeCli(
        root,
        cli,
        ['descriptor-check', '--descriptor', fixture.descriptorPath, '--kind', 'static'],
        {
          configPath: fixture.configPath,
          sensitivePaths: [resolve(root), fixture.directory],
        },
      ),
      'descriptor-check',
    );
    if (descriptorCheck !== 'descriptor check passed\n') {
      fail('plain-Node CLI descriptor-check did not confirm the static descriptor');
    }
    const staticPreview = assertCliGracefulShutdownResult(
      await runPlainNodeCli(root, cli, ['static-preview', '--descriptor', fixture.descriptorPath], {
        afterSpawn: () => probeStaticPreviewRuntime(fixture.port),
        configPath: fixture.configPath,
        sensitivePaths: [resolve(root), fixture.directory],
        terminateAfterReady: true,
      }),
      'static-preview',
    );
    if (staticPreview !== '') {
      fail('plain-Node CLI static-preview emitted unexpected output');
    }
  } catch (error) {
    staticVerificationOutcome = failedOutcome(error);
  }
  const staticCleanupFailures = await collectCleanupFailures(
    artifactTreeCleanupAttempts({
      directory: fixture.directory,
      label: 'static artifact fixture',
      lifecycle,
      hook: 'beforeStaticFixtureTreeCleanup',
      phase: 'static-fixture-tree-cleanup',
      testOnly,
      cleanupAuthority: fixture.cleanupAuthority,
    }),
  );
  throwLifecycleFailures(
    staticVerificationOutcome,
    staticCleanupFailures,
    'static artifact verification and cleanup failed',
  );

  const nativeAuthority = await createVerifiedNativeExecutionAuthority(
    root,
    cli,
    artifactSnapshot,
    lifecycle,
    testOnly,
  );
  let restoreNativeAuthority;
  let nativeVerificationOutcome = successfulOutcome();
  try {
    const nativeAuthorityRestore = await afterNativeAuthorityCreated?.(
      Object.freeze({ root: nativeAuthority.root }),
    );
    if (nativeAuthorityRestore !== undefined && typeof nativeAuthorityRestore !== 'function') {
      fail('plain-Node CLI native authority hook must return a restore function');
    }
    restoreNativeAuthority = nativeAuthorityRestore;
    const nativeSelfTest = assertCliResult(
      await runPlainNodeCli(
        nativeAuthority.root,
        nativeAuthority.cli,
        ['native-self-test', '--root', nativeAuthority.root],
        {
          sensitivePaths: [resolve(root), nativeAuthority.root],
        },
      ),
      'native-self-test',
    );
    if (nativeSelfTest !== 'native self-test passed\n') {
      fail('plain-Node CLI native-self-test did not exercise native identity and denial checks');
    }
  } catch (error) {
    nativeVerificationOutcome = failedOutcome(error);
  }

  const nativeCleanupFailures = await collectCleanupFailures([
    ...(restoreNativeAuthority === undefined
      ? []
      : [cleanupAttempt('native-authority-restore', () => restoreNativeAuthority())]),
    ...(lifecycle.beforeNativeAuthorityClose === undefined
      ? []
      : [cleanupAttempt('native-authority-close', () => lifecycle.beforeNativeAuthorityClose())]),
    cleanupAttempt('native-authority-close', () =>
      finalizeOwnedCleanupAuthority(nativeAuthority.closeAuthority),
    ),
    ...artifactTreeCleanupAttempts({
      directory: nativeAuthority.root,
      label: 'private native-self-test authority',
      lifecycle,
      hook: 'beforeNativeAuthorityTreeCleanup',
      phase: 'native-authority-tree-cleanup',
      testOnly,
      cleanupAuthority: nativeAuthority.cleanupAuthority,
    }),
  ]);
  throwLifecycleFailures(
    nativeVerificationOutcome,
    nativeCleanupFailures,
    'private native-self-test authority verification and cleanup failed',
  );
}

function assertStrictManifestFacts(facts) {
  if (
    !facts.isFile() ||
    facts.isSymbolicLink() ||
    facts.nlink !== 1n ||
    (facts.mode & 0o7777n) !== 0o644n ||
    facts.size <= 0n ||
    facts.size > BigInt(MANIFEST_MAX_BYTES)
  ) {
    fail('dist/build-manifest.json must be a regular mode 0644 canonical manifest');
  }
}

async function readStrictManifest(path) {
  if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number') {
    fail('artifact verification requires no-follow nonblocking file descriptors');
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail('missing build manifest');
    }
    if (error.code === 'ELOOP') {
      fail('dist/build-manifest.json must be a regular mode 0644 canonical manifest');
    }
    throw internalArtifactVerificationError('build manifest cannot be opened');
  }

  let readOutcome;
  try {
    const before = await handle.stat({ bigint: true });
    assertStrictManifestFacts(before);
    const size = Number(before.size);
    const contents = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(contents, offset, size - offset, offset);
      if (bytesRead === 0) {
        fail('dist/build-manifest.json changed while it was being read');
      }
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameArtifactFacts(before, after)) {
      fail('dist/build-manifest.json changed while it was being read');
    }
    readOutcome = successfulOutcome(contents.toString('utf8'));
  } catch (error) {
    readOutcome = failedOutcome(error);
  }
  return closeFileHandleWithLifecycle(
    handle,
    readOutcome,
    'build-manifest-read-close',
    'build manifest read and close failed',
  );
}

function parseManifest(contents) {
  try {
    return JSON.parse(contents);
  } catch {
    fail('dist/build-manifest.json is not valid JSON');
  }
}

async function verifiedNodeAddonContract(root) {
  const runtime = runtimeNodeContract();
  let binding;
  try {
    binding = await readBoundedRegularUtf8(
      join(root, 'binding.gyp'),
      'native Node-API build contract',
      BINDING_GYP_MAX_BYTES,
    );
  } catch (error) {
    if (lifecycleMetadataFor(error) !== undefined) {
      throw error;
    }
    fail('native Node-API build contract is unavailable');
  }
  const versions = [...binding.matchAll(/\bNAPI_VERSION=([1-9][0-9]*)\b/g)];
  const addonNapi = Number(versions[0]?.[1]);
  if (versions.length !== 1 || addonNapi !== REQUIRED_ADDON_NAPI) {
    fail(`native addon must declare exact Node-API ${REQUIRED_ADDON_NAPI}`);
  }
  return { nodeMajor: runtime.nodeMajor, napi: addonNapi };
}

async function expectedManifest(paths, { auditedCli, artifactSnapshot } = {}) {
  if (
    artifactSnapshot !== undefined &&
    (auditedCli !== undefined || !VERIFIED_ARTIFACT_SNAPSHOTS.has(artifactSnapshot))
  ) {
    fail('verified artifact snapshot authority is invalid');
  }
  const [contract, hashes] = await Promise.all([
    verifiedNodeAddonContract(paths.root),
    artifactSnapshot === undefined
      ? readVerifiedArtifacts(paths, { auditedCli })
      : Promise.resolve({
          addonHash: artifactSnapshot.addon.hash,
          cliHash: artifactSnapshot.cli.hash,
        }),
  ]);
  return buildManifest({ ...hashes, ...contract });
}

export async function publishRuntimeBuildManifest(auditedCli) {
  if ((await resolvePublishedCliAuthority(auditedCli)) === undefined) {
    fail('build manifest publication requires module-issued audited CLI authority');
  }
  const paths = artifactPaths(packageRoot);
  const manifest = await expectedManifest(paths, { auditedCli });
  try {
    await writeFile(paths.manifest, stableJson(manifest), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    });
    await chmod(paths.manifest, 0o644);
    const publishedContents = await readAuditedPublishedCli(auditedCli, paths.cli);
    if (createHash('sha256').update(publishedContents).digest('hex') !== manifest.cliSha256) {
      fail('audited CLI changed after manifest publication');
    }
  } catch (error) {
    if (error.code === 'EEXIST') {
      fail('build manifest already exists');
    }
    throw error;
  }
  return manifest;
}

export async function verifyArtifacts({ root = packageRoot, testOnly } = {}) {
  const paths = artifactPaths(root);
  const testOnlyPorts = normalizePlainNodeCliTestOnlyPorts(testOnly);
  const artifactSnapshot = await createVerifiedArtifactSnapshot(paths);
  let snapshotCliOwnershipTransferred = false;
  try {
    const expected = await expectedManifest(paths, { artifactSnapshot });
    const existing = await readStrictManifest(paths.manifest);
    assertSecretless(existing, 'dist/build-manifest.json');
    parseManifest(existing);
    if (existing !== stableJson(expected)) {
      fail(
        'dist/build-manifest.json does not match this platform, Node runtime, or artifact hashes',
      );
    }

    await testOnlyPorts?.afterArtifactSnapshotVerified?.();
    snapshotCliOwnershipTransferred = true;
    await verifyPlainNodeCli({
      root: paths.root,
      cli: paths.cli,
      expectedAddonHash: expected.addonSha256,
      expectedCliHash: expected.cliSha256,
      artifactSnapshot,
      testOnly: testOnlyPorts,
    });
    return expected;
  } catch (error) {
    if (snapshotCliOwnershipTransferred) {
      throw error;
    }
    return closeFileHandleWithLifecycle(
      artifactSnapshot.cli.handle,
      failedOutcome(error),
      'verified-artifact-snapshot-cli-close',
      'artifact verification and verified artifact snapshot CLI close failed',
      testOnlyPorts,
    );
  }
}

export function formatArtifactVerifierFailure(error) {
  const metadata = lifecycleMetadataFor(error);
  const primary = metadata?.primary ?? error;
  const primaryDiagnostic = internalArtifactVerificationErrors.has(primary)
    ? primary.message
    : 'artifact verification failed';
  const cleanupPhases = [...new Set(metadata?.cleanupPhases ?? [])];
  const cleanupEvidence =
    cleanupPhases.length === 0 ? '' : `; cleanup phases failed: ${cleanupPhases.join(', ')}`;
  return `ArtifactVerificationError: ${primaryDiagnostic}${cleanupEvidence}\n`;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 0) {
    fail('verify-artifacts.mjs accepts no arguments');
  }
  const manifest = await verifyArtifacts();
  process.stdout.write(
    `verified ${relative(packageRoot, join(packageRoot, CLI_PATH))} and ${ADDON_PATH} for ${manifest.platform}/${manifest.arch}\n`,
  );
}

const invokedPath = process.argv[1] === undefined ? null : await realpath(resolve(process.argv[1]));
if (invokedPath === (await realpath(fileURLToPath(import.meta.url)))) {
  main().catch((error) => {
    process.stderr.write(formatArtifactVerifierFailure(error));
    process.exitCode = 1;
  });
}
