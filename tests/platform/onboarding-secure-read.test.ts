import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  chown,
  link,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { createServer, type Server } from 'node:net';
import { createRequire } from 'node:module';
import { format, inspect, isDeepStrictEqual, promisify } from 'node:util';
import { basename, join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  acquireLifecycleLock,
  assertSecureReadNativeAvailable,
  createNativeViteCacheRuntimePort,
  createNativeViteRecoveryDirectoryPort,
  MAX_ACTIVE_VITE_CACHE_SESSIONS,
  MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES,
  MAX_ACTIVE_VITE_RECOVERY_DIRECTORY_SESSIONS,
  MAX_ACTIVE_VITE_SNAPSHOT_SESSIONS,
  MAX_ACTIVE_VITE_SNAPSHOT_STAGINGS,
  OnboardingNativeError,
  releaseLifecycleLock,
  readExactLifecycleWal,
  replaceReservedLifecycleFileExact,
  reserveLifecycleStagedFile,
  restoreLifecycleQuarantine,
  writeLifecycleStagedFile,
  revokeCredentialReadCapability,
  secureReadBeneath,
  secureReadCredential,
  verifyCredentialAuthority,
  verifyCredentialAuthoritySet,
  verifyManagedViteChildLaunchAuthority,
  zeroizeBuffer,
} from '../../packages/onboarding/src/native.js';
import {
  verifyCredentialAuthorities,
  withSelectedCredential,
} from '../../packages/onboarding/src/credential-authority.js';
import {
  VITE_CACHE_DIRECTORY_MODE,
  VITE_CACHE_FILE_MODE,
  type CacheNativeSession,
  type CacheRootRecord,
  type CacheTreeEntry,
  type ViteCacheLimits,
  type ViteCacheProvenance,
} from '../../packages/onboarding/src/vite/cache.js';
import {
  parseViteCacheProvenanceJson,
  reopenViteCacheSession,
  serializeViteCacheProvenanceJson,
} from '../../packages/onboarding/src/vite/index.js';
import type { CredentialAuthority, FileIdentity } from '../../packages/onboarding/src/types.js';

const isSupportedPlatform = process.platform === 'darwin' || process.platform === 'linux';
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;
const supportedHome = nativeHomeHierarchy();
const canExerciseNativeReads = isSupportedPlatform && supportedHome !== undefined;
const canExerciseForeignCacheOwnerFixture =
  canExerciseNativeReads && typeof process.geteuid === 'function' && process.geteuid() === 0;
const VITE_CACHE_WATCH_DEADLINE_MS = 2_000;
const VITE_CACHE_CANARY_READ_CHUNK_BYTES = 64 * 1024;
const directNativeRequire = createRequire(import.meta.url);
const execFileAsync = promisify(execFile);
const temporaryRoots: string[] = [];
const PATH_REPLACEMENT_WAIT_DEADLINE_MS = 5_000;
const PATH_REPLACEMENT_WORKER_DEADLINE_MS = 3_000;
const PATH_REPLACEMENT_MAX_SWAPS = 64;
const PATH_REPLACEMENT_ARMED = 1;
const PATH_REPLACEMENT_ACTIVE = 2;
const PATH_REPLACEMENT_STOPPED = 3;
const SAME_FD_FIXTURE_BYTES = 12 * 1024 * 1024;
const SAME_FD_UNAUTHENTICATED_READ_ATTEMPTS = 6;
const SAME_FD_AUTHORITY_READ_ATTEMPTS = 6;
const PATH_REPLACEMENT_WORKER_SOURCE = `
const { renameSync, statSync, writeFileSync } = require('node:fs');
const { parentPort, workerData } = require('node:worker_threads');

const control = new Int32Array(workerData.control);
const armed = 1;
const active = 2;
const deadlineMilliseconds = workerData.deadlineMilliseconds;
const maximumSwaps = workerData.maximumSwaps;
const firstBytes = workerData.firstBytes;
const secondBytes = workerData.secondBytes;

function waitForPhase(phase) {
  const deadline = Date.now() + deadlineMilliseconds;
  for (;;) {
    const current = Atomics.load(control, 0);
    if (current >= phase) {
      return current;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error('pathname replacement worker timed out waiting for synchronization');
    }
    Atomics.wait(control, 0, current, remaining);
  }
}

function prepareCandidate(bytes, label) {
  writeFileSync(workerData.stagingPath, bytes, { flag: 'w', mode: 0o600 });
  const information = statSync(workerData.stagingPath, { bigint: true });
  return {
    label,
    identity: { device: information.dev.toString(), inode: information.ino.toString() },
  };
}

try {
  let candidate = prepareCandidate(secondBytes, 'second');
  parentPort.postMessage({ type: 'prepared' });
  if (waitForPhase(armed) !== armed) {
    throw new Error('pathname replacement worker stopped before it was armed');
  }
  parentPort.postMessage({ type: 'armed' });
  if (waitForPhase(active) !== active) {
    throw new Error('pathname replacement worker stopped before reads started');
  }

  const deadline = Date.now() + deadlineMilliseconds;
  const published = [];
  let swaps = 0;
  while (
    swaps < maximumSwaps &&
    Date.now() < deadline &&
    Atomics.load(control, 0) === active
  ) {
    renameSync(workerData.stagingPath, workerData.targetPath);
    published.push(candidate);
    swaps += 1;
    const nextLabel = candidate.label === 'first' ? 'second' : 'first';
    candidate = prepareCandidate(nextLabel === 'first' ? firstBytes : secondBytes, nextLabel);
  }
  parentPort.postMessage({ type: 'done', swaps, published });
} catch (error) {
  parentPort.postMessage({
    type: 'error',
    message: error instanceof Error ? error.message : 'pathname replacement worker failed',
  });
}
`;
const NESTED_DIRECTORY_RENAME_WORKER_SOURCE = `
const { renameSync } = require('node:fs');
const { parentPort, workerData } = require('node:worker_threads');

const control = new Int32Array(workerData.control);
const armed = 1;
const active = 2;
const deadlineMilliseconds = workerData.deadlineMilliseconds;
const maximumSwaps = workerData.maximumSwaps;

function waitForPhase(phase) {
  const deadline = Date.now() + deadlineMilliseconds;
  for (;;) {
    const current = Atomics.load(control, 0);
    if (current >= phase) {
      return current;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error('nested-directory rename worker timed out waiting for synchronization');
    }
    Atomics.wait(control, 0, current, remaining);
  }
}

try {
  parentPort.postMessage({ type: 'prepared' });
  if (waitForPhase(armed) !== armed) {
    throw new Error('nested-directory rename worker stopped before it was armed');
  }
  parentPort.postMessage({ type: 'armed' });
  if (waitForPhase(active) !== active) {
    throw new Error('nested-directory rename worker stopped before scans started');
  }

  const deadline = Date.now() + deadlineMilliseconds;
  let swaps = 0;
  let inStaging = false;
  while (
    swaps < maximumSwaps &&
    Date.now() < deadline &&
    Atomics.load(control, 0) === active
  ) {
    renameSync(
      inStaging ? workerData.stagingPath : workerData.targetPath,
      inStaging ? workerData.targetPath : workerData.stagingPath,
    );
    inStaging = !inStaging;
    swaps += 1;
  }
  if (inStaging) {
    renameSync(workerData.stagingPath, workerData.targetPath);
  }
  parentPort.postMessage({ type: 'done', swaps });
} catch (error) {
  parentPort.postMessage({
    type: 'error',
    message: error instanceof Error ? error.message : 'nested-directory rename worker failed',
  });
}
`;
const LIFECYCLE_FIFO_RECOVERY_WORKER_SOURCE = `
const { parentPort, workerData } = require('node:worker_threads');

try {
  const binding = require(workerData.bindingPath);
  const lock = binding.acquireLifecycleLock({ path: workerData.lockPath });
  const result = binding.recoverLifecycleCreationIntent({
    lock,
    stagePath: workerData.stagePath,
    markerPath: workerData.markerPath,
    kind: 'file',
    mode: 0o600,
  });
  const released = binding.releaseLifecycleLock({ lock });
  parentPort.postMessage({ type: 'recovered', state: result.state, released: released.state });
} catch (error) {
  parentPort.postMessage({
    type: 'error',
    message: error instanceof Error ? error.message : 'Lifecycle FIFO recovery worker failed',
  });
}
`;

beforeEach(async () => {
  if (!canExerciseNativeReads || supportedHome === undefined) {
    return;
  }
  const root = await mkdtemp(join(supportedHome, '.scene-glass-secure-read-'));
  await chmod(root, 0o700);
  temporaryRoots.push(root);
});

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe.skipIf(!canExerciseNativeReads)('native secure reads', () => {
  it('reads a regular file below a supported /Users or /home hierarchy', async () => {
    const root = currentRoot();
    const content = join(root, 'content.txt');
    await writeSecureFile(content, 'trusted content');

    const read = await secureRead(root, 'content.txt');
    expect(read.bytes.toString('utf8')).toBe('trusted content');
    expect(read.identity).toEqual(await fileIdentity(content));
    expect(read.linkCount).toBe(1);
    expect(read.mode & 0o777).toBe(0o600);
    zeroizeBuffer(read.bytes);
  });
  it('requires expected-owner 0600 credentials on the retained FD without restricting static asset modes', async () => {
    const root = currentRoot();
    const credentialPath = join(root, 'credential-mode.env');
    const contents = 'credential mode fixture';
    const options = credentialOptions();
    await writeSecureFile(credentialPath, contents);
    const authority = await credentialAuthority('alpha', credentialPath);
    const binding = directSecureReadBinding();
    const directCredentialRead = () =>
      binding.secureReadBeneath({
        root: '/',
        expectedRoot: null,
        relativePath: credentialPath.slice(1),
        expectedAuthority: { device: authority.device, inode: authority.inode },
        deniedIdentities: [],
        maxBytes: options.maxBytes,
        readContent: true,
      });

    expect((await stat(credentialPath, { bigint: true })).uid).toBe(
      BigInt(options.expectedOwnerUid),
    );
    for (const mode of [0o644, 0o444]) {
      await chmod(credentialPath, mode);
      const staticRead = await secureRead(root, 'credential-mode.env');
      try {
        expect(staticRead.bytes.toString('utf8')).toBe(contents);
      } finally {
        zeroizeBuffer(staticRead.bytes);
      }

      const error = expectDirectNativeError(directCredentialRead);
      expect(error.code).toBe('SCG_NATIVE_PATH_DENIED');
    }

    await chmod(credentialPath, 0o600);
    const directRead = directNativeReadResult(directCredentialRead());
    try {
      expect(directRead.bytes.toString('utf8')).toBe(contents);
      expect(directRead.identity).toEqual({ device: authority.device, inode: authority.inode });
    } finally {
      zeroizeBuffer(directRead.bytes);
    }

    const verified = verifyCredentialAuthorities({
      authorities: [authority],
      selectedProjectId: 'alpha',
      ...options,
    });
    await expect(
      withSelectedCredential(verified, (credential) => credential.toString('utf8')),
    ).resolves.toBe(contents);
  });

  it('rejects a sticky world-writable /tmp root', async () => {
    const root = await mkdtemp(join(tmpdir(), 'scene-glass-unsafe-'));
    temporaryRoots.push(root);
    const content = join(root, 'content.txt');
    await writeSecureFile(content, 'unsafe');
    const temporaryRootIdentity = await fileIdentity(tmpdir());

    const error = await expectNativeError(() =>
      secureReadBeneath({
        root: tmpdir(),
        expectedRoot: temporaryRootIdentity,
        relativePath: `${basename(root)}/content.txt`,
        deniedIdentities: [],
        maxBytes: 1024,
      }),
    );

    expect(error.code).toBe('SCG_NATIVE_PATH_DENIED');
  });

  it('rejects links, unsafe modes, intermediate symlinks, and nonregular final components', async () => {
    const root = currentRoot();
    const source = join(root, 'source.txt');
    await writeSecureFile(source, 'source');
    await symlink(source, join(root, 'link.txt'));
    await link(source, join(root, 'hardlink.txt'));

    const actualDirectory = join(root, 'actual');
    await mkdir(actualDirectory, { mode: 0o700 });
    await writeSecureFile(join(actualDirectory, 'content.txt'), 'linked directory');
    await symlink('actual', join(root, 'linked-directory'));

    const unsafeDirectory = join(root, 'unsafe-directory');
    await mkdir(unsafeDirectory, { mode: 0o700 });
    await writeSecureFile(join(unsafeDirectory, 'content.txt'), 'unsafe intermediate');
    await chmod(unsafeDirectory, 0o720);

    const unsafeFile = join(root, 'unsafe-file.txt');
    await writeSecureFile(unsafeFile, 'unsafe final');
    await chmod(unsafeFile, 0o620);

    await mkdir(join(root, 'directory-final'), { mode: 0o700 });
    const before = await descriptorCount();
    const errors = await Promise.all([
      expectNativeError(() => secureRead(root, 'link.txt')),
      expectNativeError(() => secureRead(root, 'hardlink.txt')),
      expectNativeError(() => secureRead(root, 'linked-directory/content.txt')),
      expectNativeError(() => secureRead(root, 'unsafe-directory/content.txt')),
      expectNativeError(() => secureRead(root, 'unsafe-file.txt')),
      expectNativeError(() => secureRead(root, 'directory-final')),
    ]);
    const after = await descriptorCount();

    expect(errors.map((error) => error.code)).toEqual([
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
    ]);
    expect(after).toBeLessThanOrEqual(before + 2);
  });
  it('rejects access-control-list-bearing secure-read files when fixture installation is supported', async () => {
    const path = join(currentRoot(), 'acl.txt');
    await writeSecureFile(path, 'acl');
    if (!(await addUnsafeAcl(path))) {
      return;
    }

    const error = await expectNativeError(() => secureRead(currentRoot(), 'acl.txt'));
    expect(error.code).toBe('SCG_NATIVE_PATH_DENIED');
  });

  it('rejects final and intermediate credential replacements after capability issue', async () => {
    const root = currentRoot();
    const nested = join(root, 'credentials');
    await mkdir(nested, { mode: 0o700 });
    const credentialPath = join(nested, 'credential.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'first'));
    const finalAuthority = await credentialAuthority('alpha', credentialPath);
    const finalSelection = verifyCredentialAuthorities({
      authorities: [finalAuthority],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    await rename(credentialPath, join(nested, 'credential.old'));
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'replaced'));
    let finalCallbackCalled = false;
    const finalReplacementError = await expectNativeError(() =>
      withSelectedCredential(finalSelection, (credential) => {
        finalCallbackCalled = true;
        return credential.toString('utf8');
      }),
    );
    expect(finalReplacementError.code).toBe('SCG_NATIVE_IDENTITY_MISMATCH');
    expect(finalCallbackCalled).toBe(false);

    const intermediate = join(root, 'intermediate');
    await mkdir(intermediate, { mode: 0o700 });
    const intermediatePath = join(intermediate, 'credential.env');
    await writeSecureFile(intermediatePath, credentialEnvelope('beta', 'second'));
    const intermediateAuthority = await credentialAuthority('beta', intermediatePath);
    const intermediateSelection = verifyCredentialAuthorities({
      authorities: [intermediateAuthority],
      selectedProjectId: 'beta',
      ...credentialOptions(),
    });

    await rename(intermediate, join(root, 'intermediate.old'));
    await mkdir(intermediate, { mode: 0o700 });
    await writeSecureFile(intermediatePath, credentialEnvelope('beta', 'replaced-again'));
    let intermediateCallbackCalled = false;
    const intermediateReplacementError = await expectNativeError(() =>
      withSelectedCredential(intermediateSelection, (credential) => {
        intermediateCallbackCalled = true;
        return credential.toString('utf8');
      }),
    );
    expect(intermediateReplacementError.code).toBe('SCG_NATIVE_IDENTITY_MISMATCH');
    expect(intermediateCallbackCalled).toBe(false);
  });

  it('rejects an expected root identity mismatch', async () => {
    const root = currentRoot();
    await writeSecureFile(join(root, 'content.txt'), 'identity');
    const rootIdentity = await fileIdentity(root);

    const error = await expectNativeError(() =>
      secureReadBeneath({
        root,
        expectedRoot: { device: rootIdentity.device, inode: incrementDecimal(rootIdentity.inode) },
        relativePath: 'content.txt',
        deniedIdentities: [],
        maxBytes: 1024,
      }),
    );

    expect(error.code).toBe('SCG_NATIVE_IDENTITY_MISMATCH');
  });
  it('rejects NaN and nonintegral maxBytes at the direct native boundary', async () => {
    const root = currentRoot();
    await writeSecureFile(join(root, 'content.txt'), 'native boundary');
    const expectedRoot = await fileIdentity(root);

    for (const maxBytes of [Number.NaN, 1.5]) {
      const error = expectDirectNativeError(() =>
        directSecureReadBinding().secureReadBeneath({
          root,
          expectedRoot,
          relativePath: 'content.txt',
          expectedAuthority: null,
          deniedIdentities: [],
          maxBytes,
          readContent: true,
        }),
      );
      expect(error.code).toBe('SCG_NATIVE_READ_LIMIT');
    }
  });

  it('requires a selected capability before credential reads and enforces the byte cap', async () => {
    const credentialPath = join(currentRoot(), 'credential.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'too-long'));
    const authority = await credentialAuthority('alpha', credentialPath);

    const unverifiedReadError = await expectNativeError(() =>
      secureReadCredential(authority, credentialOptions()),
    );
    expect(unverifiedReadError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');

    verifyCredentialAuthority(authority, credentialOptions());
    const validatedOnlyReadError = await expectNativeError(() =>
      secureReadCredential(authority, credentialOptions()),
    );
    expect(validatedOnlyReadError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');

    const verified = verifyCredentialAuthorities({
      authorities: [authority],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    const oversizedReadError = await expectNativeError(() =>
      secureReadCredential(verified.capability, { ...credentialOptions(), maxBytes: 3 }),
    );
    expect(oversizedReadError.code).toBe('SCG_NATIVE_READ_LIMIT');
  });

  it('denies protected identities before content bytes are returned', async () => {
    const root = currentRoot();
    const credentialPath = join(root, 'credential.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'canary'));
    const identity = await fileIdentity(credentialPath);
    const rootIdentity = await fileIdentity(root);

    const error = await expectNativeError(() =>
      secureReadBeneath({
        root,
        expectedRoot: rootIdentity,
        relativePath: 'credential.env',
        deniedIdentities: [identity],
        maxBytes: 1024,
      }),
    );

    expect(error.code).toBe('SCG_NATIVE_PATH_DENIED');
  });
  it('bounds native path components and denied identities before descriptor traversal', async () => {
    const root = currentRoot();
    const rootIdentity = await fileIdentity(root);
    const binding = directSecureReadBinding();
    const tooManyComponents = Array.from({ length: 257 }, () => 'a').join('/');
    const pathError = expectDirectNativeError(() =>
      binding.secureReadBeneath({
        root,
        expectedRoot: rootIdentity,
        relativePath: tooManyComponents,
        expectedAuthority: null,
        deniedIdentities: [],
        maxBytes: 1024,
        readContent: false,
      }),
    );
    expect(pathError.code).toBe('SCG_NATIVE_PATH_DENIED');
    const oversizedRootError = expectDirectNativeError(() =>
      binding.secureReadBeneath({
        root: `/${'a'.repeat(4_096)}`,
        expectedRoot: rootIdentity,
        relativePath: 'missing.env',
        expectedAuthority: null,
        deniedIdentities: [],
        maxBytes: 1024,
        readContent: false,
      }),
    );
    expect(oversizedRootError.code).toBe('SCG_NATIVE_PATH_DENIED');

    const deniedError = expectDirectNativeError(() =>
      binding.secureReadBeneath({
        root,
        expectedRoot: rootIdentity,
        relativePath: 'missing.env',
        expectedAuthority: null,
        deniedIdentities: Array.from({ length: 1_025 }, () => rootIdentity),
        maxBytes: 1024,
        readContent: false,
      }),
    );
    expect(deniedError.code).toBe('SCG_NATIVE_PATH_DENIED');
  });
  it('keeps concurrent pathname replacements bound to one same-FD identity', async () => {
    const root = currentRoot();
    const targetPath = join(root, 'same-fd-target.bin');
    const stagingPath = join(root, 'same-fd-staging.bin');
    const firstBytes = largeFixtureBytes('FIRST_SAME_FD_FIXTURE');
    const secondBytes = largeFixtureBytes('SECOND_SAME_FD_FIXTURE');
    await writeSecureBuffer(targetPath, firstBytes);

    const firstIdentity = await fileIdentity(targetPath);
    const rootIdentity = await fileIdentity(root);
    const directBinding = directSecureReadBinding();
    const worker = await startPathReplacementWorker({
      targetPath,
      stagingPath,
      firstBytes,
      secondBytes,
    });
    const outcomes: ConcurrentReadOutcome[] = [];
    const authorityOutcomes: DirectAuthorityOutcome[] = [];
    let completion: PathReplacementCompletion | undefined;
    try {
      const armed = waitForWorkerMessage(worker.worker, 'armed');
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_ARMED);
      Atomics.notify(worker.control, 0);
      await armed;

      const done = waitForWorkerMessage(worker.worker, 'done');
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_ACTIVE);
      Atomics.notify(worker.control, 0);
      for (let attempt = 0; attempt < SAME_FD_UNAUTHENTICATED_READ_ATTEMPTS; attempt += 1) {
        try {
          const read = secureReadBeneath({
            root,
            expectedRoot: rootIdentity,
            relativePath: 'same-fd-target.bin',
            deniedIdentities: [],
            maxBytes: SAME_FD_FIXTURE_BYTES,
          });
          outcomes.push({ kind: 'read', bytes: read.bytes, identity: read.identity });
        } catch (error: unknown) {
          if (!(error instanceof OnboardingNativeError)) {
            throw error;
          }
          outcomes.push({ kind: 'rejected', error });
        }
      }
      for (let attempt = 0; attempt < SAME_FD_AUTHORITY_READ_ATTEMPTS; attempt += 1) {
        try {
          const read = directNativeReadResult(
            directBinding.secureReadBeneath({
              root,
              expectedRoot: rootIdentity,
              relativePath: 'same-fd-target.bin',
              expectedAuthority: firstIdentity,
              deniedIdentities: [],
              maxBytes: SAME_FD_FIXTURE_BYTES,
              readContent: true,
            }),
          );
          authorityOutcomes.push({ kind: 'read', bytes: read.bytes, identity: read.identity });
        } catch (error: unknown) {
          authorityOutcomes.push({ kind: 'rejected', code: directNativeErrorCode(error) });
        }
      }

      Atomics.store(worker.control, 0, PATH_REPLACEMENT_STOPPED);
      Atomics.notify(worker.control, 0);
      completion = parsePathReplacementCompletion(await done);
    } finally {
      await terminatePathReplacementWorker(worker.worker);
    }

    expect(completion).toBeDefined();
    expect(completion!.swaps).toBeGreaterThan(0);
    const expectedFixtures = new Map<string, readonly [Buffer, FileIdentity]>();
    expectedFixtures.set(identityKey(firstIdentity), [firstBytes, firstIdentity]);
    for (const { label, identity } of completion!.published) {
      expectedFixtures.set(identityKey(identity), [
        label === 'first' ? firstBytes : secondBytes,
        identity,
      ]);
    }
    const rejectedOutcomeCodes: string[] = [];
    let successfulReads = 0;
    for (const outcome of outcomes) {
      if (outcome.kind === 'rejected') {
        rejectedOutcomeCodes.push(outcome.error.code);
        continue;
      }

      successfulReads += 1;
      try {
        const expected = expectedFixtures.get(identityKey(outcome.identity));
        expect(expected).toBeDefined();
        expect(outcome.bytes.equals(expected![0])).toBe(true);
        expect(outcome.identity).toEqual(expected![1]);
      } finally {
        zeroizeBuffer(outcome.bytes);
      }
    }
    expect(rejectedOutcomeCodes.every((code) => code === 'SCG_NATIVE_PATH_DENIED')).toBe(true);
    expect(successfulReads).toBeGreaterThan(0);
    const authorityRejectionCodes: string[] = [];
    for (const outcome of authorityOutcomes) {
      if (outcome.kind === 'rejected') {
        authorityRejectionCodes.push(outcome.code);
        continue;
      }

      try {
        expect(outcome.bytes.equals(firstBytes)).toBe(true);
        expect(outcome.identity).toEqual(firstIdentity);
      } finally {
        zeroizeBuffer(outcome.bytes);
      }
    }
    expect(
      authorityRejectionCodes.every(
        (code) => code === 'SCG_NATIVE_IDENTITY_MISMATCH' || code === 'SCG_NATIVE_PATH_DENIED',
      ),
    ).toBe(true);
    expect(authorityRejectionCodes.length).toBeGreaterThan(0);
  });
  it('redacts fixture paths and credential material from identity, denial, and limit failures', async () => {
    const root = currentRoot();
    const pathCanary = 'absolute-fixture-path-canary';
    const credentialCanary = 'SCENE_GLASS_HOST_TOKEN=credential-material-canary';
    const fixturePath = join(root, pathCanary);
    await writeSecureFile(fixturePath, `${credentialCanary}\n`);
    const rootIdentity = await fileIdentity(root);
    const fixtureIdentity = await fileIdentity(fixturePath);

    const identityMismatch = await expectNativeError(() =>
      secureReadBeneath({
        root,
        expectedRoot: { device: rootIdentity.device, inode: incrementDecimal(rootIdentity.inode) },
        relativePath: pathCanary,
        deniedIdentities: [],
        maxBytes: 1024,
      }),
    );
    const denied = await expectNativeError(() =>
      secureReadBeneath({
        root,
        expectedRoot: rootIdentity,
        relativePath: pathCanary,
        deniedIdentities: [fixtureIdentity],
        maxBytes: 1024,
      }),
    );
    const limited = await expectNativeError(() =>
      secureReadBeneath({
        root,
        expectedRoot: rootIdentity,
        relativePath: pathCanary,
        deniedIdentities: [],
        maxBytes: Buffer.byteLength(`${credentialCanary}\n`) - 1,
      }),
    );

    expect([identityMismatch.code, denied.code, limited.code]).toEqual([
      'SCG_NATIVE_IDENTITY_MISMATCH',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_READ_LIMIT',
    ]);
    for (const error of [identityMismatch, denied, limited]) {
      assertNativeErrorRedacted(error, [root, fixturePath, pathCanary, credentialCanary]);
    }
  });
  it('rejects duplicate authority sets and missing selected projects', async () => {
    const root = currentRoot();
    const firstPath = join(root, 'first.env');
    const secondPath = join(root, 'second.env');
    await writeSecureFile(firstPath, credentialEnvelope('alpha', 'first'));
    await writeSecureFile(secondPath, credentialEnvelope('beta', 'second'));
    const first = await credentialAuthority('alpha', firstPath);
    const second = await credentialAuthority('beta', secondPath);

    const invalidSets = [
      {
        authorities: [first, { ...second, projectId: 'alpha' }],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [first, { ...second, path: first.path }],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [first, { ...first, projectId: 'gamma', path: second.path }],
        selectedProjectId: 'alpha',
      },
      {
        authorities: [first],
        selectedProjectId: 'missing',
      },
      {
        authorities: Array.from({ length: 65 }, () => first),
        selectedProjectId: 'alpha',
      },
    ];

    for (const invalid of invalidSets) {
      const error = await expectNativeError(() =>
        verifyCredentialAuthorities({ ...invalid, ...credentialOptions() }),
      );
      expect(error.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    }
  });

  it('issues only the immutable selected capability and zeroizes successful callbacks', async () => {
    const root = currentRoot();
    const selectedPath = join(root, 'selected.env');
    const deniedPath = join(root, 'denied.env');
    await writeSecureFile(selectedPath, credentialEnvelope('alpha', 'selected-canary'));
    await writeSecureFile(deniedPath, credentialEnvelope('beta', 'denied-canary'));
    const selected = await credentialAuthority('alpha', selectedPath);
    const denied = await credentialAuthority('beta', deniedPath);

    const verified = verifyCredentialAuthorities({
      authorities: [selected, denied],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    expect(verified.deniedIdentities).toEqual([
      { device: selected.device, inode: selected.inode },
      { device: denied.device, inode: denied.inode },
    ]);

    for (const authority of [selected, denied, { ...selected }]) {
      const error = await expectNativeError(() =>
        secureReadCredential(authority, credentialOptions()),
      );
      expect(error.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    }
    const forgedCapabilityError = await expectNativeError(() =>
      secureReadCredential(Object.freeze({}), credentialOptions()),
    );
    expect(forgedCapabilityError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');

    const forgedSelectionError = await expectNativeError(() =>
      withSelectedCredential({ ...verified } as typeof verified, () => 'forged'),
    );
    expect(forgedSelectionError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');

    let delivered: Buffer | undefined;
    const result = await withSelectedCredential(verified, async (credential) => {
      delivered = credential;
      return credential.toString('utf8');
    });
    expect(result).toBe(credentialEnvelope('alpha', 'selected-canary'));
    expect(delivered).toBeDefined();
    expect(delivered!.every((byte) => byte === 0)).toBe(true);
  });

  it('keeps issued capabilities bound to immutable authority facts after caller mutation', async () => {
    const root = currentRoot();
    const firstPath = join(root, 'first.env');
    const replacementPath = join(root, 'replacement.env');
    await writeSecureFile(firstPath, credentialEnvelope('alpha', 'first'));
    await writeSecureFile(replacementPath, credentialEnvelope('alpha', 'replacement'));
    const selected: {
      projectId: string;
      path: string;
      device: string;
      inode: string;
    } = { ...(await credentialAuthority('alpha', firstPath)) };

    const first = verifyCredentialAuthorities({
      authorities: [selected],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    const replacementIdentity = await fileIdentity(replacementPath);
    selected.path = replacementPath;
    selected.device = replacementIdentity.device;
    selected.inode = replacementIdentity.inode;

    const directCredential = secureReadCredential(first.capability, credentialOptions());
    try {
      expect(directCredential.toString('utf8')).toBe(credentialEnvelope('alpha', 'first'));
    } finally {
      zeroizeBuffer(directCredential);
    }
    await expect(
      withSelectedCredential(first, (credential) => credential.toString('utf8')),
    ).resolves.toBe(credentialEnvelope('alpha', 'first'));

    const reverified = verifyCredentialAuthorities({
      authorities: [selected],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    await expect(
      withSelectedCredential(first, (credential) => credential.toString('utf8')),
    ).resolves.toBe(credentialEnvelope('alpha', 'first'));
    await expect(
      withSelectedCredential(reverified, (credential) => credential.toString('utf8')),
    ).resolves.toBe(credentialEnvelope('alpha', 'replacement'));
  });
  it('rejects revoked or equivalently reissued capabilities before native credential reads', async () => {
    const credentialPath = join(currentRoot(), 'reentrant.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'reentrant'));
    const authority = await credentialAuthority('alpha', credentialPath);

    const revokedCapability = verifyCredentialAuthoritySet(
      [authority],
      'alpha',
      credentialOptions(),
    );
    revokeCredentialReadCapability(revokedCapability);
    const revokedError = await expectNativeError(() =>
      secureReadCredential(revokedCapability, credentialOptions()),
    );
    expect(revokedError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');

    const reissuedCapability = verifyCredentialAuthoritySet(
      [authority],
      'alpha',
      credentialOptions(),
    );
    let replacement: ReturnType<typeof verifyCredentialAuthoritySet> | undefined;
    const reissuingOptions = new Proxy(credentialOptions(), {
      get(target, property, receiver) {
        if (property === 'expectedOwnerUid' && replacement === undefined) {
          replacement = verifyCredentialAuthoritySet([authority], 'alpha', credentialOptions());
        }
        return Reflect.get(target, property, receiver);
      },
    });
    try {
      const reissuedError = await expectNativeError(() =>
        secureReadCredential(reissuedCapability, reissuingOptions),
      );
      expect(reissuedError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
      expect(replacement).toBeDefined();
    } finally {
      if (replacement !== undefined) {
        revokeCredentialReadCapability(replacement);
      }
    }
  });
  it('bounds exact credential DTO fields before capability state and authority-key creation', async () => {
    const credentialPath = join(currentRoot(), 'bounded-project.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'bounded'));
    const authority = await credentialAuthority('alpha', credentialPath);
    const oversizedProjectId = 'p'.repeat(129);
    const oversizedAuthorities: ReadonlyArray<readonly [CredentialAuthority, string]> = [
      [Object.freeze({ ...authority, projectId: oversizedProjectId }), oversizedProjectId],
      [Object.freeze({ ...authority, device: '1'.repeat(21) }), authority.projectId],
      [Object.freeze({ ...authority, inode: '1'.repeat(21) }), authority.projectId],
      [Object.freeze({ ...authority, device: '18446744073709551616' }), authority.projectId],
    ];

    for (const [oversizedAuthority, selectedProjectId] of oversizedAuthorities) {
      const error = await expectNativeError(() =>
        verifyCredentialAuthoritySet([oversizedAuthority], selectedProjectId, credentialOptions()),
      );
      expect(error.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    }
  });
  it('canonicalizes authority options and proxy accessors before issuance', async () => {
    const credentialPath = join(currentRoot(), 'proxy.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'proxy'));
    const authority = await credentialAuthority('alpha', credentialPath);
    const source = Object.freeze({ ...authority });
    const authorityReads = new Map<string, number>();
    const statefulAuthority = new Proxy(source, {
      get(target, property, receiver) {
        if (
          typeof property === 'string' &&
          ['projectId', 'path', 'device', 'inode'].includes(property)
        ) {
          const count = (authorityReads.get(property) ?? 0) + 1;
          authorityReads.set(property, count);
          if (count > 1) {
            throw new Error('authority accessor was read more than once');
          }
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const optionReads = new Map<string, number>();
    const statefulOptions = new Proxy(
      {
        authorities: [statefulAuthority],
        selectedProjectId: 'alpha',
        ...credentialOptions(),
      },
      {
        get(target, property, receiver) {
          if (
            typeof property === 'string' &&
            ['authorities', 'selectedProjectId', 'expectedOwnerUid', 'maxBytes'].includes(property)
          ) {
            const count = (optionReads.get(property) ?? 0) + 1;
            optionReads.set(property, count);
            if (count > 1) {
              throw new Error('credential option accessor was read more than once');
            }
          }
          return Reflect.get(target, property, receiver);
        },
      },
    );

    const verified = verifyCredentialAuthorities(statefulOptions);
    expect(Object.fromEntries(authorityReads)).toEqual({
      projectId: 1,
      path: 1,
      device: 1,
      inode: 1,
    });
    expect(Object.fromEntries(optionReads)).toEqual({
      authorities: 1,
      selectedProjectId: 1,
      expectedOwnerUid: 1,
      maxBytes: 1,
    });
    revokeCredentialReadCapability(verified.capability);
  });
  it('revokes a capability when an equivalent authority clone is reverified', async () => {
    const credentialPath = join(currentRoot(), 'clone.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'clone'));
    const authority = await credentialAuthority('alpha', credentialPath);
    const first = verifyCredentialAuthorities({
      authorities: [authority],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });
    const replacement = verifyCredentialAuthorities({
      authorities: [{ ...authority }],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    const staleError = await expectNativeError(() =>
      withSelectedCredential(first, (credential) => credential.toString('utf8')),
    );
    expect(staleError.code).toBe('SCG_CREDENTIAL_AUTHORITY_INVALID');
    await expect(
      withSelectedCredential(replacement, (credential) => credential.toString('utf8')),
    ).resolves.toBe(credentialEnvelope('alpha', 'clone'));
    revokeCredentialReadCapability(replacement.capability);
  });

  it('zeroizes credentials and preserves callback failures', async () => {
    const credentialPath = join(currentRoot(), 'credential.env');
    await writeSecureFile(credentialPath, credentialEnvelope('alpha', 'canary'));
    const authority = await credentialAuthority('alpha', credentialPath);
    const verified = verifyCredentialAuthorities({
      authorities: [authority],
      selectedProjectId: 'alpha',
      ...credentialOptions(),
    });

    const synchronousFailure = new Error('synchronous callback failure');
    let synchronouslyDelivered: Buffer | undefined;
    await expect(
      withSelectedCredential(verified, (credential) => {
        synchronouslyDelivered = credential;
        throw synchronousFailure;
      }),
    ).rejects.toBe(synchronousFailure);
    expect(synchronouslyDelivered).toBeDefined();
    expect(synchronouslyDelivered!.every((byte) => byte === 0)).toBe(true);

    const asynchronousFailure = new Error('asynchronous callback failure');
    let asynchronouslyDelivered: Buffer | undefined;
    await expect(
      withSelectedCredential(verified, async (credential) => {
        asynchronouslyDelivered = credential;
        throw asynchronousFailure;
      }),
    ).rejects.toBe(asynchronousFailure);
    expect(asynchronouslyDelivered).toBeDefined();
    expect(asynchronouslyDelivered!.every((byte) => byte === 0)).toBe(true);
  });
  it('uses the captured typed-array zeroizer when Buffer methods are overridden or detached', async () => {
    const overridden = Buffer.from('zeroize-canary', 'utf8');
    Object.defineProperty(overridden, 'fill', {
      configurable: true,
      value: () => {
        throw new Error('overridden Buffer.fill must not run');
      },
    });
    zeroizeBuffer(overridden);
    expect(overridden.every((byte) => byte === 0)).toBe(true);

    if (typeof structuredClone !== 'function') {
      return;
    }
    const backing = new ArrayBuffer(16);
    const detached = Buffer.from(backing);
    try {
      structuredClone(backing, { transfer: [backing] });
    } catch {
      return;
    }
    if (detached.buffer.byteLength !== 0) {
      return;
    }
    const error = await expectNativeError(() => zeroizeBuffer(detached));
    expect(error.code).toBe('SCG_NATIVE_FAILURE');
    assertNativeErrorRedacted(error, ['zeroize-canary']);
  });

  it('closes descriptors across repeated reads', async () => {
    const root = currentRoot();
    await writeSecureFile(join(root, 'content.txt'), 'fd check');
    const before = await descriptorCount();

    for (let index = 0; index < 64; index += 1) {
      const read = await secureRead(root, 'content.txt');
      zeroizeBuffer(read.bytes);
    }

    const after = await descriptorCount();
    expect(after).toBeLessThanOrEqual(before + 2);
  });
  it('reopens retained native Vite cache authority, bounds nested scans, and closes handles', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    let watcher: { readonly close: () => Promise<void> | void } | undefined;
    try {
      const nested = join(fixture.rootPath, 'nested');
      const nestedEntry = join(nested, 'cache-entry.bin');
      await mkdir(nested, { mode: VITE_CACHE_DIRECTORY_MODE });
      await chmod(nested, VITE_CACHE_DIRECTORY_MODE);
      await writeSecureFile(nestedEntry, 'cache entry');

      const tree = await port.scanCacheTree({
        session: session.nativeSession,
        provenance: session.provenance,
        limits: viteCacheLimits({ maxEntries: 3, maxFiles: 1, maxBytes: 1_024, maxDepth: 2 }),
      });
      expect(tree.rootIdentity).toEqual(fixture.provenance.root.identity);
      expect(tree.entries.map((entry) => [entry.kind, entry.depth])).toEqual([
        ['directory', 0],
        ['directory', 1],
        ['regular-file', 2],
      ]);
      expect(tree.entries.every((entry) => entry.escaped === false)).toBe(true);
      assertViteCacheEvidenceRedacted(tree, [
        fixture.parentPath,
        fixture.rootPath,
        'nested',
        'cache-entry.bin',
      ]);

      const genericEvent = deferred<void>();
      const events: string[] = [];
      let failures = 0;
      watcher = await port.watchCacheTree({
        session: session.nativeSession,
        provenance: session.provenance,
        onEvent: (event) => {
          events.push(event);
          genericEvent.resolve(undefined);
        },
        onFailure: () => {
          failures += 1;
        },
      });
      await writeSecureFile(join(fixture.rootPath, 'watch-change.bin'), 'changed');
      await waitForDeadline(
        genericEvent.promise,
        VITE_CACHE_WATCH_DEADLINE_MS,
        'Vite cache watcher event',
      );
      expect(events).toEqual(['changed']);
      expect(failures).toBe(0);

      await watcher.close();
      await watcher.close();
      const eventsBeforeClosedWrite = events.length;
      await writeSecureFile(join(fixture.rootPath, 'closed-watch.bin'), 'closed');
      await sleep(250);
      expect(events).toHaveLength(eventsBeforeClosedWrite);

      await port.closeCacheSession({ session: session.nativeSession });
      await port.closeCacheSession({ session: session.nativeSession });
      await expectNativeViteCacheFailure(() =>
        port.scanCacheTree({
          session: session.nativeSession,
          provenance: session.provenance,
          limits: viteCacheLimits(),
        }),
      );
      await expectNativeViteCacheFailure(() =>
        port.watchCacheTree({
          session: session.nativeSession,
          provenance: session.provenance,
          onEvent: () => undefined,
          onFailure: () => undefined,
        }),
      );
    } finally {
      if (watcher !== undefined) {
        await watcher.close();
      }
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });
  it('closes a watcher and reports failure when an event callback throws', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    let watcher: { readonly close: () => Promise<void> | void } | undefined;
    try {
      const failure = deferred<void>();
      let events = 0;
      let failures = 0;
      watcher = await port.watchCacheTree({
        session: session.nativeSession,
        provenance: session.provenance,
        onEvent: () => {
          events += 1;
          throw new Error('watch callback failure');
        },
        onFailure: () => {
          failures += 1;
          failure.resolve(undefined);
        },
      });
      await writeSecureFile(join(fixture.rootPath, 'watch-callback-failure.bin'), 'changed');
      await waitForDeadline(failure.promise, VITE_CACHE_WATCH_DEADLINE_MS, 'Vite watcher failure');
      expect(events).toBe(1);
      expect(failures).toBe(1);
      await watcher.close();
    } finally {
      if (watcher !== undefined) {
        await watcher.close();
      }
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });
  it('bounds watcher handles across sessions until asynchronous close completion and supports reopen churn', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const firstSession = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    const secondSession = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    const watchers: Array<{ readonly close: () => Promise<void> | void }> = [];
    try {
      for (let index = 0; index < 8; index += 1) {
        const session = index % 2 === 0 ? firstSession : secondSession;
        watchers.push(
          await port.watchCacheTree({
            session: session.nativeSession,
            provenance: session.provenance,
            onEvent: () => undefined,
            onFailure: () => undefined,
          }),
        );
      }
      await expectNativeViteCacheFailure(() =>
        port.watchCacheTree({
          session: firstSession.nativeSession,
          provenance: firstSession.provenance,
          onEvent: () => undefined,
          onFailure: () => undefined,
        }),
      );
      expect(watchers).toHaveLength(8);

      await Promise.all(watchers.map(async (watcher) => watcher.close()));
      await expectNativeViteCacheFailure(() =>
        port.watchCacheTree({
          session: secondSession.nativeSession,
          provenance: secondSession.provenance,
          onEvent: () => undefined,
          onFailure: () => undefined,
        }),
      );

      for (let iteration = 0; iteration < 3; iteration += 1) {
        await sleep(25);
        const watcher = await port.watchCacheTree({
          session: secondSession.nativeSession,
          provenance: secondSession.provenance,
          onEvent: () => undefined,
          onFailure: () => undefined,
        });
        await watcher.close();
      }
      await sleep(25);
    } finally {
      for (const watcher of watchers) {
        await watcher.close();
      }
      await port.closeCacheSession({ session: firstSession.nativeSession });
      await port.closeCacheSession({ session: secondSession.nativeSession });
    }
  });
  it('bounds cache session handles and releases a slot only after a successful native close', async () => {
    const fixture = await createNativeViteCacheFixture('session-cap');
    const port = createNativeViteCacheRuntimePort();
    const sessions: CacheNativeSession[] = [];
    try {
      for (let index = 0; index < MAX_ACTIVE_VITE_CACHE_SESSIONS; index += 1) {
        sessions.push(
          (await port.openCacheSession({ provenance: fixture.provenance })).nativeSession,
        );
      }
      const capError = await expectNativeViteCacheFailure(() =>
        port.openCacheSession({ provenance: fixture.provenance }),
      );
      expect(capError.code).toBe('SCG_NATIVE_FAILURE');

      const released = sessions.pop();
      if (released === undefined) {
        throw new Error('Native Vite cache session cap did not allocate a releasable session.');
      }
      await port.closeCacheSession({ session: released });
      sessions.push(
        (await port.openCacheSession({ provenance: fixture.provenance })).nativeSession,
      );
    } finally {
      await Promise.all(sessions.map(async (session) => port.closeCacheSession({ session })));
    }
  });

  it('fails closed when persisted Vite cache identity, ownership, device, path, or mode facts differ, including root linkage replacement', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const mismatches: ReadonlyArray<readonly [string, ViteCacheProvenance]> = [
      ['root identity', withViteCacheRootIdentityMismatch(fixture.provenance)],
      ['parent identity', withViteCacheParentIdentityMismatch(fixture.provenance)],
      ['uid', withViteCacheOwnerMismatch(fixture.provenance, 'uid')],
      ['gid', withViteCacheOwnerMismatch(fixture.provenance, 'gid')],
      ['device', withViteCacheDeviceMismatch(fixture.provenance)],
      ['canonical root path', withViteCacheRootPathMismatch(fixture.provenance)],
      ['canonical parent path', withViteCacheParentPathMismatch(fixture.provenance)],
    ];

    const failureCodes: string[] = [];
    for (const [label, provenance] of mismatches) {
      const error = await expectNativeError(() =>
        reopenViteCacheSession({ filesystem: port, provenance }),
      );
      failureCodes.push(error.code);
      assertNativeErrorRedacted(error, [label, fixture.parentPath, fixture.rootPath]);
    }

    await chmod(fixture.rootPath, 0o750);
    try {
      failureCodes.push(
        (
          await expectNativeError(() =>
            reopenViteCacheSession({ filesystem: port, provenance: fixture.provenance }),
          )
        ).code,
      );
    } finally {
      await chmod(fixture.rootPath, VITE_CACHE_DIRECTORY_MODE);
    }

    await chmod(fixture.parentPath, 0o750);
    try {
      failureCodes.push(
        (
          await expectNativeError(() =>
            reopenViteCacheSession({ filesystem: port, provenance: fixture.provenance }),
          )
        ).code,
      );
    } finally {
      await chmod(fixture.parentPath, VITE_CACHE_DIRECTORY_MODE);
    }

    const replacedRootPath = join(fixture.parentPath, 'replaced-native-vite-cache');
    await rename(fixture.rootPath, replacedRootPath);
    await mkdir(fixture.rootPath, { mode: VITE_CACHE_DIRECTORY_MODE });
    await chmod(fixture.rootPath, VITE_CACHE_DIRECTORY_MODE);
    failureCodes.push(
      (
        await expectNativeError(() =>
          reopenViteCacheSession({ filesystem: port, provenance: fixture.provenance }),
        )
      ).code,
    );
    expect(failureCodes).toEqual([
      ...mismatches.map(() => 'SCG_NATIVE_PATH_DENIED'),
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
      'SCG_NATIVE_PATH_DENIED',
    ]);
  });

  it('reports unsafe Vite traversal metadata without paths and fails canary reads closed', async () => {
    const fixture = await createNativeViteCacheFixture();
    const sourcePath = join(fixture.rootPath, 'unsafe-source.bin');
    const hardLinkPath = join(fixture.rootPath, 'unsafe-hard-link.bin');
    const symlinkPath = join(fixture.rootPath, 'unsafe-symlink.bin');
    const widenedPath = join(fixture.rootPath, 'unsafe-mode.bin');
    const fifoPath = join(fixture.rootPath, 'unsafe-fifo');
    const socketPath = join(fixture.rootPath, 'unsafe-socket');
    await writeSecureFile(sourcePath, 'unsafe source');
    await link(sourcePath, hardLinkPath);
    await symlink('unsafe-source.bin', symlinkPath);
    await writeSecureFile(widenedPath, 'unsafe mode');
    await chmod(widenedPath, 0o640);
    const fifoCreated = await createFifoIfSupported(fifoPath);
    const socket = await createUnixSocketIfSupported(socketPath);

    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    try {
      const tree = await port.scanCacheTree({
        session: session.nativeSession,
        provenance: session.provenance,
        limits: viteCacheLimits({ maxEntries: 32, maxFiles: 8, maxBytes: 4_096, maxDepth: 2 }),
      });
      const reportedEntryKinds = tree.entries.map((entry) => entry.kind);
      const requiredSpecialEntryKinds = [
        ...(fifoCreated ? ['fifo'] : []),
        ...(socket === undefined ? [] : ['socket']),
      ];
      expect(tree.entries.some((entry) => entry.kind === 'symlink')).toBe(true);
      expect(
        tree.entries.filter((entry) => entry.kind === 'regular-file' && entry.linkCount === 2)
          .length,
      ).toBeGreaterThanOrEqual(2);
      expect(tree.entries.some((entry) => entry.mode === 0o640)).toBe(true);
      expect(reportedEntryKinds).toEqual(expect.arrayContaining(requiredSpecialEntryKinds));
      assertViteCacheEvidenceRedacted(tree, [
        fixture.parentPath,
        fixture.rootPath,
        'unsafe-source.bin',
        'unsafe-hard-link.bin',
        'unsafe-symlink.bin',
        'unsafe-mode.bin',
        'unsafe-fifo',
        'unsafe-socket',
      ]);

      const error = await expectNativeViteCacheFailure(() =>
        port.scanCacheCanaries({
          session: session.nativeSession,
          provenance: session.provenance,
          trigger: 'failure',
          limits: viteCacheLimits({ maxEntries: 32, maxFiles: 8, maxBytes: 4_096, maxDepth: 2 }),
          tokenHashes: [createHash('sha256').update('safe-canary').digest('hex')],
        }),
      );
      assertNativeErrorRedacted(error, [
        fixture.parentPath,
        fixture.rootPath,
        'unsafe-source.bin',
        'unsafe-hard-link.bin',
        'unsafe-symlink.bin',
        'unsafe-mode.bin',
        'unsafe-fifo',
        'unsafe-socket',
      ]);
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
      await closeUnixSocket(socket);
    }
  });

  it.skipIf(!canExerciseForeignCacheOwnerFixture)(
    'fails canary scans closed for a wrong-owned Vite cache entry when the fixture is supported',
    async () => {
      const fixture = await createNativeViteCacheFixture();
      const foreignOwnedPath = join(fixture.rootPath, 'foreign-owner.bin');
      await writeSecureFile(foreignOwnedPath, 'foreign owner');
      const foreignUid = differentUint32(fixture.provenance.root.owner.uid);
      await chown(foreignOwnedPath, foreignUid, fixture.provenance.root.owner.gid);

      const port = createNativeViteCacheRuntimePort();
      const session = await reopenViteCacheSession({
        filesystem: port,
        provenance: fixture.provenance,
      });
      try {
        const tree = await port.scanCacheTree({
          session: session.nativeSession,
          provenance: session.provenance,
          limits: viteCacheLimits(),
        });
        expect(tree.entries.some((entry) => entry.owner.uid === foreignUid)).toBe(true);
        await expectNativeViteCacheFailure(() =>
          port.scanCacheCanaries({
            session: session.nativeSession,
            provenance: session.provenance,
            trigger: 'failure',
            limits: viteCacheLimits(),
            tokenHashes: [createHash('sha256').update('safe-canary').digest('hex')],
          }),
        );
      } finally {
        await port.closeCacheSession({ session: session.nativeSession });
      }
    },
  );
  it('fails closed for ACL-bearing Vite cache parent, root, and entries when supported', async () => {
    expect(typeof process.geteuid).toBe('function');
    const entryFixture = await createNativeViteCacheFixture('acl-entry');
    const entryPath = join(entryFixture.rootPath, 'acl-entry.bin');
    await writeSecureFile(entryPath, 'acl entry');
    if (!(await addUnsafeAcl(entryPath))) {
      return;
    }

    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: entryFixture.provenance,
    });
    try {
      await expectNativeViteCacheFailure(() =>
        port.scanCacheCanaries({
          session: session.nativeSession,
          provenance: session.provenance,
          trigger: 'failure',
          limits: viteCacheLimits(),
          tokenHashes: [createHash('sha256').update('safe-canary').digest('hex')],
        }),
      );
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
    }

    const rootFixture = await createNativeViteCacheFixture('acl-root');
    if (await addUnsafeAcl(rootFixture.rootPath)) {
      const error = await expectNativeError(() =>
        reopenViteCacheSession({ filesystem: port, provenance: rootFixture.provenance }),
      );
      assertNativeErrorCode(error, 'SCG_NATIVE_PATH_DENIED');
      assertNativeErrorRedacted(error, [rootFixture.parentPath, rootFixture.rootPath]);
    }

    const parentFixture = await createNativeViteCacheFixture('acl-parent');
    if (await addUnsafeAcl(parentFixture.parentPath)) {
      const error = await expectNativeError(() =>
        reopenViteCacheSession({ filesystem: port, provenance: parentFixture.provenance }),
      );
      assertNativeErrorCode(error, 'SCG_NATIVE_PATH_DENIED');
      assertNativeErrorRedacted(error, [parentFixture.parentPath, parentFixture.rootPath]);
    }
  });
  it('fails closed for ACL-bearing recovery directories, locks, and manifests when supported', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native recovery authority requires a POSIX effective uid.');
    }
    const port = createNativeViteRecoveryDirectoryPort();
    const ownerUid = process.geteuid();
    const createRecoveryState = async (name: string) => {
      const projectRoot = join(currentRoot(), name);
      const sceneGlassRoot = join(projectRoot, '.scg');
      const runtimeRoot = join(sceneGlassRoot, 'runtime');
      const stateRoot = join(runtimeRoot, 'vite-cache');
      await mkdir(stateRoot, { recursive: true, mode: 0o700 });
      await Promise.all([
        chmod(projectRoot, 0o700),
        chmod(sceneGlassRoot, 0o700),
        chmod(runtimeRoot, 0o700),
        chmod(stateRoot, 0o700),
      ]);
      return {
        projectRoot,
        expectedProjectRootIdentity: await fileIdentity(projectRoot),
        stateRoot,
        expectedStateRootIdentity: await fileIdentity(stateRoot),
        expectedOwnerUid: ownerUid,
      };
    };
    const identityMismatch = await createRecoveryState('recovery-identity-mismatch');
    const identityError = await expectNativeError(() =>
      port.openDirectory({
        ...identityMismatch,
        expectedProjectRootIdentity: {
          ...identityMismatch.expectedProjectRootIdentity,
          inode: '0',
        },
      }),
    );
    assertNativeErrorCode(identityError, 'SCG_NATIVE_PATH_DENIED');

    const unsafeDirectory = await createRecoveryState('recovery-acl-directory');
    if (!(await addUnsafeAcl(unsafeDirectory.stateRoot))) {
      return;
    }
    const directoryError = await expectNativeError(() => port.openDirectory(unsafeDirectory));
    assertNativeErrorCode(directoryError, 'SCG_NATIVE_PATH_DENIED');
    const unsafeSceneDirectory = await createRecoveryState('recovery-acl-scene');
    expect(await addUnsafeAcl(join(unsafeSceneDirectory.projectRoot, '.scg'))).toBe(true);
    const sceneDirectoryError = await expectNativeError(() =>
      port.openDirectory(unsafeSceneDirectory),
    );
    assertNativeErrorCode(sceneDirectoryError, 'SCG_NATIVE_PATH_DENIED');

    const unsafeLockDirectory = await createRecoveryState('recovery-acl-lock');
    const lockSession = port.openDirectory(unsafeLockDirectory);
    const lockName = 'recovery-acl-lock.recovery.v1.lock';
    try {
      expect(port.tryLock({ session: lockSession, lockName })).toBe(true);
      const childAuthority = port.createChildAuthority({
        session: lockSession,
        launchId: '12345678-1234-4abc-8def-123456789abc',
      });
      expect(childAuthority).toEqual({
        fd: expect.any(Number),
        launchId: '12345678-1234-4abc-8def-123456789abc',
      });
      expect(childAuthority.fd).toBeGreaterThanOrEqual(0);
      port.closeChildAuthority({ fd: childAuthority.fd });
      if (await addUnsafeAcl(join(unsafeLockDirectory.stateRoot, lockName))) {
        const lockError = await expectNativeError(() =>
          port.readManifest({
            session: lockSession,
            manifestName: 'recovery-acl-lock.recovery.v1.json',
          }),
        );
        assertNativeErrorCode(lockError, 'SCG_NATIVE_PATH_DENIED');
      }
    } finally {
      port.closeDirectory({ session: lockSession });
    }

    const unsafeManifestDirectory = await createRecoveryState('recovery-acl-manifest');
    const manifestSession = port.openDirectory(unsafeManifestDirectory);
    const manifestName = 'recovery-acl-manifest.recovery.v1.json';
    try {
      expect(
        port.tryLock({
          session: manifestSession,
          lockName: 'recovery-acl-manifest.recovery.v1.lock',
        }),
      ).toBe(true);
      await writeSecureFile(
        join(unsafeManifestDirectory.stateRoot, manifestName),
        '{"version":1}\n',
      );
      if (await addUnsafeAcl(join(unsafeManifestDirectory.stateRoot, manifestName))) {
        const manifestError = await expectNativeError(() =>
          port.readManifest({ session: manifestSession, manifestName }),
        );
        assertNativeErrorCode(manifestError, 'SCG_NATIVE_PATH_DENIED');
      }
    } finally {
      port.closeDirectory({ session: manifestSession });
    }
  });
  it('bounds recovery sessions and child authorities, then releases only closed slots', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native recovery authority requires a POSIX effective uid.');
    }
    const port = createNativeViteRecoveryDirectoryPort();
    const ownerUid = process.geteuid();
    const sessions: Array<{
      readonly session: ReturnType<typeof port.openDirectory>;
      readonly lockName: string;
    }> = [];
    const childAuthorities: Array<{ readonly fd: number; readonly launchId: string }> = [];
    const createState = async (index: number) => {
      const projectRoot = join(currentRoot(), `recovery-cap-${index}`);
      const stateRoot = join(projectRoot, '.scg', 'runtime', 'vite-cache');
      await mkdir(stateRoot, { recursive: true, mode: 0o700 });
      await Promise.all([
        chmod(projectRoot, 0o700),
        chmod(join(projectRoot, '.scg'), 0o700),
        chmod(join(projectRoot, '.scg', 'runtime'), 0o700),
        chmod(stateRoot, 0o700),
      ]);
      return {
        projectRoot,
        expectedProjectRootIdentity: await fileIdentity(projectRoot),
        stateRoot,
        expectedStateRootIdentity: await fileIdentity(stateRoot),
        expectedOwnerUid: ownerUid,
      };
    };
    const launchId = (index: number): string =>
      `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;

    try {
      for (let index = 0; index < MAX_ACTIVE_VITE_RECOVERY_DIRECTORY_SESSIONS; index += 1) {
        const session = port.openDirectory(await createState(index));
        const lockName = `recovery-cap-${index}.recovery.v1.lock`;
        expect(port.tryLock({ session, lockName })).toBe(true);
        sessions.push({ session, lockName });
      }

      const overCapState = await createState(MAX_ACTIVE_VITE_RECOVERY_DIRECTORY_SESSIONS);
      const sessionCapError = await expectNativeError(() => port.openDirectory(overCapState));
      assertNativeErrorCode(sessionCapError, 'SCG_NATIVE_FAILURE');

      for (let index = 0; index < MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES; index += 1) {
        childAuthorities.push(
          port.createChildAuthority({
            session: sessions[index]!.session,
            launchId: launchId(index),
          }),
        );
      }

      const childCapError = await expectNativeError(() =>
        port.createChildAuthority({
          session: sessions[MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES]!.session,
          launchId: launchId(MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES),
        }),
      );
      assertNativeErrorCode(childCapError, 'SCG_NATIVE_FAILURE');

      const released = childAuthorities.shift();
      if (released === undefined) {
        throw new Error('Native recovery child authority cap did not allocate a releasable child.');
      }
      port.closeChildAuthority({ fd: released.fd });
      childAuthorities.push(
        port.createChildAuthority({
          session: sessions[MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES]!.session,
          launchId: launchId(MAX_ACTIVE_VITE_RECOVERY_CHILD_AUTHORITIES + 1),
        }),
      );
    } finally {
      for (const childAuthority of childAuthorities) {
        port.closeChildAuthority({ fd: childAuthority.fd });
      }
      for (const { session } of sessions) {
        port.closeDirectory({ session });
      }
    }
  });
  it('denies recovery operations after canonical ancestor replacement', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native recovery authority requires a POSIX effective uid.');
    }
    const fixtureRoot = currentRoot();
    const ancestor = join(fixtureRoot, 'recovery-ancestor');
    const projectRoot = join(ancestor, 'project');
    const stateRoot = join(projectRoot, '.scg', 'runtime', 'vite-cache');
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await Promise.all([
      chmod(ancestor, 0o700),
      chmod(projectRoot, 0o700),
      chmod(join(projectRoot, '.scg'), 0o700),
      chmod(join(projectRoot, '.scg', 'runtime'), 0o700),
      chmod(stateRoot, 0o700),
    ]);
    const port = createNativeViteRecoveryDirectoryPort();
    const session = port.openDirectory({
      projectRoot,
      expectedProjectRootIdentity: await fileIdentity(projectRoot),
      stateRoot,
      expectedStateRootIdentity: await fileIdentity(stateRoot),
      expectedOwnerUid: process.geteuid(),
    });
    const movedAncestor = join(fixtureRoot, 'recovery-ancestor-retained');
    await rename(ancestor, movedAncestor);
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await Promise.all([
      chmod(ancestor, 0o700),
      chmod(projectRoot, 0o700),
      chmod(join(projectRoot, '.scg'), 0o700),
      chmod(join(projectRoot, '.scg', 'runtime'), 0o700),
      chmod(stateRoot, 0o700),
    ]);
    try {
      const error = await expectNativeError(() =>
        port.tryLock({ session, lockName: 'ancestor.recovery.v1.lock' }),
      );
      assertNativeErrorCode(error, 'SCG_NATIVE_PATH_DENIED');
      expect((await stat(join(movedAncestor, 'project'))).isDirectory()).toBe(true);
    } finally {
      port.closeDirectory({ session });
    }
  });
  it('retains recovery session state when a child-authority finalizer cannot close its handle', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native recovery authority requires a POSIX effective uid.');
    }
    const projectRoot = join(currentRoot(), 'recovery-finalizer-close-failure');
    const stateRoot = join(projectRoot, '.scg', 'runtime', 'vite-cache');
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await Promise.all([
      chmod(projectRoot, 0o700),
      chmod(join(projectRoot, '.scg'), 0o700),
      chmod(join(projectRoot, '.scg', 'runtime'), 0o700),
      chmod(stateRoot, 0o700),
    ]);
    const input = {
      projectRoot,
      expectedProjectRootIdentity: await fileIdentity(projectRoot),
      stateRoot,
      expectedStateRootIdentity: await fileIdentity(stateRoot),
      expectedOwnerUid: process.geteuid(),
    };
    const bindingPath = directNativeRequire.resolve(
      '../../packages/onboarding/build/Release/secure_read.node',
    );
    const script = `
const { closeSync, openSync } = require('node:fs');
const binding = require(process.env.SCG_NATIVE_BINDING_PATH);
const input = JSON.parse(process.env.SCG_RECOVERY_FINALIZER_INPUT);
function createFinalizingSession() {
  const session = binding.openViteRecoveryDirectorySession(input);
  if (!binding.tryLockViteRecoveryDirectorySession({
    session,
    lockName: 'finalizer.recovery.v1.lock',
  })) {
    throw new Error('Recovery lock was not acquired.');
  }
  const child = binding.createViteRecoveryChildAuthority({
    session,
    launchId: '12345678-1234-4abc-8def-123456789abc',
  });
  return { child, reference: new WeakRef(session) };
}
(async () => {
  const { child, reference } = createFinalizingSession();
  closeSync(child.fd);
  let finalized = false;
  for (let index = 0; index < 32; index += 1) {
    global.gc();
    await new Promise((resolve) => setImmediate(resolve));
    if (reference.deref() === undefined) {
      finalized = true;
      break;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  if (!finalized) {
    throw new Error('Recovery session finalizer did not run.');
  }
  const reopened = openSync(input.stateRoot, 'r');
  if (reopened !== child.fd) {
    throw new Error('Child descriptor slot was not deterministically reused.');
  }
  binding.closeViteRecoveryChildAuthority({ fd: child.fd });
  console.log('retained');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`;
    await expect(
      execFileAsync(process.execPath, ['--expose-gc', '--eval', script], {
        env: {
          ...process.env,
          SCG_NATIVE_BINDING_PATH: bindingPath,
          SCG_RECOVERY_FINALIZER_INPUT: JSON.stringify(input),
        },
      }),
    ).resolves.toMatchObject({ stdout: expect.stringContaining('retained') });
  });
  it('keeps retained snapshot finalizers inside their owner Worker environment', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native Vite snapshot authority requires a POSIX effective uid.');
    }
    const projectRoot = join(currentRoot(), 'snapshot-finalizer-worker-environment');
    await mkdir(projectRoot, { recursive: true, mode: 0o700 });
    await chmod(projectRoot, 0o700);
    const input = {
      projectRoot,
      approvedRootIdentity: await fileIdentity(projectRoot),
      expectedOwnerUid: process.geteuid(),
    };
    const bindingPath = directNativeRequire.resolve(
      '../../packages/onboarding/build/Release/secure_read.node',
    );
    const ownerSource = `
const { chmodSync } = require('node:fs');
const { join } = require('node:path');
const { parentPort } = require('node:worker_threads');
const binding = require(process.env.SCG_NATIVE_BINDING_PATH);
const input = JSON.parse(process.env.SCG_SNAPSHOT_FINALIZER_INPUT);

function retainStagingFinalizer() {
  const session = binding.openViteSnapshotSession(input);
  const staging = binding.createViteSnapshotStaging({
    session,
    approvedRootIdentity: input.approvedRootIdentity,
    installId: 'owner-retained',
    stagingName: 'owner-retained-stage',
  });
  chmodSync(
    join(input.projectRoot, '.scg', 'runtime', 'vite-staging', 'owner-retained-stage'),
    0o000,
  );
  return new WeakRef(staging);
}

(async () => {
  const reference = retainStagingFinalizer();
  for (let index = 0; index < 64; index += 1) {
    global.gc();
    await new Promise((resolve) => setImmediate(resolve));
    if (reference.deref() === undefined) {
      await new Promise((resolve) => setImmediate(resolve));
      parentPort.postMessage({ type: 'retained' });
      return;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('Snapshot staging finalizer did not run.');
})().catch((error) => {
  parentPort.postMessage({ type: 'error', phase: 'owner', detail: String(error) });
});
parentPort.on('message', () => {});
`;
    const observerSource = `
const { parentPort, workerData } = require('node:worker_threads');
const binding = require(process.env.SCG_NATIVE_BINDING_PATH);
const input = JSON.parse(process.env.SCG_SNAPSHOT_FINALIZER_INPUT);

try {
  const sessions = [];
  const stagings = [];
  let failureCode;
  for (let index = 0; index < workerData.sessionCount; index += 1) {
    sessions.push(binding.openViteSnapshotSession(input));
  }
  try {
    for (let index = 0; index < workerData.maximum; index += 1) {
      const installId = 'observer-' + index;
      try {
        stagings.push(binding.createViteSnapshotStaging({
          session: sessions[0],
          approvedRootIdentity: input.approvedRootIdentity,
          installId,
          stagingName: installId + '-stage',
        }));
      } catch (error) {
        failureCode = error && typeof error === 'object' ? error.code : undefined;
        break;
      }
    }
    const expectedFailure =
      workerData.expected === workerData.maximum ? undefined : 'SCG_NATIVE_FAILURE';
    if (stagings.length !== workerData.expected || failureCode !== expectedFailure) {
      throw new Error(
        'Snapshot finalizer capacity was not environment-scoped: ' +
          JSON.stringify({
            actual: stagings.length,
            expected: workerData.expected,
            failureCode,
            expectedFailure,
          }),
      );
    }
  } finally {
    for (const staging of stagings) {
      binding.discardViteSnapshotStaging({ staging });
    }
    for (const session of sessions) {
      binding.closeViteSnapshotSession({ session });
    }
  }
  parentPort.postMessage({ type: 'capacity', count: stagings.length });
} catch (error) {
  parentPort.postMessage({ type: 'error', phase: 'observer', detail: String(error) });
}
`;
    const script = `
const { chmodSync } = require('node:fs');
const { join } = require('node:path');
const { Worker } = require('node:worker_threads');

function waitForMessage(worker, type) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      worker.off('message', onMessage);
      worker.off('error', onError);
      worker.off('exit', onExit);
    };
    const onMessage = (message) => {
      if (message && message.type === type) {
        cleanup();
        resolve(message);
        return;
      }
      if (message && message.type === 'error') {
        cleanup();
        reject(
          new Error(
            'Worker native operation failed: ' +
              JSON.stringify({ phase: message.phase, detail: message.detail }),
          ),
        );
      }
    };
    const onError = () => {
      cleanup();
      reject(new Error('Worker native operation failed.'));
    };
    const onExit = () => {
      cleanup();
      reject(new Error('Worker exited before completing its native operation.'));
    };
    worker.on('message', onMessage);
    worker.once('error', onError);
    worker.once('exit', onExit);
  });
}

async function terminate(worker) {
  if (worker !== undefined) {
    await worker.terminate();
  }
}

(async () => {
  let owner;
  let firstObserver;
  let recoveredObserver;
  try {
    owner = new Worker(${JSON.stringify(ownerSource)}, { eval: true });
    await waitForMessage(owner, 'retained');
    chmodSync(
      join(
        JSON.parse(process.env.SCG_SNAPSHOT_FINALIZER_INPUT).projectRoot,
        '.scg',
        'runtime',
        'vite-staging',
        'owner-retained-stage',
      ),
      0o700,
    );

    firstObserver = new Worker(${JSON.stringify(observerSource)}, {
      eval: true,
      workerData: {
        maximum: Number(process.env.SCG_SNAPSHOT_FINALIZER_STAGING_CAP),
        expected: Number(process.env.SCG_SNAPSHOT_FINALIZER_STAGING_CAP) - 1,
        sessionCount: 1,
      },
    });
    await waitForMessage(firstObserver, 'capacity');
    await terminate(firstObserver);
    firstObserver = undefined;

    await terminate(owner);
    owner = undefined;

    recoveredObserver = new Worker(${JSON.stringify(observerSource)}, {
      eval: true,
      workerData: {
        maximum: Number(process.env.SCG_SNAPSHOT_FINALIZER_STAGING_CAP),
        expected: Number(process.env.SCG_SNAPSHOT_FINALIZER_STAGING_CAP),
        sessionCount: Number(process.env.SCG_SNAPSHOT_FINALIZER_SESSION_CAP),
      },
    });
    await waitForMessage(recoveredObserver, 'capacity');
    await terminate(recoveredObserver);
    recoveredObserver = undefined;
    console.log('environment-scoped');
  } finally {
    await terminate(recoveredObserver);
    await terminate(firstObserver);
    await terminate(owner);
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`;
    await expect(
      execFileAsync(process.execPath, ['--expose-gc', '--eval', script], {
        env: {
          ...process.env,
          SCG_NATIVE_BINDING_PATH: bindingPath,
          SCG_SNAPSHOT_FINALIZER_INPUT: JSON.stringify(input),
          SCG_SNAPSHOT_FINALIZER_SESSION_CAP: String(MAX_ACTIVE_VITE_SNAPSHOT_SESSIONS),
          SCG_SNAPSHOT_FINALIZER_STAGING_CAP: String(MAX_ACTIVE_VITE_SNAPSHOT_STAGINGS),
        },
      }),
    ).resolves.toMatchObject({ stdout: expect.stringContaining('environment-scoped') });
  });
  it('rejects forged managed-Vite child descriptors and releases the issued inherited descriptor', async () => {
    if (typeof process.geteuid !== 'function') {
      throw new Error('Native managed-Vite child authority requires a POSIX effective uid.');
    }
    const ownerUid = process.geteuid();
    const projectRoot = join(currentRoot(), 'managed-vite-child');
    const sceneGlassRoot = join(projectRoot, '.scg');
    const runtimeRoot = join(sceneGlassRoot, 'runtime');
    const stateRoot = join(runtimeRoot, 'vite-cache');
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await Promise.all([
      chmod(projectRoot, 0o700),
      chmod(sceneGlassRoot, 0o700),
      chmod(runtimeRoot, 0o700),
      chmod(stateRoot, 0o700),
    ]);
    const expectedStateRootIdentity = await fileIdentity(stateRoot);
    const expectedProjectRootIdentity = await fileIdentity(projectRoot);
    const verifyInput = {
      launchId: '12345678-1234-4abc-8def-123456789abc',
      installId: 'managed-child',
      expectedStateRootIdentity,
      expectedOwnerUid: ownerUid,
    };

    const forgedDirectory = await open(stateRoot, 'r');
    const forgedRegularPath = join(projectRoot, 'forged.txt');
    await writeSecureFile(forgedRegularPath, 'forged');
    const forgedRegular = await open(forgedRegularPath, 'r');
    try {
      const directoryError = await expectNativeError(() =>
        verifyManagedViteChildLaunchAuthority({ ...verifyInput, fd: forgedDirectory.fd }),
      );
      assertNativeErrorCode(directoryError, 'SCG_NATIVE_PATH_DENIED');
      const regularError = await expectNativeError(() =>
        verifyManagedViteChildLaunchAuthority({ ...verifyInput, fd: forgedRegular.fd }),
      );
      assertNativeErrorCode(regularError, 'SCG_NATIVE_PATH_DENIED');
    } finally {
      await Promise.all([forgedDirectory.close(), forgedRegular.close()]);
    }

    const port = createNativeViteRecoveryDirectoryPort();
    const session = port.openDirectory({
      projectRoot,
      expectedProjectRootIdentity,
      stateRoot,
      expectedStateRootIdentity,
      expectedOwnerUid: ownerUid,
    });
    const lockName = 'managed-child.recovery.v1.lock';
    let childAuthority: { readonly fd: number; readonly launchId: string } | undefined;
    try {
      expect(port.tryLock({ session, lockName })).toBe(true);
      childAuthority = port.createChildAuthority({
        session,
        launchId: verifyInput.launchId,
      });
      await expect(
        runManagedViteChildAuthorityCheck({
          fd: childAuthority.fd,
          stateRoot,
          useInheritedFd: true,
          launchId: '12345678-1234-4abc-8def-123456789abd',
          installId: verifyInput.installId,
          expectedStateRootIdentity,
          expectedOwnerUid: ownerUid,
        }),
      ).resolves.toBe(false);
      await expect(
        runManagedViteChildAuthorityCheck({
          fd: childAuthority.fd,
          stateRoot,
          useInheritedFd: false,
          ...verifyInput,
        }),
      ).resolves.toBe(false);
      await expect(
        runManagedViteChildAuthorityCheck({
          fd: childAuthority.fd,
          stateRoot,
          useInheritedFd: true,
          ...verifyInput,
        }),
      ).resolves.toBe(true);
    } finally {
      try {
        if (childAuthority !== undefined) {
          port.closeChildAuthority({ fd: childAuthority.fd });
        }
      } finally {
        port.closeDirectory({ session });
      }
    }
  });

  it('fails closed at Vite cache depth, entry, file, and byte traversal caps', async () => {
    const fixture = await createNativeViteCacheFixture();
    const nested = join(fixture.rootPath, 'nested');
    await mkdir(nested, { mode: VITE_CACHE_DIRECTORY_MODE });
    await chmod(nested, VITE_CACHE_DIRECTORY_MODE);
    await writeSecureFile(join(nested, 'one.bin'), '1234');
    await writeSecureFile(join(fixture.rootPath, 'two.bin'), '5678');

    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    try {
      const capFailures: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
        [
          'maxEntries',
          () =>
            port.scanCacheTree({
              session: session.nativeSession,
              provenance: session.provenance,
              limits: viteCacheLimits({ maxEntries: 1 }),
            }),
        ],
        [
          'maxFiles',
          () =>
            port.scanCacheTree({
              session: session.nativeSession,
              provenance: session.provenance,
              limits: viteCacheLimits({ maxFiles: 1 }),
            }),
        ],
        [
          'maxBytes',
          () =>
            port.scanCacheTree({
              session: session.nativeSession,
              provenance: session.provenance,
              limits: viteCacheLimits({ maxBytes: 7 }),
            }),
        ],
        [
          'maxDepth',
          () =>
            port.scanCacheTree({
              session: session.nativeSession,
              provenance: session.provenance,
              limits: viteCacheLimits({ maxDepth: 0 }),
            }),
        ],
      ];
      const capFailureCodes: string[] = [];
      for (const [label, scan] of capFailures) {
        try {
          const error = await expectNativeViteCacheFailure(scan);
          capFailureCodes.push(error.code);
        } catch (error: unknown) {
          throw new Error(`Vite cache ${label} cap did not fail closed.`, { cause: error });
        }
      }
      expect(capFailureCodes).toEqual(capFailures.map(() => 'SCG_NATIVE_FAILURE'));
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });
  it('fails nested Vite cache traversal closed during synchronized directory renames', async () => {
    const fixture = await createNativeViteCacheFixture();
    const nestedPath = join(fixture.rootPath, 'nested');
    const stagingPath = join(fixture.rootPath, 'nested-staging');
    await mkdir(nestedPath, { mode: VITE_CACHE_DIRECTORY_MODE });
    await chmod(nestedPath, VITE_CACHE_DIRECTORY_MODE);
    await Promise.all(
      Array.from({ length: 256 }, (_, index) =>
        writeSecureFile(join(nestedPath, `entry-${index}.bin`), `nested-${index}`),
      ),
    );

    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    const worker = await startNestedDirectoryRenameWorker({
      targetPath: nestedPath,
      stagingPath,
    });
    const failureCodes: string[] = [];
    const cleanEntrySets: Array<readonly CacheTreeEntry[]> = [];
    try {
      const armed = waitForWorkerMessage(worker.worker, 'armed');
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_ARMED);
      Atomics.notify(worker.control, 0);
      await armed;

      const done = waitForWorkerMessage(worker.worker, 'done');
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_ACTIVE);
      Atomics.notify(worker.control, 0);
      await sleep(10);
      for (let attempt = 0; attempt < 16; attempt += 1) {
        try {
          const tree = await port.scanCacheTree({
            session: session.nativeSession,
            provenance: session.provenance,
            limits: viteCacheLimits({
              maxEntries: 512,
              maxFiles: 256,
              maxBytes: 16 * 1024,
              maxDepth: 2,
            }),
          });
          cleanEntrySets.push(tree.entries);
        } catch (error: unknown) {
          if (!(error instanceof OnboardingNativeError)) {
            throw error;
          }
          failureCodes.push(error.code);
        }
      }
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_STOPPED);
      Atomics.notify(worker.control, 0);
      const completion = parseNestedDirectoryRenameCompletion(await done);
      expect(completion).toBeGreaterThan(0);
      expect(failureCodes).not.toHaveLength(0);
      expect(failureCodes).toEqual(
        Array.from({ length: failureCodes.length }, () => 'SCG_NATIVE_FAILURE'),
      );
      for (const entries of cleanEntrySets) {
        expect(entries[0]).toEqual(
          expect.objectContaining({
            identity: fixture.provenance.root.identity,
            parentIdentity: fixture.provenance.parent.identity,
            kind: 'directory',
            depth: 0,
            escaped: false,
          }),
        );
        expect(entries.every((entry) => entry.escaped === false)).toBe(true);
        expect(entries.every((entry) => entry.device === fixture.provenance.root.device)).toBe(
          true,
        );
      }
    } finally {
      Atomics.store(worker.control, 0, PATH_REPLACEMENT_STOPPED);
      Atomics.notify(worker.control, 0);
      await terminatePathReplacementWorker(worker.worker);
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });

  it('fails retained Vite cache sessions closed after a concurrent root replacement', async () => {
    const fixture = await createNativeViteCacheFixture();
    const originalEntryPath = join(fixture.rootPath, 'before-replacement.bin');
    await writeSecureFile(originalEntryPath, 'before');
    const originalEntryIdentity = await fileIdentity(originalEntryPath);
    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    try {
      const replacementPath = join(fixture.parentPath, 'concurrent-replacement');
      const replacement = (async (): Promise<void> => {
        await rename(fixture.rootPath, replacementPath);
        await mkdir(fixture.rootPath, { mode: VITE_CACHE_DIRECTORY_MODE });
        await chmod(fixture.rootPath, VITE_CACHE_DIRECTORY_MODE);
      })();
      const concurrentScan = Promise.resolve().then(() =>
        port.scanCacheTree({
          session: session.nativeSession,
          provenance: session.provenance,
          limits: viteCacheLimits(),
        }),
      );
      const [replacementOutcome, concurrentOutcome] = await Promise.allSettled([
        replacement,
        concurrentScan,
      ] as const);
      expect(replacementOutcome.status).toBe('fulfilled');

      const concurrentWasSafelyBound =
        concurrentOutcome.status === 'fulfilled'
          ? isDeepStrictEqual(concurrentOutcome.value, {
              rootIdentity: fixture.provenance.root.identity,
              entries: [
                {
                  identity: fixture.provenance.root.identity,
                  parentIdentity: fixture.provenance.parent.identity,
                  device: fixture.provenance.root.device,
                  owner: fixture.provenance.root.owner,
                  mode: VITE_CACHE_DIRECTORY_MODE,
                  kind: 'directory',
                  sizeBytes: 0,
                  linkCount: 1,
                  depth: 0,
                  escaped: false,
                },
                {
                  identity: originalEntryIdentity,
                  parentIdentity: fixture.provenance.root.identity,
                  device: fixture.provenance.root.device,
                  owner: fixture.provenance.root.owner,
                  mode: VITE_CACHE_FILE_MODE,
                  kind: 'regular-file',
                  sizeBytes: 4,
                  linkCount: 1,
                  depth: 1,
                  escaped: false,
                },
              ],
            })
          : concurrentOutcome.reason instanceof OnboardingNativeError &&
            concurrentOutcome.reason.code === 'SCG_NATIVE_PATH_DENIED';
      expect(concurrentWasSafelyBound).toBe(true);

      const rejectedTreeScan = await expectNativeError(() =>
        port.scanCacheTree({
          session: session.nativeSession,
          provenance: session.provenance,
          limits: viteCacheLimits(),
        }),
      );
      expect(rejectedTreeScan.code).toBe('SCG_NATIVE_PATH_DENIED');
      const rejectedCanaryScan = await expectNativeError(() =>
        port.scanCacheCanaries({
          session: session.nativeSession,
          provenance: session.provenance,
          trigger: 'failure',
          limits: viteCacheLimits(),
          tokenHashes: [createHash('sha256').update('safe-canary').digest('hex')],
        }),
      );
      expect(rejectedCanaryScan.code).toBe('SCG_NATIVE_PATH_DENIED');
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });

  it('detects literal and split raw canonical Vite cache token canaries without returning evidence', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    const literalPath = join(fixture.rootPath, 'literal-canary.bin');
    const rawPath = join(fixture.rootPath, 'split-raw-canary.bin');
    const rawCanonicalToken = 'A'.repeat(43);
    const approvedDigest = createHash('sha256').update(rawCanonicalToken, 'utf8').digest('hex');
    const nearMissDigest = `${approvedDigest.slice(0, -1)}${approvedDigest.at(-1) === '0' ? '1' : '0'}`;
    try {
      await writeSecureFile(literalPath, `\n${approvedDigest}\n`);
      const literal = await port.scanCacheCanaries({
        session: session.nativeSession,
        provenance: session.provenance,
        trigger: 'failure',
        limits: viteCacheLimits({ maxEntries: 8, maxFiles: 2, maxBytes: 128 * 1024, maxDepth: 1 }),
        tokenHashes: [approvedDigest],
      });
      expect(literal.detected).toBe(true);

      await writeSecureFile(literalPath, `\n${nearMissDigest}\n`);
      const nearMiss = await port.scanCacheCanaries({
        session: session.nativeSession,
        provenance: session.provenance,
        trigger: 'failure',
        limits: viteCacheLimits({ maxEntries: 8, maxFiles: 2, maxBytes: 128 * 1024, maxDepth: 1 }),
        tokenHashes: [approvedDigest],
      });
      expect(nearMiss.detected).toBe(false);

      const firstRawChunkBytes = Math.floor(Buffer.byteLength(rawCanonicalToken, 'utf8') / 2);
      const rawPrefixBytes = VITE_CACHE_CANARY_READ_CHUNK_BYTES - firstRawChunkBytes - 1;
      await writeSecureBuffer(
        rawPath,
        Buffer.concat([
          Buffer.alloc(rawPrefixBytes, 0x21),
          Buffer.from(`\n${rawCanonicalToken}\n`, 'utf8'),
        ]),
      );
      const raw = await port.scanCacheCanaries({
        session: session.nativeSession,
        provenance: session.provenance,
        trigger: 'failure',
        limits: viteCacheLimits({ maxEntries: 8, maxFiles: 2, maxBytes: 128 * 1024, maxDepth: 1 }),
        tokenHashes: [approvedDigest],
      });
      expect(raw.detected).toBe(true);

      const tree = await port.scanCacheTree({
        session: session.nativeSession,
        provenance: session.provenance,
        limits: viteCacheLimits({ maxEntries: 8, maxFiles: 2, maxBytes: 128 * 1024, maxDepth: 1 }),
      });
      assertViteCacheEvidenceRedacted({ literal, nearMiss, raw, tree }, [
        fixture.parentPath,
        fixture.rootPath,
        'literal-canary.bin',
        'split-raw-canary.bin',
        rawCanonicalToken,
        approvedDigest,
        nearMissDigest,
      ]);
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });
  it('fails canary scans closed when bounded matcher work is exhausted', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    const token = 'A'.repeat(43);
    const tokenHashes = Array.from({ length: 1_024 }, (_, index) =>
      createHash('sha256').update(`matcher-work-${index}`, 'utf8').digest('hex'),
    );
    try {
      await writeSecureFile(
        join(fixture.rootPath, 'matcher-budget.bin'),
        `${Array.from({ length: 65 }, () => token).join('\n')}\n`,
      );
      const error = await expectNativeViteCacheFailure(() =>
        port.scanCacheCanaries({
          session: session.nativeSession,
          provenance: session.provenance,
          trigger: 'failure',
          limits: viteCacheLimits({ maxEntries: 8, maxFiles: 1, maxBytes: 16 * 1024, maxDepth: 1 }),
          tokenHashes,
        }),
      );
      expect(error.code).toBe('SCG_NATIVE_FAILURE');
      assertNativeErrorRedacted(error, [
        fixture.parentPath,
        fixture.rootPath,
        'matcher-budget.bin',
        token,
        ...tokenHashes,
      ]);
    } finally {
      await port.closeCacheSession({ session: session.nativeSession });
    }
  });

  it('rejects forged and closed native Vite cache session handles generically', async () => {
    const fixture = await createNativeViteCacheFixture();
    const port = createNativeViteCacheRuntimePort();
    const forged = forgeNativeViteCacheSession();
    const forgedScanError = await expectNativeViteCacheFailure(() =>
      port.scanCacheTree({
        session: forged,
        provenance: fixture.provenance,
        limits: viteCacheLimits(),
      }),
    );
    const forgedWatchError = await expectNativeViteCacheFailure(() =>
      port.watchCacheTree({
        session: forged,
        provenance: fixture.provenance,
        onEvent: () => undefined,
        onFailure: () => undefined,
      }),
    );

    const session = await reopenViteCacheSession({
      filesystem: port,
      provenance: fixture.provenance,
    });
    await port.closeCacheSession({ session: session.nativeSession });
    await port.closeCacheSession({ session: session.nativeSession });
    const closedSessionError = await expectNativeViteCacheFailure(() =>
      port.scanCacheCanaries({
        session: session.nativeSession,
        provenance: session.provenance,
        trigger: 'failure',
        limits: viteCacheLimits(),
        tokenHashes: [createHash('sha256').update('safe-canary').digest('hex')],
      }),
    );
    expect([forgedScanError.code, forgedWatchError.code, closedSessionError.code]).toEqual([
      'SCG_NATIVE_FAILURE',
      'SCG_NATIVE_FAILURE',
      'SCG_NATIVE_FAILURE',
    ]);
  });
  it.skipIf(process.platform !== 'darwin')(
    'retains the generation-bound quarantine after a failed restore until verified retry',
    async () => {
      const root = currentRoot();
      const lockPath = join(root, 'lifecycle-reverse.lock');
      const stagingPath = join(root, 'lifecycle-reverse-stage');
      const targetPath = join(root, 'lifecycle-reverse-target');
      const displacedPath = join(root, 'lifecycle-reverse-displaced');
      await writeSecureFile(lockPath, 'lock');
      await writeSecureFile(targetPath, 'previous');
      const targetIdentity = await fileIdentity(targetPath);
      const lock = acquireLifecycleLock(lockPath);

      try {
        const snapshot = readExactLifecycleWal({
          lock,
          target: { path: targetPath, identity: targetIdentity, mode: 0o600 },
        });
        if (snapshot.state !== 'completed') {
          throw new Error('Exact WAL snapshot was indeterminate before replacement.');
        }
        snapshot.bytes.fill(0);
        const staged = reserveLifecycleStagedFile({ lock, path: stagingPath, mode: 0o600 });
        if (staged.state !== 'completed') {
          throw new Error('Exact WAL stage reservation was indeterminate.');
        }
        expect(
          writeLifecycleStagedFile({
            lock,
            reservation: staged.reservation,
            expectedSize: 0,
            bytes: Buffer.from('replacement', 'utf8'),
          }).state,
        ).toBe('completed');
        const replaced = replaceReservedLifecycleFileExact({
          lock,
          reservation: staged.reservation,
          targetPath,
          targetIdentity,
          targetMode: 0o600,
          targetSize: snapshot.size,
          targetDigest: snapshot.digest,
          targetStat: snapshot.stat,
        });
        expect(replaced.state).toBe('completed');
        if (replaced.quarantine === undefined) {
          throw new Error('Exact WAL replacement did not retain its quarantine capability.');
        }
        const stagingIdentity = staged.identity;

        await rename(targetPath, displacedPath);
        const interrupted = restoreLifecycleQuarantine({
          lock,
          quarantine: replaced.quarantine,
        });
        expect(interrupted.state).toBe('indeterminate');
        if (interrupted.quarantine === undefined) {
          throw new Error('Failed restore did not retain its quarantine capability.');
        }
        expect(await fileIdentity(stagingPath)).toEqual(targetIdentity);
        expect(
          await stat(targetPath).then(
            () => true,
            () => false,
          ),
        ).toBe(false);

        await rename(displacedPath, targetPath);
        expect(restoreLifecycleQuarantine({ lock, quarantine: interrupted.quarantine }).state).toBe(
          'completed',
        );
        expect(await fileIdentity(targetPath)).toEqual(targetIdentity);
        expect(await fileIdentity(stagingPath)).toEqual(stagingIdentity);
      } finally {
        expect(releaseLifecycleLock(lock).state).toBe('completed');
      }
    },
  );
  it('rejects FIFO creation-intent recovery candidates without blocking the native worker', async () => {
    const root = currentRoot();
    const lockPath = join(root, 'lifecycle-fifo.lock');
    const stagePath = join(root, 'lifecycle-fifo-stage');
    const markerPath = join(
      root,
      `.scg-intent-${'a'.repeat(16)}-file-600-${'b'.repeat(32)}.marker`,
    );
    await writeSecureFile(lockPath, 'lock');
    if (!(await createFifoIfSupported(stagePath))) {
      return;
    }

    const worker = new Worker(LIFECYCLE_FIFO_RECOVERY_WORKER_SOURCE, {
      eval: true,
      workerData: {
        bindingPath: directNativeRequire.resolve(
          '../../packages/onboarding/build/Release/secure_read.node',
        ),
        lockPath,
        stagePath,
        markerPath,
      },
    });
    try {
      const recovered = await waitForWorkerMessage(worker, 'recovered');
      expect(recovered.state).toBe('indeterminate');
      expect(recovered.released).toBe('completed');
    } finally {
      await terminatePathReplacementWorker(worker);
    }
  });
});
describe('native secure read unsupported platform behavior', () => {
  it('fails closed before native loading', () => {
    let caught: unknown;
    try {
      assertSecureReadNativeAvailable('win32');
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OnboardingNativeError);
    expect((caught as OnboardingNativeError).code).toBe('SCG_NATIVE_UNAVAILABLE');
  });
});

interface NativeViteCacheFixture {
  readonly parentPath: string;
  readonly rootPath: string;
  readonly provenance: ViteCacheProvenance;
}

async function createNativeViteCacheFixture(
  fixtureId = 'native-vite-cache',
): Promise<NativeViteCacheFixture> {
  const cacheHomePath = join(currentRoot(), `.scene-glass-${fixtureId}`);
  const parentPath = join(cacheHomePath, 'vite-cache');
  const rootPath = join(parentPath, 'native-vite-cache');
  await mkdir(cacheHomePath, { mode: VITE_CACHE_DIRECTORY_MODE });
  await chmod(cacheHomePath, VITE_CACHE_DIRECTORY_MODE);
  await mkdir(parentPath, { mode: VITE_CACHE_DIRECTORY_MODE });
  await chmod(parentPath, VITE_CACHE_DIRECTORY_MODE);
  await mkdir(rootPath, { mode: VITE_CACHE_DIRECTORY_MODE });
  await chmod(rootPath, VITE_CACHE_DIRECTORY_MODE);

  const [parent, root] = await Promise.all([
    nativeViteCacheRootRecord(parentPath),
    nativeViteCacheRootRecord(rootPath),
  ]);
  if (
    parent.identity.device !== root.identity.device ||
    parent.owner.uid !== root.owner.uid ||
    parent.owner.gid !== root.owner.gid
  ) {
    throw new Error('Native Vite cache fixture parent and root facts must share owner and device.');
  }

  const provenance: ViteCacheProvenance = Object.freeze({
    version: 1,
    installId: fixtureId,
    canonicalParentPath: parent.canonicalPath,
    root,
    parent,
    parentIdentity: parent.identity,
    inverse: Object.freeze({
      kind: 'remove-created-vite-cache',
      rootIdentity: root.identity,
      parentIdentity: parent.identity,
      canonicalPath: root.canonicalPath,
    }),
  });
  const canonicalProvenance = parseViteCacheProvenanceJson(
    serializeViteCacheProvenanceJson(provenance),
  );
  return Object.freeze({
    parentPath: parent.canonicalPath,
    rootPath: root.canonicalPath,
    provenance: canonicalProvenance,
  });
}

async function nativeViteCacheRootRecord(path: string): Promise<CacheRootRecord> {
  const [canonicalPath, information] = await Promise.all([
    realpath(path),
    stat(path, { bigint: true }),
  ]);
  const mode = Number(information.mode & 0o7777n);
  if (!information.isDirectory() || mode !== VITE_CACHE_DIRECTORY_MODE) {
    throw new Error('Native Vite cache fixture path must be a 0700 directory.');
  }
  const owner = Object.freeze({
    uid: nativeStatUint32(information.uid, 'uid'),
    gid: nativeStatUint32(information.gid, 'gid'),
  });
  const identity = Object.freeze({
    device: information.dev.toString(),
    inode: information.ino.toString(),
  });
  return Object.freeze({
    identity,
    canonicalPath,
    device: identity.device,
    owner,
    mode,
  });
}

function nativeStatUint32(value: bigint, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    throw new Error(`Native Vite cache fixture ${label} is outside the supported range.`);
  }
  return parsed;
}

function viteCacheLimits(overrides: Partial<ViteCacheLimits> = {}): ViteCacheLimits {
  return Object.freeze({
    maxEntries: overrides.maxEntries ?? 64,
    maxFiles: overrides.maxFiles ?? 32,
    maxBytes: overrides.maxBytes ?? 128 * 1024,
    maxDepth: overrides.maxDepth ?? 4,
  });
}

function withViteCacheRootIdentityMismatch(provenance: ViteCacheProvenance): ViteCacheProvenance {
  const rootIdentity = Object.freeze({
    device: provenance.root.identity.device,
    inode: differentViteCacheInode(
      provenance.root.identity.inode,
      provenance.parent.identity.inode,
    ),
  });
  return Object.freeze({
    ...provenance,
    root: Object.freeze({ ...provenance.root, identity: rootIdentity }),
    inverse: Object.freeze({ ...provenance.inverse, rootIdentity }),
  });
}

function withViteCacheParentIdentityMismatch(provenance: ViteCacheProvenance): ViteCacheProvenance {
  const parentIdentity = Object.freeze({
    device: provenance.parent.identity.device,
    inode: differentViteCacheInode(
      provenance.parent.identity.inode,
      provenance.root.identity.inode,
    ),
  });
  return Object.freeze({
    ...provenance,
    parent: Object.freeze({ ...provenance.parent, identity: parentIdentity }),
    parentIdentity,
    inverse: Object.freeze({ ...provenance.inverse, parentIdentity }),
  });
}

function withViteCacheOwnerMismatch(
  provenance: ViteCacheProvenance,
  field: 'uid' | 'gid',
): ViteCacheProvenance {
  const owner = Object.freeze({
    uid: field === 'uid' ? differentUint32(provenance.root.owner.uid) : provenance.root.owner.uid,
    gid: field === 'gid' ? differentUint32(provenance.root.owner.gid) : provenance.root.owner.gid,
  });
  return Object.freeze({
    ...provenance,
    root: Object.freeze({ ...provenance.root, owner }),
    parent: Object.freeze({ ...provenance.parent, owner }),
  });
}

function withViteCacheDeviceMismatch(provenance: ViteCacheProvenance): ViteCacheProvenance {
  const device = incrementDecimal(provenance.root.device);
  const rootIdentity = Object.freeze({ ...provenance.root.identity, device });
  const parentIdentity = Object.freeze({ ...provenance.parent.identity, device });
  return Object.freeze({
    ...provenance,
    root: Object.freeze({ ...provenance.root, identity: rootIdentity, device }),
    parent: Object.freeze({ ...provenance.parent, identity: parentIdentity, device }),
    parentIdentity,
    inverse: Object.freeze({ ...provenance.inverse, rootIdentity, parentIdentity }),
  });
}

function withViteCacheRootPathMismatch(provenance: ViteCacheProvenance): ViteCacheProvenance {
  const canonicalPath = join(provenance.canonicalParentPath, 'missing-native-vite-cache');
  return Object.freeze({
    ...provenance,
    root: Object.freeze({ ...provenance.root, canonicalPath }),
    inverse: Object.freeze({ ...provenance.inverse, canonicalPath }),
  });
}
function withViteCacheParentPathMismatch(provenance: ViteCacheProvenance): ViteCacheProvenance {
  const canonicalParentPath = join(
    provenance.canonicalParentPath,
    '..',
    'missing-native-vite-parent',
  );
  const rootCanonicalPath = join(canonicalParentPath, 'native-vite-cache');
  return Object.freeze({
    ...provenance,
    canonicalParentPath,
    parent: Object.freeze({ ...provenance.parent, canonicalPath: canonicalParentPath }),
    root: Object.freeze({ ...provenance.root, canonicalPath: rootCanonicalPath }),
    inverse: Object.freeze({ ...provenance.inverse, canonicalPath: rootCanonicalPath }),
  });
}

function differentViteCacheInode(value: string, forbidden: string): string {
  const next = incrementDecimal(value);
  return next === forbidden ? incrementDecimal(next) : next;
}
function differentUint32(value: number): number {
  return value === 0xffff_ffff ? value - 1 : value + 1;
}

function forgeNativeViteCacheSession(): CacheNativeSession {
  // Explicit forgery: no production surface accepts caller-created session handles.
  return Object.freeze({}) as unknown as CacheNativeSession;
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function waitForDeadline<T>(
  operation: Promise<T>,
  deadlineMilliseconds: number,
  label: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Timed out waiting for ${label}.`));
    }, deadlineMilliseconds);
    void operation.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

async function expectNativeViteCacheFailure(
  action: () => unknown | Promise<unknown>,
): Promise<OnboardingNativeError> {
  const error = await expectNativeError(action);
  expect(error.code).toBe('SCG_NATIVE_FAILURE');
  return error;
}

function assertViteCacheEvidenceRedacted(value: unknown, canaries: readonly string[]): void {
  const rendered = JSON.stringify(value);
  for (const canary of canaries) {
    expect(rendered).not.toContain(canary);
  }
}

async function createFifoIfSupported(path: string): Promise<boolean> {
  try {
    await execFileAsync('mkfifo', ['-m', '600', path]);
    return true;
  } catch (error: unknown) {
    if (isUnavailableNativeFixture(error)) {
      return false;
    }
    throw error;
  }
}

async function createUnixSocketIfSupported(path: string): Promise<Server | undefined> {
  const server = createServer();
  try {
    await new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        server.off('error', onError);
        server.off('listening', onListening);
      };
      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };
      const onListening = () => {
        cleanup();
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(path);
    });
    return server;
  } catch (error: unknown) {
    try {
      await closeUnixSocket(server);
    } catch {
      // The unsupported fixture may never have started listening.
    }
    if (isUnavailableNativeFixture(error)) {
      return undefined;
    }
    throw error;
  }
}

async function closeUnixSocket(server: Server | undefined): Promise<void> {
  if (server === undefined) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}

function isUnavailableNativeFixture(error: unknown): boolean {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    [
      'EACCES',
      'EAFNOSUPPORT',
      'EINVAL',
      'ENAMETOOLONG',
      'ENOENT',
      'ENOTSUP',
      'EOPNOTSUPP',
      'EPERM',
    ].includes(String(error.code))
  ) {
    return true;
  }
  return (
    error instanceof Error &&
    /not supported|operation not permitted|path too long/i.test(error.message)
  );
}
function currentRoot(): string {
  const root = temporaryRoots.at(-1);
  if (root === undefined) {
    throw new Error('test root was not created');
  }
  return root;
}

function nativeHomeHierarchy(): string | undefined {
  const home = homedir();
  if (process.platform === 'darwin' && home.startsWith('/Users/')) {
    return home;
  }
  if (process.platform === 'linux' && home.startsWith('/home/')) {
    return home;
  }
  return undefined;
}

async function runManagedViteChildAuthorityCheck(input: {
  readonly fd: number;
  readonly stateRoot: string;
  readonly useInheritedFd: boolean;
  readonly launchId: string;
  readonly installId: string;
  readonly expectedStateRootIdentity: FileIdentity;
  readonly expectedOwnerUid: number;
}): Promise<boolean> {
  const addonPath = directNativeRequire.resolve(
    '../../packages/onboarding/build/Release/secure_read.node',
  );
  const source = `
const fs = require('node:fs');
const [addonPath, launchId, installId, device, inode, ownerUid, stateRoot, useInheritedFd] =
  process.argv.slice(1);
const fd = useInheritedFd === '1' ? 6 : fs.openSync(stateRoot, 'r');
try {
  const binding = require(addonPath);
  const authority = binding.verifyManagedViteChildLaunchAuthority({
    fd,
    launchId,
    installId,
    expectedStateRootIdentity: { device, inode },
    expectedOwnerUid: Number(ownerUid),
  });
  binding.releaseManagedViteChildLaunchAuthority({ authority });
  binding.releaseManagedViteChildLaunchAuthority({ authority });
  process.exitCode = 0;
} catch {
  process.exitCode = 1;
} finally {
  if (useInheritedFd !== '1') {
    fs.closeSync(fd);
  }
}
`;
  return new Promise<boolean>((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        '-e',
        source,
        addonPath,
        input.launchId,
        input.installId,
        input.expectedStateRootIdentity.device,
        input.expectedStateRootIdentity.inode,
        String(input.expectedOwnerUid),
        input.stateRoot,
        input.useInheritedFd ? '1' : '0',
      ],
      {
        stdio: ['ignore', 'ignore', 'ignore', 'ignore', 'ignore', 'ignore', input.fd],
      },
    );
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal !== null || code === null) {
        reject(new Error('Managed-Vite child authority check terminated unexpectedly.'));
        return;
      }
      if (code === 0 || code === 1) {
        resolve(code === 0);
        return;
      }
      reject(new Error('Managed-Vite child authority check failed.'));
    });
  });
}
interface DirectSecureReadBinding {
  secureReadBeneath(options: unknown): unknown;
}

function directSecureReadBinding(): DirectSecureReadBinding {
  const candidate: unknown = directNativeRequire(
    '../../packages/onboarding/build/Release/secure_read.node',
  );
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    !('secureReadBeneath' in candidate) ||
    typeof candidate.secureReadBeneath !== 'function'
  ) {
    throw new Error('Secure native binding is unavailable for direct boundary testing.');
  }
  return candidate as DirectSecureReadBinding;
}

async function secureRead(root: string, relativePath: string) {
  return secureReadBeneath({
    root,
    expectedRoot: await fileIdentity(root),
    relativePath,
    deniedIdentities: [],
    maxBytes: 1024 * 1024,
  });
}

async function fileIdentity(path: string): Promise<FileIdentity> {
  const information = await stat(path, { bigint: true });
  return Object.freeze({ device: information.dev.toString(), inode: information.ino.toString() });
}

async function credentialAuthority(projectId: string, path: string): Promise<CredentialAuthority> {
  const identity = await fileIdentity(path);
  return Object.freeze({ projectId, path, ...identity });
}
async function addUnsafeAcl(path: string): Promise<boolean> {
  try {
    if (process.platform === 'darwin') {
      await execFileAsync('chmod', ['+a', 'everyone allow read', path]);
    } else {
      await execFileAsync('setfacl', ['-m', 'u:65534:r--', path]);
    }
    return true;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : '';
    const standardError =
      typeof error === 'object' && error !== null && 'stderr' in error ? String(error.stderr) : '';
    if (
      (typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        ['ENOENT', 'ENOTSUP', 'EOPNOTSUPP'].includes(String(error.code))) ||
      /operation not supported|not supported|acl.+unsupported/i.test(`${message}\n${standardError}`)
    ) {
      return false;
    }
    throw error;
  }
}

function credentialOptions() {
  if (typeof process.geteuid !== 'function') {
    throw new Error('native secure read tests require a POSIX effective uid');
  }
  return Object.freeze({ expectedOwnerUid: process.geteuid(), maxBytes: 8 * 1024 });
}

async function writeSecureFile(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}
async function writeSecureBuffer(path: string, contents: Buffer): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}

function largeFixtureBytes(label: string): Buffer {
  const prefix = Buffer.from(`${label}:`, 'utf8');
  const fill = label.startsWith('FIRST') ? 0x41 : 0x42;
  const contents = Buffer.alloc(SAME_FD_FIXTURE_BYTES, fill);
  prefix.copy(contents);
  return contents;
}

interface PathReplacementWorker {
  readonly worker: Worker;
  readonly control: Int32Array;
}

interface WorkerMessage {
  readonly type?: unknown;
  readonly swaps?: unknown;
  readonly published?: unknown;
  readonly message?: unknown;
  readonly state?: unknown;
  readonly released?: unknown;
}

interface PublishedFixture {
  readonly label: 'first' | 'second';
  readonly identity: FileIdentity;
}

interface PathReplacementCompletion {
  readonly swaps: number;
  readonly published: readonly PublishedFixture[];
}

type ConcurrentReadOutcome =
  | { readonly kind: 'read'; readonly bytes: Buffer; readonly identity: FileIdentity }
  | { readonly kind: 'rejected'; readonly error: OnboardingNativeError };
type DirectAuthorityOutcome =
  | { readonly kind: 'read'; readonly bytes: Buffer; readonly identity: FileIdentity }
  | { readonly kind: 'rejected'; readonly code: string };

async function startPathReplacementWorker({
  targetPath,
  stagingPath,
  firstBytes,
  secondBytes,
}: {
  readonly targetPath: string;
  readonly stagingPath: string;
  readonly firstBytes: Buffer;
  readonly secondBytes: Buffer;
}): Promise<PathReplacementWorker> {
  const control = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  const worker = new Worker(PATH_REPLACEMENT_WORKER_SOURCE, {
    eval: true,
    workerData: {
      control: control.buffer,
      targetPath,
      stagingPath,
      firstBytes,
      secondBytes,
      deadlineMilliseconds: PATH_REPLACEMENT_WORKER_DEADLINE_MS,
      maximumSwaps: PATH_REPLACEMENT_MAX_SWAPS,
    },
  });
  try {
    await waitForWorkerMessage(worker, 'prepared');
    return { worker, control };
  } catch (error: unknown) {
    await terminatePathReplacementWorker(worker);
    throw error;
  }
}
async function startNestedDirectoryRenameWorker({
  targetPath,
  stagingPath,
}: {
  readonly targetPath: string;
  readonly stagingPath: string;
}): Promise<PathReplacementWorker> {
  const control = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  const worker = new Worker(NESTED_DIRECTORY_RENAME_WORKER_SOURCE, {
    eval: true,
    workerData: {
      control: control.buffer,
      targetPath,
      stagingPath,
      deadlineMilliseconds: PATH_REPLACEMENT_WORKER_DEADLINE_MS,
      maximumSwaps: PATH_REPLACEMENT_MAX_SWAPS * 16_384,
    },
  });
  try {
    await waitForWorkerMessage(worker, 'prepared');
    return { worker, control };
  } catch (error: unknown) {
    await terminatePathReplacementWorker(worker);
    throw error;
  }
}

function parseNestedDirectoryRenameCompletion(message: WorkerMessage): number {
  if (
    typeof message.swaps !== 'number' ||
    !Number.isSafeInteger(message.swaps) ||
    message.swaps < 1
  ) {
    throw new Error('Nested-directory rename worker returned an invalid completion record.');
  }
  return message.swaps;
}
async function terminatePathReplacementWorker(worker: Worker): Promise<void> {
  await waitForWorkerDeadline(worker.terminate(), 'termination');
}

function waitForWorkerDeadline<T>(operation: Promise<T>, phase: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Timed out during pathname replacement worker ${phase}.`));
    }, PATH_REPLACEMENT_WAIT_DEADLINE_MS);
    void operation.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function waitForWorkerMessage(worker: Worker, type: string): Promise<WorkerMessage> {
  return new Promise<WorkerMessage>((resolve, reject) => {
    const timeout = setTimeout(() => {
      fail(new Error(`Timed out waiting for pathname replacement worker ${type} synchronization.`));
    }, PATH_REPLACEMENT_WAIT_DEADLINE_MS);
    const onMessage = (value: unknown) => {
      const message = asWorkerMessage(value);
      if (message?.type === 'error') {
        fail(new Error(`Pathname replacement worker failed: ${String(message.message)}`));
      } else if (message?.type === type) {
        succeed(message);
      }
    };
    const onError = (error: Error) => {
      fail(error);
    };
    const onExit = (code: number) => {
      fail(new Error(`Pathname replacement worker exited before ${type} with code ${code}.`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      worker.off('message', onMessage);
      worker.off('error', onError);
      worker.off('exit', onExit);
    };
    const succeed = (message: WorkerMessage) => {
      cleanup();
      resolve(message);
    };
    const fail = (error: Error) => {
      cleanup();
      reject(error);
    };
    worker.on('message', onMessage);
    worker.once('error', onError);
    worker.once('exit', onExit);
  });
}

function asWorkerMessage(value: unknown): WorkerMessage | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as WorkerMessage;
}

function parsePathReplacementCompletion(message: WorkerMessage): PathReplacementCompletion {
  if (
    typeof message.swaps !== 'number' ||
    !Number.isSafeInteger(message.swaps) ||
    message.swaps < 1 ||
    !Array.isArray(message.published)
  ) {
    throw new Error('Pathname replacement worker returned an invalid completion record.');
  }
  const published = message.published.map((value): PublishedFixture => {
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      !('label' in value) ||
      !('identity' in value) ||
      (value.label !== 'first' && value.label !== 'second') ||
      typeof value.identity !== 'object' ||
      value.identity === null ||
      Array.isArray(value.identity) ||
      !('device' in value.identity) ||
      !('inode' in value.identity) ||
      typeof value.identity.device !== 'string' ||
      typeof value.identity.inode !== 'string'
    ) {
      throw new Error('Pathname replacement worker returned an invalid published identity.');
    }
    return {
      label: value.label,
      identity: Object.freeze({ device: value.identity.device, inode: value.identity.inode }),
    };
  });
  if (published.length !== message.swaps) {
    throw new Error('Pathname replacement worker did not account for every pathname replacement.');
  }
  return { swaps: message.swaps, published };
}

function identityKey(identity: FileIdentity): string {
  return `${identity.device}:${identity.inode}`;
}
function directNativeReadResult(value: unknown): {
  readonly bytes: Buffer;
  readonly identity: FileIdentity;
} {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('bytes' in value) ||
    !Buffer.isBuffer(value.bytes) ||
    !('identity' in value) ||
    typeof value.identity !== 'object' ||
    value.identity === null ||
    !('device' in value.identity) ||
    !('inode' in value.identity) ||
    typeof value.identity.device !== 'string' ||
    typeof value.identity.inode !== 'string'
  ) {
    throw new Error('Expected a native secure-read result.');
  }
  return {
    bytes: value.bytes,
    identity: Object.freeze({ device: value.identity.device, inode: value.identity.inode }),
  };
}

function directNativeErrorCode(error: unknown): string {
  if (
    typeof error !== 'object' ||
    error === null ||
    !('code' in error) ||
    typeof error.code !== 'string'
  ) {
    throw error;
  }
  return error.code;
}

function assertNativeErrorCode(
  error: OnboardingNativeError,
  expectedCode: OnboardingNativeError['code'],
): void {
  expect(error.code).toBe(expectedCode);
}
function assertNativeErrorRedacted(
  error: OnboardingNativeError,
  canaries: readonly string[],
): void {
  const values: unknown[] = [error];
  const visited = new WeakSet<object>();
  const surfaces: string[] = [];
  let inspectedValues = 0;
  while (values.length > 0) {
    inspectedValues += 1;
    if (inspectedValues > 128) {
      throw new Error('Native error surface exceeded the bounded recursive inspection limit.');
    }
    const value = values.shift();
    if (typeof value === 'string') {
      surfaces.push(value);
      continue;
    }
    if (typeof value !== 'object' || value === null) {
      surfaces.push(String(value));
      continue;
    }
    if (visited.has(value)) {
      continue;
    }
    visited.add(value);
    surfaces.push(
      inspect(value, {
        depth: null,
        maxArrayLength: null,
        maxStringLength: null,
        showHidden: true,
      }),
    );
    surfaces.push(format('%O', value));
    if (value instanceof Error) {
      surfaces.push(value.message, value.stack ?? '', String(value));
    }
    for (const [key, field] of Object.entries(value)) {
      surfaces.push(key);
      values.push(field);
    }
    if (Object.prototype.hasOwnProperty.call(value, 'cause')) {
      values.push((value as { readonly cause?: unknown }).cause);
    }
  }
  const rendered = surfaces.join('\n');
  for (const canary of canaries) {
    expect(rendered).not.toContain(canary);
  }
}

async function descriptorCount(): Promise<number> {
  return (await readdir(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')).length;
}

function incrementDecimal(value: string): string {
  return (BigInt(value) + 1n).toString();
}

async function expectNativeError(
  action: () => unknown | Promise<unknown>,
): Promise<OnboardingNativeError> {
  let caught: unknown;
  try {
    await action();
  } catch (error: unknown) {
    caught = error;
  }
  if (!(caught instanceof OnboardingNativeError)) {
    throw new Error(`Expected OnboardingNativeError, received ${String(caught)}`);
  }
  return caught;
}
function expectDirectNativeError(action: () => unknown): { readonly code?: unknown } {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }
  if (typeof caught !== 'object' || caught === null) {
    throw new Error(`Expected a native error, received ${String(caught)}`);
  }
  return caught as { readonly code?: unknown };
}
