import { createHash } from 'node:crypto';
import { type Dirent } from 'node:fs';
import { spawn } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  opendir,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { serializeCredentialAuthorityRegistryV1 } from '../../packages/onboarding/src/credential-authority.js';
import {
  canonicalServerTokenEnvForProjectId,
  planConfigOperation,
  serializeConfigV1,
} from '../../packages/onboarding/src/lifecycle/config.js';
import { planHostIntegration } from '../../packages/onboarding/src/lifecycle/host-plan.js';
import {
  runSetup,
  runUninstall,
  type LifecycleSetupPreflightInput,
} from '../../packages/onboarding/src/lifecycle/engine.js';
import * as native from '../../packages/onboarding/src/native.js';
import { createNodeLifecycleEnginePort } from '../../packages/onboarding/src/lifecycle/node-engine-port.js';
import {
  parseSetupManifestJsonV1,
  parseWalRecordJsonV2,
  serializeWalRecordV2,
} from '../../packages/onboarding/src/lifecycle/provenance.js';
import {
  createNodeLifecycleVerificationPorts,
  type NodeLifecycleVerificationPorts,
} from '../../packages/onboarding/src/lifecycle/node-verification-port.js';
import { createNodeLifecycleTransactionPort } from '../../packages/onboarding/src/lifecycle/node-transaction-port.js';
import { LifecycleTransactionError } from '../../packages/onboarding/src/lifecycle/transaction.js';

const roots: string[] = [];
const TOKEN = 'A'.repeat(43);
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;
const CHILD_WAIT_TIMEOUT_MS = 10_000;
const MAX_FILESYSTEM_FILE_BYTES = 1024 * 1024;
const MAX_FILESYSTEM_TRAVERSAL_DEPTH = 16;
const MAX_FILESYSTEM_TRAVERSAL_ENTRIES = 256;
const MAX_FILESYSTEM_TRAVERSAL_MS = 5_000;
const MAX_FILESYSTEM_TRAVERSAL_BYTES = 4 * 1024 * 1024;

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe('Node onboarding lifecycle secret boundary', () => {
  it('keeps an adopted token out of setup facts, plans, and redacted preview data', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-secret-')));
    roots.push(root);
    await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
    await writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 });
    await writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
      mode: 0o600,
    });
    await writeFile(
      join(root, '.env.scene-glass.local'),
      credentialEnvelope('secret-boundary', TOKEN),
      {
        mode: 0o600,
      },
    );

    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: join(root, 'home'),
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'secret-boundary',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      verification: verification(),
    });

    const facts = await port.inspectSetupFacts();
    const config = planConfigOperation({ homes: facts.configHomes, project: facts.project });
    const host = planHostIntegration(facts.hostPlan);
    const built = await port.buildSetupPlan({ build: facts.build, config, host });
    const credentialLine = credentialEnvelope('secret-boundary', TOKEN);
    const decodedTokenDigest = `sha256:${createHash('sha256')
      .update(Buffer.from(TOKEN, 'base64url'))
      .digest('hex')}`;
    const tokenTextDigest = `sha256:${createHash('sha256').update(TOKEN).digest('hex')}`;
    const credentialContentDigest = `sha256:${createHash('sha256')
      .update(credentialLine)
      .digest('hex')}`;
    const canaries = [
      TOKEN,
      credentialLine,
      Buffer.from(credentialLine, 'utf8').toString('base64'),
      Buffer.from(credentialLine, 'utf8').toString('base64url'),
      decodedTokenDigest,
      tokenTextDigest,
      credentialContentDigest,
    ];
    const secretless = { facts, host, plan: built.plan };
    assertNoSecretBearingKeys(secretless);
    const serialized = JSON.stringify(secretless);
    for (const canary of canaries) expect(serialized).not.toContain(canary);
    expect(built.plan.preview.operations).not.toHaveLength(0);
    expect(
      built.plan.preview.operations.every(
        (operation) => !operation.hunkSubjects.some((subject) => subject.includes(TOKEN)),
      ),
    ).toBe(true);
    const preview = JSON.stringify(built.plan.preview);
    expect(preview).not.toContain(root);
    expect(preview).not.toContain(join(root, '.env.scene-glass.local'));
  });
  it('declines setup through the real Node engine without acquiring write authority', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-declined-setup-')));
    roots.push(root);
    const home = join(root, 'home');
    await Promise.all([
      mkdir(join(root, 'public'), { recursive: true, mode: 0o700 }),
      mkdir(home, { recursive: true, mode: 0o700 }),
    ]);
    await Promise.all([
      writeFile(join(root, '.gitignore'), '.credentials/token.env\n', { mode: 0o600 }),
      writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
        mode: 0o600,
      }),
    ]);
    const transactionPort = createNodeLifecycleTransactionPort();
    const mutationCounts = {
      lock: 0,
      staging: 0,
      reservation: 0,
      write: 0,
      renameOrPublication: 0,
      quarantine: 0,
      removal: 0,
    };
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    const stageWrite = transactionPort.stageWrite.bind(transactionPort);
    const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
    const reserveStagedDirectory = transactionPort.reserveStagedDirectory.bind(transactionPort);
    const writeReservedStagedWrite = transactionPort.writeReservedStagedWrite.bind(transactionPort);
    const renameReservedStagedWrite =
      transactionPort.renameReservedStagedWrite.bind(transactionPort);
    const publishReservedStagedDirectory =
      transactionPort.publishReservedStagedDirectory.bind(transactionPort);
    const publishExactStagedDirectory =
      transactionPort.publishExactStagedDirectory.bind(transactionPort);
    const replaceExactStagedFileWithQuarantine =
      transactionPort.replaceExactStagedFileWithQuarantine.bind(transactionPort);
    const replaceExactWal = transactionPort.replaceExactWal.bind(transactionPort);
    const publishExactStagedFile = transactionPort.publishExactStagedFile.bind(transactionPort);
    const quarantineExactFile = transactionPort.quarantineExactFile.bind(transactionPort);
    const quarantineExactDirectory = transactionPort.quarantineExactDirectory.bind(transactionPort);
    const finalizeQuarantine = transactionPort.finalizeQuarantine.bind(transactionPort);
    const restoreQuarantine = transactionPort.restoreQuarantine.bind(transactionPort);
    const removeExactWal = transactionPort.removeExactWal.bind(transactionPort);
    const removeExactStagedFile = transactionPort.removeExactStagedFile.bind(transactionPort);
    const discardReservedStagedWrite =
      transactionPort.discardReservedStagedWrite.bind(transactionPort);
    const discardReservedStagedDirectory =
      transactionPort.discardReservedStagedDirectory.bind(transactionPort);
    transactionPort.acquireAdvisoryLock = async (input) => {
      mutationCounts.lock += 1;
      return acquireAdvisoryLock(input);
    };
    transactionPort.stageWrite = async (input) => {
      mutationCounts.staging += 1;
      return stageWrite(input);
    };
    transactionPort.reserveStagedWrite = async (input) => {
      mutationCounts.reservation += 1;
      return reserveStagedWrite(input);
    };
    transactionPort.reserveStagedDirectory = async (input) => {
      mutationCounts.reservation += 1;
      return reserveStagedDirectory(input);
    };
    transactionPort.writeReservedStagedWrite = async (input) => {
      mutationCounts.write += 1;
      return writeReservedStagedWrite(input);
    };
    transactionPort.renameReservedStagedWrite = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return renameReservedStagedWrite(input);
    };
    transactionPort.publishReservedStagedDirectory = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return publishReservedStagedDirectory(input);
    };
    transactionPort.publishExactStagedDirectory = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return publishExactStagedDirectory(input);
    };
    transactionPort.replaceExactStagedFileWithQuarantine = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return replaceExactStagedFileWithQuarantine(input);
    };
    transactionPort.replaceExactWal = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return replaceExactWal(input);
    };
    transactionPort.publishExactStagedFile = async (input) => {
      mutationCounts.renameOrPublication += 1;
      return publishExactStagedFile(input);
    };
    transactionPort.quarantineExactFile = async (input) => {
      mutationCounts.quarantine += 1;
      return quarantineExactFile(input);
    };
    transactionPort.quarantineExactDirectory = async (input) => {
      mutationCounts.quarantine += 1;
      return quarantineExactDirectory(input);
    };
    transactionPort.finalizeQuarantine = async (input) => {
      mutationCounts.quarantine += 1;
      return finalizeQuarantine(input);
    };
    transactionPort.restoreQuarantine = async (input) => {
      mutationCounts.quarantine += 1;
      return restoreQuarantine(input);
    };
    transactionPort.removeExactWal = async (input) => {
      mutationCounts.removal += 1;
      return removeExactWal(input);
    };
    transactionPort.removeExactStagedFile = async (input) => {
      mutationCounts.removal += 1;
      return removeExactStagedFile(input);
    };
    transactionPort.discardReservedStagedWrite = async (input) => {
      mutationCounts.removal += 1;
      return discardReservedStagedWrite(input);
    };
    transactionPort.discardReservedStagedDirectory = async (input) => {
      mutationCounts.removal += 1;
      return discardReservedStagedDirectory(input);
    };
    const unreachedMutationSpies = {
      closeReservedStagedDirectory: vi.spyOn(transactionPort, 'closeReservedStagedDirectory'),
      closeReservedStagedWrite: vi.spyOn(transactionPort, 'closeReservedStagedWrite'),
      discardStagedWrite: vi.spyOn(transactionPort, 'discardStagedWrite'),
      fsyncDirectory: vi.spyOn(transactionPort, 'fsyncDirectory'),
      fsyncFile: vi.spyOn(transactionPort, 'fsyncFile'),
      fsyncParent: vi.spyOn(transactionPort, 'fsyncParent'),
      publishStagedWrite: vi.spyOn(transactionPort, 'publishStagedWrite'),
      replaceStagedWriteWithQuarantine: vi.spyOn(
        transactionPort,
        'replaceStagedWriteWithQuarantine',
      ),
      retainReservedStagedDirectoryForRecovery: vi.spyOn(
        transactionPort,
        'retainReservedStagedDirectoryForRecovery',
      ),
      retainReservedStagedWriteForRecovery: vi.spyOn(
        transactionPort,
        'retainReservedStagedWriteForRecovery',
      ),
      retainStagedWriteForRecovery: vi.spyOn(transactionPort, 'retainStagedWriteForRecovery'),
      validateExactCredential: vi.spyOn(transactionPort, 'validateExactCredential'),
      validateExactDirectory: vi.spyOn(transactionPort, 'validateExactDirectory'),
      validatePublishedCredential: vi.spyOn(transactionPort, 'validatePublishedCredential'),
    };
    let entropyCalls = 0;
    let identifierCalls = 0;
    const before = await captureFilesystemTree(root);
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.credentials/token.env'), port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'declined-setup',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      random: {
        fill: (candidate) => {
          entropyCalls += 1;
          candidate.fill(0);
        },
        uuid: () => {
          identifierCalls += 1;
          return 'declined-setup-mutation';
        },
      },
      transactionPort,
      verification: verification(),
    });

    await expect(runSetup(port)).resolves.toMatchObject({
      code: 'SCG_LIFECYCLE_DECLINED',
      state: 'never-installed',
    });
    expect(
      Object.fromEntries(
        Object.entries(unreachedMutationSpies).map(([name, spy]) => [name, spy.mock.calls.length]),
      ),
    ).toStrictEqual({
      closeReservedStagedDirectory: 0,
      closeReservedStagedWrite: 0,
      discardStagedWrite: 0,
      fsyncDirectory: 0,
      fsyncFile: 0,
      fsyncParent: 0,
      publishStagedWrite: 0,
      replaceStagedWriteWithQuarantine: 0,
      retainReservedStagedDirectoryForRecovery: 0,
      retainReservedStagedWriteForRecovery: 0,
      retainStagedWriteForRecovery: 0,
      validateExactCredential: 0,
      validateExactDirectory: 0,
      validatePublishedCredential: 0,
    });
    expect({ entropyCalls, identifierCalls, ...mutationCounts }).toStrictEqual({
      entropyCalls: 0,
      identifierCalls: 0,
      lock: 0,
      staging: 0,
      reservation: 0,
      write: 0,
      renameOrPublication: 0,
      quarantine: 0,
      removal: 0,
    });
    await expectFilesystemTree(root, before);
  });
  it('recovers a fresh Node port from the post-apply rollback phase with a complete filesystem snapshot', async () => {
    const fixture = await createSetupRecoveryFixture('created-authority');
    const beforeTree = await captureFilesystemTree(fixture.root);
    const beforeSurface = await captureRecoverySurfaceSnapshot(fixture.recoverySurfacePaths);

    const crash = await runSetupCrashChild({
      crashPoint: 'post-apply',
      credentialPath: fixture.credentialPath,
      home: fixture.home,
      projectId: 'created-authority',
      root: fixture.root,
    });

    expect(crash).toStrictEqual({
      crashPoint: 'post-apply',
      credentialPublishCalls: 1,
      credentialReserveCalls: 1,
      directoryReserveCalls: 1,
      entropyCalls: 1,
      identifierCalls: 1,
      lockAcquisitions: 1,
    });
    const durable = parseWalRecordJsonV2(await readFile(fixture.walPath, 'utf8'));
    expect(durable).toMatchObject({
      direction: 'rollback',
      operation: 'setup',
      phase: 'finalized',
    });
    assertExactSetupCredentialWal(durable, {
      path: fixture.credentialPath,
      projectId: 'created-authority',
    });
    expect(await captureFilesystemTree(fixture.root)).not.toEqual(beforeTree);

    let recoveryEntropyCalls = 0;
    let recoveryIdentifierCalls = 0;
    const freshPort = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: fixture.root,
      cwd: fixture.root,
      homeDirectory: fixture.home,
      host: { credentialPath: fixture.credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'created-authority',
        root: fixture.root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      random: {
        fill: (candidate) => {
          recoveryEntropyCalls += 1;
          candidate.fill(0);
        },
        uuid: () => {
          recoveryIdentifierCalls += 1;
          return 'recovery-must-not-create-a-mutation';
        },
      },
      transactionPort: createNodeLifecycleTransactionPort(),
      verification: verification(),
    });
    const inspection = await freshPort.inspectLifecycle({ operation: 'setup' });
    if (inspection.authorizedWal === undefined) {
      throw new Error('fresh port did not authorize canonical post-apply recovery');
    }
    await expect(
      freshPort.recoverAuthorizedWal({ recoveryId: inspection.authorizedWal.recoveryId }),
    ).resolves.toBe('recovered');
    expect({ recoveryEntropyCalls, recoveryIdentifierCalls }).toStrictEqual({
      recoveryEntropyCalls: 0,
      recoveryIdentifierCalls: 0,
    });
    await expectFilesystemTree(fixture.root, beforeTree);
    await expectRecoverySurfaceSnapshot(fixture.recoverySurfacePaths, beforeSurface);
    const freshLockPort = createNodeLifecycleTransactionPort();
    const lock = await freshLockPort.acquireAdvisoryLock(fixture.lockPath);
    await lock.release();
  });
  it('converges a fresh Node port from the commit-decided phase with a complete filesystem snapshot', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-commit-recovery-')));
    roots.push(root);
    const credentialPath = join(root, '.credentials/token.env');
    const home = join(root, 'home');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const walPath = join(root, '.scg/onboarding/lifecycle.wal.v1.json');
    const manifestPath = join(root, '.scg/onboarding/manifest.v1.json');
    await Promise.all([
      mkdir(join(root, 'public'), { recursive: true, mode: 0o700 }),
      mkdir(home, { recursive: true, mode: 0o700 }),
    ]);
    await Promise.all([
      writeFile(join(root, '.gitignore'), '.credentials/token.env\n', { mode: 0o600 }),
      writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
        mode: 0o600,
      }),
    ]);
    const transactionPort = createNodeLifecycleTransactionPort();
    let commitDecisionWal: ReturnType<typeof parseWalRecordJsonV2> | undefined;
    transactionPort.removeExactWal = async (input) => {
      expect(input.current.path).toBe(walPath);
      commitDecisionWal = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
      throw new Error('simulated process loss after durable commit decision');
    };
    const port = createNodeLifecycleEnginePort({
      approval: async () => true,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'commit-recovery',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      random: {
        fill: (candidate) => candidate.fill(0),
        uuid: () => 'commit-recovery-mutation',
      },
      transactionPort,
      verification: successfulVerification(),
    });

    const interrupted = await runSetup(port);
    expect(interrupted).toMatchObject({
      code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      state: 'recovery-required',
    });
    expect(interrupted.failures).toStrictEqual([{ stage: 'active-publication' }]);
    if (commitDecisionWal === undefined) {
      throw new Error('post-publish setup did not retain its commit-decision WAL');
    }
    expect(commitDecisionWal).toMatchObject({
      direction: 'commit',
      operation: 'setup',
      phase: 'commit-decided',
    });
    assertExactSetupCredentialWal(commitDecisionWal, {
      path: credentialPath,
      projectId: 'commit-recovery',
    });
    const postPublishSnapshot = await captureFilesystemTree(root);
    const commitRecoverySurfacePaths = [
      credentialPath,
      dirname(credentialPath),
      join(home, '.scg/config.json'),
      join(home, '.scg/credential-authorities.v1.json'),
      join(root, 'public/index.html'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/runtime/host-integration-helper.mjs'),
      lockPath,
      manifestPath,
      walPath,
      join(root, '.scg/onboarding/receipt.v1.json'),
    ];
    const postPublishSurface = await captureRecoverySurfaceSnapshot(commitRecoverySurfacePaths);
    for (const path of [
      credentialPath,
      join(home, '.scg/config.json'),
      join(home, '.scg/credential-authorities.v1.json'),
      lockPath,
      manifestPath,
      walPath,
      join(root, 'public/index.html'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/runtime/host-integration-helper.mjs'),
    ]) {
      const snapshot = postPublishSnapshot.get(path);
      if (snapshot === undefined || snapshot.kind === 'absent') {
        throw new Error(`post-publish setup snapshot omitted ${path}`);
      }
    }
    expect([...postPublishSnapshot.keys()].filter(isLifecycleTemporaryPath)).toEqual([]);
    const activeSnapshot = new Map(postPublishSnapshot);
    activeSnapshot.delete(walPath);
    const activeSurface = new Map(postPublishSurface);
    activeSurface.set(walPath, { kind: 'absent' });

    const freshPort = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'commit-recovery',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      transactionPort: createNodeLifecycleTransactionPort(),
      verification: verification(),
    });
    const inspection = await freshPort.inspectLifecycle({ operation: 'setup' });
    if (inspection.authorizedWal === undefined) {
      throw new Error('fresh port did not authorize the commit-decision WAL');
    }
    await expect(
      freshPort.recoverAuthorizedWal({ recoveryId: inspection.authorizedWal.recoveryId }),
    ).resolves.toBe('recovered');
    await expectFilesystemTree(root, activeSnapshot);
    await expectRecoverySurfaceSnapshot(commitRecoverySurfacePaths, activeSurface);
    expect(
      [...(await captureFilesystemTree(root)).keys()].filter(isLifecycleTemporaryPath),
    ).toEqual([]);
    await expect(freshPort.inspectLifecycle({ operation: 'setup' })).resolves.toMatchObject({
      state: 'active',
    });
  });
  it.each([
    ['prepared/pre-write', 'prepared-pre-write', 0, 0, 0],
    ['directory reservation', 'directory-reserved-before-identity-wal', 0, 0, 1],
    ['credential reservation', 'credential-reserved-before-identity-wal', 0, 1, 1],
    ['post-credential publication', 'post-credential-publication', 1, 1, 1],
    ['post-parent publication', 'post-parent-publication', 0, 0, 1],
  ] as const)(
    'recovers a fresh Node port from the %s durable rollback phase with complete recovery snapshots',
    async (
      _label,
      crashPoint,
      expectedCredentialPublications,
      expectedCredentialReservations,
      expectedDirectoryReservations,
    ) => {
      const projectId = `phase-recovery-${crashPoint}`;
      const fixture = await createSetupRecoveryFixture(projectId);
      const beforeTree = await captureFilesystemTree(fixture.root);
      const beforeSurface = await captureRecoverySurfaceSnapshot(fixture.recoverySurfacePaths);
      const beforeLock = await capturePathSnapshot(fixture.lockPath);

      const crash = await runSetupCrashChild({
        crashPoint,
        credentialPath: fixture.credentialPath,
        home: fixture.home,
        projectId,
        root: fixture.root,
      });

      expect(crash).toStrictEqual({
        crashPoint,
        credentialPublishCalls: expectedCredentialPublications,
        credentialReserveCalls: expectedCredentialReservations,
        directoryReserveCalls: expectedDirectoryReservations,
        entropyCalls: 1,
        identifierCalls: 1,
        lockAcquisitions: 1,
      });
      const durable = parseWalRecordJsonV2(await readFile(fixture.walPath, 'utf8'));
      expect(durable).toMatchObject({
        direction: 'rollback',
        operation: 'setup',
      });
      const expectedDurableCursor =
        crashPoint === 'credential-reserved-before-identity-wal' ||
        crashPoint === 'post-credential-publication'
          ? 1
          : 0;
      const expectedCredentialMutationCount = crashPoint === 'post-credential-publication' ? 1 : 0;
      const reservationBoundary =
        crashPoint === 'directory-reserved-before-identity-wal' ||
        crashPoint === 'credential-reserved-before-identity-wal';
      const expectedCreationIntentsAbsent =
        crashPoint !== 'prepared-pre-write' && !reservationBoundary;
      let reservationPaths: readonly string[] = [];
      if (
        crashPoint === 'prepared-pre-write' ||
        crashPoint === 'directory-reserved-before-identity-wal'
      ) {
        assertDurableCreationIntent(durable, {
          kind: 'directory',
          mode: 0o700,
          targetPath: join(fixture.root, '.scg/runtime'),
        });
      } else if (crashPoint === 'credential-reserved-before-identity-wal') {
        assertDurableCredentialCreationIntentAfterDirectory(
          durable,
          join(fixture.root, '.scg/runtime'),
          fixture.credentialPath,
        );
      } else if (crashPoint === 'post-credential-publication') {
        assertExactSetupCredentialWal(durable, {
          path: fixture.credentialPath,
          projectId,
        });
      } else {
        assertDurableDirectoryPublication(durable, join(fixture.root, '.scg/runtime'));
      }
      if (reservationBoundary) {
        reservationPaths = await assertReservedCreationIntentFilesystem(durable);
      }
      expect({
        cursor: durable.cursor,
        direction: durable.direction,
        operation: durable.operation,
        phase: durable.phase,
      }).toStrictEqual({
        cursor: expectedDurableCursor,
        direction: 'rollback',
        operation: 'setup',
        phase: 'prepared',
      });
      expect(durable.creationIntents === undefined).toBe(expectedCreationIntentsAbsent);
      expect(durable.mutations.filter((mutation) => mutation.kind === 'credential')).toHaveLength(
        expectedCredentialMutationCount,
      );

      let recoveryEntropyCalls = 0;
      let recoveryIdentifierCalls = 0;
      const freshPort = createNodeLifecycleEnginePort({
        approval: async () => false,
        checkoutRoot: fixture.root,
        cwd: fixture.root,
        homeDirectory: fixture.home,
        host: { credentialPath: fixture.credentialPath, port: 4175 },
        project: {
          allowedOrigins: ['http://127.0.0.1:4175'],
          framework: 'html',
          projectId,
          root: fixture.root,
          tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        },
        random: {
          fill: (candidate) => {
            recoveryEntropyCalls += 1;
            candidate.fill(0);
          },
          uuid: () => {
            recoveryIdentifierCalls += 1;
            return 'recovery-must-not-create-a-mutation';
          },
        },
        transactionPort: createNodeLifecycleTransactionPort(),
        verification: verification(),
      });
      let recoveryPort = freshPort;
      if (crashPoint === 'prepared-pre-write') {
        const originalWal = await readFile(fixture.walPath, 'utf8');
        const originalRecord = JSON.parse(originalWal) as Record<string, unknown>;
        const originalWalSnapshot = await capturePathSnapshot(fixture.walPath);
        if (originalWalSnapshot.kind !== 'file' || originalWalSnapshot.mode !== 0o600) {
          throw new Error('prepared WAL fixture did not retain an exact canonical WAL file');
        }
        const originalRecoveryTree = await captureFilesystemTree(fixture.root);
        const originalRecoveryLock = await capturePathSnapshot(fixture.lockPath);
        const bindCanonicalWal = (record: Record<string, unknown>): string => {
          const unbound = {
            ...record,
            authorityFingerprint: `sha256:${'0'.repeat(64)}`,
          };
          return serializeWalRecordV2({
            ...record,
            authorityFingerprint: sha256(serializeWalRecordV2(unbound)),
          });
        };
        const corruptions = [
          {
            name: 'stale-fingerprint',
            rebind: false,
            expectedFailureStage: 'wal-authority',
            corrupt: (intent: Record<string, unknown>) => {
              const validationToken = intent.validationToken;
              if (typeof validationToken !== 'string') {
                throw new Error('prepared WAL omitted its durable creation intent token');
              }
              intent.validationToken = validationToken.replace(
                /([a-f0-9]{31})([a-f0-9])$/,
                (_whole: string, prefix: string, last: string) =>
                  `${prefix}${last === '0' ? '1' : '0'}`,
              );
            },
          },
          {
            name: 'canonically-rebound-semantic-authority',
            rebind: true,
            expectedFailureStage: 'wal-authority',
            corrupt: (intent: Record<string, unknown>) => {
              const validationToken = intent.validationToken;
              if (typeof validationToken !== 'string') {
                throw new Error('prepared WAL omitted its durable creation intent token');
              }
              intent.validationToken = validationToken.replace(
                /([a-f0-9]{31})([a-f0-9])$/,
                (_whole: string, prefix: string, last: string) =>
                  `${prefix}${last === '0' ? '1' : '0'}`,
              );
            },
          },
          {
            name: 'canonically-rebound-native-authority',
            rebind: true,
            expectedFailureStage: 'wal-authority',
            corrupt: (intent: Record<string, unknown>) => {
              if (intent.kind !== 'directory' || intent.mode !== 0o700) {
                throw new Error('prepared WAL omitted its durable directory authority');
              }
              intent.mode = 0o600;
            },
          },
        ] as const;
        for (const { name, corrupt, rebind, expectedFailureStage } of corruptions) {
          const corrupted = structuredClone(originalRecord) as Record<string, unknown>;
          const creationIntents = corrupted.creationIntents;
          if (!Array.isArray(creationIntents)) {
            throw new Error('prepared WAL omitted its durable creation intent authority');
          }
          const intent = creationIntents[0];
          if (intent === null || typeof intent !== 'object' || Array.isArray(intent)) {
            throw new Error('prepared WAL omitted its durable creation intent authority');
          }
          corrupt(intent as Record<string, unknown>);
          const canonicalCorruptedWal = rebind
            ? bindCanonicalWal(corrupted)
            : serializeWalRecordV2(corrupted);
          const roundTrippedWal = serializeWalRecordV2(parseWalRecordJsonV2(canonicalCorruptedWal));
          if (roundTrippedWal !== canonicalCorruptedWal) {
            throw new Error('corrupted WAL did not preserve its canonical serialization');
          }
          await writeFile(fixture.walPath, canonicalCorruptedWal, { mode: 0o600 });
          const corruptedWal = await readFile(fixture.walPath, 'utf8');
          const corruptedTree = await captureFilesystemTree(fixture.root);
          const corruptedLock = await capturePathSnapshot(fixture.lockPath);
          const inspection = await freshPort.inspectLifecycle({ operation: 'setup' });
          if (inspection.authorizedWal === undefined) {
            throw new Error(`${name} corruption did not expose bounded recovery authority`);
          }
          const recoveryId = inspection.authorizedWal.recoveryId;
          await assertCorruptedWalRecoveryFailsClosed({
            canonicalCorruptedWal,
            corruptedLock,
            corruptionName: name,
            corruptedTree,
            corruptedWal,
            expectedFailureStage,
            lockPath: fixture.lockPath,
            recoverAuthorizedWal: () => freshPort.recoverAuthorizedWal({ recoveryId }),
            root: fixture.root,
            walPath: fixture.walPath,
          });
          await writeFile(fixture.walPath, originalWal, { mode: originalWalSnapshot.mode });
          await chmod(fixture.walPath, originalWalSnapshot.mode);
          await expectPreparedWalFixtureRestored({
            expectedLock: originalRecoveryLock,
            expectedTree: originalRecoveryTree,
            expectedWal: originalWalSnapshot,
            lockPath: fixture.lockPath,
            root: fixture.root,
            walPath: fixture.walPath,
          });
        }
        recoveryPort = createNodeLifecycleEnginePort({
          approval: async () => false,
          checkoutRoot: fixture.root,
          cwd: fixture.root,
          homeDirectory: fixture.home,
          host: { credentialPath: fixture.credentialPath, port: 4175 },
          project: {
            allowedOrigins: ['http://127.0.0.1:4175'],
            framework: 'html',
            projectId,
            root: fixture.root,
            tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
          },
          random: {
            fill: (candidate) => {
              recoveryEntropyCalls += 1;
              candidate.fill(0);
            },
            uuid: () => {
              recoveryIdentifierCalls += 1;
              return 'recovery-must-not-create-a-mutation';
            },
          },
          transactionPort: createNodeLifecycleTransactionPort(),
          verification: verification(),
        });
      }
      const inspection = await recoveryPort.inspectLifecycle({ operation: 'setup' });
      if (inspection.authorizedWal === undefined) {
        throw new Error(`fresh port did not authorize ${crashPoint} recovery`);
      }
      await expect(
        recoveryPort.recoverAuthorizedWal({ recoveryId: inspection.authorizedWal.recoveryId }),
      ).resolves.toBe('recovered');
      expect({ recoveryEntropyCalls, recoveryIdentifierCalls }).toStrictEqual({
        recoveryEntropyCalls: 0,
        recoveryIdentifierCalls: 0,
      });
      await expectFilesystemTree(fixture.root, beforeTree);
      await expectRecoverySurfaceSnapshot(fixture.recoverySurfacePaths, beforeSurface);
      await Promise.all(
        reservationPaths.map(async (path) => {
          await expect(lstat(path)).rejects.toMatchObject({ code: 'ENOENT' });
        }),
      );
      expect(await capturePathSnapshot(fixture.lockPath)).toEqual(beforeLock);
      expect(
        [...(await captureFilesystemTree(fixture.root)).keys()].filter(isLifecycleTemporaryPath),
      ).toEqual([]);
      const freshLockPort = createNodeLifecycleTransactionPort();
      const lock = await freshLockPort.acquireAdvisoryLock(fixture.lockPath);
      await lock.release();
    },
  );
  it('rejects stale, foreign, and reused WAL snapshot capabilities without detaching an unproven reservation', async () => {
    const stale = await createWalSnapshotRetentionFixture('stale');
    const stalePort = createNodeLifecycleTransactionPort();
    const staleLock = await stalePort.acquireAdvisoryLock(stale.lockPath);
    const staleSnapshot = await stalePort.readWalFileNoFollow({
      lock: staleLock,
      path: stale.walPath,
    });
    if (staleSnapshot === undefined) {
      throw new Error('stale snapshot fixture did not expose its canonical WAL');
    }
    staleSnapshot.bytes.fill(0);
    const staleReservation = await stalePort.reserveStagedDirectory({
      lock: staleLock,
      creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
        stale.stagingPath,
        'directory',
        0o700,
      ),
      path: stale.stagingPath,
      targetPath: stale.targetPath,
      mode: 0o700,
    });
    await rm(stale.walPath, { force: true });
    await writeFile(stale.walPath, 'replacement-wal\n', { mode: 0o600 });
    const staleTreeBefore = await captureFilesystemTree(stale.root);
    const staleLockBefore = await capturePathSnapshot(stale.lockPath);
    const staleFirst = await stalePort.retainReservedStagedDirectoryForRecovery({
      lock: staleLock,
      reservation: staleReservation,
      snapshot: staleSnapshot.snapshot,
    });
    const [staleTreeAfterFirst, staleLockAfterFirst] = await Promise.all([
      captureFilesystemTree(stale.root),
      capturePathSnapshot(stale.lockPath),
    ]);
    const staleSecond = await stalePort.retainReservedStagedDirectoryForRecovery({
      lock: staleLock,
      reservation: staleReservation,
      snapshot: staleSnapshot.snapshot,
    });
    const [staleTreeAfterSecond, staleLockAfterSecond] = await Promise.all([
      captureFilesystemTree(stale.root),
      capturePathSnapshot(stale.lockPath),
    ]);
    expect({
      results: [staleFirst, staleSecond],
      trees: [staleTreeAfterFirst, staleTreeAfterSecond],
      locks: [staleLockAfterFirst, staleLockAfterSecond],
    }).toStrictEqual({
      results: [{ state: 'indeterminate' }, { state: 'indeterminate' }],
      trees: [staleTreeBefore, staleTreeBefore],
      locks: [staleLockBefore, staleLockBefore],
    });
    await expect(
      stalePort.discardReservedStagedDirectory({
        lock: staleLock,
        reservation: staleReservation,
      }),
    ).resolves.toEqual({ state: 'completed' });
    await expect(lstat(stale.stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await staleLock.release();
    const generation = await createWalSnapshotRetentionFixture('lock-generation');
    const generationPort = createNodeLifecycleTransactionPort();
    const generationLockA = await generationPort.acquireAdvisoryLock(generation.lockPath);
    const generationSnapshot = await generationPort.readWalFileNoFollow({
      lock: generationLockA,
      path: generation.walPath,
    });
    if (generationSnapshot === undefined) {
      throw new Error('lock-generation fixture did not expose its canonical WAL');
    }
    generationSnapshot.bytes.fill(0);
    await generationLockA.release();
    const generationLockB = await generationPort.acquireAdvisoryLock(generation.lockPath);
    const generationReservation = await generationPort.reserveStagedDirectory({
      lock: generationLockB,
      creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
        generation.stagingPath,
        'directory',
        0o700,
      ),
      path: generation.stagingPath,
      targetPath: generation.targetPath,
      mode: 0o700,
    });
    const generationTreeBefore = await captureFilesystemTree(generation.root);
    const generationLockBefore = await capturePathSnapshot(generation.lockPath);
    const generationRetention = await generationPort.retainReservedStagedDirectoryForRecovery({
      lock: generationLockB,
      reservation: generationReservation,
      snapshot: generationSnapshot.snapshot,
    });
    const [generationTreeAfter, generationLockAfter] = await Promise.all([
      captureFilesystemTree(generation.root),
      capturePathSnapshot(generation.lockPath),
    ]);
    expect({
      result: generationRetention,
      tree: generationTreeAfter,
      lock: generationLockAfter,
    }).toStrictEqual({
      result: { state: 'indeterminate' },
      tree: generationTreeBefore,
      lock: generationLockBefore,
    });
    await expect(
      generationPort.discardReservedStagedDirectory({
        lock: generationLockB,
        reservation: generationReservation,
      }),
    ).resolves.toEqual({ state: 'completed' });
    await expect(lstat(generation.stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await generationLockB.release();

    const foreignSource = await createWalSnapshotRetentionFixture('foreign-source');
    const foreignSourcePort = createNodeLifecycleTransactionPort();
    const foreignSourceLock = await foreignSourcePort.acquireAdvisoryLock(foreignSource.lockPath);
    const foreignSnapshot = await foreignSourcePort.readWalFileNoFollow({
      lock: foreignSourceLock,
      path: foreignSource.walPath,
    });
    if (foreignSnapshot === undefined) {
      throw new Error('foreign snapshot fixture did not expose its canonical WAL');
    }
    foreignSnapshot.bytes.fill(0);
    await foreignSourceLock.release();

    const foreign = await createWalSnapshotRetentionFixture('foreign-target');
    const foreignPort = createNodeLifecycleTransactionPort();
    const foreignLock = await foreignPort.acquireAdvisoryLock(foreign.lockPath);
    const foreignReservation = await foreignPort.reserveStagedDirectory({
      lock: foreignLock,
      creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
        foreign.stagingPath,
        'directory',
        0o700,
      ),
      path: foreign.stagingPath,
      targetPath: foreign.targetPath,
      mode: 0o700,
    });
    const foreignTreeBefore = await captureFilesystemTree(foreign.root);
    const foreignLockBefore = await capturePathSnapshot(foreign.lockPath);
    const foreignFirst = await foreignPort.retainReservedStagedDirectoryForRecovery({
      lock: foreignLock,
      reservation: foreignReservation,
      snapshot: foreignSnapshot.snapshot,
    });
    const [foreignTreeAfterFirst, foreignLockAfterFirst] = await Promise.all([
      captureFilesystemTree(foreign.root),
      capturePathSnapshot(foreign.lockPath),
    ]);
    const foreignSecond = await foreignPort.retainReservedStagedDirectoryForRecovery({
      lock: foreignLock,
      reservation: foreignReservation,
      snapshot: foreignSnapshot.snapshot,
    });
    const [foreignTreeAfterSecond, foreignLockAfterSecond] = await Promise.all([
      captureFilesystemTree(foreign.root),
      capturePathSnapshot(foreign.lockPath),
    ]);
    expect({
      results: [foreignFirst, foreignSecond],
      trees: [foreignTreeAfterFirst, foreignTreeAfterSecond],
      locks: [foreignLockAfterFirst, foreignLockAfterSecond],
    }).toStrictEqual({
      results: [{ state: 'indeterminate' }, { state: 'indeterminate' }],
      trees: [foreignTreeBefore, foreignTreeBefore],
      locks: [foreignLockBefore, foreignLockBefore],
    });
    await expect(
      foreignPort.discardReservedStagedDirectory({
        lock: foreignLock,
        reservation: foreignReservation,
      }),
    ).resolves.toEqual({ state: 'completed' });
    await expect(lstat(foreign.stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await foreignLock.release();

    const reused = await createWalSnapshotRetentionFixture('reused');
    const reusedPort = createNodeLifecycleTransactionPort();
    const reusedLock = await reusedPort.acquireAdvisoryLock(reused.lockPath);
    const reusedSnapshot = await reusedPort.readWalFileNoFollow({
      lock: reusedLock,
      path: reused.walPath,
    });
    if (reusedSnapshot === undefined) {
      throw new Error('reused snapshot fixture did not expose its canonical WAL');
    }
    reusedSnapshot.bytes.fill(0);
    const firstReservation = await reusedPort.reserveStagedDirectory({
      lock: reusedLock,
      creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
        reused.stagingPath,
        'directory',
        0o700,
      ),
      path: reused.stagingPath,
      targetPath: reused.targetPath,
      mode: 0o700,
    });
    await expect(
      reusedPort.retainReservedStagedDirectoryForRecovery({
        lock: reusedLock,
        reservation: firstReservation,
        snapshot: reusedSnapshot.snapshot,
      }),
    ).resolves.toEqual({ state: 'completed' });
    const reusedReservationPath = `${reused.stagingPath}.reused`;
    const reusedReservation = await reusedPort.reserveStagedDirectory({
      lock: reusedLock,
      creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
        reusedReservationPath,
        'directory',
        0o700,
      ),
      path: reusedReservationPath,
      targetPath: `${reused.targetPath}.reused`,
      mode: 0o700,
    });
    const reusedTreeBefore = await captureFilesystemTree(reused.root);
    const reusedLockBefore = await capturePathSnapshot(reused.lockPath);
    const reusedFirst = await reusedPort.retainReservedStagedDirectoryForRecovery({
      lock: reusedLock,
      reservation: reusedReservation,
      snapshot: reusedSnapshot.snapshot,
    });
    const [reusedTreeAfterFirst, reusedLockAfterFirst] = await Promise.all([
      captureFilesystemTree(reused.root),
      capturePathSnapshot(reused.lockPath),
    ]);
    const reusedSecond = await reusedPort.retainReservedStagedDirectoryForRecovery({
      lock: reusedLock,
      reservation: reusedReservation,
      snapshot: reusedSnapshot.snapshot,
    });
    const [reusedTreeAfterSecond, reusedLockAfterSecond] = await Promise.all([
      captureFilesystemTree(reused.root),
      capturePathSnapshot(reused.lockPath),
    ]);
    expect({
      results: [reusedFirst, reusedSecond],
      trees: [reusedTreeAfterFirst, reusedTreeAfterSecond],
      locks: [reusedLockAfterFirst, reusedLockAfterSecond],
    }).toStrictEqual({
      results: [{ state: 'indeterminate' }, { state: 'indeterminate' }],
      trees: [reusedTreeBefore, reusedTreeBefore],
      locks: [reusedLockBefore, reusedLockBefore],
    });
    await expect(
      reusedPort.discardReservedStagedDirectory({
        lock: reusedLock,
        reservation: reusedReservation,
      }),
    ).resolves.toEqual({ state: 'completed' });
    await expect(lstat(reusedReservationPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await reusedLock.release();
  });
  it('rejects stale WAL snapshots for generic and credential retained stages without mutation', async () => {
    for (const surface of ['generic', 'credential'] as const) {
      const fixture = await createWalSnapshotRetentionFixture(`stale-${surface}`);
      const port = createNodeLifecycleTransactionPort();
      const lock = await port.acquireAdvisoryLock(fixture.lockPath);
      const snapshot = await port.readWalFileNoFollow({ lock, path: fixture.walPath });
      if (snapshot === undefined) {
        throw new Error('retention fixture did not expose its canonical WAL');
      }
      snapshot.bytes.fill(0);
      let retain: () => Promise<unknown>;
      let discard: () => Promise<unknown>;
      let stagePath: string;
      if (surface === 'generic') {
        stagePath = `${fixture.stagingPath}.file`;
        const stage = await port.stageWrite({
          lock,
          stagingPath: stagePath,
          creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(stagePath, 'file', 0o600),
          bytes: Buffer.from('noncredential-stage\n', 'utf8'),
          mode: 0o600,
        });
        retain = () =>
          port.retainStagedWriteForRecovery({ lock, stage, snapshot: snapshot.snapshot });
        discard = () => port.discardStagedWrite({ lock, stage });
      } else {
        stagePath = `${fixture.stagingPath}.credential`;
        const reservation = await port.reserveStagedWrite({
          lock,
          creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
            stagePath,
            'credential',
            0o600,
          ),
          path: stagePath,
          mode: 0o600,
        });
        retain = () =>
          port.retainReservedStagedWriteForRecovery({
            lock,
            reservation,
            snapshot: snapshot.snapshot,
          });
        discard = () => port.discardReservedStagedWrite({ lock, reservation });
      }
      await rm(fixture.walPath, { force: true });
      await writeFile(fixture.walPath, 'replacement-wal\n', { mode: 0o600 });
      const treeBefore = await captureFilesystemTree(fixture.root);
      const lockBefore = await capturePathSnapshot(fixture.lockPath);
      const first = await retain();
      const [treeAfterFirst, lockAfterFirst] = await Promise.all([
        captureFilesystemTree(fixture.root),
        capturePathSnapshot(fixture.lockPath),
      ]);
      const second = await retain();
      const [treeAfterSecond, lockAfterSecond] = await Promise.all([
        captureFilesystemTree(fixture.root),
        capturePathSnapshot(fixture.lockPath),
      ]);
      expect({
        surface,
        results: [first, second],
        trees: [treeAfterFirst, treeAfterSecond],
        locks: [lockAfterFirst, lockAfterSecond],
      }).toStrictEqual({
        surface,
        results: [{ state: 'indeterminate' }, { state: 'indeterminate' }],
        trees: [treeBefore, treeBefore],
        locks: [lockBefore, lockBefore],
      });
      await expect(discard()).resolves.toEqual({ state: 'completed' });
      await expect(lstat(stagePath)).rejects.toMatchObject({ code: 'ENOENT' });
      await lock.release();
    }
  });
  it('rejects every production lifecycle auxiliary naming class from terminal trees', () => {
    expect(
      [
        '/fixture/lifecycle.wal.v1.json.scene-glass-wal.stage',
        '/fixture/manifest.v1.json.scene-glass-operation-0.rollback',
        '/fixture/receipt.v1.json.scene-glass-operation-0.quarantine',
        '/fixture/.scg-intent-0123456789abcdef-credential-600-0123456789abcdef0123456789abcdef.marker',
      ].every(isLifecycleTemporaryPath),
    ).toBe(true);
    expect(
      [
        '/fixture/.scg/onboarding/manifest.v1.json',
        '/fixture/.scg/runtime/host-descriptor.v1.json',
        '/fixture/credential-authorities.v1.json',
      ].some(isLifecycleTemporaryPath),
    ).toBe(false);
  });
  it('runs setup once under durable lock/WAL authority before deleting its created credential on uninstall', async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), 'scene-glass-node-uninstall-secret-')),
    );
    roots.push(root);
    const credentialPath = join(root, '.env.scene-glass.local');
    const home = join(root, 'home');
    await Promise.all([
      mkdir(join(root, 'public'), { recursive: true, mode: 0o700 }),
      mkdir(home, { recursive: true, mode: 0o700 }),
    ]);
    await Promise.all([
      writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 }),
      writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
        mode: 0o600,
      }),
    ]);
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const walPath = join(root, '.scg/onboarding/lifecycle.wal.v1.json');
    const transactionPort = createNodeLifecycleTransactionPort();
    const serializedWals: string[] = [];
    const observedWalStagePaths: string[] = [];
    const expectedWalStagePaths: string[] = [];
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    const stageWrite = transactionPort.stageWrite.bind(transactionPort);
    const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
    const renameReservedStagedWrite =
      transactionPort.renameReservedStagedWrite.bind(transactionPort);
    const writeReservedStagedWrite = transactionPort.writeReservedStagedWrite.bind(transactionPort);
    const quarantineExactFile = transactionPort.quarantineExactFile.bind(transactionPort);
    const issuedCandidates: Uint8Array[] = [];
    let entropyCalls = 0;
    let identifierCalls = 0;
    let credentialReserveCount = 0;
    let credentialWriteCount = 0;
    let credentialPublishCount = 0;
    let setupCommitObservedHeldLock = false;
    let setupCommitLockError: unknown;
    let preparedCredentialWal: ReturnType<typeof parseWalRecordJsonV2> | undefined;
    let credentialDeletionObservedLock = false;
    let credentialDeletionLockError: unknown;
    let credentialDeletionWal: ReturnType<typeof parseWalRecordJsonV2> | undefined;
    transactionPort.acquireAdvisoryLock = async (path) => {
      expect(path).toBe(lockPath);
      return acquireAdvisoryLock(path);
    };
    transactionPort.stageWrite = async (input) => {
      const walStagePrefix = `${walPath}.scene-glass-`;
      if (input.stagingPath.startsWith(walStagePrefix) && input.stagingPath.endsWith('.stage')) {
        const serializedWal = new TextDecoder('utf-8', { fatal: true }).decode(input.bytes);
        const record = parseWalRecordJsonV2(serializedWal);
        observedWalStagePaths.push(input.stagingPath);
        expectedWalStagePaths.push(`${walPath}.scene-glass-wal.stage`);
        serializedWals.push(serializedWal);
        if (record.operation === 'setup' && record.direction === 'commit') {
          setupCommitLockError = await expectLifecycleLockContention(() =>
            acquireAdvisoryLock(lockPath),
          );
          setupCommitObservedHeldLock = true;
        }
      }
      return stageWrite(input);
    };
    transactionPort.reserveStagedWrite = async (input) => {
      credentialReserveCount += 1;
      expect(input.mode).toBe(0o600);
      return reserveStagedWrite(input);
    };
    transactionPort.writeReservedStagedWrite = async (input) => {
      credentialWriteCount += 1;
      await expectLifecycleLockContention(() => acquireAdvisoryLock(lockPath));
      const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
      expect(durable).toMatchObject({
        direction: 'rollback',
        operation: 'setup',
        phase: 'prepared',
      });
      assertExactSetupCredentialWal(durable, {
        path: credentialPath,
        projectId: 'uninstall-created-credential',
      });
      preparedCredentialWal = durable;
      return writeReservedStagedWrite(input);
    };
    transactionPort.renameReservedStagedWrite = async (input) => {
      credentialPublishCount += 1;
      expect(input.targetPath).toBe(credentialPath);
      return renameReservedStagedWrite(input);
    };
    transactionPort.quarantineExactFile = async (input) => {
      if (input.path === credentialPath) {
        credentialDeletionLockError = await expectLifecycleLockContention(() =>
          acquireAdvisoryLock(lockPath),
        );
        credentialDeletionObservedLock = true;
        credentialDeletionWal = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
      }
      return quarantineExactFile(input);
    };
    const port = createNodeLifecycleEnginePort({
      approval: async () => true,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'uninstall-created-credential',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      random: {
        fill: (candidate) => {
          entropyCalls += 1;
          issuedCandidates.push(candidate);
          candidate.fill(0);
        },
        uuid: () => {
          identifierCalls += 1;
          return 'uninstall-created-credential-mutation';
        },
      },
      transactionPort,
      verification: successfulVerification(),
    });

    const setupResult = await runSetup(port);
    expect(setupResult).toMatchObject({
      code: 'SCG_LIFECYCLE_ACTIVE',
      state: 'active',
    });
    const expectedCredentialLine = credentialEnvelope('uninstall-created-credential', TOKEN);
    const credentialCanaries = credentialSecretCanaries(TOKEN, expectedCredentialLine);
    expect(setupCommitObservedHeldLock).toBe(true);
    expectLifecycleLockContentionError(setupCommitLockError);
    const lockAfterSetup = await acquireAdvisoryLock(lockPath);
    await lockAfterSetup.release();
    const runtimeDirectoryPath = join(root, '.scg/runtime');
    const [credentialStat, runtimeDirectoryStat] = await Promise.all([
      lstat(credentialPath, { bigint: true }),
      lstat(runtimeDirectoryPath, { bigint: true }),
    ]);
    expect(credentialStat.isFile()).toBe(true);
    expect(Number(credentialStat.mode & 0o777n)).toBe(0o600);
    expect(issuedCandidates).toEqual([new Uint8Array(32)]);
    expect(entropyCalls).toBe(1);
    expect(identifierCalls).toBe(1);
    expect(credentialReserveCount).toBe(1);
    expect(credentialWriteCount).toBe(1);
    expect(credentialPublishCount).toBe(1);
    if (preparedCredentialWal === undefined) {
      throw new Error('credential write did not observe a durable prepared WAL');
    }
    assertExactSetupCredentialWal(preparedCredentialWal, {
      path: credentialPath,
      projectId: 'uninstall-created-credential',
    });
    expect(preparedCredentialWal).toMatchObject({
      direction: 'rollback',
      operation: 'setup',
      phase: 'prepared',
    });
    const expectedCredentialObservation = {
      kind: 'file',
      identity: {
        device: credentialStat.dev.toString(10),
        inode: credentialStat.ino.toString(10),
      },
      mode: 0o600,
    };
    const configPath = join(home, '.scg/config.json');
    const registryPath = join(home, '.scg/credential-authorities.v1.json');
    const loaderPath = join(root, 'public/index.html');
    const descriptorPath = join(root, '.scg/runtime/host-descriptor.v1.json');
    const helperPath = join(root, '.scg/runtime/host-integration-helper.mjs');
    const serverTokenEnv = canonicalServerTokenEnvForProjectId('uninstall-created-credential');
    const selectedProject = {
      allowedOrigins: ['http://127.0.0.1:4175'],
      framework: 'html',
      projectId: 'uninstall-created-credential',
      root,
      tokenEnv: serverTokenEnv,
    };
    const configImage = { schemaVersion: 1 as const, projects: [selectedProject] };
    const registryEntry = {
      projectId: 'uninstall-created-credential',
      tokenEnv: serverTokenEnv,
      canonicalRoot: root,
      credentialPath,
      device: credentialStat.dev.toString(10),
      inode: credentialStat.ino.toString(10),
    };
    const registryImage = { schemaVersion: 1 as const, projects: [registryEntry] };
    const configBytes = serializeConfigV1(configImage);
    const registryBytes = serializeCredentialAuthorityRegistryV1(registryImage);
    await expect(readFile(configPath, 'utf8')).resolves.toBe(configBytes);
    await expect(readFile(registryPath, 'utf8')).resolves.toBe(registryBytes);
    await expect(readFile(credentialPath, 'utf8')).resolves.toBe(expectedCredentialLine);
    await expectNoSecretResidualFiles([root, home], new Set([credentialPath]), credentialCanaries);
    const [loaderBytes, descriptorBytes, helperBytes, manifestBytes] = await Promise.all([
      readFile(loaderPath),
      readFile(descriptorPath),
      readFile(helperPath),
      readFile(join(root, '.scg/onboarding/manifest.v1.json'), 'utf8'),
    ]);
    const persistedDescriptor = JSON.parse(descriptorBytes.toString('utf8')) as {
      readonly credentialAuthorities?: unknown;
    };
    expect(persistedDescriptor.credentialAuthorities).toEqual([
      {
        device: credentialStat.dev.toString(10),
        inode: credentialStat.ino.toString(10),
        path: credentialPath,
        projectId: 'uninstall-created-credential',
      },
    ]);
    const loaderFingerprint = sha256(loaderBytes);
    const descriptorFingerprint = sha256(descriptorBytes);
    const helperFingerprint = sha256(helperBytes);
    const configFingerprint = sha256(configBytes);
    const registryFingerprint = sha256(registryBytes);
    const configHunk = {
      fingerprint: sha256(JSON.stringify(JSON.parse(configBytes) as unknown)),
      id: lifecycleId(`config-hunk:${configPath}:uninstall-created-credential`),
      operation: 'insert',
      subject: 'uninstall-created-credential',
    };
    const loaderHunk = {
      fingerprint: loaderFingerprint,
      id: `scg-html-loader-${sha256('id:uninstall-created-credential:html:loader').slice(7, 23)}`,
      operation: 'insert',
      subject: 'scg-html-loader',
    };
    const descriptorHunk = {
      fingerprint: descriptorFingerprint,
      id: `scg-html-descriptor-${sha256('id:uninstall-created-credential:html:descriptor').slice(7, 23)}`,
      operation: 'insert',
      subject: 'scg-html-descriptor',
    };
    const helperHunk = {
      fingerprint: helperFingerprint,
      id: `scg-html-helper-${sha256('id:uninstall-created-credential:html:helper').slice(7, 23)}`,
      operation: 'insert',
      subject: 'scg-html-helper',
    };
    const createdDirectoryArtifact = (path: string, stat: Awaited<ReturnType<typeof lstat>>) => ({
      identity: {
        device: stat.dev.toString(10),
        inode: stat.ino.toString(10),
      },
      inverse: {
        emptyOnly: true,
        identity: {
          device: stat.dev.toString(10),
          inode: stat.ino.toString(10),
        },
        kind: 'delete-created-directory' as const,
        mode: 0o700,
        path,
      },
      kind: 'directory' as const,
      mode: 0o700,
      path,
    });
    expect(parseSetupManifestJsonV1(manifestBytes)).toEqual({
      artifacts: [
        {
          fingerprint: configFingerprint,
          hunks: [configHunk],
          inverse: {
            kind: 'restore-config',
            path: configPath,
            postimage: configImage,
            preimage: { schemaVersion: 1, projects: [] },
          },
          kind: 'config',
          path: configPath,
          postimage: configImage,
          preimage: { schemaVersion: 1, projects: [] },
        },
        {
          fingerprint: loaderFingerprint,
          hunks: [loaderHunk],
          inverse: {
            hunks: [loaderHunk],
            kind: 'restore-owned-file',
            path: loaderPath,
            postimageFingerprint: loaderFingerprint,
            preimageFingerprint: sha256('<html><head></head><body></body></html>\n'),
            ownedInsertion: 'preceding-newline-line',
          },
          kind: 'file',
          path: loaderPath,
        },
        {
          fingerprint: descriptorFingerprint,
          hunks: [descriptorHunk],
          inverse: {
            expectedFingerprint: descriptorFingerprint,
            kind: 'delete-created-file',
            path: descriptorPath,
          },
          kind: 'file',
          path: descriptorPath,
        },
        {
          fingerprint: helperFingerprint,
          hunks: [helperHunk],
          inverse: {
            expectedFingerprint: helperFingerprint,
            kind: 'delete-created-file',
            path: helperPath,
          },
          kind: 'file',
          path: helperPath,
        },
        {
          identity: {
            device: credentialStat.dev.toString(10),
            inode: credentialStat.ino.toString(10),
          },
          inverse: {
            kind: 'delete-created-credential',
            path: credentialPath,
            projectId: 'uninstall-created-credential',
            identity: {
              device: credentialStat.dev.toString(10),
              inode: credentialStat.ino.toString(10),
            },
            mode: 0o600,
            linkCount: 1,
          },
          kind: 'credential',
          linkCount: 1,
          mode: 0o600,
          ownership: 'setup-created',
          path: credentialPath,
          projectId: 'uninstall-created-credential',
        },
        {
          fingerprint: registryFingerprint,
          inverse: {
            kind: 'restore-credential-authority-registry-entry',
            path: registryPath,
            postimage: registryImage,
            preimage: { schemaVersion: 1, projects: [] },
          },
          kind: 'credential-authority-registry',
          path: registryPath,
          postimage: registryImage,
          preimage: { schemaVersion: 1, projects: [] },
        },
        createdDirectoryArtifact(runtimeDirectoryPath, runtimeDirectoryStat),
      ],
      installId: lifecycleId(
        JSON.stringify({
          canonicalRoot: root,
          projectId: 'uninstall-created-credential',
          predecessor: { state: 'absent' },
        }),
      ),
      kind: 'scene-glass-setup-manifest',
      schemaVersion: 1,
      state: 'active',
    });
    const lstatNoFollow = transactionPort.lstatNoFollow.bind(transactionPort);
    const readFileNoFollow = transactionPort.readFileNoFollow.bind(transactionPort);
    let credentialLstatCount = 0;
    const credentialObservations: unknown[] = [];
    transactionPort.lstatNoFollow = async (path) => {
      const observed = await lstatNoFollow(path);
      if (path === credentialPath) {
        credentialLstatCount += 1;
        credentialObservations.push(observed);
      }
      return observed;
    };
    transactionPort.readFileNoFollow = async (path) => {
      if (path === credentialPath) {
        throw new Error('credential bytes must not cross the uninstall transaction boundary');
      }
      return readFileNoFollow(path);
    };

    await expect(runUninstall(port)).resolves.toMatchObject({
      code: 'SCG_LIFECYCLE_UNINSTALLED',
      state: 'uninstalled',
    });
    const lockAfterUninstall = await acquireAdvisoryLock(lockPath);
    await lockAfterUninstall.release();
    expect(credentialLstatCount).toBeGreaterThan(1);
    expect(credentialObservations).toEqual([
      ...Array.from(
        { length: credentialObservations.length - 1 },
        () => expectedCredentialObservation,
      ),
      undefined,
    ]);
    expect(credentialDeletionObservedLock).toBe(true);
    expectLifecycleLockContentionError(credentialDeletionLockError);
    expect(credentialDeletionWal).toMatchObject({
      direction: 'commit',
      operation: 'uninstall',
      phase: 'commit-decided',
    });
    await expect(readFile(credentialPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(
      readFile(join(root, '.scg/onboarding/lifecycle.wal.v1.json'), 'utf8'),
    ).rejects.toMatchObject({ code: 'ENOENT' });
    expect(serializedWals).not.toHaveLength(0);
    expect(observedWalStagePaths).toStrictEqual(expectedWalStagePaths);
    await expectNoSecretResidualFiles([root, home], new Set(), credentialCanaries, {
      rejectLifecycleTemporaryPaths: true,
    });
    const walRecords = serializedWals.map((serializedWal) => parseWalRecordJsonV2(serializedWal));
    const setupWals = walRecords.filter((record) => record.operation === 'setup');
    const setupCredentialWals = setupWals.filter((record) =>
      record.mutations.some((mutation) => mutation.kind === 'credential'),
    );
    expect(setupCredentialWals).not.toHaveLength(0);
    setupCredentialWals.forEach((setupWal) => {
      assertExactSetupCredentialWal(setupWal, {
        path: credentialPath,
        projectId: 'uninstall-created-credential',
      });
    });
    const nonCredentialSetupWalCredentialPreimages = setupWals
      .filter((setupWal) => !setupWal.mutations.some((mutation) => mutation.kind === 'credential'))
      .flatMap((setupWal) =>
        setupWal.preimages.filter((preimage) => preimage.kind === 'credential'),
      );
    expect(nonCredentialSetupWalCredentialPreimages).toEqual([]);
    const uninstallWals = walRecords.filter((record) => record.operation === 'uninstall');
    expect(uninstallWals).not.toHaveLength(0);
    for (const record of uninstallWals) {
      assertExactUninstallCredentialWal(record, credentialPath);
    }
    for (const serializedWal of serializedWals) {
      for (const canary of credentialCanaries) expect(serializedWal).not.toContain(canary);
    }
  });
  it('compensates exact setup preimages after failure injected beyond credential and parent publication', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-rollback-')));
    roots.push(root);
    await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
    await writeFile(join(root, '.gitignore'), '.credentials/token.env\n', { mode: 0o600 });
    await writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
      mode: 0o600,
    });

    const credentialPath = join(root, '.credentials/token.env');
    const home = join(root, 'home');
    await mkdir(home, { recursive: true, mode: 0o700 });
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const manifestPath = join(root, '.scg/onboarding/manifest.v1.json');
    const walPath = join(root, '.scg/onboarding/lifecycle.wal.v1.json');
    const infrastructurePaths = [
      join(root, '.scg'),
      join(root, '.scg/onboarding'),
      lockPath,
    ] as const;
    let infrastructureAtInjection: ReadonlyMap<string, PathSnapshot> | undefined;
    const transactionPort = createNodeLifecycleTransactionPort();
    const ephemeralPaths = new Set<string>();
    const cleanupAttempts = new Map<string, number>();
    const stagedWritePaths = new Set<string>();
    let remainingStagePathsAtInjection: readonly string[] = [];
    const stagedFileCleanupAttempts = new Map<string, number>();
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    const stageWrite = transactionPort.stageWrite.bind(transactionPort);
    const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
    const reserveStagedDirectory = transactionPort.reserveStagedDirectory.bind(transactionPort);
    const publishReservedStagedDirectory =
      transactionPort.publishReservedStagedDirectory.bind(transactionPort);
    const renameReservedStagedWrite =
      transactionPort.renameReservedStagedWrite.bind(transactionPort);
    const discardReservedStagedWrite =
      transactionPort.discardReservedStagedWrite.bind(transactionPort);
    const discardReservedStagedDirectory =
      transactionPort.discardReservedStagedDirectory.bind(transactionPort);
    const quarantineExactFile = transactionPort.quarantineExactFile.bind(transactionPort);
    const quarantineExactDirectory = transactionPort.quarantineExactDirectory.bind(transactionPort);
    const discardStagedWrite = transactionPort.discardStagedWrite.bind(transactionPort);
    let cleanupObservedCanonicalLock = false;
    let directoryPublished = false;
    let credentialPublished = false;
    const finalizationStagePublicationStates: Array<{
      readonly directoryPublished: boolean;
      readonly credentialPublished: boolean;
    }> = [];
    const observedWalStagePaths: string[] = [];
    const expectedWalStagePaths: string[] = [];
    const rememberEphemeral = (path: string): void => {
      ephemeralPaths.add(path);
    };
    const recordCleanup = async (kind: string, path: string): Promise<void> => {
      await expectLifecycleLockContention(() => acquireAdvisoryLock(lockPath));
      cleanupObservedCanonicalLock = true;
      const key = `${kind}:${path}`;
      cleanupAttempts.set(key, (cleanupAttempts.get(key) ?? 0) + 1);
    };
    transactionPort.acquireAdvisoryLock = async (path) => {
      expect(path).toBe(lockPath);
      return acquireAdvisoryLock(path);
    };
    transactionPort.stageWrite = async (input) => {
      const walStagePrefix = `${walPath}.scene-glass-`;
      if (input.stagingPath.startsWith(walStagePrefix) && input.stagingPath.endsWith('.stage')) {
        const serializedWal = new TextDecoder('utf-8', { fatal: true }).decode(input.bytes);
        const record = parseWalRecordJsonV2(serializedWal);
        observedWalStagePaths.push(input.stagingPath);
        expectedWalStagePaths.push(`${walPath}.scene-glass-wal.stage`);
        if (
          record.operation === 'setup' &&
          record.direction === 'rollback' &&
          record.phase === 'finalized' &&
          record.manifestPath === manifestPath
        ) {
          finalizationStagePublicationStates.push({ directoryPublished, credentialPublished });
          remainingStagePathsAtInjection = (
            await Promise.all(
              [...stagedWritePaths].map(async (path) => {
                try {
                  await lstat(path);
                  return path;
                } catch (error: unknown) {
                  if (
                    typeof error === 'object' &&
                    error !== null &&
                    'code' in error &&
                    error.code === 'ENOENT'
                  ) {
                    return undefined;
                  }
                  throw error;
                }
              }),
            )
          ).filter((path): path is string => path !== undefined);
          infrastructureAtInjection = await captureRecoverySurfaceSnapshot(infrastructurePaths);
          throw new Error('post-publication compensation injection');
        }
      }
      const staged = await stageWrite(input);
      stagedWritePaths.add(staged.path);
      rememberEphemeral(staged.path);
      return staged;
    };
    transactionPort.reserveStagedWrite = async (input) => {
      rememberEphemeral(input.path);
      return reserveStagedWrite(input);
    };
    transactionPort.reserveStagedDirectory = async (input) => {
      rememberEphemeral(input.path);
      return reserveStagedDirectory(input);
    };
    transactionPort.publishReservedStagedDirectory = async (input) => {
      await publishReservedStagedDirectory(input);
      directoryPublished = true;
    };
    transactionPort.renameReservedStagedWrite = async (input) => {
      await renameReservedStagedWrite(input);
      credentialPublished = true;
    };
    transactionPort.discardReservedStagedWrite = async (input) => {
      await recordCleanup('reserved-file', input.reservation.path);
      return discardReservedStagedWrite(input);
    };
    transactionPort.discardReservedStagedDirectory = async (input) => {
      await recordCleanup('reserved-directory', input.reservation.path);
      return discardReservedStagedDirectory(input);
    };
    transactionPort.discardStagedWrite = async (input) => {
      await recordCleanup('staged-file', input.stage.path);
      stagedFileCleanupAttempts.set(
        input.stage.path,
        (stagedFileCleanupAttempts.get(input.stage.path) ?? 0) + 1,
      );
      return discardStagedWrite(input);
    };
    transactionPort.quarantineExactFile = async (input) => {
      await recordCleanup('file', input.path);
      return quarantineExactFile(input);
    };
    transactionPort.quarantineExactDirectory = async (input) => {
      await recordCleanup('directory', input.path);
      return quarantineExactDirectory(input);
    };
    const port = createNodeLifecycleEnginePort({
      approval: async () => true,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'rollback-created-credential',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      verification: successfulVerification(),
      random: { fill: (candidate) => candidate.fill(0) },
      transactionPort,
    });

    let preimages: ReadonlyMap<string, PathSnapshot> | undefined;
    const openSetupTransaction = port.openSetupTransaction.bind(port);
    port.openSetupTransaction = async (input) => {
      preimages = await captureFilesystemTree(root);
      return openSetupTransaction(input);
    };
    const result = await runSetup(port);
    expect(result).toMatchObject({
      code: 'SCG_LIFECYCLE_FAILED',
      state: 'never-installed',
    });
    expect(result.failures).toStrictEqual([{ stage: 'transaction-apply' }]);
    expect(observedWalStagePaths).toStrictEqual(expectedWalStagePaths);
    expect(finalizationStagePublicationStates).toEqual([
      { directoryPublished: true, credentialPublished: true },
    ]);
    expect(ephemeralPaths.size).toBeGreaterThan(0);
    for (const path of ephemeralPaths) {
      const observation: unknown = await lstat(path).catch((error: unknown) => error);
      if (!(observation instanceof Error)) {
        throw new Error(`ephemeral path remained after compensation: ${path}`);
      }
      expect(observation).toMatchObject({ code: 'ENOENT' });
    }
    if (preimages === undefined) {
      throw new Error('engine flow did not reach the prepared transaction boundary');
    }
    if (infrastructureAtInjection === undefined) {
      throw new Error('compensation failure injection did not capture infrastructure authority');
    }
    const afterCompensation = await captureFilesystemTree(root);
    const expectedAfterCompensation = new Map(preimages);
    for (const path of infrastructurePaths) {
      const snapshot = infrastructureAtInjection.get(path);
      if (snapshot === undefined) {
        throw new Error(`failure injection omitted infrastructure authority: ${path}`);
      }
      expectedAfterCompensation.set(path, snapshot);
    }
    expect(afterCompensation).toEqual(expectedAfterCompensation);
    const lockAfterCompensation = await acquireAdvisoryLock(lockPath);
    await lockAfterCompensation.release();
    expect(cleanupObservedCanonicalLock).toBe(true);
    expect(cleanupAttempts.size).toBeGreaterThan(0);
    for (const attempts of cleanupAttempts.values()) expect(attempts).toBe(1);
    expect(remainingStagePathsAtInjection).not.toHaveLength(0);
    expect([...stagedFileCleanupAttempts.keys()].sort()).toEqual(
      [...remainingStagePathsAtInjection].sort(),
    );
    for (const attempts of stagedFileCleanupAttempts.values()) expect(attempts).toBe(1);
    const credentialLine = credentialEnvelope('rollback-created-credential', TOKEN);
    await expectNoSecretResidualFiles(
      [root],
      new Set([credentialPath]),
      credentialSecretCanaries(TOKEN, credentialLine),
    );
  });
  it('replays every accepted setup capability boundary without side effects', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-receipt-a-')));
    const alternateRoot = await realpath(
      await mkdtemp(join(tmpdir(), 'scene-glass-node-receipt-b-')),
    );
    roots.push(root, alternateRoot);
    for (const fixtureRoot of [root, alternateRoot]) {
      await mkdir(join(fixtureRoot, 'public'), { recursive: true, mode: 0o700 });
      await writeFile(join(fixtureRoot, '.gitignore'), '.credentials/token.env\n', { mode: 0o600 });
      await writeFile(
        join(fixtureRoot, 'public/index.html'),
        '<html><head></head><body></body></html>\n',
        { mode: 0o600 },
      );
    }
    const credentialPath = join(root, '.credentials/token.env');
    const home = join(root, 'home');
    await mkdir(home, { recursive: true, mode: 0o700 });
    const transactionPort = createNodeLifecycleTransactionPort();
    const writeCapableSpies = {
      lock: vi.spyOn(transactionPort, 'acquireAdvisoryLock'),
      stageWrite: vi.spyOn(transactionPort, 'stageWrite'),
      reserveStagedWrite: vi.spyOn(transactionPort, 'reserveStagedWrite'),
      reserveStagedDirectory: vi.spyOn(transactionPort, 'reserveStagedDirectory'),
      writeReservedStagedWrite: vi.spyOn(transactionPort, 'writeReservedStagedWrite'),
      renameReservedStagedWrite: vi.spyOn(transactionPort, 'renameReservedStagedWrite'),
      publishReservedStagedDirectory: vi.spyOn(transactionPort, 'publishReservedStagedDirectory'),
      publishStagedWrite: vi.spyOn(transactionPort, 'publishStagedWrite'),
      replaceStagedWriteWithQuarantine: vi.spyOn(
        transactionPort,
        'replaceStagedWriteWithQuarantine',
      ),
      retainReservedStagedDirectoryForRecovery: vi.spyOn(
        transactionPort,
        'retainReservedStagedDirectoryForRecovery',
      ),
      retainReservedStagedWriteForRecovery: vi.spyOn(
        transactionPort,
        'retainReservedStagedWriteForRecovery',
      ),
      retainStagedWriteForRecovery: vi.spyOn(transactionPort, 'retainStagedWriteForRecovery'),
      publishExactStagedDirectory: vi.spyOn(transactionPort, 'publishExactStagedDirectory'),
      replaceExactStagedFileWithQuarantine: vi.spyOn(
        transactionPort,
        'replaceExactStagedFileWithQuarantine',
      ),
      replaceExactWal: vi.spyOn(transactionPort, 'replaceExactWal'),
      publishExactStagedFile: vi.spyOn(transactionPort, 'publishExactStagedFile'),
      quarantineExactFile: vi.spyOn(transactionPort, 'quarantineExactFile'),
      quarantineExactDirectory: vi.spyOn(transactionPort, 'quarantineExactDirectory'),
      finalizeQuarantine: vi.spyOn(transactionPort, 'finalizeQuarantine'),
      restoreQuarantine: vi.spyOn(transactionPort, 'restoreQuarantine'),
      removeExactWal: vi.spyOn(transactionPort, 'removeExactWal'),
      removeExactStagedFile: vi.spyOn(transactionPort, 'removeExactStagedFile'),
      discardReservedStagedWrite: vi.spyOn(transactionPort, 'discardReservedStagedWrite'),
      discardReservedStagedDirectory: vi.spyOn(transactionPort, 'discardReservedStagedDirectory'),
      closeReservedStagedDirectory: vi.spyOn(transactionPort, 'closeReservedStagedDirectory'),
      closeReservedStagedWrite: vi.spyOn(transactionPort, 'closeReservedStagedWrite'),
      discardStagedWrite: vi.spyOn(transactionPort, 'discardStagedWrite'),
      fsyncDirectory: vi.spyOn(transactionPort, 'fsyncDirectory'),
      fsyncFile: vi.spyOn(transactionPort, 'fsyncFile'),
      fsyncParent: vi.spyOn(transactionPort, 'fsyncParent'),
    };
    let entropyCalls = 0;
    let identifierCalls = 0;
    const port = createNodeLifecycleEnginePort({
      approval: async () => true,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'receipt-a',
        root,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      random: {
        fill: (candidate) => {
          entropyCalls += 1;
          candidate.fill(0);
        },
        uuid: () => {
          identifierCalls += 1;
          return 'receipt-a-mutation';
        },
      },
      transactionPort,
      verification: successfulVerification(),
    });
    const alternateCredentialPath = join(alternateRoot, '.credentials/token.env');
    const alternatePort = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: alternateRoot,
      cwd: alternateRoot,
      homeDirectory: join(alternateRoot, 'home'),
      host: { credentialPath: alternateCredentialPath, port: 4175 },
      project: {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html',
        projectId: 'receipt-b',
        root: alternateRoot,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      },
      verification: verification(),
    });
    const alternateFacts = await alternatePort.inspectSetupFacts();
    const alternateConfig = planConfigOperation({
      homes: alternateFacts.configHomes,
      project: alternateFacts.project,
    });
    const alternateHost = planHostIntegration(alternateFacts.hostPlan);
    const alternateBuilt = await alternatePort.buildSetupPlan({
      build: alternateFacts.build,
      config: alternateConfig,
      host: alternateHost,
    });
    const sideEffectSnapshot = await captureFilesystemTree(root);
    const issuedCandidates: Uint8Array[] = [];
    const mutationCounts = () => ({
      entropyCalls,
      identifierCalls,
      lock: writeCapableSpies.lock.mock.calls.length,
      stageWrite: writeCapableSpies.stageWrite.mock.calls.length,
      reserveStagedWrite: writeCapableSpies.reserveStagedWrite.mock.calls.length,
      reserveStagedDirectory: writeCapableSpies.reserveStagedDirectory.mock.calls.length,
      writeReservedStagedWrite: writeCapableSpies.writeReservedStagedWrite.mock.calls.length,
      renameReservedStagedWrite: writeCapableSpies.renameReservedStagedWrite.mock.calls.length,
      publishReservedStagedDirectory:
        writeCapableSpies.publishReservedStagedDirectory.mock.calls.length,
      publishStagedWrite: writeCapableSpies.publishStagedWrite.mock.calls.length,
      replaceStagedWriteWithQuarantine:
        writeCapableSpies.replaceStagedWriteWithQuarantine.mock.calls.length,
      retainReservedStagedDirectoryForRecovery:
        writeCapableSpies.retainReservedStagedDirectoryForRecovery.mock.calls.length,
      retainReservedStagedWriteForRecovery:
        writeCapableSpies.retainReservedStagedWriteForRecovery.mock.calls.length,
      retainStagedWriteForRecovery:
        writeCapableSpies.retainStagedWriteForRecovery.mock.calls.length,
      publishExactStagedDirectory: writeCapableSpies.publishExactStagedDirectory.mock.calls.length,
      replaceExactStagedFileWithQuarantine:
        writeCapableSpies.replaceExactStagedFileWithQuarantine.mock.calls.length,
      replaceExactWal: writeCapableSpies.replaceExactWal.mock.calls.length,
      publishExactStagedFile: writeCapableSpies.publishExactStagedFile.mock.calls.length,
      quarantineExactFile: writeCapableSpies.quarantineExactFile.mock.calls.length,
      quarantineExactDirectory: writeCapableSpies.quarantineExactDirectory.mock.calls.length,
      finalizeQuarantine: writeCapableSpies.finalizeQuarantine.mock.calls.length,
      restoreQuarantine: writeCapableSpies.restoreQuarantine.mock.calls.length,
      removeExactWal: writeCapableSpies.removeExactWal.mock.calls.length,
      removeExactStagedFile: writeCapableSpies.removeExactStagedFile.mock.calls.length,
      discardReservedStagedWrite: writeCapableSpies.discardReservedStagedWrite.mock.calls.length,
      discardReservedStagedDirectory:
        writeCapableSpies.discardReservedStagedDirectory.mock.calls.length,
      closeReservedStagedDirectory:
        writeCapableSpies.closeReservedStagedDirectory.mock.calls.length,
      closeReservedStagedWrite: writeCapableSpies.closeReservedStagedWrite.mock.calls.length,
      discardStagedWrite: writeCapableSpies.discardStagedWrite.mock.calls.length,
      fsyncDirectory: writeCapableSpies.fsyncDirectory.mock.calls.length,
      fsyncFile: writeCapableSpies.fsyncFile.mock.calls.length,
      fsyncParent: writeCapableSpies.fsyncParent.mock.calls.length,
    });
    const expectRejectedWithoutMutation = async (
      action: () => Promise<unknown>,
      message: string,
    ): Promise<void> => {
      const counts = mutationCounts();
      const snapshot = await captureFilesystemTree(root);
      const rejection = await action().then(
        () => {
          throw new Error(`expected exact rejection: ${message}`);
        },
        (error: unknown) => error,
      );
      if (!(rejection instanceof Error)) {
        throw new Error(`expected an Error with exact message: ${message}`);
      }
      expect(rejection.message).toBe(message);
      expect(mutationCounts()).toStrictEqual(counts);
      await expectFilesystemTree(root, snapshot);
    };

    const requestSetupApproval = port.requestSetupApproval.bind(port);
    port.requestSetupApproval = async (input) => {
      const approved = await requestSetupApproval(input);
      await expectFilesystemTree(root, sideEffectSnapshot);
      await expectRejectedWithoutMutation(
        () => requestSetupApproval(input),
        'setup approval does not match an authorized receipt',
      );
      return approved;
    };
    const generateCredentialToken = port.generateCredentialToken.bind(port);
    port.generateCredentialToken = async (input) => {
      await expectRejectedWithoutMutation(
        () => generateCredentialToken({ ...input, receiptId: alternateBuilt.receiptId }),
        'credential generation does not match an approved receipt',
      );
      const candidate = await generateCredentialToken(input);
      issuedCandidates.push(candidate);
      await expectRejectedWithoutMutation(
        () => generateCredentialToken(input),
        'credential generation does not match an approved receipt',
      );
      return candidate;
    };
    const prepareSetupMutation = port.prepareSetupMutation.bind(port);
    port.prepareSetupMutation = async (input) => {
      const prepared = await prepareSetupMutation(input);
      await expectRejectedWithoutMutation(
        () => prepareSetupMutation(input),
        'setup plan authority is unavailable',
      );
      return prepared;
    };
    const preflightSetup = port.preflightSetup.bind(port);
    port.preflightSetup = async (input) => {
      const replay = cloneSetupPreflightForReplay(input);
      await preflightSetup(input);
      const replayMessage =
        input.stage === 3
          ? 'finalized setup candidate is unavailable'
          : 'prepared setup authority is unavailable';
      await expectRejectedWithoutMutation(() => preflightSetup(replay), replayMessage);
    };

    const result = await runSetup(port);
    expect(result).toMatchObject({ code: 'SCG_LIFECYCLE_ACTIVE', state: 'active' });
    expect(entropyCalls).toBe(1);
    expect(identifierCalls).toBe(1);
    expect(writeCapableSpies.lock).toHaveBeenCalledTimes(1);
    expect(issuedCandidates).toEqual([new Uint8Array(32)]);
  });
  it('revokes the finalized-validation credential capability without retaining it', async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), 'scene-glass-node-finalized-capability-')),
    );
    roots.push(root);
    await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
    await writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 });
    await writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
      mode: 0o600,
    });
    await writeFile(
      join(root, '.env.scene-glass.local'),
      credentialEnvelope('finalized-capability', TOKEN),
      { mode: 0o600 },
    );
    const credentialPath = join(root, '.env.scene-glass.local');
    const capabilityEvents: string[] = [];
    let acquiredCapability: ReturnType<typeof native.verifyCredentialAuthoritySet> | undefined;
    const verifyCredentialAuthoritySet = native.verifyCredentialAuthoritySet;
    const revokeCredentialReadCapability = native.revokeCredentialReadCapability;
    const verify = vi
      .spyOn(native, 'verifyCredentialAuthoritySet')
      .mockImplementation((authorities, selectedProjectId, options) => {
        const capability = verifyCredentialAuthoritySet(authorities, selectedProjectId, options);
        acquiredCapability = capability;
        capabilityEvents.push('acquire');
        return capability;
      });
    const revoke = vi
      .spyOn(native, 'revokeCredentialReadCapability')
      .mockImplementation((capability) => {
        expect(capability).toBe(acquiredCapability);
        capabilityEvents.push('revoke');
        revokeCredentialReadCapability(capability);
      });
    await mkdir(join(root, 'home'), { recursive: true, mode: 0o700 });
    try {
      const port = createNodeLifecycleEnginePort({
        approval: async () => true,
        checkoutRoot: root,
        cwd: root,
        homeDirectory: join(root, 'home'),
        host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
        project: {
          allowedOrigins: ['http://127.0.0.1:4175'],
          framework: 'html',
          projectId: 'finalized-capability',
          root,
          tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        },
        verification: successfulVerification(),
        random: {
          fill: () => {
            throw new Error('adopted credential must not generate bytes');
          },
        },
      });

      await expect(runSetup(port)).resolves.toMatchObject({ code: 'SCG_LIFECYCLE_ACTIVE' });
      expect(verify).toHaveBeenCalledTimes(1);
      expect(revoke).toHaveBeenCalledTimes(1);
      expect(capabilityEvents).toEqual(['acquire', 'revoke']);
      if (acquiredCapability === undefined) {
        throw new Error('finalized validation did not acquire a capability');
      }
      expect(() => native.secureReadCredential(acquiredCapability)).toThrow();
      const persistedCredential = await readFile(credentialPath);
      const persistedIdentity = await lstat(credentialPath);
      const activeManifest = parseSetupManifestJsonV1(
        await readFile(join(root, '.scg/onboarding/manifest.v1.json'), 'utf8'),
      );
      const adoptedCredential = activeManifest.artifacts.find(
        (artifact) => artifact.kind === 'credential',
      );
      if (adoptedCredential === undefined) {
        throw new Error('adopted credential is absent from the active manifest');
      }
      expect(adoptedCredential).toMatchObject({
        ownership: 'adopted',
        inverse: { kind: 'none' },
      });

      await expect(runUninstall(port)).resolves.toMatchObject({
        code: 'SCG_LIFECYCLE_UNINSTALLED',
        state: 'uninstalled',
      });
      expect(revoke).toHaveBeenCalledTimes(1);
      expect(await readFile(credentialPath)).toEqual(persistedCredential);
      const retainedIdentity = await lstat(credentialPath);
      expect({ device: String(retainedIdentity.dev), inode: String(retainedIdentity.ino) }).toEqual(
        {
          device: String(persistedIdentity.dev),
          inode: String(persistedIdentity.ino),
        },
      );
      expect(retainedIdentity.mode & 0o777).toBe(persistedIdentity.mode & 0o777);
    } finally {
      verify.mockRestore();
      revoke.mockRestore();
    }
  });
  it('revokes the finalized-validation capability when revocation makes validation fail', async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), 'scene-glass-node-finalized-capability-failure-')),
    );
    roots.push(root);
    await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
    await writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 });
    await writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
      mode: 0o600,
    });
    const credentialPath = join(root, '.env.scene-glass.local');
    const credentialBytes = Buffer.from(
      credentialEnvelope('finalized-capability-failure', TOKEN),
      'utf8',
    );
    await writeFile(credentialPath, credentialBytes, { mode: 0o600 });
    const capabilityEvents: string[] = [];
    let acquiredCapability: ReturnType<typeof native.verifyCredentialAuthoritySet> | undefined;
    const verifyCredentialAuthoritySet = native.verifyCredentialAuthoritySet;
    const revokeCredentialReadCapability = native.revokeCredentialReadCapability;
    const verify = vi
      .spyOn(native, 'verifyCredentialAuthoritySet')
      .mockImplementation((authorities, selectedProjectId, options) => {
        const capability = verifyCredentialAuthoritySet(authorities, selectedProjectId, options);
        acquiredCapability = capability;
        capabilityEvents.push('acquire');
        return capability;
      });
    const revoke = vi
      .spyOn(native, 'revokeCredentialReadCapability')
      .mockImplementation((capability) => {
        expect(capability).toBe(acquiredCapability);
        capabilityEvents.push('revoke');
        revokeCredentialReadCapability(capability);
        throw new Error('injected finalized-validation revocation failure');
      });

    const home = join(root, 'home');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    await mkdir(home, { recursive: true, mode: 0o700 });
    await Promise.all([
      mkdir(join(root, '.scg/onboarding'), { recursive: true, mode: 0o700 }),
      writeFile(lockPath, 'lock\n', { mode: 0o600 }),
    ]);
    const before = await captureFilesystemTree(root);
    const transactionPort = createNodeLifecycleTransactionPort();
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    let compensationCalls = 0;
    try {
      const port = createNodeLifecycleEnginePort({
        approval: async () => true,
        checkoutRoot: root,
        cwd: root,
        homeDirectory: home,
        host: { credentialPath, port: 4175 },
        project: {
          allowedOrigins: ['http://127.0.0.1:4175'],
          framework: 'html',
          projectId: 'finalized-capability-failure',
          root,
          tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        },
        random: {
          fill: () => {
            throw new Error('adopted credential must not generate bytes');
          },
        },
        transactionPort,
        verification: successfulVerification(),
      });
      const openSetupTransaction = port.openSetupTransaction.bind(port);
      port.openSetupTransaction = async (input) => {
        const transaction = await openSetupTransaction(input);
        return Object.freeze({
          apply: transaction.apply.bind(transaction),
          compensate: async () => {
            compensationCalls += 1;
            return transaction.compensate();
          },
          publishActive: transaction.publishActive.bind(transaction),
        });
      };

      const result = await runSetup(port);
      expect(result).toMatchObject({
        code: 'SCG_LIFECYCLE_FAILED',
        state: 'never-installed',
      });
      expect(result.failures).toStrictEqual([{ stage: 'authority-validation' }]);
      expect(verify).toHaveBeenCalledTimes(1);
      expect(revoke).toHaveBeenCalledTimes(1);
      expect(compensationCalls).toBe(1);
      expect(capabilityEvents).toEqual(['acquire', 'revoke']);
      if (acquiredCapability === undefined) {
        throw new Error('failed validation did not acquire a capability');
      }
      expect(() => native.secureReadCredential(acquiredCapability)).toThrow();
      await expectFilesystemTree(root, before);
      const reacquiredLock = await acquireAdvisoryLock(lockPath);
      await reacquiredLock.release();
    } finally {
      verify.mockRestore();
      revoke.mockRestore();
    }
  });
  it('rejects parent durability after a retained ancestor is replaced', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-parent-fsync-race-')));
    roots.push(root);
    const lockPath = join(root, 'lifecycle.lock');
    const parentPath = join(root, 'cache');
    const parentStagePath = join(root, '.cache.stage');
    const archivedParentPath = join(root, '.cache.replaced');
    const childDirectoryStagePath = join(parentPath, '.child.stage');
    const childDirectoryPath = join(parentPath, 'child');
    const childStagePath = join(childDirectoryPath, '.wal.stage');
    const childPath = join(childDirectoryPath, 'wal.json');
    await writeFile(lockPath, 'lock\n', { mode: 0o600 });

    const port = createNodeLifecycleTransactionPort();
    const durabilityCalls: string[] = [];
    const publishStagedWrite = port.publishStagedWrite.bind(port);
    const fsyncFile = port.fsyncFile.bind(port);
    const fsyncParent = port.fsyncParent.bind(port);
    port.publishStagedWrite = async (input) => {
      await publishStagedWrite(input);
      if (input.targetPath === childPath) {
        durabilityCalls.push('mutation');
      }
    };
    port.fsyncFile = async (input) => {
      await fsyncFile(input);
      if (input.path === childPath) {
        durabilityCalls.push('file-fsync');
      }
    };
    port.fsyncParent = async (input) => {
      await fsyncParent(input);
      if (input.path === childPath) {
        durabilityCalls.push('parent-fsync');
      }
    };
    const lock = await port.acquireAdvisoryLock(lockPath);
    try {
      const parent = await port.reserveStagedDirectory({
        lock,
        path: parentStagePath,
        targetPath: parentPath,
        creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
          parentStagePath,
          'directory',
          0o700,
        ),
        mode: 0o700,
      });
      await port.publishReservedStagedDirectory({
        lock,
        reservation: parent,
        targetPath: parentPath,
      });
      await port.fsyncDirectory({ lock, path: parentPath });
      await port.fsyncParent({ lock, path: parentPath });
      await port.closeReservedStagedDirectory({ lock, reservation: parent });
      await rename(parentPath, archivedParentPath);
      await mkdir(parentPath, { mode: 0o700 });
      await expect(
        port.reserveStagedDirectory({
          lock,
          path: childDirectoryStagePath,
          targetPath: childDirectoryPath,
          creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
            childDirectoryStagePath,
            'directory',
            0o700,
          ),
          mode: 0o700,
        }),
      ).rejects.toThrow('reserved lifecycle directory durability');
      await rm(parentPath, { force: true, recursive: true });
      await rename(archivedParentPath, parentPath);
      const childDirectory = await port.reserveStagedDirectory({
        lock,
        path: childDirectoryStagePath,
        targetPath: childDirectoryPath,
        creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
          childDirectoryStagePath,
          'directory',
          0o700,
        ),
        mode: 0o700,
      });
      await port.publishReservedStagedDirectory({
        lock,
        reservation: childDirectory,
        targetPath: childDirectoryPath,
      });
      await port.fsyncDirectory({ lock, path: childDirectoryPath });
      await port.fsyncParent({ lock, path: childDirectoryPath });
      await port.closeReservedStagedDirectory({ lock, reservation: childDirectory });

      const stage = await port.stageWrite({
        lock,
        stagingPath: childStagePath,
        creationIntentMarkerPath: testLifecycleCreationIntentMarkerPath(
          childStagePath,
          'file',
          0o600,
        ),
        bytes: Buffer.from('{"cursor":1}\n', 'utf8'),
        mode: 0o600,
      });
      await port.publishStagedWrite({ lock, stage, targetPath: childPath });
      await port.fsyncFile({ lock, path: childPath });

      await rename(parentPath, archivedParentPath);
      await mkdir(parentPath, { mode: 0o700 });
      await expect(port.fsyncParent({ lock, path: childPath })).rejects.toThrow(
        'reserved lifecycle directory durability',
      );

      await rm(parentPath, { force: true, recursive: true });
      await rename(archivedParentPath, parentPath);
      await port.fsyncParent({ lock, path: childPath });
      expect(durabilityCalls).toEqual(['mutation', 'file-fsync', 'parent-fsync']);
    } finally {
      await lock.release();
    }
  });
});

function verification() {
  return createNodeLifecycleVerificationPorts({
    loaderPort: 4175,
    startBootstrapProfile: async () => {
      throw new Error('not reached');
    },
    startBrowserProfile: async () => {
      throw new Error('not reached');
    },
    startLoopbackMcp: async () => {
      throw new Error('not reached');
    },
  });
}
function successfulVerification(): NodeLifecycleVerificationPorts {
  const unavailable = async (): Promise<never> => {
    throw new Error('successful verification test double must not enter a nested verifier');
  };
  return Object.freeze({
    host: { start: unavailable },
    mcp: { startLoopback: unavailable },
    browser: { startProfile: unavailable },
    bootstrap: { startEmptyWorkersEnabledProfile: unavailable },
    runNativeSelfTest: async () => undefined,
    runBootstrapSmoke: async () => undefined,
    runLiveDiagnostics: async () => undefined,
  });
}

function sha256(value: Uint8Array | string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function lifecycleId(value: string): string {
  return `scg-${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 48)}`;
}
function assertNoSecretBearingKeys(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) assertNoSecretBearingKeys(item);
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, nested] of Object.entries(value)) {
    expect(key).not.toMatch(
      /^(?:token|secret)(?:Bytes|Content|Digest|Text|Value)?$|^credential(?:Bytes|Content|Digest|Text|Value)$/i,
    );
    assertNoSecretBearingKeys(nested);
  }
}

function assertExactSetupCredentialWal(
  record: ReturnType<typeof parseWalRecordJsonV2>,
  expected: Readonly<{ readonly path: string; readonly projectId: string }>,
): void {
  expect(record.operation).toBe('setup');
  expect(record.creationIntents?.every((intent) => intent.kind === 'file') ?? true).toBe(true);
  const credentialMutations = record.mutations.filter((mutation) => mutation.kind === 'credential');
  expect(credentialMutations).toHaveLength(1);
  const credential = credentialMutations[0];
  if (credential === undefined || credential.kind !== 'credential') {
    throw new Error('setup WAL does not contain one credential mutation');
  }
  expect(Object.keys(credential).sort()).toEqual([
    'kind',
    'mode',
    'path',
    'projectId',
    'stagingIdentity',
    'stagingPath',
    'step',
    'targetIdentity',
  ]);
  expect(credential).toMatchObject({
    kind: 'credential',
    mode: 0o600,
    path: expected.path,
    projectId: expected.projectId,
  });
  expect(record.preimages.filter((preimage) => preimage.path === expected.path)).toEqual([
    { kind: 'absent', path: expected.path },
  ]);
  expect(record.preimages.filter((preimage) => preimage.kind === 'credential')).toEqual([]);
}
function assertDurableCreationIntent(
  record: ReturnType<typeof parseWalRecordJsonV2>,
  expected: Readonly<{
    readonly kind: 'credential' | 'directory' | 'file';
    readonly mode: number;
    readonly targetPath: string;
  }>,
): void {
  expect({
    cursor: record.cursor,
    direction: record.direction,
    operation: record.operation,
    phase: record.phase,
  }).toStrictEqual({
    cursor: 0,
    direction: 'rollback',
    operation: 'setup',
    phase: 'prepared',
  });
  expect(record.mutations).toStrictEqual([]);
  expect(record.creationIntents).toHaveLength(1);
  const [intent] = record.creationIntents ?? [];
  if (intent === undefined) {
    throw new Error('prepared WAL omitted its durable creation intent authority');
  }
  expect(Object.keys(intent).sort()).toEqual([
    'kind',
    'mode',
    'stagingPath',
    'stagingPreimage',
    'step',
    'targetPath',
    'targetPreimage',
    'validationToken',
  ]);
  expect({
    kind: intent.kind,
    mode: intent.mode,
    step: intent.step,
    targetPath: intent.targetPath,
  }).toStrictEqual({
    ...expected,
    step: 0,
  });
  expect(intent.validationToken).toMatch(/^[a-f0-9]{32}$/);
  expect(record.preimages[intent.targetPreimage]).toEqual({
    kind: 'absent',
    path: intent.targetPath,
  });
  expect(record.preimages[intent.stagingPreimage]).toEqual({
    kind: 'absent',
    path: intent.stagingPath,
  });
}
function assertDurableCredentialCreationIntentAfterDirectory(
  record: ReturnType<typeof parseWalRecordJsonV2>,
  directoryPath: string,
  credentialPath: string,
): void {
  expect({
    cursor: record.cursor,
    direction: record.direction,
    operation: record.operation,
    phase: record.phase,
  }).toStrictEqual({
    cursor: 1,
    direction: 'rollback',
    operation: 'setup',
    phase: 'prepared',
  });
  expect(record.creationIntents).toHaveLength(1);
  expect(record.mutations).toHaveLength(1);
  const [intent] = record.creationIntents ?? [];
  const [directory] = record.mutations;
  if (intent === undefined || directory === undefined || directory.kind !== 'ordinary') {
    throw new Error(
      'credential reservation WAL omitted its durable directory and creation authority',
    );
  }
  expect({
    directory: {
      kind: directory.kind,
      result: directory.result.kind,
      mode: directory.result.kind === 'directory' ? directory.result.mode : undefined,
      step: directory.step,
      targetPath: directory.targetPath,
    },
    intent: {
      kind: intent.kind,
      mode: intent.mode,
      step: intent.step,
      targetPath: intent.targetPath,
    },
  }).toStrictEqual({
    directory: {
      kind: 'ordinary',
      result: 'directory',
      mode: 0o700,
      step: 0,
      targetPath: directoryPath,
    },
    intent: {
      kind: 'credential',
      mode: 0o600,
      step: 1,
      targetPath: credentialPath,
    },
  });
  expect(record.preimages[intent.targetPreimage]).toEqual({
    kind: 'absent',
    path: credentialPath,
  });
  expect(record.preimages[intent.stagingPreimage]).toEqual({
    kind: 'absent',
    path: intent.stagingPath,
  });
}
function creationIntentMarkerPath(
  stagingPath: string,
  kind: 'credential' | 'directory' | 'file',
  mode: number,
  validationToken: string,
): string {
  const stageToken = createHash('sha256').update(stagingPath, 'utf8').digest('hex').slice(0, 16);
  return join(
    dirname(stagingPath),
    `.scg-intent-${stageToken}-${kind}-${mode.toString(8).padStart(3, '0')}-${validationToken}.marker`,
  );
}
async function assertReservedCreationIntentFilesystem(
  record: ReturnType<typeof parseWalRecordJsonV2>,
): Promise<readonly string[]> {
  const [intent] = record.creationIntents ?? [];
  if (intent === undefined) {
    throw new Error('reservation boundary WAL omitted its durable creation intent');
  }
  const markerPath = creationIntentMarkerPath(
    intent.stagingPath,
    intent.kind,
    intent.mode,
    intent.validationToken,
  );
  const [stage, marker] = await Promise.all([
    capturePathSnapshot(intent.stagingPath),
    capturePathSnapshot(markerPath),
  ]);
  if (stage.kind === 'absent') {
    throw new Error('reservation boundary did not retain its reserved stage inode');
  }
  expect({
    stage: { kind: stage.kind, mode: stage.mode },
    marker,
  }).toStrictEqual({
    stage: {
      kind: intent.kind === 'directory' ? 'directory' : 'file',
      mode: intent.mode,
    },
    marker: { kind: 'absent' },
  });
  return [intent.stagingPath, markerPath];
}

function assertDurableDirectoryPublication(
  record: ReturnType<typeof parseWalRecordJsonV2>,
  targetPath: string,
): void {
  expect({
    cursor: record.cursor,
    direction: record.direction,
    operation: record.operation,
    phase: record.phase,
  }).toStrictEqual({
    cursor: 0,
    direction: 'rollback',
    operation: 'setup',
    phase: 'prepared',
  });
  expect(record.creationIntents).toBeUndefined();
  expect(record.mutations).toHaveLength(1);
  const [directory] = record.mutations;
  if (directory === undefined || directory.kind !== 'ordinary') {
    throw new Error('post-parent WAL omitted its durable directory authority');
  }
  expect(Object.keys(directory.result).sort()).toEqual(['identity', 'kind', 'mode']);
  if (directory.result.kind !== 'directory') {
    throw new Error('post-parent WAL directory authority has an invalid result kind');
  }
  expect({
    kind: directory.kind,
    mode: directory.result.mode,
    result: directory.result.kind,
    step: directory.step,
    targetPath: directory.targetPath,
  }).toStrictEqual({
    kind: 'ordinary',
    mode: 0o700,
    result: 'directory',
    step: 0,
    targetPath,
  });
  expect(record.preimages[directory.preimage]).toEqual({
    kind: 'absent',
    path: targetPath,
  });
}

function assertExactUninstallCredentialWal(
  record: ReturnType<typeof parseWalRecordJsonV2>,
  credentialPath: string,
): void {
  expect(record.operation).toBe('uninstall');
  expect(record.mutations.filter((mutation) => mutation.kind === 'credential')).toEqual([]);
  const credentialPreimages = record.preimages.filter((preimage) => preimage.kind === 'credential');
  expect(credentialPreimages).toHaveLength(1);
  const credential = credentialPreimages[0];
  if (credential === undefined || credential.kind !== 'credential') {
    throw new Error('uninstall WAL does not contain one credential preimage');
  }
  expect(Object.keys(credential).sort()).toEqual(['identity', 'kind', 'mode', 'path']);
  expect(credential).toMatchObject({
    kind: 'credential',
    mode: 0o600,
    path: credentialPath,
  });
}
async function expectLifecycleLockContention(
  acquire: () => Promise<{ readonly release: () => Promise<void> }>,
): Promise<unknown> {
  const error = await acquire().then(
    async (lock) => {
      await lock.release();
      return undefined;
    },
    (rejection: unknown) => rejection,
  );
  expectLifecycleLockContentionError(error);
  return error;
}

function expectLifecycleLockContentionError(error: unknown): void {
  expect(error).toMatchObject({
    code: 'SCG_NATIVE_PATH_DENIED',
    message: 'Secure native read was denied.',
  });
}
type SetupCrashPoint =
  | 'directory-reserved-before-identity-wal'
  | 'credential-reserved-before-identity-wal'
  | 'post-apply'
  | 'post-credential-publication'
  | 'post-parent-publication'
  | 'prepared-pre-write';
interface SetupCrashReport {
  readonly crashPoint: SetupCrashPoint;
  readonly credentialPublishCalls: number;
  readonly credentialReserveCalls: number;
  readonly directoryReserveCalls: number;
  readonly entropyCalls: number;
  readonly identifierCalls: number;
  readonly lockAcquisitions: number;
}

interface SetupRecoveryFixture {
  readonly credentialPath: string;
  readonly home: string;
  readonly lockPath: string;
  readonly recoverySurfacePaths: readonly string[];
  readonly root: string;
  readonly walPath: string;
}

function cloneSetupPreflightForReplay(
  input: LifecycleSetupPreflightInput,
): LifecycleSetupPreflightInput {
  return structuredClone(input) as LifecycleSetupPreflightInput;
}
interface WalSnapshotRetentionFixture {
  readonly lockPath: string;
  readonly root: string;
  readonly stagingPath: string;
  readonly targetPath: string;
  readonly walPath: string;
}
async function createWalSnapshotRetentionFixture(
  label: string,
): Promise<WalSnapshotRetentionFixture> {
  const root = await realpath(await mkdtemp(join(tmpdir(), `scene-glass-wal-snapshot-${label}-`)));
  roots.push(root);
  const lockPath = join(root, 'lifecycle.lock');
  const walPath = join(root, 'lifecycle.wal.v1.json');
  await Promise.all([
    writeFile(lockPath, 'lock\n', { mode: 0o600 }),
    writeFile(walPath, 'snapshot-wal\n', { mode: 0o600 }),
  ]);
  return {
    lockPath,
    root,
    stagingPath: join(root, '.retained.stage'),
    targetPath: join(root, 'retained-target'),
    walPath,
  };
}
function testLifecycleCreationIntentMarkerPath(
  stagePath: string,
  kind: 'credential' | 'directory' | 'file',
  mode: number,
): string {
  const digest = createHash('sha256').update(stagePath, 'utf8').digest('hex');
  return join(
    dirname(stagePath),
    `.scg-intent-${digest.slice(0, 16)}-${kind}-${mode
      .toString(8)
      .padStart(3, '0')}-${digest.slice(16, 48)}.marker`,
  );
}

async function createSetupRecoveryFixture(projectId: string): Promise<SetupRecoveryFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), `scene-glass-node-recovery-${projectId}-`)),
  );
  roots.push(root);
  const home = join(root, 'home');
  const credentialPath = join(root, '.env.scene-glass.local');
  const lockPath = join(home, '.scene-glass-onboarding.lock');
  const walPath = join(root, '.scg/onboarding/lifecycle.wal.v1.json');
  await Promise.all([
    mkdir(join(root, 'public'), { recursive: true, mode: 0o700 }),
    mkdir(join(root, '.scg/onboarding'), { recursive: true, mode: 0o700 }),
    mkdir(join(home, '.scg'), { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 }),
    writeFile(join(root, 'public/index.html'), '<html><head></head><body></body></html>\n', {
      mode: 0o600,
    }),
    writeFile(lockPath, 'lock\n', { mode: 0o600 }),
  ]);
  return {
    credentialPath,
    home,
    lockPath,
    recoverySurfacePaths: [
      credentialPath,
      dirname(credentialPath),
      join(home, '.scg/config.json'),
      join(home, '.scg/credential-authorities.v1.json'),
      join(root, 'public/index.html'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/runtime/host-integration-helper.mjs'),
      lockPath,
      walPath,
      join(root, '.scg/onboarding/manifest.v1.json'),
      join(root, '.scg/onboarding/receipt.v1.json'),
    ],
    root,
    walPath,
  };
}

async function runSetupCrashChild(input: {
  readonly crashPoint: SetupCrashPoint;
  readonly credentialPath: string;
  readonly home: string;
  readonly projectId: string;
  readonly root: string;
}): Promise<SetupCrashReport> {
  const childRoot = await mkdtemp(join(tmpdir(), 'scene-glass-node-crash-child-'));
  roots.push(childRoot);
  const scriptPath = join(childRoot, 'setup-crash.ts');
  const engineUrl = new URL('../../packages/onboarding/src/lifecycle/engine.ts', import.meta.url)
    .href;
  const nodeEnginePortUrl = new URL(
    '../../packages/onboarding/src/lifecycle/node-engine-port.ts',
    import.meta.url,
  ).href;
  const nodeTransactionPortUrl = new URL(
    '../../packages/onboarding/src/lifecycle/node-transaction-port.ts',
    import.meta.url,
  ).href;
  const provenanceUrl = new URL(
    '../../packages/onboarding/src/lifecycle/provenance.ts',
    import.meta.url,
  ).href;
  await writeFile(
    scriptPath,
    `
import { lstat, readFile } from 'node:fs/promises';
import { runSetup } from ${JSON.stringify(engineUrl)};
import { createNodeLifecycleEnginePort } from ${JSON.stringify(nodeEnginePortUrl)};
import { createNodeLifecycleTransactionPort } from ${JSON.stringify(nodeTransactionPortUrl)};
import { parseWalRecordJsonV2 } from ${JSON.stringify(provenanceUrl)};

const main = async (): Promise<void> => {
const input = JSON.parse(process.env.SCG_SETUP_CRASH_INPUT ?? '');
const walPath = \`\${input.root}/.scg/onboarding/lifecycle.wal.v1.json\`;
const transactionPort = createNodeLifecycleTransactionPort();
let crashed = false;
let credentialPublishCalls = 0;
let credentialReserveCalls = 0;
let directoryReserveCalls = 0;
let entropyCalls = 0;
let identifierCalls = 0;
let lockAcquisitions = 0;
const report = () => ({
  crashPoint: input.crashPoint,
  credentialPublishCalls,
  credentialReserveCalls,
  directoryReserveCalls,
  entropyCalls,
  identifierCalls,
  lockAcquisitions,
});
const crash = async () => {
  if (crashed) throw new Error('crash hook invoked more than once');
  crashed = true;
  await new Promise((resolve, reject) => {
    process.stdout.write(JSON.stringify(report()) + '\\n', (error) => {
      if (error === undefined || error === null) resolve(undefined);
      else reject(error);
    });
  });
  process.exit(91);
};

const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
transactionPort.acquireAdvisoryLock = async (path) => {
  lockAcquisitions += 1;
  return acquireAdvisoryLock(path);
};
const publishStagedWrite = transactionPort.publishStagedWrite.bind(transactionPort);
transactionPort.publishStagedWrite = async (operation) => {
  await publishStagedWrite(operation);
  if (
    input.crashPoint === 'prepared-pre-write' &&
    operation.targetPath === walPath &&
    !crashed
  ) {
    const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    if (
      durable.operation === 'setup' &&
      durable.direction === 'rollback' &&
      durable.phase === 'prepared' &&
      durable.creationIntents?.length === 1
    ) {
      await crash();
    }
  }
};
const replaceExactWal = transactionPort.replaceExactWal.bind(transactionPort);
transactionPort.replaceExactWal = async (operation) => {
  const result = await replaceExactWal(operation);
  if (input.crashPoint === 'prepared-pre-write' && result.state === 'completed' && !crashed) {
    const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    if (
      durable.operation === 'setup' &&
      durable.direction === 'rollback' &&
      durable.phase === 'prepared' &&
      durable.creationIntents?.length === 1
    ) {
      await crash();
    }
  }
  return result;
};
const renameReservedStagedWrite = transactionPort.renameReservedStagedWrite.bind(transactionPort);
transactionPort.renameReservedStagedWrite = async (operation) => {
  await renameReservedStagedWrite(operation);
  credentialPublishCalls += 1;
  if (input.crashPoint === 'post-credential-publication' && !crashed) {
    await crash();
  }
};
const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
transactionPort.reserveStagedWrite = async (operation) => {
  credentialReserveCalls += 1;
  if (input.crashPoint === 'credential-reserved-before-identity-wal' && !crashed) {
    const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    const [intent] = durable.creationIntents ?? [];
    let stageAbsent = false;
    try {
      await lstat(operation.path);
    } catch (error: unknown) {
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') {
        stageAbsent = true;
      } else {
        throw error;
      }
    }
    if (
      !(
        durable.operation === 'setup' &&
        durable.direction === 'rollback' &&
        durable.phase === 'prepared' &&
        intent?.kind === 'credential' &&
        intent.stagingPath === operation.path &&
        stageAbsent
      )
    ) {
      throw new Error('credential reservation began without durable absent-stage intent');
    }
  }
  const reservation = await reserveStagedWrite(operation);
  if (input.crashPoint === 'credential-reserved-before-identity-wal' && !crashed) {
    const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    const [intent] = durable.creationIntents ?? [];
    if (
      durable.operation === 'setup' &&
      durable.direction === 'rollback' &&
      durable.phase === 'prepared' &&
      intent?.kind === 'credential' &&
      intent.stagingPath === operation.path
    ) {
      await crash();
    }
  }
  return reservation;
};
const reserveStagedDirectory = transactionPort.reserveStagedDirectory.bind(transactionPort);
transactionPort.reserveStagedDirectory = async (operation) => {
  directoryReserveCalls += 1;
  const reservation = await reserveStagedDirectory(operation);
  if (input.crashPoint === 'directory-reserved-before-identity-wal' && !crashed) {
    const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    const [intent] = durable.creationIntents ?? [];
    if (
      durable.operation === 'setup' &&
      durable.direction === 'rollback' &&
      durable.phase === 'prepared' &&
      intent?.kind === 'directory' &&
      intent.stagingPath === operation.path &&
      intent.targetPath === operation.targetPath
    ) {
      await crash();
    }
  }
  return reservation;
};
const publishReservedStagedDirectory =
  transactionPort.publishReservedStagedDirectory.bind(transactionPort);
transactionPort.publishReservedStagedDirectory = async (operation) => {
  await publishReservedStagedDirectory(operation);
  if (input.crashPoint === 'post-parent-publication' && !crashed) {
    await crash();
  }
};

const port = createNodeLifecycleEnginePort({
  approval: async () => true,
  checkoutRoot: input.root,
  cwd: input.root,
  homeDirectory: input.home,
  host: { credentialPath: input.credentialPath, port: 4175 },
  project: {
    allowedOrigins: ['http://127.0.0.1:4175'],
    framework: 'html',
    projectId: input.projectId,
    root: input.root,
    tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
  },
  random: {
    fill: (candidate) => {
      entropyCalls += 1;
      candidate.fill(0);
    },
    uuid: () => {
      identifierCalls += 1;
      return 'crash-child-mutation';
    },
  },
  transactionPort,
  verification: {
    bootstrap: { startEmptyWorkersEnabledProfile: async () => { throw new Error('not reached'); } },
    browser: { startProfile: async () => { throw new Error('not reached'); } },
    host: { start: async () => { throw new Error('not reached'); } },
    mcp: { startLoopback: async () => { throw new Error('not reached'); } },
    runBootstrapSmoke: async () => undefined,
    runLiveDiagnostics: async () => undefined,
    runNativeSelfTest: async () => undefined,
  },
});
if (input.crashPoint === 'post-apply') {
  const openSetupTransaction = port.openSetupTransaction.bind(port);
  port.openSetupTransaction = async (operation) => {
    const transaction = await openSetupTransaction(operation);
    return Object.freeze({
      apply: async (applyInput) => {
        const receipt = await transaction.apply(applyInput);
        await crash();
        return receipt;
      },
      compensate: transaction.compensate.bind(transaction),
      publishActive: transaction.publishActive.bind(transaction),
    });
  };
}
await runSetup(port);
throw new Error('setup crash hook did not fire');
};
void main().catch(() => {
  process.exitCode = 1;
});
`,
    { mode: 0o600 },
  );
  const childResult = await new Promise<{
    readonly code: number | null;
    readonly signal: NodeJS.Signals | null;
    readonly stderr: string;
    readonly stdout: string;
  }>((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', scriptPath], {
      cwd: process.cwd(),
      env: { ...process.env, SCG_SETUP_CRASH_INPUT: JSON.stringify(input) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let settled = false;
    const timeout: { value: NodeJS.Timeout | undefined } = { value: undefined };
    const failClosed = (error: Error): void => {
      if (settled) return;
      settled = true;
      if (timeout.value !== undefined) clearTimeout(timeout.value);
      child.kill('SIGKILL');
      reject(error);
    };
    const stdoutStream = child.stdout;
    const stderrStream = child.stderr;
    if (stdoutStream === null || stderrStream === null) {
      failClosed(new Error('setup crash child did not expose bounded output pipes'));
      return;
    }
    let stderr = '';
    let stdout = '';
    timeout.value = setTimeout(
      () => failClosed(new Error('setup crash child exceeded its bounded wait')),
      CHILD_WAIT_TIMEOUT_MS,
    );
    stdoutStream.setEncoding('utf8');
    stderrStream.setEncoding('utf8');
    stdoutStream.on('data', (chunk: string) => {
      if (settled) return;
      if (Buffer.byteLength(stdout, 'utf8') + Buffer.byteLength(chunk, 'utf8') > 4 * 1024) {
        failClosed(new Error('setup crash child exceeded its bounded stdout'));
        return;
      }
      stdout += chunk;
    });
    stderrStream.on('data', (chunk: string) => {
      if (settled) return;
      if (Buffer.byteLength(stderr, 'utf8') + Buffer.byteLength(chunk, 'utf8') > 4 * 1024) {
        failClosed(new Error('setup crash child exceeded its bounded stderr'));
        return;
      }
      stderr += chunk;
    });
    child.once('error', (error) => failClosed(error));
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      if (timeout.value !== undefined) clearTimeout(timeout.value);
      resolve({ code, signal, stderr, stdout });
    });
  });
  if (childResult.code !== 91 || childResult.signal !== null) {
    throw new Error('setup crash child did not exit at its crash boundary');
  }
  if (childResult.stderr !== '') {
    throw new Error('setup crash child wrote to stderr');
  }
  const lines = childResult.stdout.trim().split('\n');
  if (lines.length !== 1 || lines[0] === undefined) {
    throw new Error('setup crash child did not emit exactly one bounded crash report');
  }
  const report: unknown = JSON.parse(lines[0]);
  if (
    report === null ||
    typeof report !== 'object' ||
    Array.isArray(report) ||
    Object.keys(report).sort().join(',') !==
      'crashPoint,credentialPublishCalls,credentialReserveCalls,directoryReserveCalls,entropyCalls,identifierCalls,lockAcquisitions'
  ) {
    throw new Error('setup crash child emitted an invalid crash report');
  }
  const typed = report as SetupCrashReport;
  if (
    typed.crashPoint !== input.crashPoint ||
    !Number.isSafeInteger(typed.credentialPublishCalls) ||
    !Number.isSafeInteger(typed.credentialReserveCalls) ||
    !Number.isSafeInteger(typed.directoryReserveCalls) ||
    !Number.isSafeInteger(typed.entropyCalls) ||
    !Number.isSafeInteger(typed.identifierCalls) ||
    !Number.isSafeInteger(typed.lockAcquisitions)
  ) {
    throw new Error('setup crash child emitted malformed crash report fields');
  }
  return typed;
}

type PathSnapshot =
  | { readonly kind: 'absent' }
  | {
      readonly kind: 'directory';
      readonly identity: { readonly device: number; readonly inode: number };
      readonly mode: number;
    }
  | {
      readonly kind: 'file';
      readonly identity: { readonly device: number; readonly inode: number };
      readonly mode: number;
      readonly bytes: Buffer;
    };
async function expectPreparedWalFixtureRestored(input: {
  readonly expectedLock: PathSnapshot;
  readonly expectedTree: ReadonlyMap<string, PathSnapshot>;
  readonly expectedWal: PathSnapshot;
  readonly lockPath: string;
  readonly root: string;
  readonly walPath: string;
}): Promise<void> {
  const [tree, lock, wal] = await Promise.all([
    captureFilesystemTree(input.root),
    capturePathSnapshot(input.lockPath),
    capturePathSnapshot(input.walPath),
  ]);
  expect({ tree, lock, wal }).toStrictEqual({
    tree: input.expectedTree,
    lock: input.expectedLock,
    wal: input.expectedWal,
  });
}
interface CorruptedWalRecoveryAssertion {
  readonly canonicalCorruptedWal: string;
  readonly corruptedLock: PathSnapshot;
  readonly corruptedTree: ReadonlyMap<string, PathSnapshot>;
  readonly corruptionName: string;
  readonly corruptedWal: string;
  readonly expectedFailureStage: 'third-state' | 'wal-authority';
  readonly lockPath: string;
  readonly recoverAuthorizedWal: () => Promise<unknown>;
  readonly root: string;
  readonly walPath: string;
}

async function assertCorruptedWalRecoveryFailsClosed(
  input: CorruptedWalRecoveryAssertion,
): Promise<void> {
  const corruptedWalSnapshot = input.corruptedTree.get(input.walPath);
  if (corruptedWalSnapshot === undefined) {
    throw new Error('corrupted WAL snapshot omitted the configured WAL path');
  }
  const recover = async (): Promise<
    | { readonly state: 'fulfilled'; readonly value: unknown }
    | {
        readonly state: 'rejected';
        readonly name: string;
        readonly message: string;
        readonly failures: readonly unknown[];
      }
  > =>
    input.recoverAuthorizedWal().then(
      (value) => ({ state: 'fulfilled' as const, value }),
      (error: unknown) => {
        if (!(error instanceof LifecycleTransactionError)) {
          throw new Error('corrupted WAL recovery rejected with an unexpected error type');
        }
        return {
          state: 'rejected' as const,
          name: error.name,
          message: error.message,
          failures: error.failures,
        };
      },
    );
  const firstRecovery = await recover();
  const [walAfterFirstRecovery, treeAfterFirstRecovery, lockAfterFirstRecovery] = await Promise.all(
    [
      capturePathSnapshot(input.walPath),
      captureFilesystemTree(input.root),
      capturePathSnapshot(input.lockPath),
    ],
  );
  const secondRecovery = await recover();
  const [walAfterSecondRecovery, treeAfterSecondRecovery, lockAfterSecondRecovery] =
    await Promise.all([
      capturePathSnapshot(input.walPath),
      captureFilesystemTree(input.root),
      capturePathSnapshot(input.lockPath),
    ]);
  const expectedRecovery = {
    state: 'rejected' as const,
    name: 'LifecycleTransactionError',
    message: 'lifecycle recovery transaction failed',
    failures: [{ stage: input.expectedFailureStage }],
  };
  expect({
    corruptionName: input.corruptionName,
    persistedWal: input.corruptedWal,
    recoveries: [firstRecovery, secondRecovery],
    walAfterRecoveries: [walAfterFirstRecovery, walAfterSecondRecovery],
    treesAfterRecoveries: [treeAfterFirstRecovery, treeAfterSecondRecovery],
    locksAfterRecoveries: [lockAfterFirstRecovery, lockAfterSecondRecovery],
  }).toStrictEqual({
    persistedWal: input.canonicalCorruptedWal,
    corruptionName: input.corruptionName,
    recoveries: [expectedRecovery, expectedRecovery],
    walAfterRecoveries: [corruptedWalSnapshot, corruptedWalSnapshot],
    treesAfterRecoveries: [input.corruptedTree, input.corruptedTree],
    locksAfterRecoveries: [input.corruptedLock, input.corruptedLock],
  });
}

interface FilesystemTraversal {
  readonly deadline: number;
  entries: number;
  bytes: number;
}

interface SecretResidualScanOptions {
  readonly rejectLifecycleTemporaryPaths?: boolean;
}

function credentialSecretCanaries(token: string, credentialLine: string): readonly Buffer[] {
  const canaries = new Map<string, Buffer>();
  const add = (value: string | Uint8Array): void => {
    const bytes = Buffer.from(value);
    canaries.set(bytes.toString('hex'), bytes);
  };
  for (const material of [
    Buffer.from(token, 'utf8'),
    Buffer.from(token, 'base64url'),
    Buffer.from(credentialLine, 'utf8'),
  ]) {
    add(material);
    add(material.toString('base64'));
    add(material.toString('base64url'));
    const digest = createHash('sha256').update(material).digest('hex');
    add(digest);
    add(`sha256:${digest}`);
  }
  return [...canaries.values()];
}

function createFilesystemTraversal(): FilesystemTraversal {
  return { deadline: Date.now() + MAX_FILESYSTEM_TRAVERSAL_MS, entries: 0, bytes: 0 };
}

function enterFilesystemTraversal(
  traversal: FilesystemTraversal,
  path: string,
  depth: number,
): void {
  if (depth > MAX_FILESYSTEM_TRAVERSAL_DEPTH) {
    throw new Error(`filesystem traversal exceeded its bounded depth at ${path}`);
  }
  if (traversal.entries >= MAX_FILESYSTEM_TRAVERSAL_ENTRIES) {
    throw new Error(`filesystem traversal exceeded its bounded entry count at ${path}`);
  }
  if (Date.now() >= traversal.deadline) {
    throw new Error(`filesystem traversal exceeded its bounded deadline at ${path}`);
  }
  traversal.entries += 1;
}

async function awaitFilesystemOperation<T>(
  traversal: FilesystemTraversal,
  description: string,
  operation: Promise<T>,
): Promise<T> {
  const remaining = traversal.deadline - Date.now();
  if (remaining <= 0) {
    throw new Error(`filesystem traversal exceeded its bounded deadline before ${description}`);
  }
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`filesystem traversal timed out while ${description}`)),
      remaining,
    );
    void operation.then(
      (result) => {
        clearTimeout(timeout);
        resolve(result);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function readBoundedFile(
  path: string,
  size: number,
  traversal: FilesystemTraversal,
): Promise<Buffer> {
  if (
    !Number.isSafeInteger(size) ||
    size < 0 ||
    size > MAX_FILESYSTEM_FILE_BYTES ||
    traversal.bytes + size > MAX_FILESYSTEM_TRAVERSAL_BYTES
  ) {
    throw new Error(`filesystem traversal encountered an oversized file at ${path}`);
  }
  traversal.bytes += size;
  const bytes = await awaitFilesystemOperation(traversal, `reading ${path}`, readFile(path));
  const byteDelta = bytes.byteLength - size;
  if (
    !Number.isSafeInteger(bytes.byteLength) ||
    bytes.byteLength > MAX_FILESYSTEM_FILE_BYTES ||
    (byteDelta > 0 && traversal.bytes + byteDelta > MAX_FILESYSTEM_TRAVERSAL_BYTES)
  ) {
    bytes.fill(0);
    throw new Error(`filesystem traversal read an oversized file at ${path}`);
  }
  traversal.bytes += byteDelta;
  return bytes;
}

async function readBoundedRegularFile(
  path: string,
  traversal: FilesystemTraversal,
): Promise<Buffer> {
  const observed = await awaitFilesystemOperation(traversal, `stating ${path}`, lstat(path));
  if (!observed.isFile()) {
    throw new Error(`filesystem traversal encountered a non-regular file at ${path}`);
  }
  return readBoundedFile(path, observed.size, traversal);
}
async function readBoundedDirectory(
  path: string,
  traversal: FilesystemTraversal,
): Promise<readonly Dirent[]> {
  const directory = await awaitFilesystemOperation(
    traversal,
    `opening directory ${path}`,
    opendir(path, { bufferSize: 16 }),
  );
  const entries: Dirent[] = [];
  let primary: unknown;
  let hasPrimaryError = false;
  try {
    for (;;) {
      const entry = await awaitFilesystemOperation(
        traversal,
        `reading directory ${path}`,
        directory.read(),
      );
      if (entry === null) break;
      if (entries.length >= MAX_FILESYSTEM_TRAVERSAL_ENTRIES) {
        throw new Error(`filesystem traversal exceeded its bounded entry count at ${path}`);
      }
      entries.push(entry);
    }
  } catch (error) {
    hasPrimaryError = true;
    primary = error;
  }

  let closeError: unknown;
  let hasCloseError = false;
  try {
    await awaitFilesystemOperation(traversal, `closing directory ${path}`, directory.close());
  } catch (error) {
    hasCloseError = true;
    closeError = error;
  }
  if (hasPrimaryError) throw primary;
  if (hasCloseError) throw closeError;
  return entries.sort((left, right) => left.name.localeCompare(right.name));
}

async function capturePathSnapshot(
  path: string,
  traversal = createFilesystemTraversal(),
): Promise<PathSnapshot> {
  try {
    const observed = await awaitFilesystemOperation(traversal, `stating ${path}`, lstat(path));
    const identity = { device: observed.dev, inode: observed.ino };
    const mode = observed.mode & 0o777;
    if (observed.isDirectory()) return { kind: 'directory', identity, mode };
    if (observed.isFile()) {
      return {
        kind: 'file',
        identity,
        mode,
        bytes: await readBoundedFile(path, observed.size, traversal),
      };
    }
    throw new Error(`fixture contains unsupported planned target kind at ${path}`);
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') {
      return { kind: 'absent' };
    }
    throw error;
  }
}

async function captureRecoverySurfaceSnapshot(
  paths: readonly string[],
): Promise<ReadonlyMap<string, PathSnapshot>> {
  if (paths.length > MAX_FILESYSTEM_TRAVERSAL_ENTRIES) {
    throw new Error('recovery surface exceeds the bounded filesystem traversal entry count');
  }
  const traversal = createFilesystemTraversal();
  return new Map(
    await Promise.all(
      paths.map(async (path) => {
        enterFilesystemTraversal(traversal, path, 0);
        return [path, await capturePathSnapshot(path, traversal)] as const;
      }),
    ),
  );
}

async function expectRecoverySurfaceSnapshot(
  paths: readonly string[],
  expected: ReadonlyMap<string, PathSnapshot>,
): Promise<void> {
  await expect(captureRecoverySurfaceSnapshot(paths)).resolves.toEqual(expected);
}

async function captureFilesystemTree(root: string): Promise<ReadonlyMap<string, PathSnapshot>> {
  const snapshots = new Map<string, PathSnapshot>();
  const traversal = createFilesystemTraversal();
  const visit = async (path: string, depth: number): Promise<void> => {
    enterFilesystemTraversal(traversal, path, depth);
    const snapshot = await capturePathSnapshot(path, traversal);
    snapshots.set(path, snapshot);
    if (snapshot.kind !== 'directory') return;
    const entries = await readBoundedDirectory(path, traversal);
    for (const entry of entries) {
      await visit(join(path, entry.name), depth + 1);
    }
  };
  await visit(root, 0);
  return snapshots;
}

async function expectFilesystemTree(
  root: string,
  expected: ReadonlyMap<string, PathSnapshot>,
): Promise<void> {
  await expect(captureFilesystemTree(root)).resolves.toEqual(expected);
}

function isLifecycleTemporaryPath(path: string): boolean {
  const name = path.slice(path.lastIndexOf('/') + 1);
  return (
    (name.includes('.scene-glass-') && /\.(?:stage|rollback|quarantine)$/.test(name)) ||
    (name.startsWith('.scg-intent-') && name.endsWith('.marker'))
  );
}

function containsByteSequence(value: Uint8Array, candidate: Uint8Array): boolean {
  if (candidate.byteLength === 0) return true;
  for (let offset = 0; offset <= value.byteLength - candidate.byteLength; offset += 1) {
    let matches = true;
    for (let index = 0; index < candidate.byteLength; index += 1) {
      if (value[offset + index] !== candidate[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

async function expectNoSecretResidualFiles(
  roots: readonly string[],
  excludedPaths: ReadonlySet<string>,
  canaries: readonly Uint8Array[],
  options: SecretResidualScanOptions = {},
): Promise<void> {
  const traversal = createFilesystemTraversal();
  const visited = new Set<string>();
  const visit = async (path: string, depth: number): Promise<void> => {
    if (visited.has(path)) return;
    visited.add(path);
    enterFilesystemTraversal(traversal, path, depth);
    const entries = await readBoundedDirectory(path, traversal);
    for (const entry of entries) {
      const child = join(path, entry.name);
      if (visited.has(child)) continue;
      if (options.rejectLifecycleTemporaryPaths && isLifecycleTemporaryPath(child)) {
        throw new Error(`lifecycle temporary residue remained at ${child}`);
      }
      if (entry.isDirectory()) {
        await visit(child, depth + 1);
        continue;
      }
      if (!entry.isFile()) {
        throw new Error(`filesystem traversal encountered a non-regular entry at ${child}`);
      }
      visited.add(child);
      enterFilesystemTraversal(traversal, child, depth + 1);
      if (excludedPaths.has(child)) continue;
      const bytes = await readBoundedRegularFile(child, traversal);
      try {
        for (const canary of canaries) expect(containsByteSequence(bytes, canary)).toBe(false);
      } finally {
        bytes.fill(0);
      }
    }
  };
  for (const root of roots) await visit(root, 0);
}
