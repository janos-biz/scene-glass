import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { serializeStaticHostDescriptorV1 } from '../../packages/onboarding/src/descriptors.js';
import {
  parseCredentialAuthorityRegistryJsonV1,
  serializeCredentialAuthorityRegistryV1,
} from '../../packages/onboarding/src/credential-authority.js';
import {
  canonicalServerTokenEnvForProjectId,
  planConfigOperation,
} from '../../packages/onboarding/src/lifecycle/config.js';
import { planHostIntegration } from '../../packages/onboarding/src/lifecycle/host-plan.js';
import {
  LifecyclePreparedStartUnavailableError,
  LifecycleStartDiagnosticError,
  runSetup,
  runStart,
  runUninstall,
} from '../../packages/onboarding/src/lifecycle/engine.js';
import { createNodeLifecycleEnginePort } from '../../packages/onboarding/src/lifecycle/node-engine-port.js';
import {
  parseSetupManifestJsonV1,
  parseWalRecordJsonV2,
  serializeLifecycleReceiptV1,
  serializeSetupManifestV1,
  serializeWalRecordV1,
  serializeWalRecordV2,
} from '../../packages/onboarding/src/lifecycle/provenance.js';
import {
  createNodeLifecycleVerificationPorts,
  type NodeLifecycleVerificationPorts,
} from '../../packages/onboarding/src/lifecycle/node-verification-port.js';
import { createNodeLifecycleTransactionPort } from '../../packages/onboarding/src/lifecycle/node-transaction-port.js';
import type { LifecycleTransactionPort } from '../../packages/onboarding/src/lifecycle/transaction.js';
import type { SetupManifestV1 } from '../../packages/onboarding/src/lifecycle/types.js';

const roots: string[] = [];
const NODE_LIFECYCLE_SERVER_TOKEN_ENV = canonicalServerTokenEnvForProjectId('node-lifecycle');
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe('Node onboarding lifecycle adapter', () => {
  it('leaves every Node-port mutation boundary untouched when setup approval is declined', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const legacy = join(home, '.config/scene-glass/config.json');
    const current = join(home, '.scg/config.json');
    const legacyBytes = `${JSON.stringify({ schemaVersion: 1, projects: [project(root)] }, null, 2)}\n`;
    const stateRoot = join(root, '.scg/onboarding');
    const credentialPath = join(root, '.env.scene-glass.local');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    await mkdir(dirname(legacy), { recursive: true, mode: 0o700 });
    await writeFile(legacy, legacyBytes, { mode: 0o600 });
    const transactionPort = createNodeLifecycleTransactionPort();
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    const stageWrite = transactionPort.stageWrite.bind(transactionPort);
    const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
    const reserveStagedDirectory = transactionPort.reserveStagedDirectory.bind(transactionPort);
    const renameReservedStagedWrite =
      transactionPort.renameReservedStagedWrite.bind(transactionPort);
    const publishReservedStagedDirectory =
      transactionPort.publishReservedStagedDirectory.bind(transactionPort);
    const calls = {
      entropy: 0,
      lock: 0,
      publish: 0,
      rename: 0,
      reserve: 0,
      stage: 0,
      uuid: 0,
    };
    transactionPort.acquireAdvisoryLock = async (path) => {
      calls.lock += 1;
      return acquireAdvisoryLock(path);
    };
    transactionPort.stageWrite = async (input) => {
      calls.stage += 1;
      return stageWrite(input);
    };
    transactionPort.reserveStagedWrite = async (input) => {
      calls.reserve += 1;
      return reserveStagedWrite(input);
    };
    transactionPort.reserveStagedDirectory = async (input) => {
      calls.reserve += 1;
      return reserveStagedDirectory(input);
    };
    transactionPort.renameReservedStagedWrite = async (input) => {
      calls.rename += 1;
      return renameReservedStagedWrite(input);
    };
    transactionPort.publishReservedStagedDirectory = async (input) => {
      calls.publish += 1;
      return publishReservedStagedDirectory(input);
    };
    const invariantPaths = [
      root,
      join(root, '.gitignore'),
      join(root, 'public'),
      join(root, 'public/index.html'),
      join(root, '.scg'),
      stateRoot,
      join(stateRoot, 'lifecycle.wal.v1.json'),
      join(stateRoot, 'manifest.v1.json'),
      join(stateRoot, 'receipt.v1.json'),
      credentialPath,
      home,
      join(home, '.config'),
      dirname(legacy),
      legacy,
      join(home, '.scg'),
      current,
      join(home, '.scg/credential-authorities.v1.json'),
      lockPath,
    ];
    const snapshot = await captureFilesystemSnapshot(invariantPaths);
    const entries = await captureDirectoryEntries([
      root,
      home,
      join(home, '.config'),
      dirname(legacy),
    ]);
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: {
        credentialPath,
        port: 4175,
      },
      project: project(root),
      random: {
        fill: () => {
          calls.entropy += 1;
        },
        uuid: () => {
          calls.uuid += 1;
          return 'declined-setup';
        },
      },
      transactionPort,
      verification: verification(),
    });

    const facts = await port.inspectSetupFacts();
    const repeatedFacts = await port.inspectSetupFacts();
    expect(repeatedFacts.build).toEqual(facts.build);
    const plan = planConfigOperation({ homes: facts.configHomes, project: facts.project });
    const result = await runSetup(port);

    expect(plan.configOperation).toBe('legacy-move');
    expect(result.code).toBe('SCG_LIFECYCLE_DECLINED');
    await expectFilesystemSnapshot(snapshot);
    await expect(
      captureDirectoryEntries([root, home, join(home, '.config'), dirname(legacy)]),
    ).resolves.toEqual(entries);
    expect(calls).toEqual({
      entropy: 0,
      lock: 0,
      publish: 0,
      rename: 0,
      reserve: 0,
      stage: 0,
      uuid: 0,
    });
  });
  it('uses one approved credential candidate under the real lock and recovers its committed authority without regeneration', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const configDirectory = join(home, '.scg');
    const configPath = join(configDirectory, 'config.json');
    const registryPath = join(configDirectory, 'credential-authorities.v1.json');
    const stateRoot = join(root, '.scg/onboarding');
    const credentialPath = join(root, '.env.scene-glass.local');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const walPath = join(stateRoot, 'lifecycle.wal.v1.json');
    const manifestPath = join(stateRoot, 'manifest.v1.json');
    const entropyCounterPath = join(root, 'entropy-count');
    const mutationId = 'approved-setup-lock-proof';
    const credentialStagingPath = `${credentialPath}.scene-glass-${mutationId}.credential.stage`;
    const runtimePath = join(root, '.scg/runtime');
    await mkdir(configDirectory, { recursive: true, mode: 0o700 });
    await writeFile(entropyCounterPath, '0\n', { mode: 0o600 });

    const plannedPaths = [
      configPath,
      registryPath,
      join(root, 'public/index.html'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/runtime/host-integration-helper.mjs'),
      credentialPath,
    ];
    const plannedPreimages = await captureFilesystemSnapshot(plannedPaths);
    const expectedPreimages = plannedPaths
      .filter((path) => path !== credentialPath)
      .sort()
      .map((path) => {
        const snapshot = plannedPreimages.get(path);
        if (snapshot === undefined) throw new Error(`fixture preimage is missing ${path}`);
        return expectedWalPreimage(path, snapshot);
      });
    const credentialPreimage = plannedPreimages.get(credentialPath);
    if (credentialPreimage === undefined) {
      throw new Error('fixture credential preimage is missing');
    }
    expectedPreimages.push(expectedWalPreimage(credentialPath, credentialPreimage));
    const runtimePreimage = (await captureFilesystemSnapshot([runtimePath])).get(runtimePath);
    if (runtimePreimage === undefined) {
      throw new Error('fixture runtime preimage is missing');
    }
    expectedPreimages.push(expectedWalPreimage(runtimePath, runtimePreimage));

    const transactionPort = createNodeLifecycleTransactionPort();
    const acquireAdvisoryLock = transactionPort.acquireAdvisoryLock.bind(transactionPort);
    const reserveStagedWrite = transactionPort.reserveStagedWrite.bind(transactionPort);
    const writeReservedStagedWrite = transactionPort.writeReservedStagedWrite.bind(transactionPort);
    const fsyncParent = transactionPort.fsyncParent.bind(transactionPort);
    let credentialReservations = 0;
    let credentialWrites = 0;
    let commitDecisionFailures = 0;
    let entropyFills = 0;
    let candidateRequests = 0;
    let uuidRequests = 0;
    let approvalRequests = 0;
    let firstCredentialWriteWal: ReturnType<typeof parseWalRecordJsonV2> | undefined;

    const assertConfiguredLockHeld = async (): Promise<void> => {
      const contention = await acquireAdvisoryLock(lockPath).then(
        async (lock) => {
          await lock.release();
          return undefined;
        },
        (error: unknown) => error,
      );
      expectConfiguredNodeLockContention(contention);
    };

    transactionPort.reserveStagedWrite = async (input) => {
      credentialReservations += 1;
      expect({ path: input.path, mode: input.mode }).toEqual({
        path: credentialStagingPath,
        mode: 0o600,
      });
      await assertConfiguredLockHeld();
      return reserveStagedWrite(input);
    };
    transactionPort.writeReservedStagedWrite = async (input) => {
      credentialWrites += 1;
      await assertConfiguredLockHeld();
      const staged = await lstat(credentialStagingPath, { bigint: true });
      const runtime = await lstat(runtimePath, { bigint: true });
      const expectedPreparedWal = {
        schemaVersion: 2 as const,
        kind: 'scene-glass-lifecycle-wal' as const,
        operationId: mutationId,
        installId: expectedInstallId,
        operation: 'setup' as const,
        direction: 'rollback' as const,
        phase: 'prepared' as const,
        lockPath,
        manifestPath,
        cursor: 1,
        preimages: expectedPreimages,
        mutations: [
          {
            step: 0,
            kind: 'ordinary' as const,
            targetPath: runtimePath,
            sourcePath: `${runtimePath}.scene-glass-${mutationId}-0.rollback`,
            stagingPath: `${runtimePath}.scene-glass-${mutationId}.directory.stage`,
            preimage: expectedPreimages.length - 1,
            result: {
              kind: 'directory' as const,
              identity: {
                device: runtime.dev.toString(10),
                inode: runtime.ino.toString(10),
              },
              mode: 0o700,
            },
          },
          {
            step: 1,
            kind: 'credential' as const,
            projectId: 'node-lifecycle',
            path: credentialPath,
            mode: 0o600,
            stagingPath: credentialStagingPath,
            stagingIdentity: {
              device: staged.dev.toString(10),
              inode: staged.ino.toString(10),
            },
            targetIdentity: {
              device: staged.dev.toString(10),
              inode: staged.ino.toString(10),
            },
          },
        ],
      };
      firstCredentialWriteWal = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
      const { authorityFingerprint, replacedWalStage, ...observedPreparedWal } =
        firstCredentialWriteWal;
      expect(observedPreparedWal).toEqual(expectedPreparedWal);
      expect(replacedWalStage).toMatchObject({
        mode: 0o600,
        authorityFingerprint: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
        identity: {
          device: expect.stringMatching(/^(?:0|[1-9][0-9]*)$/u),
          inode: expect.stringMatching(/^(?:0|[1-9][0-9]*)$/u),
        },
      });
      expect(authorityFingerprint).toBe(
        sha(
          new TextEncoder().encode(
            serializeWalRecordV2({
              ...firstCredentialWriteWal,
              authorityFingerprint: `sha256:${'0'.repeat(64)}`,
            }),
          ),
        ),
      );
      return writeReservedStagedWrite(input);
    };
    transactionPort.fsyncParent = async (input) => {
      await fsyncParent(input);
      if (input.path !== walPath || commitDecisionFailures !== 0) return;
      const durable = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
      if (
        durable.operation === 'setup' &&
        durable.direction === 'commit' &&
        durable.phase === 'commit-decided'
      ) {
        commitDecisionFailures += 1;
        throw new Error('simulated process loss after the durable commit decision');
      }
    };

    const port = createNodeLifecycleEnginePort({
      approval: async () => {
        approvalRequests += 1;
        return true;
      },
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath, port: 4175 },
      project: project(root),
      random: {
        fill: (candidate) => {
          entropyFills += 1;
          const count = Number.parseInt(readFileSync(entropyCounterPath, 'utf8'), 10);
          writeFileSync(entropyCounterPath, `${count + 1}\n`, { mode: 0o600 });
          candidate.set(Uint8Array.from({ length: 32 }, (_, index) => index));
        },
        uuid: () => {
          uuidRequests += 1;
          return mutationId;
        },
      },
      transactionPort,
      verification: successfulVerification(),
    });
    const facts = await port.inspectSetupFacts();
    const expectedInstallId = planHostIntegration(facts.hostPlan).installId;
    const generateCredentialToken = port.generateCredentialToken.bind(port);
    port.generateCredentialToken = async (input) => {
      candidateRequests += 1;
      return generateCredentialToken(input);
    };
    const setupResult = await runSetup(port);

    expect(setupResult).toMatchObject({
      code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      state: 'recovery-required',
    });
    expect({
      approvalRequests,
      entropyFills,
      candidateRequests,
      credentialReservations,
      credentialWrites,
      commitDecisionFailures,
      uuidRequests,
    }).toEqual({
      approvalRequests: 1,
      entropyFills: 1,
      candidateRequests: 1,
      credentialReservations: 1,
      credentialWrites: 1,
      commitDecisionFailures: 1,
      uuidRequests: 1,
    });
    if (firstCredentialWriteWal === undefined) {
      throw new Error('setup did not reach the credential write authority boundary');
    }
    const durableCommitWal = parseWalRecordJsonV2(await readFile(walPath, 'utf8'));
    expect({
      operation: durableCommitWal.operation,
      direction: durableCommitWal.direction,
      phase: durableCommitWal.phase,
      operationId: durableCommitWal.operationId,
    }).toEqual({
      operation: 'setup',
      direction: 'commit',
      phase: 'commit-decided',
      operationId: mutationId,
    });
    const lockBeforeRecovery = await captureFilesystemEntry(lockPath);
    const released = await acquireAdvisoryLock(lockPath);
    await released.release();

    expect(
      await runFreshSetupRecoveryChild({
        root,
        home,
        credentialPath,
        entropyCounterPath,
      }),
    ).toEqual({ code: 'SCG_LIFECYCLE_ACTIVE', state: 'active' });
    expect(Number.parseInt(await readFile(entropyCounterPath, 'utf8'), 10)).toBe(1);

    const expectedToken = Buffer.from(
      Uint8Array.from({ length: 32 }, (_, index) => index),
    ).toString('base64url');
    const expectedCredential = credentialEnvelope('node-lifecycle', expectedToken);
    expect(expectedCredential).toContain(`SCENE_GLASS_HOST_TOKEN=${expectedToken}\n`);
    expect(expectedCredential).not.toContain(NODE_LIFECYCLE_SERVER_TOKEN_ENV);
    const credential = await lstat(credentialPath, { bigint: true });
    expect(await readFile(credentialPath, 'utf8')).toBe(expectedCredential);
    expect(Number(credential.mode & 0o777n)).toBe(0o600);
    const expectedRegistry = {
      schemaVersion: 1,
      projects: [
        {
          projectId: 'node-lifecycle',
          tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
          canonicalRoot: root,
          credentialPath,
          device: credential.dev.toString(10),
          inode: credential.ino.toString(10),
        },
      ],
    };
    const expectedRegistryFingerprint = sha(
      new TextEncoder().encode(serializeCredentialAuthorityRegistryV1(expectedRegistry)),
    );
    const registry = await lstat(registryPath, { bigint: true });
    expect(Number(registry.mode & 0o777n)).toBe(0o600);
    expect(parseCredentialAuthorityRegistryJsonV1(await readFile(registryPath, 'utf8'))).toEqual(
      expectedRegistry,
    );
    const manifestStat = await lstat(manifestPath, { bigint: true });
    expect(Number(manifestStat.mode & 0o777n)).toBe(0o600);
    const manifest = parseSetupManifestJsonV1(await readFile(manifestPath, 'utf8'));
    expect({
      schemaVersion: manifest.schemaVersion,
      kind: manifest.kind,
      installId: manifest.installId,
      state: manifest.state,
      credentialAuthorities: manifest.artifacts.filter(
        (artifact) =>
          artifact.kind === 'credential' || artifact.kind === 'credential-authority-registry',
      ),
    }).toEqual({
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: expectedInstallId,
      state: 'active',
      credentialAuthorities: [
        {
          path: credentialPath,
          kind: 'credential',
          ownership: 'setup-created',
          projectId: 'node-lifecycle',
          identity: {
            device: credential.dev.toString(10),
            inode: credential.ino.toString(10),
          },
          mode: 0o600,
          linkCount: 1,
          inverse: {
            kind: 'delete-created-credential',
            path: credentialPath,
            projectId: 'node-lifecycle',
            identity: {
              device: credential.dev.toString(10),
              inode: credential.ino.toString(10),
            },
            mode: 0o600,
            linkCount: 1,
          },
        },
        {
          path: registryPath,
          kind: 'credential-authority-registry',
          fingerprint: expectedRegistryFingerprint,
          preimage: { schemaVersion: 1, projects: [] },
          postimage: expectedRegistry,
          inverse: {
            kind: 'restore-credential-authority-registry-entry',
            path: registryPath,
            preimage: { schemaVersion: 1, projects: [] },
            postimage: expectedRegistry,
          },
        },
      ],
    });
    expect(await captureFilesystemEntry(lockPath)).toEqual(lockBeforeRecovery);
  });
  it('fails closed for missing-registry homes outside the selected legacy bootstrap', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const legacy = join(home, '.config/scene-glass/config.json');
    const current = join(home, '.scg/config.json');
    const common = {
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      verification: verification(),
    };

    const legacyBytes = '{\n  "schemaVersion": 1,\n  "projects": []\n}\n';
    const registry = join(home, '.scg/credential-authorities.v1.json');
    const stateRoot = join(root, '.scg/onboarding');
    const invariantPaths = [
      root,
      join(root, '.gitignore'),
      join(root, 'public'),
      join(root, 'public/index.html'),
      join(root, '.scg'),
      stateRoot,
      join(stateRoot, 'lifecycle.wal.v1.json'),
      join(stateRoot, 'manifest.v1.json'),
      join(stateRoot, 'receipt.v1.json'),
      join(root, '.env.scene-glass.local'),
      home,
      join(home, '.config'),
      dirname(legacy),
      legacy,
      join(home, '.scg'),
      current,
      registry,
      join(home, '.scene-glass-onboarding.lock'),
    ];
    await mkdir(dirname(legacy), { recursive: true, mode: 0o700 });
    await writeFile(legacy, legacyBytes, { mode: 0o600 });
    const legacySnapshot = await captureFilesystemSnapshot(invariantPaths);
    await expect(createNodeLifecycleEnginePort(common).inspectSetupFacts()).rejects.toThrow(
      'legacy setup requires one selected project and no registry',
    );
    await expectFilesystemSnapshot(legacySnapshot);
    await rm(legacy);

    const currentBytes = `${JSON.stringify({ schemaVersion: 1, projects: [project(root)] }, null, 2)}\n`;
    await mkdir(dirname(current), { recursive: true, mode: 0o700 });
    await writeFile(current, currentBytes, { mode: 0o600 });
    const currentSnapshot = await captureFilesystemSnapshot(invariantPaths);
    await expect(createNodeLifecycleEnginePort(common).inspectSetupFacts()).rejects.toThrow(
      'current config requires a canonical authority registry',
    );
    await expectFilesystemSnapshot(currentSnapshot);
  });
  it('fails closed on an on-disk WAL with no in-memory recovery authority', async () => {
    const root = await fixture();
    const stateRoot = join(root, '.scg/onboarding');
    const walPath = join(stateRoot, 'lifecycle.wal.v1.json');
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    const persistedWal = serializeWalRecordV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'recovery-wal',
      installId: 'recovery-install',
      operation: 'setup',
      phase: 'prepared',
      manifestFingerprint: `sha256:${'a'.repeat(64)}`,
    });
    await writeFile(walPath, persistedWal, { mode: 0o600 });
    const persistedWalStat = await lstat(walPath);

    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: join(root, 'home'),
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      verification: verification(),
    });

    const inspection = await port.inspectLifecycle({ operation: 'setup' });

    expect(inspection.state).toBe('recovery-required');
    expect(inspection.authorizedWal).toBeUndefined();
    await expect(port.recoverAuthorizedWal({ recoveryId: 'untrusted-v1' })).resolves.toBe(
      'recovery-required',
    );
    expect(await readFile(walPath, 'utf8')).toBe(persistedWal);
    const preservedWalStat = await lstat(walPath);
    expect({
      device: preservedWalStat.dev,
      inode: preservedWalStat.ino,
      mode: preservedWalStat.mode & 0o777,
    }).toEqual({
      device: persistedWalStat.dev,
      inode: persistedWalStat.ino,
      mode: persistedWalStat.mode & 0o777,
    });
  });
  it('converges when a new active manifest supersedes a prior terminal receipt', async () => {
    const root = await fixture();
    const stateRoot = join(root, '.scg/onboarding');
    const target = join(root, 'owned.txt');
    const receiptPath = join(stateRoot, 'receipt.v1.json');
    const manifestPath = join(stateRoot, 'manifest.v1.json');
    const bytes = new TextEncoder().encode('owned-beta');
    const fingerprint = sha(bytes);
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    const home = join(root, 'home');
    await mkdir(join(home, '.scg'), { recursive: true, mode: 0o700 });
    await writeFile(join(home, '.scene-glass-onboarding.lock'), 'lock\n', { mode: 0o600 });
    await writeFile(target, bytes, { mode: 0o600 });
    await writeFile(
      receiptPath,
      serializeLifecycleReceiptV1({
        schemaVersion: 1,
        kind: 'scene-glass-lifecycle-receipt',
        operationId: 'uninstall-alpha',
        installId: 'install-alpha',
        terminalState: 'uninstalled',
        manifestFingerprint: sha(new TextEncoder().encode('manifest-alpha')),
      }),
      { mode: 0o600 },
    );
    await writeFile(
      manifestPath,
      serializeSetupManifestV1({
        schemaVersion: 1,
        kind: 'scene-glass-setup-manifest',
        installId: 'install-beta',
        state: 'active',
        artifacts: [
          {
            path: target,
            kind: 'file',
            fingerprint,
            hunks: [],
            inverse: {
              kind: 'delete-created-file',
              path: target,
              expectedFingerprint: fingerprint,
            },
          },
        ],
      }),
      { mode: 0o600 },
    );
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      verification: verification(),
    });

    await expect(port.inspectLifecycle({ operation: 'start' })).resolves.toMatchObject({
      state: 'active',
      activeManifest: { installId: 'install-beta' },
    });
    const uninstall = await runUninstall(port);
    expect(uninstall).toMatchObject({
      code: 'SCG_LIFECYCLE_UNINSTALLED',
      state: 'uninstalled',
    });
    expect(JSON.parse(await readFile(receiptPath, 'utf8'))).toMatchObject({
      installId: 'install-beta',
      terminalState: 'uninstalled',
    });
    await expect(readFile(target)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(manifestPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(join(stateRoot, 'lifecycle.wal.v1.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    await expect(runUninstall(port)).resolves.toMatchObject({
      code: 'SCG_LIFECYCLE_ALREADY_UNINSTALLED',
      state: 'uninstalled',
    });
  });
  it('refuses a changed active-manifest target without creating a terminal receipt', async () => {
    const root = await fixture();
    const stateRoot = join(root, '.scg/onboarding');
    const target = join(root, 'owned.txt');
    const manifestPath = join(stateRoot, 'manifest.v1.json');
    const receiptPath = join(stateRoot, 'receipt.v1.json');
    const original = new TextEncoder().encode('owned-original');
    const originalFingerprint = sha(original);
    const sourceManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'refused-uninstall',
      state: 'active',
      artifacts: [
        {
          path: target,
          kind: 'file',
          fingerprint: originalFingerprint,
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: target,
            expectedFingerprint: originalFingerprint,
          },
        },
      ],
    };
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await Promise.all([
      writeFile(target, 'third-party replacement', { mode: 0o600 }),
      writeFile(manifestPath, serializeSetupManifestV1(sourceManifest), { mode: 0o600 }),
    ]);
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: join(root, 'home'),
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      verification: verification(),
    });

    await expect(runUninstall(port)).resolves.toMatchObject({
      code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      state: 'active',
    });
    await expect(readFile(target, 'utf8')).resolves.toBe('third-party replacement');
    await expect(readFile(manifestPath, 'utf8')).resolves.toBe(
      serializeSetupManifestV1(sourceManifest),
    );
    await expect(readFile(receiptPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(join(stateRoot, 'lifecycle.wal.v1.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });
  it('holds the prepared config-home lock through the foreground session and releases after cleanup', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const independentPath = join(home, '.independent-lock');
    await activeStartFixture(root, home);
    const lock = preparedStartLock();
    let bindObservedLock = false;
    let waitObservedLock = false;
    let cleanupObservedLock = false;
    let cleanupCalls = 0;
    let launchInput: unknown;

    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      transactionPort: lock.port,
      foregroundMcp: {
        launch: async (input) => {
          launchInput = input;
          bindObservedLock = lock.isHeld(lockPath);
          expect(lock.acquisitionPaths()[0]).toBe(lockPath);
          await expect(lock.port.acquireAdvisoryLock(lockPath)).rejects.toThrow(
            'prepared start mutation is blocked by the shared lock',
          );
          const independent = await lock.port.acquireAdvisoryLock(independentPath);
          expect(lock.isHeld(independentPath)).toBe(true);
          await independent.release();
          expect(lock.isHeld(independentPath)).toBe(false);
          return {
            waitForExit: async () => {
              waitObservedLock = lock.isHeld(lockPath);
              return { reason: 'exit', exitCode: 0 };
            },
            cleanup: async () => {
              cleanupCalls += 1;
              cleanupObservedLock = lock.isHeld(lockPath);
            },
          };
        },
      },
      verification: verification(),
    });

    await expect(runStart(port)).resolves.toMatchObject({ code: 'SCG_LIFECYCLE_START_EXITED' });
    expect(launchInput).toMatchObject({
      selectedProjectId: 'node-lifecycle',
      projects: [
        {
          projectId: 'node-lifecycle',
          tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
        },
        {
          projectId: 'vite-lifecycle',
          tokenEnv: canonicalServerTokenEnvForProjectId('vite-lifecycle'),
        },
      ],
      lifecycleOrigin: {
        binding: {
          projects: [
            {
              projectId: 'node-lifecycle',
              tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
            },
            {
              projectId: 'vite-lifecycle',
              tokenEnv: canonicalServerTokenEnvForProjectId('vite-lifecycle'),
            },
          ],
        },
        replacements: [
          {
            projectId: 'vite-lifecycle',
            baseline: ['http://127.0.0.1:5174', 'http://localhost:5174'],
            origins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
          },
        ],
      },
    });
    expect(bindObservedLock).toBe(true);
    expect(waitObservedLock).toBe(true);
    expect(cleanupObservedLock).toBe(true);
    expect(cleanupCalls).toBe(1);
    expect(lock.isHeld(lockPath)).toBe(false);
    expect(lock.releaseCount(lockPath)).toBe(1);
    expect(lock.releaseAttemptCount(lockPath)).toBe(1);
    expect(lock.releaseCount(independentPath)).toBe(1);
  });

  it('releases a prepared lock when foreground launch fails', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    await activeStartFixture(root, home);
    const lock = preparedStartLock();
    const immutablePaths = [
      join(home, '.scg/config.json'),
      join(home, '.scg/credential-authorities.v1.json'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/onboarding/manifest.v1.json'),
    ];
    const beforeLaunchFailure = await captureFilesystemSnapshot(immutablePaths);

    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      transactionPort: lock.port,
      foregroundMcp: { launch: async () => Promise.reject(new Error('launch failure')) },
      verification: verification(),
    });

    await expect(runStart(port)).resolves.toMatchObject({ code: 'SCG_LIFECYCLE_FAILED' });
    await expectFilesystemSnapshot(beforeLaunchFailure);
    expect(lock.isHeld(lockPath)).toBe(false);
    expect(lock.releaseCount(lockPath)).toBe(1);
    expect(lock.releaseAttemptCount(lockPath)).toBe(1);
  });
  it('rejects a changed declared Vite input before foreground launch without lifecycle writes', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const manifest = await activeStartFixture(root, home);
    const immutablePaths = [
      join(home, '.scg/config.json'),
      join(home, '.scg/credential-authorities.v1.json'),
      join(root, '.scg/runtime/host-descriptor.v1.json'),
      join(root, '.scg/onboarding/manifest.v1.json'),
    ];
    const snapshot = await captureFilesystemSnapshot(immutablePaths);
    let launches = 0;
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      foregroundMcp: {
        launch: async () => {
          launches += 1;
          throw new Error('foreground launch must not run');
        },
      },
      verification: verification(),
    });
    const facts = await port.inspectStartFacts({ manifest });
    if (port.prepareStart === undefined) throw new Error('prepared start is unavailable');
    const prepared = await port.prepareStart({ manifest, facts });
    await writeFile(
      join(root, 'vite-project/vite.config.ts'),
      "import { defineConfig } from 'vite';\nimport react from '@vitejs/plugin-react';\nexport default defineConfig({ plugins: [react()], server: { host: '127.0.0.1', port: 5175, strictPort: true } });\n",
      { mode: 0o600 },
    );

    await expect(
      port.finalizePreparedStart({ preparationId: prepared.preparationId }),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof LifecycleStartDiagnosticError &&
        error.diagnostic.code === 'SCG_START_VITE_INPUT_CHANGED' &&
        error.diagnostic.projectId === 'vite-lifecycle',
    );
    await port.discardPreparedStart({ preparationId: prepared.preparationId });
    expect(launches).toBe(0);
    await expectFilesystemSnapshot(snapshot);
  });
  it('keeps unsafe declared Vite source replacement failures out of the closed diagnostic channel', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    await activeStartFixture(root, home);
    const viteConfigPath = join(root, 'vite-project/vite.config.ts');
    await rm(viteConfigPath);
    await symlink(join(root, 'vite-project/package.json'), viteConfigPath);
    let launches = 0;
    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      foregroundMcp: {
        launch: async () => {
          launches += 1;
          throw new Error('foreground launch must not run');
        },
      },
      verification: verification(),
    });

    const result = await runStart(port);

    expect(result).toMatchObject({
      code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      failures: [{ stage: 'start-registry-preflight' }],
    });
    expect(result).not.toHaveProperty('startDiagnostic');
    expect(launches).toBe(0);
  });

  it('retries a failed foreground lock release without duplicate cleanup or foreign release', async () => {
    const root = await fixture();
    const home = join(root, 'home');
    const lockPath = join(home, '.scene-glass-onboarding.lock');
    const manifest = await activeStartFixture(root, home);
    const releaseFailure = new Error('release failure');
    const lock = preparedStartLock([releaseFailure]);
    let cleanupCalls = 0;

    const port = createNodeLifecycleEnginePort({
      approval: async () => false,
      checkoutRoot: root,
      cwd: root,
      homeDirectory: home,
      host: { credentialPath: join(root, '.env.scene-glass.local'), port: 4175 },
      project: project(root),
      transactionPort: lock.port,
      foregroundMcp: {
        launch: async () => ({
          waitForExit: async () => ({ reason: 'exit', exitCode: 0 }),
          cleanup: async () => {
            cleanupCalls += 1;
          },
        }),
      },
      verification: verification(),
    });
    const facts = await port.inspectStartFacts({ manifest });
    if (port.prepareStart === undefined) throw new Error('prepared start is unavailable');
    const prepared = await port.prepareStart({ manifest, facts });
    if (port.finalizePreparedStart === undefined) {
      throw new Error('prepared start finalization is unavailable');
    }
    await port.finalizePreparedStart({ preparationId: prepared.preparationId });
    const foreground = await port.launchMcpForeground({
      manifest,
      preparationId: prepared.preparationId,
    });
    await expect(
      port.launchMcpForeground({
        manifest,
        preparationId: prepared.preparationId,
      }),
    ).rejects.toBeInstanceOf(LifecyclePreparedStartUnavailableError);
    await expect(
      port.finalizePreparedStart({ preparationId: prepared.preparationId }),
    ).rejects.toBeInstanceOf(LifecyclePreparedStartUnavailableError);

    await expect(foreground.cleanup()).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.message === 'Prepared start launch and cleanup failed.' &&
        error.errors.length === 2 &&
        error.errors[0] instanceof Error &&
        error.errors[0].message === 'foreground MCP cleanup failed' &&
        error.errors[1] === releaseFailure,
    );
    expect(cleanupCalls).toBe(1);
    expect(lock.isHeld(lockPath)).toBe(true);
    expect(lock.releaseCount(lockPath)).toBe(0);
    expect(lock.releaseAttemptCount(lockPath)).toBe(1);
    if (port.discardPreparedStart === undefined)
      throw new Error('prepared start discard is unavailable');
    await expect(
      port.discardPreparedStart({ preparationId: prepared.preparationId }),
    ).resolves.toBeUndefined();
    expect(cleanupCalls).toBe(1);
    expect(lock.isHeld(lockPath)).toBe(false);
    expect(lock.releaseCount(lockPath)).toBe(1);
    expect(lock.releaseAttemptCount(lockPath)).toBe(2);
    expect(lock.acquisitionPaths()).toEqual([lockPath]);
    await expect(
      port.discardPreparedStart({ preparationId: prepared.preparationId }),
    ).rejects.toThrow('prepared start authority is unavailable');
    expect(cleanupCalls).toBe(1);
    expect(lock.releaseCount(lockPath)).toBe(1);
    expect(lock.releaseAttemptCount(lockPath)).toBe(2);
  });
});

async function fixture(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-node-lifecycle-')));
  roots.push(root);
  await mkdir(join(root, 'public'), { recursive: true, mode: 0o700 });
  await writeFile(join(root, '.gitignore'), '.env.scene-glass.local\n', { mode: 0o600 });
  await writeFile(
    join(root, 'public/index.html'),
    '<!doctype html><html><head></head><body></body></html>\n',
    { mode: 0o600 },
  );
  return root;
}

function sha(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function dirname(path: string): string {
  const slash = path.lastIndexOf('/');
  if (slash <= 0) throw new Error('fixture path is invalid');
  return path.slice(0, slash);
}

function project(root: string): object {
  return {
    allowedOrigins: ['http://127.0.0.1:4175'],
    framework: 'html',
    projectId: 'node-lifecycle',
    root,
    tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
  };
}
async function activeStartFixture(root: string, home: string): Promise<SetupManifestV1> {
  const viteRoot = join(root, 'vite-project');
  const viteCredentialPath = join(viteRoot, '.env.scene-glass.local');
  const viteTokenEnv = canonicalServerTokenEnvForProjectId('vite-lifecycle');
  const config = {
    schemaVersion: 1 as const,
    projects: [
      {
        allowedOrigins: ['http://127.0.0.1:4175'],
        framework: 'html' as const,
        projectId: 'node-lifecycle',
        root,
        tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
      },
      {
        allowedOrigins: ['http://127.0.0.1:5174', 'http://localhost:5174'],
        framework: 'react' as const,
        projectId: 'vite-lifecycle',
        root: viteRoot,
        tokenEnv: viteTokenEnv,
      },
    ],
  };
  const credentialPath = join(root, '.env.scene-glass.local');
  const descriptorPath = join(root, '.scg/runtime/host-descriptor.v1.json');
  const configDirectory = join(home, '.scg');
  const configPath = join(configDirectory, 'config.json');
  const registryPath = join(configDirectory, 'credential-authorities.v1.json');
  const stateRoot = join(root, '.scg/onboarding');
  await mkdir(join(root, '.scg/runtime'), { recursive: true, mode: 0o700 });
  await mkdir(configDirectory, { recursive: true, mode: 0o700 });
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  await Promise.all([
    mkdir(viteRoot, { recursive: true, mode: 0o700 }),
    writeFile(credentialPath, credentialEnvelope('node-lifecycle', 'A'.repeat(43)), {
      mode: 0o600,
    }),
  ]);
  await Promise.all([
    writeFile(viteCredentialPath, credentialEnvelope('vite-lifecycle', 'B'.repeat(43)), {
      mode: 0o600,
    }),
    writeFile(
      join(viteRoot, 'package.json'),
      '{"name":"vite-lifecycle","scripts":{"dev":"vite --host 127.0.0.1 --port 5174"}}\n',
      { mode: 0o600 },
    ),
    writeFile(
      join(viteRoot, 'vite.config.ts'),
      "import { defineConfig } from 'vite';\nimport react from '@vitejs/plugin-react';\nexport default defineConfig({ plugins: [react()], server: { host: '127.0.0.1', port: 5174, strictPort: true } });\n",
      { mode: 0o600 },
    ),
  ]);
  const [credential, viteCredential, publicRoot, viteRootFacts] = await Promise.all([
    lstat(credentialPath),
    lstat(viteCredentialPath),
    lstat(join(root, 'public')),
    lstat(viteRoot),
  ]);
  const authority = {
    projectId: 'node-lifecycle',
    path: credentialPath,
    device: String(credential.dev),
    inode: String(credential.ino),
  };
  const registryEntry = {
    projectId: 'node-lifecycle',
    tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
    canonicalRoot: root,
    credentialPath,
    device: String(credential.dev),
    inode: String(credential.ino),
  };
  const viteAuthority = {
    projectId: 'vite-lifecycle',
    path: viteCredentialPath,
    device: String(viteCredential.dev),
    inode: String(viteCredential.ino),
  };
  const viteRegistryEntry = {
    projectId: 'vite-lifecycle',
    tokenEnv: viteTokenEnv,
    canonicalRoot: viteRoot,
    credentialPath: viteCredentialPath,
    device: String(viteCredential.dev),
    inode: String(viteCredential.ino),
  };
  const configPreimage = Object.freeze({ schemaVersion: 1 as const, projects: Object.freeze([]) });
  const configPostimage = Object.freeze({
    schemaVersion: 1 as const,
    projects: Object.freeze(config.projects),
  });
  const registryPreimage = Object.freeze({
    schemaVersion: 1 as const,
    projects: Object.freeze([]),
  });
  const registryPostimage = Object.freeze({
    schemaVersion: 1 as const,
    projects: Object.freeze([registryEntry]),
  });
  const configBytes = `${JSON.stringify(config, null, 2)}\n`;
  const registryBytes = serializeCredentialAuthorityRegistryV1({
    schemaVersion: 1,
    projects: [registryEntry, viteRegistryEntry],
  });
  const configFingerprint = sha(new TextEncoder().encode(configBytes));
  const registryFingerprint = sha(new TextEncoder().encode(registryBytes));
  const trustedProjects = {
    projects: [
      {
        projectId: 'node-lifecycle',
        canonicalRoot: root,
        publicRootIdentity: { device: String(publicRoot.dev), inode: String(publicRoot.ino) },
        tokenEnv: NODE_LIFECYCLE_SERVER_TOKEN_ENV,
        credentialAuthority: authority,
      },
      {
        projectId: 'vite-lifecycle',
        canonicalRoot: viteRoot,
        publicRootIdentity: {
          device: String(viteRootFacts.dev),
          inode: String(viteRootFacts.ino),
        },
        tokenEnv: viteTokenEnv,
        credentialAuthority: viteAuthority,
      },
    ],
  };
  const descriptor = serializeStaticHostDescriptorV1(
    {
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port: 4175,
      projectId: 'node-lifecycle',
      loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
      credentialProjectId: 'node-lifecycle',
      credentialKey: 'SCENE_GLASS_HOST_TOKEN',
      navigation: 'document',
      readinessPath: '/__scene-glass/ready',
      approvedRootIdentity: { device: String(publicRoot.dev), inode: String(publicRoot.ino) },
      credentialAuthorities: [authority],
    },
    trustedProjects,
  );
  const descriptorFingerprint = sha(new TextEncoder().encode(descriptor));
  const configHunk = {
    id: 'config-node-lifecycle',
    fingerprint: sha(new TextEncoder().encode(JSON.stringify(configPostimage))),
    operation: 'insert' as const,
    subject: 'node-lifecycle',
  };
  const manifest: SetupManifestV1 = {
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId: 'start-fixture',
    state: 'active',
    artifacts: [
      {
        path: configPath,
        kind: 'config',
        fingerprint: configFingerprint,
        hunks: [configHunk],
        preimage: configPreimage,
        postimage: configPostimage,
        inverse: {
          kind: 'restore-config',
          path: configPath,
          preimage: configPreimage,
          postimage: configPostimage,
        },
      },
      {
        path: registryPath,
        kind: 'credential-authority-registry',
        fingerprint: registryFingerprint,
        preimage: registryPreimage,
        postimage: registryPostimage,
        inverse: {
          kind: 'restore-credential-authority-registry-entry',
          path: registryPath,
          preimage: registryPreimage,
          postimage: registryPostimage,
        },
      },
      {
        path: descriptorPath,
        kind: 'file',
        fingerprint: descriptorFingerprint,
        hunks: [
          {
            id: 'descriptor-node-lifecycle',
            fingerprint: descriptorFingerprint,
            operation: 'insert',
            subject: 'scg-html-descriptor',
          },
        ],
        inverse: {
          kind: 'delete-created-file',
          path: descriptorPath,
          expectedFingerprint: descriptorFingerprint,
        },
      },
      {
        path: credentialPath,
        kind: 'credential',
        ownership: 'adopted',
        inverse: { kind: 'none' },
      },
    ],
  };
  const serializedManifest = serializeSetupManifestV1(manifest);
  await Promise.all([
    writeFile(configPath, configBytes, { mode: 0o600 }),
    writeFile(registryPath, registryBytes, { mode: 0o600 }),
    writeFile(descriptorPath, descriptor, { mode: 0o600 }),
    writeFile(join(home, '.scene-glass-onboarding.lock'), 'lock\n', { mode: 0o600 }),
    writeFile(join(stateRoot, 'manifest.v1.json'), serializedManifest, {
      mode: 0o600,
    }),
  ]);
  return parseSetupManifestJsonV1(serializedManifest);
}

type FilesystemSnapshot =
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

async function captureFilesystemEntry(path: string): Promise<FilesystemSnapshot> {
  try {
    const observed = await lstat(path);
    const identity = { device: observed.dev, inode: observed.ino };
    const mode = observed.mode & 0o777;
    if (observed.isDirectory()) return { kind: 'directory', identity, mode };
    if (observed.isFile()) return { kind: 'file', identity, mode, bytes: await readFile(path) };
    throw new Error(`fixture contains unsupported filesystem entry at ${path}`);
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') {
      return { kind: 'absent' };
    }
    throw error;
  }
}

async function captureFilesystemSnapshot(
  paths: readonly string[],
): Promise<ReadonlyMap<string, FilesystemSnapshot>> {
  const snapshots = new Map<string, FilesystemSnapshot>();
  for (const path of paths) {
    if (!snapshots.has(path)) snapshots.set(path, await captureFilesystemEntry(path));
  }
  return snapshots;
}

async function expectFilesystemSnapshot(
  expected: ReadonlyMap<string, FilesystemSnapshot>,
): Promise<void> {
  for (const [path, snapshot] of expected) {
    expect(await captureFilesystemEntry(path)).toEqual(snapshot);
  }
}
async function captureDirectoryEntries(
  paths: readonly string[],
): Promise<ReadonlyMap<string, readonly string[] | undefined>> {
  const entries = new Map<string, readonly string[] | undefined>();
  for (const path of paths) {
    try {
      entries.set(path, Object.freeze((await readdir(path)).sort()));
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        entries.set(path, undefined);
        continue;
      }
      throw error;
    }
  }
  return entries;
}
function expectedWalPreimage(
  path: string,
  snapshot: FilesystemSnapshot,
):
  | { readonly path: string; readonly kind: 'absent' }
  | {
      readonly path: string;
      readonly kind: 'directory';
      readonly identity: { readonly device: string; readonly inode: string };
      readonly mode: number;
    }
  | {
      readonly path: string;
      readonly kind: 'file';
      readonly identity: { readonly device: string; readonly inode: string };
      readonly mode: number;
      readonly bytes: string;
    } {
  if (snapshot.kind === 'absent') return { path, kind: 'absent' };
  const identity = {
    device: snapshot.identity.device.toString(10),
    inode: snapshot.identity.inode.toString(10),
  };
  if (snapshot.kind === 'directory') {
    return { path, kind: 'directory', identity, mode: snapshot.mode };
  }
  return {
    path,
    kind: 'file',
    identity,
    mode: snapshot.mode,
    bytes: snapshot.bytes.toString('base64'),
  };
}

function expectConfiguredNodeLockContention(error: unknown): void {
  expect(error).toMatchObject({
    name: 'OnboardingNativeError',
    code: 'SCG_NATIVE_PATH_DENIED',
    message: 'Secure native read was denied.',
  });
}

function successfulVerification(): NodeLifecycleVerificationPorts {
  const unavailable = async (): Promise<never> => {
    throw new Error('successful lifecycle test must not enter a nested verifier');
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

interface FreshSetupRecoveryChildInput {
  readonly root: string;
  readonly home: string;
  readonly credentialPath: string;
  readonly entropyCounterPath: string;
}

function freshSetupRecoveryChildScript(): string {
  const engineModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/engine.ts', import.meta.url).href,
  );
  const portModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/node-engine-port.ts', import.meta.url).href,
  );
  return [
    "import { readFileSync, writeFileSync } from 'node:fs';",
    `import { runSetup } from ${engineModule};`,
    `import { createNodeLifecycleEnginePort } from ${portModule};`,
    "const input = JSON.parse(process.env.SCG_FRESH_SETUP_RECOVERY_INPUT ?? '');",
    'const verification = {',
    '  runNativeSelfTest: async () => undefined,',
    '  runLiveDiagnostics: async () => undefined,',
    '};',
    'const port = createNodeLifecycleEnginePort({',
    '  approval: async () => true,',
    '  checkoutRoot: input.root,',
    '  cwd: input.root,',
    '  homeDirectory: input.home,',
    '  host: { credentialPath: input.credentialPath, port: 4175 },',
    "  project: { allowedOrigins: ['http://127.0.0.1:4175'], framework: 'html', projectId: 'node-lifecycle', root: input.root, tokenEnv: 'SCENE_GLASS_HOST_TOKEN' },",
    '  random: {',
    '    fill: (candidate) => {',
    "      const count = Number.parseInt(readFileSync(input.entropyCounterPath, 'utf8'), 10);",
    '      writeFileSync(input.entropyCounterPath, `${count + 1}\\n`, { mode: 0o600 });',
    '      candidate.fill(0);',
    '    },',
    "    uuid: () => 'fresh-recovery-setup',",
    '  },',
    '  verification,',
    '});',
    'const result = await runSetup(port);',
    'process.stdout.write(JSON.stringify({ code: result.code, state: result.state }) + "\\n");',
  ].join('\n');
}

async function runFreshSetupRecoveryChild(
  input: FreshSetupRecoveryChildInput,
): Promise<{ readonly code: string; readonly state: string }> {
  return new Promise((resolveChild, rejectChild) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', '--input-type=module', '--eval', freshSetupRecoveryChildScript()],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SCG_FRESH_SETUP_RECOVERY_INPUT: JSON.stringify(input),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const maximumOutputBytes = 4096;
    let stdout = '';
    let stderr = '';
    let settled = false;
    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.kill('SIGKILL');
      rejectChild(new Error(message));
    };
    const timeout = setTimeout(() => fail('fresh setup recovery child timed out'), 5_000);
    const append = (stream: 'stdout' | 'stderr', chunk: string): void => {
      const current = stream === 'stdout' ? stdout : stderr;
      if (
        Buffer.byteLength(current, 'utf8') + Buffer.byteLength(chunk, 'utf8') >
        maximumOutputBytes
      ) {
        fail(`fresh setup recovery child emitted unbounded ${stream}`);
        return;
      }
      if (stream === 'stdout') stdout += chunk;
      else stderr += chunk;
    };
    child.once('error', () => fail('fresh setup recovery child could not start'));
    if (child.stdout === null || child.stderr === null) {
      fail('fresh setup recovery child did not expose bounded output streams');
      return;
    }
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => append('stdout', chunk));
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => append('stderr', chunk));
    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code !== 0 || stderr !== '') {
        rejectChild(new Error('fresh setup recovery child did not exit successfully'));
        return;
      }
      const lines = stdout.trim().split('\n');
      if (lines.length !== 1 || lines[0] === undefined) {
        rejectChild(
          new Error('fresh setup recovery child did not produce one bounded JSON result'),
        );
        return;
      }
      try {
        const result: unknown = JSON.parse(lines[0]);
        if (
          result === null ||
          typeof result !== 'object' ||
          !('code' in result) ||
          !('state' in result) ||
          typeof result.code !== 'string' ||
          typeof result.state !== 'string'
        ) {
          rejectChild(new Error('fresh setup recovery child returned an invalid lifecycle result'));
          return;
        }
        resolveChild({ code: result.code, state: result.state });
      } catch {
        rejectChild(new Error('fresh setup recovery child produced invalid JSON'));
      }
    });
  });
}
function preparedStartLock(releaseFailures: readonly Error[] = []): {
  readonly port: LifecycleTransactionPort;
  readonly isHeld: (path: string) => boolean;
  readonly releaseCount: (path: string) => number;
  readonly releaseAttemptCount: (path: string) => number;
  readonly acquisitionPaths: () => readonly string[];
} {
  const heldPaths = new Set<string>();
  const releases = new Map<string, number>();
  const releaseAttempts = new Map<string, number>();
  const pendingFailures = [...releaseFailures];
  const acquisitions: string[] = [];
  const port = createNodeLifecycleTransactionPort();
  port.acquireAdvisoryLock = async (path) => {
    acquisitions.push(path);
    if (heldPaths.has(path))
      throw new Error('prepared start mutation is blocked by the shared lock');
    heldPaths.add(path);
    return {
      revalidate: async () => undefined,
      release: async () => {
        releaseAttempts.set(path, (releaseAttempts.get(path) ?? 0) + 1);
        const failure = pendingFailures.shift();
        if (failure !== undefined) throw failure;
        if (!heldPaths.delete(path)) throw new Error('prepared start lock was released twice');
        releases.set(path, (releases.get(path) ?? 0) + 1);
      },
    };
  };
  return {
    port,
    isHeld: (path) => heldPaths.has(path),
    releaseCount: (path) => releases.get(path) ?? 0,
    releaseAttemptCount: (path) => releaseAttempts.get(path) ?? 0,
    acquisitionPaths: () => Object.freeze([...acquisitions]),
  };
}

function verification() {
  return createNodeLifecycleVerificationPorts({
    loaderPort: 4175,
    startBootstrapProfile: async () => {
      throw new Error('verification must not start before approval');
    },
    startBrowserProfile: async () => {
      throw new Error('verification must not start before approval');
    },
    startLoopbackMcp: async () => {
      throw new Error('verification must not start before approval');
    },
  });
}
