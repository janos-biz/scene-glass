import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rmdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createNodeLifecycleTransactionPort } from '../../packages/onboarding/src/lifecycle/node-transaction-port.js';
import { STATIC_LOADER_MARKER } from '../../packages/onboarding/src/lifecycle/host-plan.js';
import {
  parseCredentialAuthorityRegistryJsonV1,
  serializeCredentialAuthorityRegistryV1,
} from '../../packages/onboarding/src/credential-authority.js';
import {
  parseLifecycleReceiptJsonV1,
  parseSetupManifestV1,
  parseWalRecordJsonV2,
  serializeWalRecordV2,
  serializeLifecycleReceiptV1,
  serializeSetupManifestV1,
  validateUninstallPreflight,
} from '../../packages/onboarding/src/lifecycle/provenance.js';
import {
  applySetupTransaction,
  applyUninstallTransaction,
  compensateSetupTransaction,
  openSetupTransactionAuthority,
  publishSetupTransaction,
  recoverLifecycle,
  LifecycleTransactionError,
  type LifecyclePreimage,
  type LifecycleTransactionPort,
  type SetupReservedCredentialAuthority,
  type SetupFinalization,
} from '../../packages/onboarding/src/lifecycle/transaction.js';

const roots: string[] = [];
const encoder = new TextEncoder();
const ZERO_WAL_AUTHORITY_FINGERPRINT = `sha256:${'0'.repeat(64)}`;
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;
interface ObservedIdentity {
  readonly identity: { readonly device: number; readonly inode: number };
  readonly mode: number;
}

type ObservedPath =
  | ({
      readonly state: 'present';
      readonly isDirectory: boolean;
      readonly isFile: boolean;
      readonly contents: string | undefined;
    } & ObservedIdentity)
  | {
      readonly state: 'error';
      readonly code: string | undefined;
    };

type DirectoryPreservationScenario = 'both' | 'wrong-kind' | 'nonempty';

interface DirectoryPreservationPaths {
  readonly target: ObservedPath;
  readonly staging: ObservedPath;
  readonly child?: ObservedPath;
}

interface DirectoryPreservationObservation {
  readonly scenario: DirectoryPreservationScenario;
  readonly state: string;
  readonly walBefore: string;
  readonly walAfter: string;
  readonly actual: DirectoryPreservationPaths;
  readonly expected: DirectoryPreservationPaths;
}

const manifest = (installId: string) => ({
  schemaVersion: 1 as const,
  kind: 'scene-glass-setup-manifest' as const,
  installId,
  state: 'active' as const,
  artifacts: [],
});
function ownedFileArtifact(path: string, bytes: Uint8Array) {
  const postimageFingerprint = fingerprint(bytes);
  return {
    path,
    kind: 'file' as const,
    fingerprint: postimageFingerprint,
    hunks: [],
    inverse: {
      kind: 'delete-created-file' as const,
      path,
      expectedFingerprint: postimageFingerprint,
    },
  };
}

function createdCredentialFinalization(
  installId: string,
  registryPath: string,
  canonicalRoot: string,
  createdCredential: SetupReservedCredentialAuthority,
  extraArtifacts: readonly unknown[] = [],
): SetupFinalization {
  const registryPreimage = { schemaVersion: 1 as const, projects: [] };
  const registryPostimage = {
    schemaVersion: 1 as const,
    projects: [
      {
        projectId: createdCredential.projectId,
        tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
        canonicalRoot,
        credentialPath: createdCredential.path,
        device: createdCredential.identity.device,
        inode: createdCredential.identity.inode,
      },
    ],
  };
  const registryFingerprint = fingerprint(
    encoder.encode(serializeCredentialAuthorityRegistryV1(registryPostimage)),
  );
  return {
    manifest: {
      schemaVersion: 1 as const,
      kind: 'scene-glass-setup-manifest' as const,
      installId,
      state: 'active' as const,
      artifacts: [
        {
          path: createdCredential.path,
          kind: 'credential' as const,
          ownership: 'setup-created' as const,
          projectId: createdCredential.projectId,
          identity: createdCredential.identity,
          mode: 0o600 as const,
          linkCount: 1 as const,
          inverse: {
            kind: 'delete-created-credential' as const,
            path: createdCredential.path,
            projectId: createdCredential.projectId,
            identity: createdCredential.identity,
            mode: 0o600 as const,
            linkCount: 1 as const,
          },
        },
        {
          path: registryPath,
          kind: 'credential-authority-registry' as const,
          fingerprint: registryFingerprint,
          preimage: registryPreimage,
          postimage: registryPostimage,
          inverse: {
            kind: 'restore-credential-authority-registry-entry' as const,
            path: registryPath,
            preimage: registryPreimage,
            postimage: registryPostimage,
          },
        },
        ...extraArtifacts,
      ],
    },
    operations: [
      {
        kind: 'apply-credential-authority-registry' as const,
        path: registryPath,
        preimage: registryPreimage,
        postimage: registryPostimage,
        fingerprint: registryFingerprint,
        mode: 0o600,
      },
    ],
    preimages: [absent(registryPath)],
  };
}
function immutableFinalization(finalization: SetupFinalization): SetupFinalization {
  return Object.freeze({
    manifest: finalization.manifest,
    operations: Object.freeze([...finalization.operations]),
    preimages: Object.freeze([...finalization.preimages]),
  });
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<{
  root: string;
  port: LifecycleTransactionPort;
  lockPath: string;
  walPath: string;
  manifestPath: string;
}> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-transaction-v2-')));
  roots.push(root);
  const lockPath = join(root, 'lifecycle.lock');
  await writeFile(lockPath, 'lock\n', { mode: 0o600 });
  return {
    root,
    port: createNodeLifecycleTransactionPort(),
    lockPath,
    walPath: join(root, 'lifecycle.wal.v1.json'),
    manifestPath: join(root, 'manifest.v1.json'),
  };
}

function absent(path: string): LifecyclePreimage {
  return Object.freeze({ path, state: 'absent' as const });
}
function fingerprint(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function credentialCanaries(
  token: string,
  serializedCredential: string,
): readonly {
  readonly subject: 'token' | 'serialized-credential';
  readonly form: string;
  readonly value: string;
}[] {
  return [
    ['token', token] as const,
    ['serialized-credential', serializedCredential] as const,
  ].flatMap(([subject, value]) => {
    const bytes = Buffer.from(value, 'utf8');
    const digest = createHash('sha256').update(bytes).digest('hex');
    return [
      { subject, form: 'raw', value },
      { subject, form: 'base64', value: bytes.toString('base64') },
      { subject, form: 'base64url', value: bytes.toString('base64url') },
      { subject, form: 'sha256', value: digest },
      { subject, form: 'sha256-prefixed', value: `sha256:${digest}` },
    ] as const;
  });
}

async function credentialCanaryLeaks(
  paths: readonly string[],
  canaries: readonly {
    readonly subject: 'token' | 'serialized-credential';
    readonly form: string;
    readonly value: string;
  }[],
): Promise<
  readonly {
    readonly path: string;
    readonly subject: 'token' | 'serialized-credential';
    readonly form: string;
  }[]
> {
  const snapshots = await Promise.all(
    [...new Set(paths)].map(async (path) => ({ path, snapshot: await observePath(path) })),
  );
  return snapshots.flatMap(({ path, snapshot }) => {
    if (snapshot.state !== 'present' || !snapshot.isFile) return [];
    if (snapshot.contents === undefined) {
      throw new Error(`durable non-credential authority was not readable: ${path}`);
    }
    const contents = snapshot.contents;
    return canaries
      .filter(({ value }) => contents.includes(value))
      .map(({ subject, form }) => ({ path, subject, form }));
  });
}
function bindRecoveryWal(record: Record<string, unknown>): string {
  const unbound = { ...record, authorityFingerprint: ZERO_WAL_AUTHORITY_FINGERPRINT };
  const authorityFingerprint = fingerprint(encoder.encode(serializeWalRecordV2(unbound)));
  return serializeWalRecordV2({ ...record, authorityFingerprint });
}

async function preparedDirectoryRollbackWal(
  item: Awaited<ReturnType<typeof fixture>>,
  targetPath: string,
  operationId: string,
): Promise<string> {
  const target = await item.port.lstatNoFollow(targetPath);
  if (target === undefined || target.kind !== 'directory') {
    throw new Error('recovery target directory was not observed');
  }
  return bindRecoveryWal({
    schemaVersion: 2,
    kind: 'scene-glass-lifecycle-wal',
    operationId,
    installId: 'recovery-id-install',
    operation: 'setup',
    direction: 'rollback',
    phase: 'prepared',
    lockPath: item.lockPath,
    manifestPath: item.manifestPath,
    cursor: 1,
    preimages: [{ path: targetPath, kind: 'absent' }],
    mutations: [
      {
        step: 0,
        kind: 'ordinary',
        targetPath,
        sourcePath: join(item.root, '.recovery-source'),
        stagingPath: join(item.root, '.recovery-stage'),
        preimage: 0,
        result: { kind: 'directory', identity: target.identity, mode: target.mode },
      },
    ],
  });
}

function observeIdentity(stats: {
  readonly dev: number;
  readonly ino: number;
  readonly mode: number;
}): ObservedIdentity {
  return {
    identity: { device: stats.dev, inode: stats.ino },
    mode: stats.mode & 0o777,
  };
}

async function observePath(path: string): Promise<ObservedPath> {
  try {
    const stats = await lstat(path);
    return {
      state: 'present',
      isDirectory: stats.isDirectory(),
      isFile: stats.isFile(),
      ...observeIdentity(stats),
      contents: stats.isFile() ? await readFile(path, 'utf8') : undefined,
    };
  } catch (error) {
    return {
      state: 'error',
      code:
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        typeof error.code === 'string'
          ? error.code
          : undefined,
    };
  }
}
async function snapshotSetupAuthorityTree(
  root: string,
): Promise<ReadonlyMap<string, ObservedPath>> {
  const tree = new Map<string, ObservedPath>();
  const visit = async (path: string): Promise<void> => {
    const observed = await observePath(path);
    tree.set(path, observed);
    if (observed.state !== 'present' || !observed.isDirectory) {
      return;
    }
    for (const entry of (await readdir(path)).sort()) {
      await visit(join(path, entry));
    }
  };
  await visit(root);
  return tree;
}
function expectConfiguredLockContention(error: unknown): void {
  expect(error).toMatchObject({
    code: 'SCG_NATIVE_PATH_DENIED',
    message: 'Secure native read was denied.',
  });
}

describe('onboarding lifecycle v2 transactions', () => {
  it('holds the exact lock from open through publish and writes no target before WAL ownership', async () => {
    const item = await fixture();
    const target = join(item.root, 'owned.txt');
    let observedFirstTargetMutation = false;
    let firstTargetMutationObservation:
      | {
          readonly targetError: unknown;
          readonly wal: ReturnType<typeof parseWalRecordJsonV2>;
          readonly lockState: 'acquired' | 'rejected';
          readonly lockError: unknown;
        }
      | undefined;
    const publishTarget = item.port.publishStagedWrite.bind(item.port);
    let targetPublishDelegations = 0;
    item.port.publishStagedWrite = async (input) => {
      if (input.targetPath === target && !observedFirstTargetMutation) {
        observedFirstTargetMutation = true;
        let targetError: unknown;
        try {
          await lstat(target);
        } catch (error) {
          targetError = error;
        }
        const wal = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
        const lockAcquisition = await item.port.acquireAdvisoryLock(item.lockPath).then(
          (lock) => ({ state: 'acquired' as const, lock }),
          (error: unknown) => ({ state: 'rejected' as const, error }),
        );
        if (lockAcquisition.state === 'acquired') {
          await lockAcquisition.lock.release();
        }
        firstTargetMutationObservation = {
          targetError,
          wal,
          lockState: lockAcquisition.state,
          lockError: lockAcquisition.state === 'rejected' ? lockAcquisition.error : undefined,
        };
      }
      if (input.targetPath === target) {
        targetPublishDelegations += 1;
      }
      return publishTarget(input);
    };
    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-transaction-alpha',
      installId: 'install-transaction-alpha',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(target)],
    });

    const blockedAfterOpen = await item.port.acquireAdvisoryLock(item.lockPath).then(
      (lock) => ({ state: 'acquired' as const, lock }),
      (error: unknown) => ({ state: 'rejected' as const, error }),
    );
    if (blockedAfterOpen.state === 'acquired') {
      await blockedAfterOpen.lock.release();
      throw new Error('setup authority did not retain the configured advisory lock');
    }
    expectConfiguredLockContention(blockedAfterOpen.error);
    const finalization = immutableFinalization({
      manifest: {
        ...manifest('install-transaction-alpha'),
        artifacts: [ownedFileArtifact(target, encoder.encode('owned'))],
      },
      operations: [
        { kind: 'write-file', path: target, bytes: encoder.encode('owned'), mode: 0o600 },
      ],
      preimages: [absent(target)],
    });
    const applied = await applySetupTransaction({
      authority,
      operationId: 'setup-transaction-alpha',
      installId: 'install-transaction-alpha',
      finalization,
    });
    if (!('manifest' in applied)) {
      throw new Error('setup apply unexpectedly compensated');
    }

    expect(targetPublishDelegations).toBe(1);
    if (firstTargetMutationObservation === undefined) {
      throw new Error('setup did not attempt the first target mutation');
    }
    expect(firstTargetMutationObservation.targetError).toBeInstanceOf(Error);
    expect((firstTargetMutationObservation.targetError as { readonly code?: unknown }).code).toBe(
      'ENOENT',
    );
    const [targetMutation, manifestMutation] = firstTargetMutationObservation.wal.mutations;
    if (
      targetMutation === undefined ||
      targetMutation.kind !== 'ordinary' ||
      manifestMutation === undefined ||
      manifestMutation.kind !== 'ordinary' ||
      targetMutation.result.kind !== 'file' ||
      manifestMutation.result.kind !== 'file'
    ) {
      throw new Error('first target publication did not observe the exact ordinary WAL mutations');
    }
    const manifestAuthorityPath = `${item.manifestPath}.scene-glass-setup-transaction-alpha.manifest-authority`;
    const manifestStagingPath = `${manifestAuthorityPath}.scene-glass-setup-transaction-alpha-1.stage`;
    const [targetStats, manifestAuthorityStats] = await Promise.all([
      lstat(target, { bigint: true }),
      lstat(manifestStagingPath, { bigint: true }),
    ]);
    expect({
      schemaVersion: firstTargetMutationObservation.wal.schemaVersion,
      kind: firstTargetMutationObservation.wal.kind,
      operationId: firstTargetMutationObservation.wal.operationId,
      installId: firstTargetMutationObservation.wal.installId,
      operation: firstTargetMutationObservation.wal.operation,
      direction: firstTargetMutationObservation.wal.direction,
      phase: firstTargetMutationObservation.wal.phase,
      lockPath: firstTargetMutationObservation.wal.lockPath,
      manifestPath: firstTargetMutationObservation.wal.manifestPath,
      cursor: firstTargetMutationObservation.wal.cursor,
      preimages: firstTargetMutationObservation.wal.preimages.map(({ path, kind }) => ({
        path,
        kind,
      })),
      mutations: [
        {
          step: targetMutation.step,
          kind: targetMutation.kind,
          targetPath: targetMutation.targetPath,
          preimage: targetMutation.preimage,
          result: targetMutation.result,
        },
        {
          step: manifestMutation.step,
          kind: manifestMutation.kind,
          targetPath: manifestMutation.targetPath,
          preimage: manifestMutation.preimage,
          result: manifestMutation.result,
        },
      ],
    }).toEqual({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'setup-transaction-alpha',
      installId: 'install-transaction-alpha',
      operation: 'setup',
      direction: 'rollback',
      phase: 'finalized',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      cursor: 2,
      preimages: [
        { path: target, kind: 'absent' },
        { path: manifestAuthorityPath, kind: 'absent' },
      ],
      mutations: [
        {
          step: 0,
          kind: 'ordinary',
          targetPath: target,
          preimage: 0,
          result: {
            kind: 'file',
            identity: {
              device: targetStats.dev.toString(10),
              inode: targetStats.ino.toString(10),
            },
            mode: 0o600,
            bytes: Buffer.from('owned', 'utf8').toString('base64'),
          },
        },
        {
          step: 1,
          kind: 'ordinary',
          targetPath: manifestAuthorityPath,
          preimage: 1,
          result: {
            kind: 'file',
            identity: {
              device: manifestAuthorityStats.dev.toString(10),
              inode: manifestAuthorityStats.ino.toString(10),
            },
            mode: 0o600,
            bytes: Buffer.from(serializeSetupManifestV1(finalization.manifest), 'utf8').toString(
              'base64',
            ),
          },
        },
      ],
    });
    expect(firstTargetMutationObservation.lockState).toBe('rejected');
    expectConfiguredLockContention(firstTargetMutationObservation.lockError);
    expect(await readFile(target, 'utf8')).toBe('owned');
    const blockedAfterApply = await item.port.acquireAdvisoryLock(item.lockPath).then(
      (lock) => ({ state: 'acquired' as const, lock }),
      (error: unknown) => ({ state: 'rejected' as const, error }),
    );
    if (blockedAfterApply.state === 'acquired') {
      await blockedAfterApply.lock.release();
      throw new Error('setup authority released the configured advisory lock before publish');
    }
    expectConfiguredLockContention(blockedAfterApply.error);
    expect(await publishSetupTransaction(applied)).toEqual({ state: 'active', failures: [] });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    const releasedLock = await item.port.acquireAdvisoryLock(item.lockPath);
    await releasedLock.release();
  });
  it('rejects unbound postimage provenance before it stages or mutates a target', async () => {
    const item = await fixture();
    const target = join(item.root, 'unbound-postimage.txt');
    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-unbound-postimage',
      installId: 'install-unbound-postimage',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(target)],
    });
    const bytes = encoder.encode('actual postimage\n');
    const artifact = ownedFileArtifact(target, bytes);
    const result = applySetupTransaction({
      authority,
      operationId: 'setup-unbound-postimage',
      installId: 'install-unbound-postimage',
      finalization: immutableFinalization({
        manifest: {
          ...manifest('install-unbound-postimage'),
          artifacts: [
            {
              ...artifact,
              fingerprint: fingerprint(encoder.encode('wrong bytes\n')),
              inverse: {
                ...artifact.inverse,
                expectedFingerprint: fingerprint(encoder.encode('wrong bytes\n')),
              },
            },
          ],
        },
        operations: [{ kind: 'write-file', path: target, bytes, mode: 0o600 }],
        preimages: [absent(target)],
      }),
    });
    await expect(result).rejects.toBeInstanceOf(LifecycleTransactionError);
    await expect(lstat(target)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('recovers an ordinary setup stage after its exact identity WAL is published but not durable', async () => {
    const item = await fixture();
    const target = join(item.root, 'ordinary-stage-crash-target');
    const failurePoint = item.port.failurePoint.bind(item.port);
    const stageWrite = item.port.stageWrite.bind(item.port);
    const ordinaryStagePath = `${target}.scene-glass-setup-ordinary-stage-crash-0.stage`;
    let ordinaryStageCreated = false;
    item.port.stageWrite = async (input) => {
      const stage = await stageWrite(input);
      if (input.stagingPath === ordinaryStagePath) {
        ordinaryStageCreated = true;
      }
      return stage;
    };
    item.port.failurePoint = async (name) => {
      if (ordinaryStageCreated && name === 'wal-fsync') {
        throw new Error('simulated post-stage WAL crash');
      }
      await failurePoint(name);
    };

    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-ordinary-stage-crash',
      installId: 'install-ordinary-stage-crash',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(target)],
    });
    const bytes = encoder.encode('ordinary-stage-bytes');
    const applied = await applySetupTransaction({
      authority,
      operationId: 'setup-ordinary-stage-crash',
      installId: 'install-ordinary-stage-crash',
      finalization: immutableFinalization({
        manifest: {
          ...manifest('install-ordinary-stage-crash'),
          artifacts: [ownedFileArtifact(target, bytes)],
        },
        operations: [
          {
            kind: 'write-file',
            path: target,
            bytes,
            mode: 0o600,
          },
        ],
        preimages: [absent(target)],
      }),
    });
    item.port.failurePoint = failurePoint;
    item.port.stageWrite = stageWrite;

    expect(ordinaryStageCreated).toBe(true);
    expect(applied).toMatchObject({ state: 'recovery-required' });
    const staged = await lstat(ordinaryStagePath, { bigint: true });
    const persisted = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
    expect(
      persisted.mutations.find(
        (mutation) => mutation.kind === 'ordinary' && mutation.targetPath === target,
      ),
    ).toMatchObject({
      stagingPath: ordinaryStagePath,
      result: {
        kind: 'file',
        identity: {
          device: staged.dev.toString(10),
          inode: staged.ino.toString(10),
        },
        mode: 0o600,
      },
    });
    await expect(readFile(target, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });

    await expect(
      recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        lockPath: item.lockPath,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
      }),
    ).resolves.toEqual({ state: 'never-installed', failures: [] });
    await expect(readFile(target, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('retains finalized WAL authority after native publication becomes indeterminate', async () => {
    const item = await fixture();
    const target = join(item.root, 'indeterminate-publication-target');
    const operationId = 'setup-indeterminate-publication';
    const stagePath = `${target}.scene-glass-${operationId}-0.stage`;
    const publishStagedWrite = item.port.publishStagedWrite.bind(item.port);
    let nativePublicationCalls = 0;
    let walAtPublication: string | undefined;
    item.port.publishStagedWrite = async (input) => {
      const published = await publishStagedWrite(input);
      if (input.stage.path === stagePath) {
        nativePublicationCalls += 1;
        walAtPublication = await readFile(item.walPath, 'utf8');
        throw new Error('simulated native publication outcome is indeterminate');
      }
      return published;
    };

    const authority = await openSetupTransactionAuthority({
      operationId,
      installId: 'install-indeterminate-publication',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(target)],
    });
    const bytes = encoder.encode('indeterminate native publication bytes\n');
    const result = await applySetupTransaction({
      authority,
      operationId,
      installId: 'install-indeterminate-publication',
      finalization: immutableFinalization({
        manifest: {
          ...manifest('install-indeterminate-publication'),
          artifacts: [ownedFileArtifact(target, bytes)],
        },
        operations: [{ kind: 'write-file', path: target, bytes, mode: 0o600 }],
        preimages: [absent(target)],
      }),
    });

    expect(result).toEqual({
      state: 'recovery-required',
      failures: [{ stage: 'indeterminate' }, { stage: 'cleanup' }],
    });
    expect(nativePublicationCalls).toBe(1);
    if (walAtPublication === undefined) {
      throw new Error('native publication did not observe finalized WAL authority');
    }
    await expect(readFile(item.walPath, 'utf8')).resolves.toBe(walAtPublication);
    expect(parseWalRecordJsonV2(walAtPublication)).toMatchObject({
      operation: 'setup',
      direction: 'rollback',
      phase: 'finalized',
      mutations: expect.arrayContaining([
        expect.objectContaining({
          kind: 'ordinary',
          targetPath: target,
          stagingPath: stagePath,
          result: expect.objectContaining({ kind: 'file' }),
        }),
      ]),
    });
    await expect(readFile(target, 'utf8')).resolves.toBe(
      'indeterminate native publication bytes\n',
    );
    await expect(lstat(stagePath)).rejects.toMatchObject({ code: 'ENOENT' });

    await expect(
      recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        lockPath: item.lockPath,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
      }),
    ).resolves.toEqual({ state: 'never-installed', failures: [] });
    await expect(readFile(target)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('retains a foreign WAL without write-capable calls and releases its exact lock authority', async () => {
    const item = await fixture();
    const foreign = '{"foreign":"wal"}\n';
    await writeFile(item.walPath, foreign, { mode: 0o600 });
    const before = await snapshotSetupAuthorityTree(item.root);
    const writeCapableSpies = [
      vi.spyOn(item.port, 'stageWrite'),
      vi.spyOn(item.port, 'publishStagedWrite'),
      vi.spyOn(item.port, 'replaceStagedWriteWithQuarantine'),
      vi.spyOn(item.port, 'discardStagedWrite'),
      vi.spyOn(item.port, 'retainStagedWriteForRecovery'),
      vi.spyOn(item.port, 'reserveStagedWrite'),
      vi.spyOn(item.port, 'writeReservedStagedWrite'),
      vi.spyOn(item.port, 'renameReservedStagedWrite'),
      vi.spyOn(item.port, 'retainReservedStagedWriteForRecovery'),
      vi.spyOn(item.port, 'retainReservedStagedDirectoryForRecovery'),
      vi.spyOn(item.port, 'closeReservedStagedWrite'),
      vi.spyOn(item.port, 'discardReservedStagedWrite'),
      vi.spyOn(item.port, 'reserveStagedDirectory'),
      vi.spyOn(item.port, 'publishReservedStagedDirectory'),
      vi.spyOn(item.port, 'closeReservedStagedDirectory'),
      vi.spyOn(item.port, 'discardReservedStagedDirectory'),
      vi.spyOn(item.port, 'recoverCreationIntent'),
      vi.spyOn(item.port, 'publishExactStagedDirectory'),
      vi.spyOn(item.port, 'fsyncDirectory'),
      vi.spyOn(item.port, 'replaceExactStagedFileWithQuarantine'),
      vi.spyOn(item.port, 'replaceExactWal'),
      vi.spyOn(item.port, 'publishExactStagedFile'),
      vi.spyOn(item.port, 'fsyncFile'),
      vi.spyOn(item.port, 'fsyncParent'),
      vi.spyOn(item.port, 'removeExactWal'),
      vi.spyOn(item.port, 'removeExactStagedFile'),
      vi.spyOn(item.port, 'quarantineExactFile'),
      vi.spyOn(item.port, 'quarantineExactDirectory'),
      vi.spyOn(item.port, 'finalizeQuarantine'),
      vi.spyOn(item.port, 'restoreQuarantine'),
    ];
    let thrown: unknown;
    try {
      await openSetupTransactionAuthority({
        operationId: 'setup-foreign-wal',
        installId: 'install-foreign-wal',
        port: item.port,
        lockPath: item.lockPath,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
        preimages: [],
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(LifecycleTransactionError);
    expect(thrown).toMatchObject({ failures: [{ stage: 'setup-authority' }] });
    expect(await snapshotSetupAuthorityTree(item.root)).toEqual(before);
    expect(writeCapableSpies.map((spy) => spy.mock.calls.length)).toStrictEqual(
      new Array(writeCapableSpies.length).fill(0),
    );
    const reacquired = await item.port.acquireAdvisoryLock(item.lockPath);
    await reacquired.release();
    const released = await item.port.acquireAdvisoryLock(item.lockPath);
    await released.release();
  });

  it('finalizes a published credential with exact identity authority and no durable secret forms', async () => {
    const item = await fixture();
    const credentialPath = join(item.root, 'credential');
    const stagingPath = join(item.root, '.credential.stage');
    const registryPath = join(item.root, 'credential-authorities.v1.json');
    const token = 'credential-token-canary-never-in-authority';
    const serializedCredential = credentialEnvelope('project-alpha', token);
    const contentBytes = encoder.encode(serializedCredential);
    const canaries = credentialCanaries(token, serializedCredential);
    const credentialCandidate = {
      projectId: 'project-alpha',
      path: credentialPath,
      stagingPath,
      mode: 0o600,
    };
    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-credential-alpha',
      installId: 'install-credential-alpha',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(credentialPath)],
      credential: credentialCandidate,
    });
    const reservedCreatedCredential = authority.reservedCreatedCredential;
    if (reservedCreatedCredential === undefined) {
      throw new Error('opening setup authority did not reserve the created credential');
    }
    expect({
      projectId: reservedCreatedCredential.projectId,
      path: reservedCreatedCredential.path,
      mode: reservedCreatedCredential.mode,
    }).toEqual({
      projectId: credentialCandidate.projectId,
      path: credentialCandidate.path,
      mode: credentialCandidate.mode,
    });
    const precomputedFinalization = immutableFinalization(
      createdCredentialFinalization(
        'install-credential-alpha',
        registryPath,
        item.root,
        reservedCreatedCredential,
      ),
    );
    expect(Object.isFrozen(precomputedFinalization)).toBe(true);
    expect(Object.isFrozen(precomputedFinalization.operations)).toBe(true);
    expect(Object.isFrozen(precomputedFinalization.preimages)).toBe(true);
    const applied = await applySetupTransaction({
      authority,
      operationId: 'setup-credential-alpha',
      installId: 'install-credential-alpha',
      credential: { ...credentialCandidate, contentBytes },
      finalization: precomputedFinalization,
    });
    if (!('manifest' in applied)) {
      throw new Error('credential setup unexpectedly compensated');
    }
    const createdCredential = reservedCreatedCredential;
    const credentialStats = await lstat(credentialPath, { bigint: true });
    expect(await observePath(stagingPath)).toEqual({ state: 'error', code: 'ENOENT' });
    expect({
      projectId: createdCredential.projectId,
      path: createdCredential.path,
      identity: createdCredential.identity,
      mode: createdCredential.mode,
      published: {
        isFile: credentialStats.isFile(),
        identity: {
          device: credentialStats.dev.toString(10),
          inode: credentialStats.ino.toString(10),
        },
        mode: Number(credentialStats.mode & 0o777n),
      },
    }).toEqual({
      projectId: credentialCandidate.projectId,
      path: credentialCandidate.path,
      identity: createdCredential.identity,
      mode: credentialCandidate.mode,
      published: {
        isFile: true,
        identity: createdCredential.identity,
        mode: createdCredential.mode,
      },
    });
    const expectedCredentialAuthority = {
      projectId: 'project-alpha',
      path: credentialPath,
      identity: {
        device: credentialStats.dev.toString(10),
        inode: credentialStats.ino.toString(10),
      },
      mode: Number(credentialStats.mode & 0o777n),
    };
    const expectedRegistry = {
      schemaVersion: 1 as const,
      projects: [
        {
          projectId: 'project-alpha',
          tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
          canonicalRoot: item.root,
          credentialPath,
          device: expectedCredentialAuthority.identity.device,
          inode: expectedCredentialAuthority.identity.inode,
        },
      ],
    };
    const expectedManifest = {
      schemaVersion: 1 as const,
      kind: 'scene-glass-setup-manifest' as const,
      installId: 'install-credential-alpha',
      state: 'active' as const,
      artifacts: [
        {
          path: credentialPath,
          kind: 'credential' as const,
          ownership: 'setup-created' as const,
          projectId: 'project-alpha',
          identity: expectedCredentialAuthority.identity,
          mode: 0o600 as const,
          linkCount: 1 as const,
          inverse: {
            kind: 'delete-created-credential' as const,
            path: credentialPath,
            projectId: 'project-alpha',
            identity: expectedCredentialAuthority.identity,
            mode: 0o600 as const,
            linkCount: 1 as const,
          },
        },
        {
          path: registryPath,
          kind: 'credential-authority-registry' as const,
          fingerprint: fingerprint(
            encoder.encode(serializeCredentialAuthorityRegistryV1(expectedRegistry)),
          ),
          preimage: { schemaVersion: 1 as const, projects: [] },
          postimage: expectedRegistry,
          inverse: {
            kind: 'restore-credential-authority-registry-entry' as const,
            path: registryPath,
            preimage: { schemaVersion: 1 as const, projects: [] },
            postimage: expectedRegistry,
          },
        },
      ],
    };
    expect(parseCredentialAuthorityRegistryJsonV1(await readFile(registryPath, 'utf8'))).toEqual(
      expectedRegistry,
    );
    const manifestAuthorityPath = `${item.manifestPath}.scene-glass-setup-credential-alpha.manifest-authority`;
    const manifestStagingPath = `${manifestAuthorityPath}.scene-glass-setup-credential-alpha-2.stage`;
    const manifestSourcePath = `${manifestAuthorityPath}.scene-glass-setup-credential-alpha-2.rollback`;
    expect(await readFile(manifestStagingPath, 'utf8')).toBe(
      serializeSetupManifestV1(expectedManifest),
    );
    await expect(readFile(item.manifestPath)).rejects.toMatchObject({ code: 'ENOENT' });
    const wal = await readFile(item.walPath, 'utf8');
    const parsedWal = parseWalRecordJsonV2(wal);
    const credentialMutation = parsedWal.mutations.find(
      (mutation) => mutation.kind === 'credential' && mutation.path === credentialPath,
    );
    const manifestStageStats = await lstat(manifestStagingPath, { bigint: true });
    const manifestMutation = parsedWal.mutations.find(
      (mutation) =>
        mutation.kind === 'ordinary' &&
        mutation.targetPath === manifestAuthorityPath &&
        mutation.result.kind === 'file',
    );
    if (
      credentialMutation === undefined ||
      credentialMutation.kind !== 'credential' ||
      manifestMutation === undefined ||
      manifestMutation.kind !== 'ordinary' ||
      manifestMutation.result.kind !== 'file' ||
      manifestMutation.targetPath !== manifestAuthorityPath ||
      manifestMutation.preimage !== 2
    ) {
      throw new Error(
        'credential WAL did not retain its exact credential and manifest authorities',
      );
    }
    expect({
      operation: parsedWal.operation,
      direction: parsedWal.direction,
      phase: parsedWal.phase,
      cursor: parsedWal.cursor,
      preimages: parsedWal.preimages.map(({ path, kind }) => ({ path, kind })),
      credentialMutation,
      manifestAuthority: {
        step: manifestMutation.step,
        targetPath: manifestMutation.targetPath,
        sourcePath: manifestMutation.sourcePath,
        stagingPath: manifestMutation.stagingPath,
        preimage: manifestMutation.preimage,
        result: manifestMutation.result,
      },
    }).toEqual({
      operation: 'setup',
      direction: 'rollback',
      phase: 'finalized',
      cursor: 3,
      preimages: [
        { path: registryPath, kind: 'absent' },
        { path: credentialPath, kind: 'absent' },
        { path: manifestAuthorityPath, kind: 'absent' },
      ],
      credentialMutation: {
        step: 0,
        kind: 'credential',
        projectId: 'project-alpha',
        path: credentialPath,
        mode: 0o600,
        stagingPath,
        stagingIdentity: expectedCredentialAuthority.identity,
        targetIdentity: expectedCredentialAuthority.identity,
      },
      manifestAuthority: {
        step: 2,
        targetPath: manifestAuthorityPath,
        sourcePath: manifestSourcePath,
        stagingPath: manifestStagingPath,
        preimage: 2,
        result: {
          kind: 'file',
          identity: {
            device: manifestStageStats.dev.toString(10),
            inode: manifestStageStats.ino.toString(10),
          },
          mode: 0o600,
          bytes: Buffer.from(serializeSetupManifestV1(expectedManifest), 'utf8').toString('base64'),
        },
      },
    });
    expect([...contentBytes]).toEqual(new Array(contentBytes.byteLength).fill(0));
    expect(
      await credentialCanaryLeaks(
        [
          item.lockPath,
          item.walPath,
          item.manifestPath,
          registryPath,
          ...parsedWal.mutations.flatMap((mutation) =>
            mutation.kind === 'ordinary'
              ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
              : [],
          ),
        ],
        canaries,
      ),
    ).toEqual([]);

    expect(await publishSetupTransaction(applied)).toEqual({ state: 'active', failures: [] });
    const published = await lstat(credentialPath, { bigint: true });
    expect(await observePath(stagingPath)).toEqual({ state: 'error', code: 'ENOENT' });
    expect({
      isFile: published.isFile(),
      identity: {
        device: published.dev.toString(10),
        inode: published.ino.toString(10),
      },
      mode: Number(published.mode & 0o777n),
    }).toEqual({
      isFile: true,
      identity: createdCredential.identity,
      mode: createdCredential.mode,
    });
    expect(parseCredentialAuthorityRegistryJsonV1(await readFile(registryPath, 'utf8'))).toEqual(
      expectedRegistry,
    );
    expect(parseSetupManifestV1(JSON.parse(await readFile(item.manifestPath, 'utf8')))).toEqual(
      expectedManifest,
    );
    expect(
      await credentialCanaryLeaks(
        [item.lockPath, item.walPath, item.manifestPath, registryPath],
        canaries,
      ),
    ).toEqual([]);
  });
  it('merges unrelated registry entries while retaining exact selected-entry provenance', async () => {
    const item = await fixture();
    const registryPath = join(item.root, 'credential-authorities.v1.json');
    const credentialPath = join(item.root, 'selected-credential');
    const stagingPath = join(item.root, '.selected-credential.stage');
    const unrelated = {
      projectId: 'project-unrelated',
      tokenEnv: 'UNRELATED_TOKEN',
      canonicalRoot: '/srv/unrelated',
      credentialPath: '/srv/unrelated/.token',
      device: '101',
      inode: '202',
    };
    const physicalPreimage = { schemaVersion: 1 as const, projects: [unrelated] };
    const physicalPreimageJson = serializeCredentialAuthorityRegistryV1(physicalPreimage);
    await writeFile(registryPath, physicalPreimageJson, { mode: 0o600 });
    const registryStats = await lstat(registryPath, { bigint: true });
    const registryPreimage: LifecyclePreimage = Object.freeze({
      path: registryPath,
      state: 'file' as const,
      identity: {
        device: registryStats.dev.toString(10),
        inode: registryStats.ino.toString(10),
      },
      mode: Number(registryStats.mode & 0o777n),
      bytes: encoder.encode(physicalPreimageJson),
    });
    const operationId = 'setup-registry-merge';
    const authority = await openSetupTransactionAuthority({
      operationId,
      installId: 'install-registry-merge',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [registryPreimage, absent(credentialPath)],
      credential: {
        projectId: 'project-selected',
        path: credentialPath,
        stagingPath,
        mode: 0o600,
      },
    });
    const createdCredential = authority.reservedCreatedCredential;
    if (createdCredential === undefined) {
      throw new Error('registry merge setup did not reserve the selected credential');
    }
    const selected = {
      projectId: createdCredential.projectId,
      tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
      canonicalRoot: item.root,
      credentialPath,
      device: createdCredential.identity.device,
      inode: createdCredential.identity.inode,
    };
    const selectedPreimage = { schemaVersion: 1 as const, projects: [] };
    const selectedPostimage = { schemaVersion: 1 as const, projects: [selected] };
    const physicalPostimage = {
      schemaVersion: 1 as const,
      projects: [selected, unrelated],
    };
    const physicalPostimageFingerprint = fingerprint(
      encoder.encode(serializeCredentialAuthorityRegistryV1(physicalPostimage)),
    );
    const proposed = createdCredentialFinalization(
      'install-registry-merge',
      registryPath,
      item.root,
      createdCredential,
    );
    const proposedManifest = parseSetupManifestV1(proposed.manifest);
    const finalization = immutableFinalization({
      manifest: {
        ...proposedManifest,
        artifacts: proposedManifest.artifacts.map((artifact) =>
          artifact.kind === 'credential-authority-registry'
            ? { ...artifact, fingerprint: physicalPostimageFingerprint }
            : artifact,
        ),
      },
      operations: proposed.operations.map((operation) =>
        operation.kind === 'apply-credential-authority-registry'
          ? { ...operation, fingerprint: physicalPostimageFingerprint }
          : operation,
      ),
      preimages: [registryPreimage],
    });

    const applied = await applySetupTransaction({
      authority,
      operationId,
      installId: 'install-registry-merge',
      credential: {
        projectId: 'project-selected',
        path: credentialPath,
        stagingPath,
        mode: 0o600,
        contentBytes: encoder.encode(
          credentialEnvelope('project-selected', 'registry-merge-token'),
        ),
      },
      finalization,
    });
    if (!('manifest' in applied)) {
      throw new Error('registry merge setup unexpectedly compensated');
    }
    const registryArtifact = applied.manifest.artifacts.find(
      (
        artifact,
      ): artifact is Extract<
        (typeof applied.manifest.artifacts)[number],
        { readonly kind: 'credential-authority-registry' }
      > => artifact.kind === 'credential-authority-registry',
    );
    if (registryArtifact === undefined) {
      throw new Error('registry merge manifest omitted selected registry provenance');
    }
    expect({
      fingerprint: registryArtifact.fingerprint,
      preimage: registryArtifact.preimage,
      postimage: registryArtifact.postimage,
    }).toEqual({
      fingerprint: physicalPostimageFingerprint,
      preimage: selectedPreimage,
      postimage: selectedPostimage,
    });
    const registryMutation = parseWalRecordJsonV2(
      await readFile(item.walPath, 'utf8'),
    ).mutations.find(
      (mutation) =>
        mutation.kind === 'ordinary' &&
        mutation.targetPath === registryPath &&
        mutation.result.kind === 'file',
    );
    if (
      registryMutation === undefined ||
      registryMutation.kind !== 'ordinary' ||
      registryMutation.result.kind !== 'file'
    ) {
      throw new Error('registry merge WAL omitted its exact physical postimage');
    }
    expect({
      targetPath: registryMutation.targetPath,
      mode: registryMutation.result.mode,
      bytes: registryMutation.result.bytes,
    }).toEqual({
      targetPath: registryPath,
      mode: 0o600,
      bytes: Buffer.from(
        serializeCredentialAuthorityRegistryV1(physicalPostimage),
        'utf8',
      ).toString('base64'),
    });
    await expect(readFile(registryPath, 'utf8')).resolves.toBe(
      serializeCredentialAuthorityRegistryV1(physicalPostimage),
    );

    await expect(publishSetupTransaction(applied)).resolves.toEqual({
      state: 'active',
      failures: [],
    });
    expect(parseSetupManifestV1(JSON.parse(await readFile(item.manifestPath, 'utf8')))).toEqual(
      applied.manifest,
    );
    await expect(readFile(registryPath, 'utf8')).resolves.toBe(
      serializeCredentialAuthorityRegistryV1(physicalPostimage),
    );
    expect(parseCredentialAuthorityRegistryJsonV1(await readFile(registryPath, 'utf8'))).toEqual(
      physicalPostimage,
    );
  });
  it('persists absent parent authority before mkdir, journals identities before publish, and reverses nested directories last', async () => {
    const item = await fixture();
    const parent = join(item.root, 'setup');
    const child = join(parent, 'credentials');
    const parentStage = join(item.root, '.setup.stage');
    const childStage = join(parent, '.credentials.stage');
    const credentialPath = join(child, 'credential');
    const credentialStage = join(child, '.credential.stage');
    const ownedPath = join(child, 'owned.txt');
    const registryPath = join(child, 'credential-authorities.v1.json');
    const directories = [
      { path: parent, stagingPath: parentStage, mode: 0o700 },
      { path: child, stagingPath: childStage, mode: 0o700 },
    ];
    const events: string[] = [];
    const reserveDirectory = item.port.reserveStagedDirectory.bind(item.port);
    const publishDirectory = item.port.publishReservedStagedDirectory.bind(item.port);
    const reserveCredential = item.port.reserveStagedWrite.bind(item.port);
    const removeDirectory = item.port.quarantineExactDirectory.bind(item.port);
    const removeFile = item.port.quarantineExactFile.bind(item.port);
    item.port.reserveStagedDirectory = async (candidate) => {
      const targetPath = candidate.targetPath;
      if (targetPath === undefined) {
        throw new Error('preauthorized directory intent omitted its target authority');
      }
      const expectedIntent =
        candidate.path === parentStage
          ? { path: parentStage, targetPath: parent, mode: 0o700 }
          : candidate.path === childStage
            ? { path: childStage, targetPath: child, mode: 0o700 }
            : (() => {
                throw new Error('unexpected nested directory stage reservation');
              })();
      expect({
        path: candidate.path,
        targetPath,
        mode: candidate.mode,
      }).toEqual(expectedIntent);
      const walBeforeReservation = await readFile(item.walPath, 'utf8')
        .then((raw) => parseWalRecordJsonV2(raw))
        .catch((error: unknown) => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
            return undefined;
          }
          throw error;
        });
      expect(
        walBeforeReservation?.mutations.filter(
          (mutation) =>
            mutation.kind === 'ordinary' &&
            (mutation.targetPath === targetPath || mutation.stagingPath === candidate.path),
        ) ?? [],
      ).toEqual([]);
      await expect(lstat(targetPath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(lstat(candidate.path)).rejects.toMatchObject({ code: 'ENOENT' });
      const reservation = await reserveDirectory(candidate);
      expect({
        path: reservation.path,
        mode: reservation.mode,
        state: reservation.state,
      }).toEqual({
        path: candidate.path,
        mode: candidate.mode,
        state: 'completed',
      });
      events.push(`reserve:${candidate.path}`);
      return reservation;
    };
    item.port.publishReservedStagedDirectory = async (input) => {
      const wal = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
      const mutation = wal.mutations[wal.mutations.length - 1];
      if (
        mutation === undefined ||
        mutation.kind !== 'ordinary' ||
        mutation.result.kind !== 'directory'
      ) {
        throw new Error('directory publication was not preceded by a directory WAL authority');
      }
      const expectedStep =
        input.targetPath === parent ? 0 : input.targetPath === child ? 1 : undefined;
      if (expectedStep === undefined) {
        throw new Error('unexpected nested directory publication target');
      }
      expect({
        operation: wal.operation,
        direction: wal.direction,
        phase: wal.phase,
        cursor: wal.cursor,
        mutation,
      }).toEqual({
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        cursor: expectedStep,
        mutation: {
          step: expectedStep,
          kind: 'ordinary',
          targetPath: input.targetPath,
          sourcePath: `${input.targetPath}.scene-glass-setup-nested-directories-${expectedStep}.rollback`,
          stagingPath: expectedStep === 0 ? parentStage : childStage,
          preimage: expectedStep,
          result: {
            kind: 'directory',
            identity: input.reservation.identity,
            mode: 0o700,
          },
        },
      });
      await expect(lstat(input.targetPath)).rejects.toMatchObject({ code: 'ENOENT' });
      events.push(`publish:${input.targetPath}`);
      return publishDirectory(input);
    };
    item.port.reserveStagedWrite = async (candidate) => {
      events.push(`credential:${candidate.path}`);
      return reserveCredential(candidate);
    };
    item.port.quarantineExactDirectory = async (
      candidate: Parameters<LifecycleTransactionPort['quarantineExactDirectory']>[0],
    ) => {
      events.push(`remove-directory:${candidate.path}`);
      return removeDirectory(candidate);
    };
    item.port.quarantineExactFile = async (
      candidate: Parameters<LifecycleTransactionPort['quarantineExactFile']>[0],
    ) => {
      if (candidate.path === credentialPath) {
        events.push(`remove-credential:${candidate.path}`);
      }
      return removeFile(candidate);
    };

    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-nested-directories',
      installId: 'install-nested-directories',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(parent), absent(child), absent(credentialPath)],
      directories,
      credential: {
        projectId: 'project-nested',
        path: credentialPath,
        stagingPath: credentialStage,
        mode: 0o600,
      },
    });
    const reservedCreatedCredential = authority.reservedCreatedCredential;
    if (reservedCreatedCredential === undefined) {
      throw new Error('nested setup authority did not reserve the created credential');
    }
    expect({
      projectId: reservedCreatedCredential.projectId,
      path: reservedCreatedCredential.path,
      mode: reservedCreatedCredential.mode,
    }).toEqual({
      projectId: 'project-nested',
      path: credentialPath,
      mode: 0o600,
    });
    const token = 'nested-credential-token-never-in-authority';
    const serializedCredential = credentialEnvelope('project-nested', token);
    const secret = encoder.encode(serializedCredential);
    const canaries = credentialCanaries(token, serializedCredential);
    const credentialFinalization = createdCredentialFinalization(
      'install-nested-directories',
      registryPath,
      item.root,
      reservedCreatedCredential,
      [ownedFileArtifact(ownedPath, encoder.encode('owned'))],
    );
    const precomputedFinalization = immutableFinalization({
      ...credentialFinalization,
      operations: [
        {
          kind: 'write-file' as const,
          path: ownedPath,
          bytes: encoder.encode('owned'),
          mode: 0o600,
        },
        ...credentialFinalization.operations,
      ],
      preimages: [absent(ownedPath), ...credentialFinalization.preimages],
    });
    const applied = await applySetupTransaction({
      authority,
      operationId: 'setup-nested-directories',
      installId: 'install-nested-directories',
      directories,
      credential: {
        projectId: 'project-nested',
        path: credentialPath,
        stagingPath: credentialStage,
        mode: 0o600,
        contentBytes: secret,
      },
      finalization: precomputedFinalization,
    });
    if (!('manifest' in applied)) {
      throw new Error('nested directory setup unexpectedly compensated');
    }
    const directoryArtifacts = applied.manifest.artifacts.filter(
      (
        artifact,
      ): artifact is Extract<
        (typeof applied.manifest.artifacts)[number],
        { readonly kind: 'directory' }
      > => artifact.kind === 'directory',
    );
    expect(directoryArtifacts).toEqual([]);

    expect(events).toEqual([
      `reserve:${parentStage}`,
      `publish:${parent}`,
      `reserve:${childStage}`,
      `publish:${child}`,
      `credential:${credentialStage}`,
    ]);
    const wal = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
    const manifestMutation = wal.mutations[5];
    if (
      manifestMutation === undefined ||
      manifestMutation.kind !== 'ordinary' ||
      manifestMutation.targetPath === parent ||
      manifestMutation.targetPath === child ||
      manifestMutation.targetPath === ownedPath ||
      manifestMutation.targetPath === registryPath ||
      manifestMutation.result.kind !== 'file'
    ) {
      throw new Error('nested setup WAL did not retain a distinct manifest authority mutation');
    }
    expect({
      operation: wal.operation,
      direction: wal.direction,
      phase: wal.phase,
      cursor: wal.cursor,
      mutations: wal.mutations.slice(0, 5).map((mutation) => ({
        step: mutation.step,
        kind: mutation.kind,
        path: mutation.kind === 'credential' ? mutation.path : mutation.targetPath,
      })),
      manifestAuthority: {
        step: manifestMutation.step,
        kind: manifestMutation.kind,
        targetPath: manifestMutation.targetPath,
        preimage: manifestMutation.preimage,
        result: manifestMutation.result,
      },
    }).toEqual({
      operation: 'setup',
      direction: 'rollback',
      phase: 'finalized',
      cursor: 6,
      mutations: [
        { step: 0, kind: 'ordinary', path: parent },
        { step: 1, kind: 'ordinary', path: child },
        { step: 2, kind: 'credential', path: credentialPath },
        { step: 3, kind: 'ordinary', path: ownedPath },
        { step: 4, kind: 'ordinary', path: registryPath },
      ],
      manifestAuthority: {
        step: 5,
        kind: 'ordinary',
        targetPath: manifestMutation.targetPath,
        preimage: 5,
        result: manifestMutation.result,
      },
    });
    expect(
      await credentialCanaryLeaks(
        [
          item.lockPath,
          item.walPath,
          item.manifestPath,
          registryPath,
          ...wal.mutations.flatMap((mutation) =>
            mutation.kind === 'ordinary'
              ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
              : [],
          ),
        ],
        canaries,
      ),
    ).toEqual([]);
    expect([...secret]).toEqual(new Array(secret.byteLength).fill(0));

    expect((await compensateSetupTransaction(authority)).state).toBe('never-installed');
    await expect(readFile(registryPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(events).toEqual([
      `reserve:${parentStage}`,
      `publish:${parent}`,
      `reserve:${childStage}`,
      `publish:${child}`,
      `credential:${credentialStage}`,
      `remove-credential:${credentialPath}`,
      `remove-directory:${child}`,
      `remove-directory:${parent}`,
    ]);
    await expect(lstat(parent)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(credentialPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('recovers an exact intent-authorized directory stage when identity journaling fails', async () => {
    const item = await fixture();
    const target = join(item.root, 'setup');
    const stagingPath = join(item.root, '.setup.stage');
    const portFailurePoint = item.port.failurePoint.bind(item.port);
    item.port.failurePoint = async (name) => {
      if (name === 'directory-identity-wal') {
        throw new Error('simulated crash boundary');
      }
      await portFailurePoint(name);
    };

    let thrown: unknown;
    try {
      await openSetupTransactionAuthority({
        operationId: 'setup-unknown-directory-stage',
        installId: 'install-unknown-directory-stage',
        port: item.port,
        lockPath: item.lockPath,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
        preimages: [absent(target)],
        directories: [{ path: target, stagingPath, mode: 0o700 }],
      });
    } catch (error) {
      thrown = error;
    } finally {
      item.port.failurePoint = portFailurePoint;
    }

    expect(thrown).toBeInstanceOf(LifecycleTransactionError);
    expect(thrown).toMatchObject({ failures: [{ stage: 'directory-identity-wal' }] });
    expect(await observePath(target)).toEqual({ state: 'error', code: 'ENOENT' });
    expect((await lstat(stagingPath)).isDirectory()).toBe(true);
    const wal = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
    expect({
      operationId: wal.operationId,
      installId: wal.installId,
      direction: wal.direction,
      phase: wal.phase,
      cursor: wal.cursor,
      preimages: wal.preimages.map(({ path, kind }) => ({ path, kind })),
      mutations: wal.mutations,
      creationIntents: wal.creationIntents?.map((intent) => ({
        step: intent.step,
        kind: intent.kind,
        targetPath: intent.targetPath,
        stagingPath: intent.stagingPath,
        mode: intent.mode,
      })),
    }).toEqual({
      operationId: 'setup-unknown-directory-stage',
      installId: 'install-unknown-directory-stage',
      direction: 'rollback',
      phase: 'prepared',
      cursor: 0,
      preimages: [
        { path: target, kind: 'absent' },
        { path: stagingPath, kind: 'absent' },
      ],
      mutations: [],
      creationIntents: [
        {
          step: 0,
          kind: 'directory',
          targetPath: target,
          stagingPath,
          mode: 0o700,
        },
      ],
    });

    await expect(
      recoverLifecycle({
        port: item.port,
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
      }),
    ).resolves.toEqual({ state: 'never-installed', failures: [] });
    await expect(lstat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rolls back the exact staged directory identity after publication is interrupted', async () => {
    const item = await fixture();
    const target = join(item.root, 'setup');
    const stagingPath = join(item.root, '.setup.stage');
    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-stage-idempotence',
      installId: 'install-stage-idempotence',
      port: item.port,
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [absent(target)],
      directories: [{ path: target, stagingPath, mode: 0o700 }],
    });
    const finalization = immutableFinalization({
      manifest: manifest('install-stage-idempotence'),
      operations: [],
      preimages: [],
    });
    const applied = await applySetupTransaction({
      authority,
      operationId: 'setup-stage-idempotence',
      installId: 'install-stage-idempotence',
      directories: [{ path: target, stagingPath, mode: 0o700 }],
      finalization,
    });
    if (!('manifest' in applied)) {
      throw new Error('directory setup unexpectedly compensated');
    }

    await rename(target, stagingPath);
    expect((await compensateSetupTransaction(authority)).state).toBe('never-installed');
    await expect(lstat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('preserves both, wrong-kind, and nonempty directory states with their exact WAL', async () => {
    const observations: DirectoryPreservationObservation[] = [];

    for (const scenario of ['both', 'wrong-kind', 'nonempty'] as const) {
      const item = await fixture();
      const target = join(item.root, 'setup');
      const stagingPath = join(item.root, '.setup.stage');
      const authority = await openSetupTransactionAuthority({
        operationId: `setup-directory-${scenario}`,
        installId: `install-directory-${scenario}`,
        port: item.port,
        lockPath: item.lockPath,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
        preimages: [absent(target)],
        directories: [{ path: target, stagingPath, mode: 0o700 }],
      });
      const finalization = immutableFinalization({
        manifest: manifest(`install-directory-${scenario}`),
        operations: [],
        preimages: [],
      });
      const applied = await applySetupTransaction({
        authority,
        operationId: `setup-directory-${scenario}`,
        installId: `install-directory-${scenario}`,
        directories: [{ path: target, stagingPath, mode: 0o700 }],
        finalization,
      });
      if (!('manifest' in applied)) {
        throw new Error('directory setup unexpectedly compensated');
      }

      const originalDirectory = await lstat(target);
      let childPath: string | undefined;
      let expected: DirectoryPreservationPaths;
      if (scenario === 'both') {
        await mkdir(stagingPath, { mode: 0o700 });
        const staged = await lstat(stagingPath);
        expected = {
          target: {
            state: 'present',
            isDirectory: true,
            isFile: false,
            identity: { device: originalDirectory.dev, inode: originalDirectory.ino },
            mode: originalDirectory.mode & 0o777,
            contents: undefined,
          },
          staging: {
            state: 'present',
            isDirectory: true,
            isFile: false,
            identity: { device: staged.dev, inode: staged.ino },
            mode: staged.mode & 0o777,
            contents: undefined,
          },
        };
      } else if (scenario === 'wrong-kind') {
        await rmdir(target);
        await writeFile(target, 'replacement', { mode: 0o600 });
        const replaced = await lstat(target);
        expected = {
          target: {
            state: 'present',
            isDirectory: false,
            isFile: true,
            identity: { device: replaced.dev, inode: replaced.ino },
            mode: replaced.mode & 0o777,
            contents: 'replacement',
          },
          staging: { state: 'error', code: 'ENOENT' },
        };
      } else {
        childPath = join(target, 'child');
        await writeFile(childPath, 'nonempty', { mode: 0o600 });
        const child = await lstat(childPath);
        expected = {
          target: {
            state: 'present',
            isDirectory: true,
            isFile: false,
            identity: { device: originalDirectory.dev, inode: originalDirectory.ino },
            mode: originalDirectory.mode & 0o777,
            contents: undefined,
          },
          staging: { state: 'error', code: 'ENOENT' },
          child: {
            state: 'present',
            isDirectory: false,
            isFile: true,
            identity: { device: child.dev, inode: child.ino },
            mode: child.mode & 0o777,
            contents: 'nonempty',
          },
        };
      }
      const walBefore = await readFile(item.walPath, 'utf8');

      const result = await compensateSetupTransaction(authority);
      const walAfter = await readFile(item.walPath, 'utf8');
      const actual: DirectoryPreservationPaths = {
        target: await observePath(target),
        staging: await observePath(stagingPath),
        ...(childPath === undefined ? {} : { child: await observePath(childPath) }),
      };
      observations.push({
        scenario,
        state: result.state,
        walBefore,
        walAfter,
        actual,
        expected,
      });
    }

    expect(
      observations.map(({ scenario, state, actual }) => ({ scenario, state, actual })),
    ).toEqual(
      observations.map(({ scenario, expected }) => ({
        scenario,
        state: 'recovery-required',
        actual: expected,
      })),
    );
    expect(observations.map(({ walAfter }) => walAfter)).toStrictEqual(
      observations.map(({ walBefore }) => walBefore),
    );
  });
  it('rejects a mismatched recovery ID under the held lock without target mutation', async () => {
    const item = await fixture();
    const targetPath = join(item.root, 'recovery-target');
    await mkdir(targetPath, { mode: 0o700 });
    const targetBefore = await observePath(targetPath);
    const wal = await preparedDirectoryRollbackWal(item, targetPath, 'recovery-id-authorized-wal');
    await writeFile(item.walPath, wal, { mode: 0o600 });

    const acquireLock = item.port.acquireAdvisoryLock.bind(item.port);
    const readWalFileNoFollow = item.port.readWalFileNoFollow.bind(item.port);
    const walReadLockStates: boolean[] = [];
    item.port.readWalFileNoFollow = async (input) => {
      if (input.path === item.walPath) {
        const competingLockDenied = await acquireLock(item.lockPath).then(
          async (lock) => {
            await lock.release();
            return false;
          },
          (error: unknown) => {
            expectConfiguredLockContention(error);
            return true;
          },
        );
        walReadLockStates.push(competingLockDenied);
      }
      return readWalFileNoFollow(input);
    };

    expect(
      await recoverLifecycle({
        port: item.port,
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        expectedRecoveryId: 'scg-wrong-recovery-id',
      }),
    ).toEqual({ state: 'recovery-required', failures: [{ stage: 'wal-authority' }] });
    expect(walReadLockStates).toEqual([true]);
    await expect(readFile(item.walPath, 'utf8')).resolves.toBe(wal);
    expect(await observePath(targetPath)).toEqual(targetBefore);
  });
  it('derives uninstall authority under lock from a parsed manifest and exact preflight', async () => {
    const item = await fixture();
    const targetPath = join(item.root, 'owned.txt');
    const receiptPath = join(item.root, 'receipt.v1.json');
    const targetBytes = encoder.encode('owned uninstall target\n');
    const sourceManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'uninstall-transaction-alpha',
      state: 'active',
      artifacts: [
        {
          path: targetPath,
          kind: 'file',
          fingerprint: fingerprint(targetBytes),
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: targetPath,
            expectedFingerprint: fingerprint(targetBytes),
          },
        },
      ],
    };
    const parsedManifest = parseSetupManifestV1(sourceManifest);
    const artifact = parsedManifest.artifacts[0];
    if (artifact === undefined) {
      throw new Error('uninstall fixture did not produce an owned file artifact');
    }
    const preflight = validateUninstallPreflight({
      manifest: parsedManifest,
      observed: [
        {
          path: targetPath,
          fingerprint: fingerprint(targetBytes),
          hunks: [],
          semanticConfig: undefined,
        },
      ],
    });
    const staleReceipt = serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'prior-uninstall',
      installId: 'retired-install',
      terminalState: 'uninstalled',
      manifestFingerprint: fingerprint(encoder.encode('retired manifest\n')),
    });
    const walRecords: Array<ReturnType<typeof parseWalRecordJsonV2>> = [];
    const observedWalStagePaths: string[] = [];
    const walStagePath = `${item.walPath}.scene-glass-wal.stage`;
    const expectedWalStagePaths = Array.from({ length: 6 }, () => walStagePath);
    const publishStagedWrite = item.port.publishStagedWrite.bind(item.port);
    item.port.publishStagedWrite = async (candidate) => {
      await publishStagedWrite(candidate);
      if (candidate.targetPath !== item.walPath) {
        return;
      }
      expect(candidate.stage.path).toBe(walStagePath);
      observedWalStagePaths.push(candidate.stage.path);
      walRecords.push(parseWalRecordJsonV2(await readFile(item.walPath, 'utf8')));
    };
    const replaceExactWal = item.port.replaceExactWal.bind(item.port);
    item.port.replaceExactWal = async (candidate) => {
      const result = await replaceExactWal(candidate);
      expect(result.state).toBe('completed');
      expect(candidate.replacement.path).toBe(walStagePath);
      observedWalStagePaths.push(candidate.replacement.path);
      walRecords.push(parseWalRecordJsonV2(await readFile(item.walPath, 'utf8')));
      return result;
    };
    await Promise.all([
      writeFile(targetPath, targetBytes, { mode: 0o600 }),
      writeFile(item.manifestPath, serializeSetupManifestV1(parsedManifest), { mode: 0o600 }),
      writeFile(receiptPath, staleReceipt, { mode: 0o600 }),
    ]);

    expect(preflight).toEqual({
      canUninstall: true,
      writes: [],
      inverse: [artifact.inverse],
      issues: [],
    });
    const result = await applyUninstallTransaction({
      manifest: parsedManifest,
      operationId: 'uninstall-transaction-operation',
      preflight,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      receiptPath,
      lockPath: item.lockPath,
      port: item.port,
    });
    expect(observedWalStagePaths).toStrictEqual(expectedWalStagePaths);
    const prepared = walRecords.find(
      (record) =>
        record.operation === 'uninstall' &&
        record.direction === 'rollback' &&
        record.mutations.some(
          (mutation) => mutation.kind === 'ordinary' && mutation.targetPath === receiptPath,
        ) &&
        record.mutations.some(
          (mutation) => mutation.kind === 'ordinary' && mutation.targetPath === item.manifestPath,
        ),
    );
    if (prepared === undefined) {
      throw new Error('uninstall did not persist its prepared WAL authority');
    }

    expect(result).toEqual({ state: 'uninstalled', failures: [] });
    expect(prepared.preimages.map((preimage) => preimage.path)).toEqual([
      item.manifestPath,
      targetPath,
      receiptPath,
    ]);
    expect(prepared.preimages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: targetPath,
          kind: 'file',
          bytes: Buffer.from(targetBytes).toString('base64'),
        }),
        expect.objectContaining({
          path: receiptPath,
          kind: 'file',
          bytes: Buffer.from(staleReceipt, 'utf8').toString('base64'),
        }),
      ]),
    );
    expect(prepared.mutations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ targetPath }),
        expect.objectContaining({ targetPath: receiptPath }),
        expect.objectContaining({ targetPath: item.manifestPath, result: { kind: 'absent' } }),
      ]),
    );
    await expect(readFile(targetPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.manifestPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(parseLifecycleReceiptJsonV1(await readFile(receiptPath, 'utf8'))).toEqual({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'uninstall-transaction-operation',
      installId: parsedManifest.installId,
      terminalState: 'uninstalled',
      manifestFingerprint: fingerprint(encoder.encode(serializeSetupManifestV1(parsedManifest))),
    });
    expect(
      await recoverLifecycle({
        port: item.port,
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath,
      }),
    ).toEqual({ state: 'uninstalled', failures: [] });
  });
  it('retains the prepared WAL when disk rollback finds an untouched manifest preimage changed', async () => {
    const item = await fixture();
    const targetPath = join(item.root, 'disk-rollback-owned.txt');
    const receiptPath = join(item.root, 'disk-rollback-receipt.v1.json');
    const targetBytes = encoder.encode('disk rollback target\n');
    const sourceManifest = {
      ...manifest('disk-rollback-install'),
      artifacts: [ownedFileArtifact(targetPath, targetBytes)],
    };
    const parsedManifest = parseSetupManifestV1(sourceManifest);
    const preflight = validateUninstallPreflight({
      manifest: parsedManifest,
      observed: [
        {
          path: targetPath,
          fingerprint: fingerprint(targetBytes),
          hunks: [],
          semanticConfig: undefined,
        },
      ],
    });
    await Promise.all([
      writeFile(targetPath, targetBytes, { mode: 0o600 }),
      writeFile(item.manifestPath, serializeSetupManifestV1(parsedManifest), { mode: 0o600 }),
    ]);

    let rollbackMutationPublished = false;
    let manifestTampered = false;
    const replaceExactWal = item.port.replaceExactWal.bind(item.port);
    const failurePoint = item.port.failurePoint.bind(item.port);
    item.port.replaceExactWal = async (input) => {
      const result = await replaceExactWal(input);
      const record = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
      if (
        record.operation === 'uninstall' &&
        record.direction === 'rollback' &&
        record.mutations.length === 1
      ) {
        rollbackMutationPublished = true;
      }
      return result;
    };
    item.port.failurePoint = async (point) => {
      if (point === 'target-rename' && rollbackMutationPublished && !manifestTampered) {
        manifestTampered = true;
        await writeFile(item.manifestPath, 'tampered manifest authority\n', { mode: 0o600 });
        throw new Error('simulated target publication failure after manifest tampering');
      }
      await failurePoint(point);
    };

    const result = await applyUninstallTransaction({
      manifest: parsedManifest,
      operationId: 'disk-rollback-operation',
      preflight,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      receiptPath,
      lockPath: item.lockPath,
      port: item.port,
    });

    expect(manifestTampered).toBe(true);
    expect(result).toEqual({
      state: 'recovery-required',
      failures: [{ stage: 'third-state' }, { stage: 'target-rename' }],
    });
    await expect(readFile(targetPath)).resolves.toEqual(Buffer.from(targetBytes));
    await expect(readFile(item.manifestPath, 'utf8')).resolves.toBe(
      'tampered manifest authority\n',
    );
    const retained = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
    expect(retained).toMatchObject({
      operation: 'uninstall',
      direction: 'rollback',
      phase: 'prepared',
      mutations: [expect.objectContaining({ targetPath })],
    });
  });

  it('refuses tampered, reordered, and extra preflight inverses before a target mutation', async () => {
    const item = await fixture();
    const firstPath = join(item.root, 'first-owned.txt');
    const secondPath = join(item.root, 'second-owned.txt');
    const firstBytes = encoder.encode('first owned target\n');
    const secondBytes = encoder.encode('second owned target\n');
    const sourceManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'uninstall-preflight-alpha',
      state: 'active',
      artifacts: [
        {
          path: firstPath,
          kind: 'file',
          fingerprint: fingerprint(firstBytes),
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: firstPath,
            expectedFingerprint: fingerprint(firstBytes),
          },
        },
        {
          path: secondPath,
          kind: 'file',
          fingerprint: fingerprint(secondBytes),
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: secondPath,
            expectedFingerprint: fingerprint(secondBytes),
          },
        },
      ],
    };
    const parsedManifest = parseSetupManifestV1(sourceManifest);
    const preflight = validateUninstallPreflight({
      manifest: parsedManifest,
      observed: [
        {
          path: firstPath,
          fingerprint: fingerprint(firstBytes),
          hunks: [],
          semanticConfig: undefined,
        },
        {
          path: secondPath,
          fingerprint: fingerprint(secondBytes),
          hunks: [],
          semanticConfig: undefined,
        },
      ],
    });
    const firstInverse = preflight.inverse[0];
    const secondInverse = preflight.inverse[1];
    if (
      firstInverse === undefined ||
      firstInverse.kind !== 'delete-created-file' ||
      secondInverse === undefined ||
      secondInverse.kind !== 'delete-created-file'
    ) {
      throw new Error('uninstall fixture did not produce two file-delete inverses');
    }
    const invalidPreflights = [
      {
        name: 'tampered',
        preflight: {
          ...preflight,
          inverse: [
            {
              ...firstInverse,
              expectedFingerprint: fingerprint(encoder.encode('tampered inverse\n')),
            },
            secondInverse,
          ],
        },
      },
      {
        name: 'reordered',
        preflight: { ...preflight, inverse: [secondInverse, firstInverse] },
      },
      {
        name: 'extra',
        preflight: { ...preflight, inverse: [firstInverse, secondInverse, firstInverse] },
      },
    ];
    const targetMutations: string[] = [];
    const publishTarget = item.port.publishExactStagedFile.bind(item.port);
    const replaceTarget = item.port.replaceExactStagedFileWithQuarantine.bind(item.port);
    const removeTarget = item.port.quarantineExactFile.bind(item.port);
    item.port.publishExactStagedFile = async (input) => {
      if (
        input.stagingPath === firstPath ||
        input.stagingPath === secondPath ||
        input.targetPath === firstPath ||
        input.targetPath === secondPath
      ) {
        targetMutations.push(`publish:${input.stagingPath}:${input.targetPath}`);
      }
      return publishTarget(input);
    };
    item.port.replaceExactStagedFileWithQuarantine = async (
      input: Parameters<LifecycleTransactionPort['replaceExactStagedFileWithQuarantine']>[0],
    ) => {
      if (
        input.stagingPath === firstPath ||
        input.stagingPath === secondPath ||
        input.targetPath === firstPath ||
        input.targetPath === secondPath
      ) {
        targetMutations.push(`replace:${input.stagingPath}:${input.targetPath}`);
      }
      return replaceTarget(input);
    };
    item.port.quarantineExactFile = async (
      candidate: Parameters<LifecycleTransactionPort['quarantineExactFile']>[0],
    ) => {
      if (candidate.path === firstPath || candidate.path === secondPath) {
        targetMutations.push(`remove:${candidate.path}`);
      }
      return removeTarget(candidate);
    };
    await Promise.all([
      writeFile(firstPath, firstBytes, { mode: 0o600 }),
      writeFile(secondPath, secondBytes, { mode: 0o600 }),
      writeFile(item.manifestPath, serializeSetupManifestV1(parsedManifest), { mode: 0o600 }),
    ]);

    for (const { name, preflight: invalidPreflight } of invalidPreflights) {
      expect(
        await applyUninstallTransaction({
          manifest: parsedManifest,
          operationId: `uninstall-preflight-${name}`,
          preflight: invalidPreflight,
          walPath: item.walPath,
          manifestPath: item.manifestPath,
          receiptPath: join(item.root, 'receipt.v1.json'),
          lockPath: item.lockPath,
          port: item.port,
        }),
      ).toEqual({ state: 'recovery-required', failures: [{ stage: 'uninstall-authority' }] });
      await expect(readFile(firstPath, 'utf8')).resolves.toBe('first owned target\n');
      await expect(readFile(secondPath, 'utf8')).resolves.toBe('second owned target\n');
      await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    }
    expect(targetMutations).toEqual([]);
    await expect(readFile(item.manifestPath, 'utf8')).resolves.toBe(
      serializeSetupManifestV1(parsedManifest),
    );
  });

  it('refuses a replaced target identity and content before a target mutation', async () => {
    const item = await fixture();
    const targetPath = join(item.root, 'owned.txt');
    const targetBytes = encoder.encode('owned target\n');
    const sourceManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'uninstall-replaced-target',
      state: 'active',
      artifacts: [
        {
          path: targetPath,
          kind: 'file',
          fingerprint: fingerprint(targetBytes),
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: targetPath,
            expectedFingerprint: fingerprint(targetBytes),
          },
        },
      ],
    };
    const parsedManifest = parseSetupManifestV1(sourceManifest);
    const preflight = validateUninstallPreflight({
      manifest: parsedManifest,
      observed: [
        {
          path: targetPath,
          fingerprint: fingerprint(targetBytes),
          hunks: [],
          semanticConfig: undefined,
        },
      ],
    });
    const replacementPath = join(item.root, 'replacement.txt');
    const targetMutations: string[] = [];
    const publishTarget = item.port.publishExactStagedFile.bind(item.port);
    const replaceTarget = item.port.replaceExactStagedFileWithQuarantine.bind(item.port);
    const removeTarget = item.port.quarantineExactFile.bind(item.port);
    item.port.publishExactStagedFile = async (input) => {
      if (input.stagingPath === targetPath || input.targetPath === targetPath) {
        targetMutations.push(`publish:${input.stagingPath}:${input.targetPath}`);
      }
      return publishTarget(input);
    };
    item.port.replaceExactStagedFileWithQuarantine = async (
      input: Parameters<LifecycleTransactionPort['replaceExactStagedFileWithQuarantine']>[0],
    ) => {
      if (input.stagingPath === targetPath || input.targetPath === targetPath) {
        targetMutations.push(`replace:${input.stagingPath}:${input.targetPath}`);
      }
      return replaceTarget(input);
    };
    item.port.quarantineExactFile = async (
      candidate: Parameters<LifecycleTransactionPort['quarantineExactFile']>[0],
    ) => {
      if (candidate.path === targetPath) {
        targetMutations.push(`remove:${candidate.path}`);
      }
      return removeTarget(candidate);
    };
    await Promise.all([
      writeFile(targetPath, targetBytes, { mode: 0o600 }),
      writeFile(item.manifestPath, serializeSetupManifestV1(parsedManifest), { mode: 0o600 }),
    ]);
    const original = await lstat(targetPath);
    await writeFile(replacementPath, 'replacement target\n', { mode: 0o600 });
    await rename(replacementPath, targetPath);
    const replacement = await lstat(targetPath);

    expect({ device: replacement.dev, inode: replacement.ino }).not.toEqual({
      device: original.dev,
      inode: original.ino,
    });
    expect(
      await applyUninstallTransaction({
        manifest: parsedManifest,
        operationId: 'uninstall-replaced-target-operation',
        preflight,
        walPath: item.walPath,
        manifestPath: item.manifestPath,
        receiptPath: join(item.root, 'receipt.v1.json'),
        lockPath: item.lockPath,
        port: item.port,
      }),
    ).toEqual({ state: 'recovery-required', failures: [{ stage: 'uninstall-authority' }] });
    await expect(readFile(targetPath, 'utf8')).resolves.toBe('replacement target\n');
    await expect(readFile(item.manifestPath, 'utf8')).resolves.toBe(
      serializeSetupManifestV1(parsedManifest),
    );
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(targetMutations).toEqual([]);
  });

  it('materializes a semantic uninstall inverse without observing or mutating a target', async () => {
    const port = createNodeLifecycleTransactionPort();
    const path = '/srv/semantic/config.json';
    const project: {
      readonly allowedOrigins: readonly string[];
      readonly framework: 'html';
      readonly projectId: string;
      readonly root: string;
      readonly tokenEnv: string;
    } = {
      allowedOrigins: ['http://127.0.0.1:4175'],
      framework: 'html',
      projectId: 'semantic-project',
      root: '/srv/semantic',
      tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
    };
    const currentBytes = encoder.encode(
      `${JSON.stringify({ schemaVersion: 1, projects: [project] }, null, 2)}\n`,
    );
    const originalBytes = [...currentBytes];
    port.lstatNoFollow = async () => {
      throw new Error('pure inverse renderer must not observe targets');
    };
    port.readFileNoFollow = async () => {
      throw new Error('pure inverse renderer must not read targets');
    };

    const rendered = await port.materializeUninstallInverse({
      inverse: {
        kind: 'restore-config',
        path,
        preimage: { schemaVersion: 1, projects: [] },
        postimage: { schemaVersion: 1, projects: [project] },
      },
      expected: {
        path,
        state: 'file',
        identity: { device: '11', inode: '12' },
        mode: 0o600,
        bytes: currentBytes,
      },
    });

    expect(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rendered))).toEqual({
      schemaVersion: 1,
      projects: [],
    });
    expect([...currentBytes]).toEqual(originalBytes);
  });
  it('materializes owned loader uninstall from current static, Vue, and React bytes without losing unrelated edits', async () => {
    const port = createNodeLifecycleTransactionPort();
    const viteLoader =
      '<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>';
    const scenarios = [
      { subject: 'scg-html-loader' as const, loader: STATIC_LOADER_MARKER },
      { subject: 'scg-vue3-loader' as const, loader: viteLoader },
      { subject: 'scg-react-loader' as const, loader: viteLoader },
    ];

    for (const { subject, loader } of scenarios) {
      const path = `/workspace/${subject}/index.html`;
      const preimage =
        '<!doctype html><html><head>\n  <meta charset="utf-8">\n  </head><body>original</body></html>\n';
      const postimage = `<!doctype html><html><head>\n  <meta charset="utf-8">\n${loader}\n  </head><body>original</body></html>\n`;
      const inverse = {
        kind: 'restore-owned-file' as const,
        path,
        preimageFingerprint: fingerprint(encoder.encode(preimage)),
        postimageFingerprint: fingerprint(encoder.encode(postimage)),
        ownedInsertion: 'line' as const,
        hunks: [
          {
            id: `scg-loader-hunk-${subject}`,
            operation: 'insert' as const,
            subject,
            fingerprint: fingerprint(encoder.encode(postimage)),
          },
        ],
      };
      const expected = (bytes: string) => ({
        path,
        state: 'file' as const,
        identity: { device: '11', inode: '12' },
        mode: 0o600,
        bytes: encoder.encode(bytes),
      });

      await expect(
        port.materializeUninstallInverse({ inverse, expected: expected(postimage) }),
      ).resolves.toEqual(encoder.encode(preimage));

      const current = `<!doctype html><html><head>\n  <meta charset="utf-8">\n  <!-- user-before -->\n${loader}\n  </head><body>original</body></html>\n<!-- user-after -->\n`;
      const preserved = `<!doctype html><html><head>\n  <meta charset="utf-8">\n  <!-- user-before -->\n  </head><body>original</body></html>\n<!-- user-after -->\n`;
      await expect(
        port.materializeUninstallInverse({ inverse, expected: expected(current) }),
      ).resolves.toEqual(encoder.encode(preserved));

      for (const invalid of [
        current.replace(loader, `${loader} altered`),
        current.replace(`${loader}\n`, ''),
        current.replace(loader, `${loader}\n${loader}`),
        current.replace(`${loader}\n  </head>`, `</head>\n${loader}`),
        current.replace('</head>', '</head></head>'),
      ]) {
        await expect(
          port.materializeUninstallInverse({ inverse, expected: expected(invalid) }),
        ).rejects.toThrow('owned file restoration preimage does not match');
      }
    }
  });
});
