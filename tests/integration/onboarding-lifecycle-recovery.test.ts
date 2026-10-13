import { spawn } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createNodeLifecycleTransactionPort } from '../../packages/onboarding/src/lifecycle/node-transaction-port.js';
import {
  applySetupTransaction,
  applyUninstallTransaction,
  openSetupTransactionAuthority,
  publishSetupTransaction,
  recoverLifecycle,
  type LifecycleTransactionPort,
} from '../../packages/onboarding/src/lifecycle/transaction.js';
import { serializeCredentialAuthorityRegistryV1 } from '../../packages/onboarding/src/credential-authority.js';
import {
  parseLifecycleReceiptJsonV1,
  parseWalRecordJsonV2,
  serializeLifecycleReceiptV1,
  serializeSetupManifestV1,
  serializeWalRecordV1,
  serializeWalRecordV2,
  validateUninstallPreflight,
} from '../../packages/onboarding/src/lifecycle/provenance.js';

const roots: string[] = [];
const ZERO_FINGERPRINT = `sha256:${'0'.repeat(64)}`;
const credentialEnvelope = (projectId: string, token: string) =>
  `VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js\nVITE_SCENE_GLASS_PROJECT_ID=${projectId}\nVITE_SCENE_GLASS_PROJECT_TOKEN=${token}\nSCENE_GLASS_HOST_TOKEN=${token}\n`;

const activeManifest = (installId: string) => ({
  schemaVersion: 1 as const,
  kind: 'scene-glass-setup-manifest' as const,
  installId,
  state: 'active' as const,
  artifacts: [],
});

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-recovery-v2-')));
  roots.push(root);
  const lockPath = join(root, 'lifecycle.lock');
  const walPath = join(root, 'lifecycle.wal.v1.json');
  const manifestPath = join(root, 'manifest.v1.json');
  const receiptPath = join(root, 'receipt.v1.json');
  await writeFile(lockPath, 'lock\n', { mode: 0o600 });
  return { root, lockPath, walPath, manifestPath, receiptPath };
}

function withWalFingerprint(
  record: Record<string, unknown>,
  authorityFingerprint: string,
): Record<string, unknown> {
  const {
    replacedWalStage,
    authorityFingerprint: ignoredAuthorityFingerprint,
    ...withoutTransportAuthority
  } = record;
  void ignoredAuthorityFingerprint;
  if (record.operation !== 'uninstall') {
    return {
      ...withoutTransportAuthority,
      authorityFingerprint,
      ...(replacedWalStage === undefined ? {} : { replacedWalStage }),
    };
  }
  const { receiptPath, manifest, ...common } = withoutTransportAuthority;
  return {
    ...common,
    authorityFingerprint,
    receiptPath,
    manifest,
    ...(replacedWalStage === undefined ? {} : { replacedWalStage }),
  };
}

function bindWal(record: Record<string, unknown>): string {
  const unbound = withWalFingerprint(record, ZERO_FINGERPRINT);
  const authorityFingerprint = `sha256:${createHash('sha256').update(serializeWalRecordV2(unbound)).digest('hex')}`;
  return serializeWalRecordV2(withWalFingerprint(record, authorityFingerprint));
}
async function identity(
  path: string,
): Promise<{ identity: { device: string; inode: string }; mode: number }> {
  const observed = await lstat(path, { bigint: true });
  return {
    identity: {
      device: observed.dev.toString(10),
      inode: observed.ino.toString(10),
    },
    mode: Number(observed.mode & 0o777n),
  };
}
type RecoveryPathSnapshot =
  | {
      readonly state: 'absent';
      readonly code: string | undefined;
    }
  | {
      readonly state: 'present';
      readonly kind: 'directory' | 'file' | 'other';
      readonly identity: { readonly device: string; readonly inode: string };
      readonly mode: number;
      readonly contents: string | undefined;
    };
type RecoveryFileSnapshot = {
  readonly state: 'present';
  readonly kind: 'file';
  readonly identity: { readonly device: string; readonly inode: string };
  readonly mode: number;
  readonly contents: string;
};
function isExactRecoveryFileSnapshot(
  snapshot: RecoveryPathSnapshot,
): snapshot is RecoveryFileSnapshot {
  return (
    snapshot.state === 'present' && snapshot.kind === 'file' && snapshot.contents !== undefined
  );
}

async function snapshotRecoveryPath(path: string): Promise<RecoveryPathSnapshot> {
  try {
    const observed = await lstat(path, { bigint: true });
    const kind = observed.isDirectory() ? 'directory' : observed.isFile() ? 'file' : 'other';
    return {
      state: 'present',
      kind,
      identity: {
        device: observed.dev.toString(10),
        inode: observed.ino.toString(10),
      },
      mode: Number(observed.mode & 0o777n),
      contents: kind === 'file' ? await readFile(path, 'utf8') : undefined,
    };
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') {
      return { state: 'absent', code: 'ENOENT' };
    }
    throw error;
  }
}
type ExactFileAuthorityMismatch = 'identity' | 'mode' | 'content';

async function snapshotRecoveryFilesystemTree(
  root: string,
): Promise<ReadonlyMap<string, RecoveryPathSnapshot>> {
  const tree = new Map<string, RecoveryPathSnapshot>();
  const visit = async (path: string): Promise<void> => {
    const snapshot = await snapshotRecoveryPath(path);
    tree.set(path, snapshot);
    if (snapshot.state !== 'present' || snapshot.kind !== 'directory') {
      return;
    }
    for (const entry of (await readdir(path)).sort()) {
      await visit(join(path, entry));
    }
  };
  await visit(root);
  return tree;
}
type RedactedRecoveryPathSnapshot =
  | {
      readonly state: 'absent';
      readonly code: string | undefined;
    }
  | {
      readonly state: 'present';
      readonly kind: 'directory' | 'file' | 'other';
      readonly identity: { readonly device: string; readonly inode: string };
      readonly mode: number;
      readonly content?: { readonly byteLength: number; readonly sha256: string };
    };
function redactRecoveryPathSnapshot(snapshot: RecoveryPathSnapshot): RedactedRecoveryPathSnapshot {
  if (snapshot.state === 'absent') {
    return snapshot;
  }
  if (snapshot.contents === undefined) {
    return {
      state: snapshot.state,
      kind: snapshot.kind,
      identity: snapshot.identity,
      mode: snapshot.mode,
    };
  }
  return {
    state: snapshot.state,
    kind: snapshot.kind,
    identity: snapshot.identity,
    mode: snapshot.mode,
    content: {
      byteLength: Buffer.byteLength(snapshot.contents, 'utf8'),
      sha256: `sha256:${createHash('sha256').update(snapshot.contents, 'utf8').digest('hex')}`,
    },
  };
}
async function snapshotRedactedRecoveryFilesystemTree(
  root: string,
): Promise<ReadonlyMap<string, RedactedRecoveryPathSnapshot>> {
  const tree = await snapshotRecoveryFilesystemTree(root);
  return new Map(
    [...tree].map(([path, snapshot]) => [path, redactRecoveryPathSnapshot(snapshot)] as const),
  );
}
async function recoverFailClosedPreservingFilesystem(
  input: RecoveryChildInput & { readonly root: string },
): Promise<readonly [RecoveryChildDetailedResult, RecoveryChildDetailedResult]> {
  const treeBefore = await snapshotRedactedRecoveryFilesystemTree(input.root);
  const lockBefore = await snapshotRecoveryPath(input.lockPath);
  const first = await runRecoveryChildDetailed(input);
  const [treeAfterFirst, lockAfterFirst] = await Promise.all([
    snapshotRedactedRecoveryFilesystemTree(input.root),
    snapshotRecoveryPath(input.lockPath),
  ]);
  const second = await runRecoveryChildDetailed(input);
  const [treeAfterSecond, lockAfterSecond] = await Promise.all([
    snapshotRedactedRecoveryFilesystemTree(input.root),
    snapshotRecoveryPath(input.lockPath),
  ]);
  expect([treeAfterFirst, treeAfterSecond]).toEqual([treeBefore, treeBefore]);
  expect([lockAfterFirst, lockAfterSecond]).toEqual([lockBefore, lockBefore]);
  return [first, second];
}

async function tamperExactFileAuthority(
  path: string,
  mismatch: ExactFileAuthorityMismatch,
  corruptedContents: string,
): Promise<{
  readonly original: RecoveryFileSnapshot;
  readonly replacement: RecoveryFileSnapshot;
}> {
  const original = await snapshotRecoveryPath(path);
  if (!isExactRecoveryFileSnapshot(original)) {
    throw new Error(`exact file authority fixture is not readable: ${path}`);
  }
  if (mismatch === 'identity') {
    const replacementPath = `${path}.replacement`;
    await writeFile(replacementPath, original.contents, { mode: original.mode });
    await chmod(replacementPath, original.mode);
    await rename(replacementPath, path);
  } else if (mismatch === 'mode') {
    await chmod(path, original.mode === 0o600 ? 0o640 : 0o600);
  } else {
    await writeFile(path, corruptedContents, { mode: original.mode });
    await chmod(path, original.mode);
  }
  const replacement = await snapshotRecoveryPath(path);
  if (!isExactRecoveryFileSnapshot(replacement)) {
    throw new Error(`exact file authority replacement is not readable: ${path}`);
  }
  return { original, replacement };
}
interface RecoveryAuthorityTreeInput {
  readonly root: string;
  readonly lockPath: string;
  readonly walPath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly registryPath: string;
  readonly credentialPath: string;
  readonly credentialStagingPath: string;
  readonly authorityPaths?: readonly string[];
}

interface RecoveryAuthorityTree {
  readonly rootPath: string;
  readonly lockPath: string;
  readonly walPath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly registryPath: string;
  readonly credentialPath: string;
  readonly credentialStagingPath: string;
  readonly root: RecoveryPathSnapshot;
  readonly rootEntries: readonly string[];
  readonly lock: RecoveryPathSnapshot;
  readonly receipt: RecoveryPathSnapshot;
  readonly wal: RecoveryPathSnapshot;
  readonly manifest: RecoveryPathSnapshot;
  readonly registry: RecoveryPathSnapshot;
  readonly credential: RecoveryPathSnapshot;
  readonly credentialStaging: RecoveryPathSnapshot;
  readonly walAuthorities: readonly {
    readonly path: string;
    readonly snapshot: RecoveryPathSnapshot;
  }[];
}

function absentRecoveryPath(): RecoveryPathSnapshot {
  return { state: 'absent', code: 'ENOENT' };
}

async function snapshotRecoveryAuthorityTree(
  input: RecoveryAuthorityTreeInput,
): Promise<RecoveryAuthorityTree> {
  const wal = await snapshotRecoveryPath(input.walPath);
  const authorityPaths = new Set(input.authorityPaths ?? []);
  if (wal.state === 'present' && wal.kind === 'file' && wal.contents !== undefined) {
    for (const mutation of parseWalRecordJsonV2(wal.contents).mutations) {
      if (mutation.kind === 'credential') {
        authorityPaths.add(mutation.path);
        authorityPaths.add(mutation.stagingPath);
      } else {
        authorityPaths.add(mutation.targetPath);
        authorityPaths.add(mutation.sourcePath);
        authorityPaths.add(mutation.stagingPath);
      }
    }
  }
  const [
    root,
    lock,
    receipt,
    manifest,
    registry,
    credential,
    credentialStaging,
    rootEntries,
    walAuthorities,
  ] = await Promise.all([
    snapshotRecoveryPath(input.root),
    snapshotRecoveryPath(input.lockPath),
    snapshotRecoveryPath(input.receiptPath),
    snapshotRecoveryPath(input.manifestPath),
    snapshotRecoveryPath(input.registryPath),
    snapshotRecoveryPath(input.credentialPath),
    snapshotRecoveryPath(input.credentialStagingPath),
    readdir(input.root).then((entries) => Object.freeze(entries.sort())),
    Promise.all(
      [...authorityPaths]
        .sort()
        .map(async (path) => Object.freeze({ path, snapshot: await snapshotRecoveryPath(path) })),
    ),
  ]);
  return Object.freeze({
    rootPath: input.root,
    lockPath: input.lockPath,
    walPath: input.walPath,
    manifestPath: input.manifestPath,
    receiptPath: input.receiptPath,
    registryPath: input.registryPath,
    credentialPath: input.credentialPath,
    credentialStagingPath: input.credentialStagingPath,
    root,
    rootEntries,
    lock,
    receipt,
    wal,
    manifest,
    registry,
    credential,
    credentialStaging,
    walAuthorities: Object.freeze(walAuthorities),
  });
}

function recoveryAuthorityTreeEntries(
  tree: RecoveryAuthorityTree,
): ReadonlyMap<string, RecoveryPathSnapshot> {
  const entries = new Map<string, RecoveryPathSnapshot>([
    [tree.rootPath, tree.root],
    [tree.lockPath, tree.lock],
    [tree.receiptPath, tree.receipt],
    [tree.walPath, tree.wal],
    [tree.manifestPath, tree.manifest],
    [tree.registryPath, tree.registry],
    [tree.credentialPath, tree.credential],
    [tree.credentialStagingPath, tree.credentialStaging],
  ]);
  for (const authority of tree.walAuthorities) {
    entries.set(authority.path, authority.snapshot);
  }
  return entries;
}

function recoveryAuthoritySnapshot(tree: RecoveryAuthorityTree, key: string): RecoveryPathSnapshot {
  const snapshot = recoveryAuthorityTreeEntries(tree).get(key);
  if (snapshot === undefined) throw new Error(`recovery authority snapshot omitted ${key}`);
  return snapshot;
}

function expectRecoveryAuthorityTreeDelta(
  before: RecoveryAuthorityTree,
  after: RecoveryAuthorityTree,
  changes: ReadonlyMap<string, RecoveryPathSnapshot>,
): void {
  expect(before.lock).toEqual({
    state: 'present',
    kind: 'file',
    identity: before.lock.state === 'present' ? before.lock.identity : undefined,
    mode: 0o600,
    contents: 'lock\n',
  });
  const beforeEntries = recoveryAuthorityTreeEntries(before);
  const afterEntries = recoveryAuthorityTreeEntries(after);
  expect([...afterEntries.keys()].sort()).toEqual([...beforeEntries.keys()].sort());
  const expectedRootEntries = new Set(before.rootEntries);
  for (const [path, expected] of changes) {
    if (!beforeEntries.has(path)) {
      throw new Error(`recovery delta references an uncaptured authority ${path}`);
    }
    if (dirname(path) === before.rootPath) {
      if (expected.state === 'absent') expectedRootEntries.delete(basename(path));
      else expectedRootEntries.add(basename(path));
    }
  }
  expect(after.rootEntries).toEqual([...expectedRootEntries].sort());
  for (const [path, beforeSnapshot] of beforeEntries) {
    expect(afterEntries.get(path)).toEqual(changes.get(path) ?? beforeSnapshot);
  }
}
interface CredentialCanary {
  readonly subject: 'token' | 'serialized-credential';
  readonly form: 'raw' | 'base64' | 'base64url' | 'sha256' | 'sha256-prefixed';
  readonly value: string;
}

function credentialCanaries(
  token: string,
  serializedCredential: string,
): readonly CredentialCanary[] {
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

async function durableNonCredentialAuthorityLeaks(
  paths: readonly string[],
  canaries: readonly CredentialCanary[],
): Promise<
  readonly {
    readonly path: string;
    readonly subject: CredentialCanary['subject'];
    readonly form: CredentialCanary['form'];
  }[]
> {
  const snapshots = await Promise.all(
    [...new Set(paths)].map(async (path) => ({ path, snapshot: await snapshotRecoveryPath(path) })),
  );
  return snapshots.flatMap(({ path, snapshot }) => {
    if (snapshot.state !== 'present' || snapshot.kind !== 'file') return [];
    if (snapshot.contents === undefined) {
      throw new Error(`durable non-credential authority was not readable: ${path}`);
    }
    const contents = snapshot.contents;
    return canaries
      .filter(({ value }) => contents.includes(value))
      .map(({ subject, form }) => ({ path, subject, form }));
  });
}

describe('onboarding lifecycle disk-authoritative recovery', () => {
  it('propagates non-ENOENT recovery snapshot inspection failures', async () => {
    const item = await fixture();
    const blockedDirectory = join(item.root, 'blocked');
    const blockedPath = join(blockedDirectory, 'authority');
    await mkdir(blockedDirectory, { mode: 0o700 });
    await writeFile(blockedPath, 'non-secret fixture bytes\n', { mode: 0o600 });
    await chmod(blockedDirectory, 0o000);
    try {
      await expect(snapshotRecoveryPath(blockedPath)).rejects.toMatchObject({ code: 'EACCES' });
    } finally {
      await chmod(blockedDirectory, 0o700);
    }
  });
  it('rolls back a prepared setup from canonical WAL alone and reports convergence', async () => {
    const item = await fixture();
    await writeFile(
      item.walPath,
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'setup-recovery-prepared',
        installId: 'install-recovery-prepared',
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        cursor: 0,
        preimages: [],
        mutations: [],
      }),
      { mode: 0o600 },
    );

    const result = await recoverLifecycle({
      port: createNodeLifecycleTransactionPort(),
      walPath: item.walPath,
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      receiptPath: item.receiptPath,
    });
    expect(result.state).toBe('never-installed');
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects an uninstall commit WAL that lacks receipt and manifest mutation authority', async () => {
    const item = await fixture();
    const manifest = activeManifest('install-uninstall-commit');
    await writeFile(item.manifestPath, serializeSetupManifestV1(manifest), { mode: 0o600 });

    expect(() =>
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'uninstall-recovery-commit',
        installId: manifest.installId,
        operation: 'uninstall',
        direction: 'commit',
        phase: 'commit-decided',
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
        manifest,
        cursor: 0,
        preimages: [],
        mutations: [],
      }),
    ).toThrow('uninstall WAL v2 terminal receipt mutation lacks exact authority');

    await expect(readFile(item.manifestPath, 'utf8')).resolves.toBe(
      serializeSetupManifestV1(manifest),
    );
    await expect(readFile(item.receiptPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('classifies a legacy v1 WAL without filesystem mutation', async () => {
    const item = await fixture();
    const legacy = serializeWalRecordV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'legacy-recovery',
      installId: 'legacy-install',
      operation: 'setup',
      phase: 'prepared',
      manifestFingerprint: `sha256:${'a'.repeat(64)}`,
    });
    await writeFile(item.walPath, legacy, { mode: 0o600 });

    const [first, second] = await recoverFailClosedPreservingFilesystem({
      ...item,
      root: item.root,
    });
    expect([first, second]).toEqual([
      { state: 'recovery-required', failures: [{ stage: 'legacy-v1-recovery-required' }] },
      { state: 'recovery-required', failures: [{ stage: 'legacy-v1-recovery-required' }] },
    ]);
    expect(await readFile(item.walPath, 'utf8')).toBe(legacy);
  });

  it('rejects foreign lock/path authority before any cleanup write', async () => {
    const item = await fixture();
    const foreignLock = join(item.root, 'foreign.lock');
    await writeFile(foreignLock, 'lock\n', { mode: 0o600 });
    const wal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'foreign-authority',
      installId: 'foreign-install',
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: foreignLock,
      manifestPath: item.manifestPath,
      cursor: 0,
      preimages: [],
      mutations: [],
    });
    await writeFile(item.walPath, wal, { mode: 0o600 });

    const [first, second] = await recoverFailClosedPreservingFilesystem({
      ...item,
      root: item.root,
    });
    expect([first, second]).toEqual([
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
    ]);
    expect(await readFile(item.walPath, 'utf8')).toBe(wal);
  });

  it('rejects fingerprint tampering before mutation and leaves the canonical WAL intact', async () => {
    const item = await fixture();
    const wal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'tampered-authority',
      installId: 'tampered-install',
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      cursor: 0,
      preimages: [],
      mutations: [],
    });
    const tampered = wal.replace(/sha256:[a-f0-9]{64}/, `sha256:${'b'.repeat(64)}`);
    await writeFile(item.walPath, tampered, { mode: 0o600 });

    const [first, second] = await recoverFailClosedPreservingFilesystem({
      ...item,
      root: item.root,
    });
    expect([first, second]).toEqual([
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
    ]);
    expect(await readFile(item.walPath, 'utf8')).toBe(tampered);
  });
  it('fails closed on malformed, noncanonical, and non-file canonical WAL authority without mutation', async () => {
    const canonical = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'hostile-wal-authority',
      installId: 'hostile-wal-install',
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: '/untrusted/lock-path',
      manifestPath: '/untrusted/manifest-path',
      cursor: 0,
      preimages: [],
      mutations: [],
    });
    const cases = [
      {
        name: 'malformed-json',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          await writeFile(item.walPath, '{"schemaVersion":', { mode: 0o600 });
        },
      },
      {
        name: 'truncated-json',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          await writeFile(item.walPath, canonical.slice(0, -1), { mode: 0o600 });
        },
      },
      {
        name: 'noncanonical-json',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          await writeFile(item.walPath, `${canonical}\n`, { mode: 0o600 });
        },
      },
      {
        name: 'wrong-mode',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          await writeFile(item.walPath, canonical, { mode: 0o640 });
          await chmod(item.walPath, 0o640);
        },
      },
      {
        name: 'directory-canonical-wal',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          await mkdir(item.walPath, { mode: 0o700 });
          await chmod(item.walPath, 0o700);
        },
      },
      {
        name: 'symlink-canonical-wal',
        install: async (item: Awaited<ReturnType<typeof fixture>>) => {
          const foreignWalPath = join(item.root, 'foreign-lifecycle.wal.v1.json');
          await writeFile(foreignWalPath, canonical, { mode: 0o600 });
          await symlink(foreignWalPath, item.walPath);
        },
      },
    ] as const;

    for (const scenario of cases) {
      const item = await fixture();
      await scenario.install(item);
      const [first, second] = await recoverFailClosedPreservingFilesystem({
        ...item,
        root: item.root,
      });
      expect({ name: scenario.name, recoveries: [first, second] }).toEqual({
        name: scenario.name,
        recoveries: [
          { state: 'recovery-required', failures: [{ stage: 'recovery' }] },
          { state: 'recovery-required', failures: [{ stage: 'recovery' }] },
        ],
      });
    }
  });
  it('fresh-process rollback removes only the exact staged directory from a prepared WAL', async () => {
    const item = await fixture();
    const targetPath = join(item.root, 'setup');
    const stagingPath = join(item.root, '.setup.stage');
    await mkdir(stagingPath, { mode: 0o700 });
    await chmod(stagingPath, 0o700);
    const staged = await identity(stagingPath);
    await writeFile(
      item.walPath,
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'directory-prepared-recovery',
        installId: 'directory-prepared-install',
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        cursor: 0,
        preimages: [{ path: targetPath, kind: 'absent' }],
        mutations: [
          {
            step: 0,
            kind: 'ordinary',
            targetPath,
            sourcePath: join(item.root, '.setup.rollback'),
            stagingPath,
            preimage: 0,
            result: { kind: 'directory', identity: staged.identity, mode: staged.mode },
          },
        ],
      }),
      { mode: 0o600 },
    );

    expect(await runRecoveryChild(item)).toEqual({ state: 'never-installed' });
    await expect(lstat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('converges exact absent-result preimages retained at staging paths in commit and rollback recovery', async () => {
    const observations: Array<{
      readonly direction: 'commit' | 'rollback';
      readonly result: Awaited<ReturnType<typeof runRecoveryChildDetailed>>;
      readonly target: RecoveryPathSnapshot;
      readonly manifest: RecoveryPathSnapshot;
      readonly stagedPreimage: IdentityWithMode;
      readonly stagedManifest: IdentityWithMode;
      readonly preimageContents: string;
      readonly manifestContents: string;
    }> = [];
    for (const direction of ['commit', 'rollback'] as const) {
      const item = await fixture();
      const operationId = `staged-preimage-${direction}`;
      const installId = `staged-preimage-${direction}-install`;
      const targetPath = join(item.root, `${direction}-owned.txt`);
      const stagingPath = join(item.root, `.${direction}-owned.stage`);
      const sourcePath = join(item.root, `.${direction}-owned.source`);
      const manifestAuthorityPath = `${item.manifestPath}.scene-glass-${operationId}.manifest-authority`;
      const manifestStagingPath = join(item.root, `.${direction}-manifest.stage`);
      const manifestSourcePath = join(item.root, `.${direction}-manifest.source`);
      const preimageBytes = Buffer.from(`${direction} retained preimage\n`, 'utf8');
      const manifestJson = serializeSetupManifestV1(activeManifest(installId));
      await Promise.all([
        writeFile(stagingPath, preimageBytes, { mode: 0o600 }),
        writeFile(manifestStagingPath, manifestJson, { mode: 0o600 }),
      ]);
      const [stagedPreimage, stagedManifest] = await Promise.all([
        identity(stagingPath),
        identity(manifestStagingPath),
      ]);
      await writeFile(
        item.walPath,
        bindWal({
          schemaVersion: 2,
          kind: 'scene-glass-lifecycle-wal',
          operationId,
          installId,
          operation: 'setup',
          direction,
          phase: direction === 'commit' ? 'commit-decided' : 'prepared',
          lockPath: item.lockPath,
          manifestPath: item.manifestPath,
          cursor: 2,
          preimages: [
            {
              path: targetPath,
              kind: 'file',
              identity: stagedPreimage.identity,
              mode: stagedPreimage.mode,
              bytes: preimageBytes.toString('base64'),
            },
            { path: manifestAuthorityPath, kind: 'absent' },
          ],
          mutations: [
            {
              step: 0,
              kind: 'ordinary',
              targetPath,
              sourcePath,
              stagingPath,
              preimage: 0,
              result: { kind: 'absent' },
            },
            {
              step: 1,
              kind: 'ordinary',
              targetPath: manifestAuthorityPath,
              sourcePath: manifestSourcePath,
              stagingPath: manifestStagingPath,
              preimage: 1,
              result: {
                kind: 'file',
                identity: stagedManifest.identity,
                mode: stagedManifest.mode,
                bytes: Buffer.from(manifestJson, 'utf8').toString('base64'),
              },
            },
          ],
        }),
        { mode: 0o600 },
      );

      const result = await runRecoveryChildDetailed(item);
      observations.push({
        direction,
        result,
        target: await snapshotRecoveryPath(targetPath),
        manifest: await snapshotRecoveryPath(item.manifestPath),
        stagedPreimage,
        stagedManifest,
        preimageContents: preimageBytes.toString('utf8'),
        manifestContents: manifestJson,
      });
      await expect(lstat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(lstat(sourcePath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(lstat(manifestAuthorityPath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(lstat(manifestStagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(lstat(manifestSourcePath)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    }
    const commit = observations.find(({ direction }) => direction === 'commit');
    const rollback = observations.find(({ direction }) => direction === 'rollback');
    if (commit === undefined || rollback === undefined) {
      throw new Error('recovery direction observation missing');
    }
    expect(commit.result).toEqual({ state: 'active', failures: [] });
    expect(commit.target).toEqual({ state: 'absent', code: 'ENOENT' });
    expect(commit.manifest).toEqual({
      state: 'present',
      kind: 'file',
      identity: commit.stagedManifest.identity,
      mode: commit.stagedManifest.mode,
      contents: commit.manifestContents,
    });
    expect(rollback.result).toEqual({ state: 'never-installed', failures: [] });
    expect(rollback.target).toEqual({
      state: 'present',
      kind: 'file',
      identity: rollback.stagedPreimage.identity,
      mode: rollback.stagedPreimage.mode,
      contents: rollback.preimageContents,
    });
    expect(rollback.manifest).toEqual({ state: 'absent', code: 'ENOENT' });
  });
  it('reconciles a retained created-directory removal quarantine before completing uninstall recovery', async () => {
    const item = await fixture();
    const operationId = 'directory-removal-quarantine';
    const installId = 'directory-removal-quarantine-install';
    const directoryPath = join(item.root, 'owned-directory');
    const stagingPath = join(item.root, '.owned-directory.stage');
    const authority = await openSetupTransactionAuthority({
      operationId: 'setup-directory-removal-quarantine',
      installId,
      port: createNodeLifecycleTransactionPort(),
      lockPath: item.lockPath,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      preimages: [{ path: directoryPath, state: 'absent' }],
      directories: [{ path: directoryPath, stagingPath, mode: 0o700 }],
    });
    const setup = await applySetupTransaction({
      authority,
      operationId: 'setup-directory-removal-quarantine',
      installId,
      directories: [{ path: directoryPath, stagingPath, mode: 0o700 }],
      finalization: {
        manifest: activeManifest(installId),
        operations: [],
        preimages: [],
      },
    });
    if (!('manifest' in setup)) {
      throw new Error('directory setup unexpectedly compensated');
    }
    await expect(publishSetupTransaction(setup)).resolves.toEqual({
      state: 'active',
      failures: [],
    });
    const installedManifest = setup.manifest;
    const directory = await identity(directoryPath);
    const preflight = validateUninstallPreflight({ manifest: installedManifest, observed: [] });
    const quarantinePath = `${directoryPath}.scene-glass-${operationId}.directory-quarantine`;
    const reconciliationPath = `${quarantinePath}.reconcile`;
    const port = createNodeLifecycleTransactionPort();
    const quarantineExactDirectory = port.quarantineExactDirectory.bind(port);
    const finalizeQuarantine = port.finalizeQuarantine.bind(port);
    let retainedDirectoryQuarantine = false;
    port.quarantineExactDirectory = async (
      input: Parameters<LifecycleTransactionPort['quarantineExactDirectory']>[0],
    ) => {
      const quarantined = await quarantineExactDirectory(input);
      if (input.path === directoryPath && input.quarantinePath === quarantinePath) {
        retainedDirectoryQuarantine = quarantined.state === 'completed';
      }
      return quarantined;
    };
    port.finalizeQuarantine = async (input) =>
      retainedDirectoryQuarantine
        ? Object.freeze({ state: 'indeterminate' as const })
        : finalizeQuarantine(input);

    const interrupted = await applyUninstallTransaction({
      manifest: installedManifest,
      operationId,
      preflight,
      walPath: item.walPath,
      manifestPath: item.manifestPath,
      receiptPath: item.receiptPath,
      lockPath: item.lockPath,
      port,
    });

    expect(interrupted.state).toBe('recovery-required');
    expect(retainedDirectoryQuarantine).toBe(true);
    await expect(lstat(directoryPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await identity(quarantinePath)).toEqual(directory);
    await expect(lstat(reconciliationPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'))).toMatchObject({
      operation: 'uninstall',
      direction: 'commit',
      phase: 'commit-decided',
    });

    await expect(runRecoveryChildDetailed(item)).resolves.toEqual({
      state: 'uninstalled',
      failures: [],
    });
    await expect(lstat(directoryPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(quarantinePath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(reconciliationPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.manifestPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(parseLifecycleReceiptJsonV1(await readFile(item.receiptPath, 'utf8'))).toMatchObject({
      operationId,
      installId,
      terminalState: 'uninstalled',
    });
  });
  it('reports a post-effect native WAL cleanup indeterminacy and converges only in a fresh recovery', async () => {
    const item = await fixture();
    const terminalTree = await snapshotRecoveryFilesystemTree(item.root);
    const terminalLock = await snapshotRecoveryPath(item.lockPath);
    const targetPath = join(item.root, 'indeterminate-target');
    const stagingPath = join(item.root, '.indeterminate-target.stage');
    await mkdir(stagingPath, { mode: 0o700 });
    await chmod(stagingPath, 0o700);
    const staged = await identity(stagingPath);
    await writeFile(
      item.walPath,
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'indeterminate-wal-cleanup',
        installId: 'indeterminate-wal-install',
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        cursor: 0,
        preimages: [{ path: targetPath, kind: 'absent' }],
        mutations: [
          {
            step: 0,
            kind: 'ordinary',
            targetPath,
            sourcePath: join(item.root, '.indeterminate-target.rollback'),
            stagingPath,
            preimage: 0,
            result: { kind: 'directory', identity: staged.identity, mode: staged.mode },
          },
        ],
      }),
      { mode: 0o600 },
    );
    const port = createNodeLifecycleTransactionPort();
    const finalizeQuarantine = port.finalizeQuarantine.bind(port);
    let finalizedQuarantines = 0;
    port.finalizeQuarantine = async (input) => {
      const completed = await finalizeQuarantine(input);
      if (completed.state !== 'completed') {
        throw new Error('native quarantine did not finalize before indeterminacy injection');
      }
      finalizedQuarantines += 1;
      if (finalizedQuarantines === 1) {
        return completed;
      }
      if (finalizedQuarantines === 2) {
        return Object.freeze({ state: 'indeterminate' as const });
      }
      throw new Error('recovery finalized an unexpected additional quarantine');
    };

    await expect(
      recoverLifecycle({
        port,
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
      }),
    ).resolves.toEqual({
      state: 'never-installed',
      failures: [],
    });
    expect(finalizedQuarantines).toBe(1);
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(terminalTree);
    expect(await snapshotRecoveryPath(item.lockPath)).toEqual(terminalLock);

    expect(await runRecoveryChild(item)).toEqual({ state: 'never-installed' });
    expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(terminalTree);
    expect(await snapshotRecoveryPath(item.lockPath)).toEqual(terminalLock);
  });
  it('recovers prepared-before-stage and durable exact credential-stage WAL boundaries without regeneration', async () => {
    const boundaries = ['prepared-before-stage', 'credential-staged-before-publication'] as const;
    const observations: Array<{
      readonly boundary: (typeof boundaries)[number];
      readonly wal: ReturnType<typeof parseWalRecordJsonV2>;
      readonly credentialBefore: RecoveryPathSnapshot;
      readonly stageBefore: RecoveryPathSnapshot;
      readonly recovery: RecoveryChildResult;
      readonly credentialAfter: RecoveryPathSnapshot;
      readonly stageAfter: RecoveryPathSnapshot;
      readonly registryAfter: RecoveryPathSnapshot;
      readonly manifestAfter: RecoveryPathSnapshot;
      readonly walAfter: RecoveryPathSnapshot;
    }> = [];

    for (const boundary of boundaries) {
      const item = await fixture();
      const operationId = `prepublication-${boundary}-operation`;
      const credentialPath = join(item.root, `${boundary}-credential`);
      const credentialStagingPath = join(item.root, `.${boundary}-credential.stage`);
      const registryPath = join(item.root, `${boundary}-registry.v1.json`);
      const token = `prepublication-${boundary}-token-never-in-authority`;
      const credentialContent = credentialEnvelope('producer-credential-project', token);
      const canaries = credentialCanaries(token, credentialContent);
      await runProducerAndKill({
        ...item,
        root: item.root,
        boundary,
        operationId,
        installId: `prepublication-${boundary}-install`,
        credentialPath,
        credentialStagingPath,
        registryPath,
        credentialContent,
      });

      const walText = await readFile(item.walPath, 'utf8');
      const wal = parseWalRecordJsonV2(walText);
      const beforeAuthority = await snapshotRecoveryAuthorityTree({
        ...item,
        registryPath,
        credentialPath,
        credentialStagingPath,
      });
      const credentialBefore = beforeAuthority.credential;
      const stageBefore = beforeAuthority.credentialStaging;
      expect(
        await durableNonCredentialAuthorityLeaks(
          [item.lockPath, item.walPath, item.manifestPath, registryPath],
          canaries,
        ),
      ).toEqual([]);

      const boundaryAuthority =
        boundary === 'prepared-before-stage'
          ? {
              observed: {
                operation: wal.operation,
                direction: wal.direction,
                phase: wal.phase,
                cursor: wal.cursor,
                preimages: wal.preimages.map(({ path, kind }) => ({ path, kind })),
                mutations: wal.mutations,
                credentialBefore,
                stageBefore,
              },
              expected: {
                operation: 'setup',
                direction: 'rollback',
                phase: 'prepared',
                cursor: 0,
                preimages: [
                  { path: credentialPath, kind: 'absent' },
                  { path: credentialStagingPath, kind: 'absent' },
                ],
                mutations: [],
                credentialBefore: { state: 'absent', code: 'ENOENT' },
                stageBefore: { state: 'absent', code: 'ENOENT' },
              },
            }
          : await (async () => {
              if (stageBefore.state !== 'present' || stageBefore.kind !== 'file') {
                throw new Error(
                  'durable credential-stage boundary did not retain its exact file stage',
                );
              }
              return {
                observed: {
                  operation: wal.operation,
                  direction: wal.direction,
                  phase: wal.phase,
                  cursor: wal.cursor,
                  preimages: wal.preimages.map(({ path, kind }) => ({ path, kind })),
                  mutations: wal.mutations,
                  credentialBefore,
                  stageBefore,
                },
                expected: {
                  operation: 'setup',
                  direction: 'rollback',
                  phase: 'prepared',
                  cursor: 0,
                  preimages: [{ path: credentialPath, kind: 'absent' }],
                  mutations: [
                    {
                      step: 0,
                      kind: 'credential',
                      projectId: 'producer-credential-project',
                      path: credentialPath,
                      mode: 0o600,
                      stagingPath: credentialStagingPath,
                      stagingIdentity: stageBefore.identity,
                      targetIdentity: stageBefore.identity,
                    },
                  ],
                  credentialBefore: { state: 'absent', code: 'ENOENT' },
                  stageBefore: {
                    state: 'present',
                    kind: 'file',
                    identity: stageBefore.identity,
                    mode: 0o600,
                    contents: credentialContent,
                  },
                },
              };
            })();
      expect(boundaryAuthority.observed).toEqual(boundaryAuthority.expected);

      const recovery = await runRecoveryChild(item);
      const afterAuthority = await snapshotRecoveryAuthorityTree({
        ...item,
        registryPath,
        credentialPath,
        credentialStagingPath,
        authorityPaths: beforeAuthority.walAuthorities.map(({ path }) => path),
      });
      expectRecoveryAuthorityTreeDelta(
        beforeAuthority,
        afterAuthority,
        new Map([
          [item.walPath, absentRecoveryPath()],
          [item.manifestPath, absentRecoveryPath()],
          [registryPath, absentRecoveryPath()],
          [credentialPath, absentRecoveryPath()],
          [credentialStagingPath, absentRecoveryPath()],
        ]),
      );
      const credentialAfter = afterAuthority.credential;
      const stageAfter = afterAuthority.credentialStaging;
      const registryAfter = afterAuthority.registry;
      const manifestAfter = afterAuthority.manifest;
      const walAfter = afterAuthority.wal;
      expect(
        await durableNonCredentialAuthorityLeaks(
          [item.lockPath, item.walPath, item.manifestPath, registryPath],
          canaries,
        ),
      ).toEqual([]);
      observations.push({
        boundary,
        wal,
        credentialBefore,
        stageBefore,
        recovery,
        credentialAfter,
        stageAfter,
        registryAfter,
        manifestAfter,
        walAfter,
      });
    }

    expect(
      observations.map(
        ({
          boundary,
          recovery,
          credentialAfter,
          stageAfter,
          registryAfter,
          manifestAfter,
          walAfter,
        }) => ({
          boundary,
          recovery,
          credentialAfter,
          stageAfter,
          registryAfter,
          manifestAfter,
          walAfter,
        }),
      ),
    ).toEqual(
      boundaries.map((boundary) => ({
        boundary,
        recovery: { state: 'never-installed' },
        credentialAfter: { state: 'absent', code: 'ENOENT' },
        stageAfter: { state: 'absent', code: 'ENOENT' },
        registryAfter: { state: 'absent', code: 'ENOENT' },
        manifestAfter: { state: 'absent', code: 'ENOENT' },
        walAfter: { state: 'absent', code: 'ENOENT' },
      })),
    );
  });

  it('preserves unknown, replacement, wrong-kind, and mode-mismatched prepublication stages with byte-identical WALs', async () => {
    const scenarios = [
      { name: 'unknown-stage' as const, boundary: 'prepared-before-stage' as const },
      {
        name: 'replacement-stage' as const,
        boundary: 'credential-staged-before-publication' as const,
      },
      {
        name: 'wrong-kind-stage' as const,
        boundary: 'credential-staged-before-publication' as const,
      },
      {
        name: 'mode-mismatch-stage' as const,
        boundary: 'credential-staged-before-publication' as const,
      },
    ];
    const observations: Array<{
      readonly scenario: (typeof scenarios)[number]['name'];
      readonly result: RecoveryChildDetailedResult;
      readonly walBefore: string;
      readonly walAfter: string;
      readonly expectedStageIdentity: IdentityWithMode | undefined;
      readonly stageBefore: RecoveryPathSnapshot;
      readonly stageAfter: RecoveryPathSnapshot;
      readonly credentialAfter: RecoveryPathSnapshot;
      readonly registryAfter: RecoveryPathSnapshot;
      readonly manifestAfter: RecoveryPathSnapshot;
    }> = [];

    for (const scenario of scenarios) {
      const item = await fixture();
      const operationId = `${scenario.name}-operation`;
      const credentialPath = join(item.root, `${scenario.name}-credential`);
      const credentialStagingPath = join(item.root, `.${scenario.name}-credential.stage`);
      const registryPath = join(item.root, `${scenario.name}-registry.v1.json`);
      const token = `${scenario.name}-token-never-in-authority`;
      const credentialContent = credentialEnvelope('producer-credential-project', token);
      const canaries = credentialCanaries(token, credentialContent);
      await runProducerAndKill({
        ...item,
        root: item.root,
        boundary: scenario.boundary,
        operationId,
        installId: `${scenario.name}-install`,
        credentialPath,
        credentialStagingPath,
        registryPath,
        credentialContent,
      });

      const walBefore = await readFile(item.walPath, 'utf8');
      const wal = parseWalRecordJsonV2(walBefore);
      const credentialMutation = wal.mutations.find(
        (mutation) => mutation.kind === 'credential' && mutation.path === credentialPath,
      );
      const scenarioAuthority =
        scenario.name === 'unknown-stage'
          ? {
              credentialMutation: undefined,
              expectedStageIdentity: undefined,
              observed: {
                direction: wal.direction,
                phase: wal.phase,
                cursor: wal.cursor,
                preimages: wal.preimages.map(({ path, kind }) => ({ path, kind })),
                mutations: wal.mutations,
              },
              expected: {
                direction: 'rollback',
                phase: 'prepared',
                cursor: 0,
                preimages: [
                  { path: credentialPath, kind: 'absent' },
                  { path: credentialStagingPath, kind: 'absent' },
                ],
                mutations: [],
              },
            }
          : await (async () => {
              if (credentialMutation === undefined || credentialMutation.kind !== 'credential') {
                throw new Error('exact credential stage did not have a credential WAL authority');
              }
              const expectedStageIdentity = {
                identity: credentialMutation.stagingIdentity,
                mode: credentialMutation.mode,
              };
              const journaledStage = await snapshotRecoveryPath(credentialStagingPath);
              if (journaledStage.state !== 'present' || journaledStage.kind !== 'file') {
                throw new Error(
                  'credential WAL authority did not retain an inspectable exact stage',
                );
              }
              return {
                credentialMutation,
                expectedStageIdentity,
                observed: {
                  operation: wal.operation,
                  direction: wal.direction,
                  phase: wal.phase,
                  cursor: wal.cursor,
                  preimages: wal.preimages.map(({ path, kind }) => ({ path, kind })),
                  mutations: wal.mutations,
                  journaledStage: {
                    kind: journaledStage.kind,
                    identity: journaledStage.identity,
                    mode: journaledStage.mode,
                    contents: journaledStage.contents,
                  },
                },
                expected: {
                  operation: 'setup',
                  direction: 'rollback',
                  phase: 'prepared',
                  cursor: 0,
                  preimages: [{ path: credentialPath, kind: 'absent' }],
                  mutations: [
                    {
                      step: 0,
                      kind: 'credential',
                      projectId: 'producer-credential-project',
                      path: credentialPath,
                      mode: 0o600,
                      stagingPath: credentialStagingPath,
                      stagingIdentity: journaledStage.identity,
                      targetIdentity: journaledStage.identity,
                    },
                  ],
                  journaledStage: {
                    kind: 'file',
                    identity: journaledStage.identity,
                    mode: 0o600,
                    contents: credentialContent,
                  },
                },
              };
            })();
      expect(scenarioAuthority.observed).toEqual(scenarioAuthority.expected);
      if (scenarioAuthority.credentialMutation === undefined) {
        await writeFile(credentialStagingPath, 'unknown-stage', { mode: 0o600 });
        await chmod(credentialStagingPath, 0o600);
      } else {
        const credentialMutation = scenarioAuthority.credentialMutation;
        if (scenario.name === 'replacement-stage') {
          const replacement = `${credentialStagingPath}.replacement`;
          await writeFile(replacement, 'replacement-stage', { mode: credentialMutation.mode });
          await chmod(replacement, credentialMutation.mode);
          await rename(replacement, credentialStagingPath);
        } else if (scenario.name === 'wrong-kind-stage') {
          await rm(credentialStagingPath, { force: true });
          await mkdir(credentialStagingPath, { mode: 0o700 });
          await chmod(credentialStagingPath, credentialMutation.mode);
        } else {
          await chmod(credentialStagingPath, 0o640);
        }
      }

      const stageBefore = await snapshotRecoveryPath(credentialStagingPath);
      const credentialBefore = await snapshotRecoveryPath(credentialPath);
      expect(credentialBefore).toEqual({ state: 'absent', code: 'ENOENT' });
      expect(
        await durableNonCredentialAuthorityLeaks(
          [item.lockPath, item.walPath, item.manifestPath, registryPath],
          canaries,
        ),
      ).toEqual([]);
      const [result, repeatedResult] = await recoverFailClosedPreservingFilesystem({
        ...item,
        root: item.root,
      });
      expect(repeatedResult).toEqual(result);
      const walAfter = await readFile(item.walPath, 'utf8');
      const stageAfter = await snapshotRecoveryPath(credentialStagingPath);
      const credentialAfter = await snapshotRecoveryPath(credentialPath);
      const registryAfter = await snapshotRecoveryPath(registryPath);
      const manifestAfter = await snapshotRecoveryPath(item.manifestPath);
      expect(
        await durableNonCredentialAuthorityLeaks(
          [item.lockPath, item.walPath, item.manifestPath, registryPath],
          canaries,
        ),
      ).toEqual([]);
      observations.push({
        scenario: scenario.name,
        result,
        walBefore,
        walAfter,
        expectedStageIdentity: scenarioAuthority.expectedStageIdentity,
        stageBefore,
        stageAfter,
        credentialAfter,
        registryAfter,
        manifestAfter,
      });
    }

    expect(observations.map(({ scenario, result }) => ({ scenario, result }))).toEqual(
      scenarios.map(({ name }) => ({
        scenario: name,
        result: {
          state: 'recovery-required',
          failures: [{ stage: name === 'unknown-stage' ? 'indeterminate' : 'third-state' }],
        },
      })),
    );
    expect(observations.map(({ walAfter }) => walAfter)).toEqual(
      observations.map(({ walBefore }) => walBefore),
    );
    expect(observations.map(({ stageAfter }) => stageAfter)).toEqual(
      observations.map(({ stageBefore }) => stageBefore),
    );
    expect(
      observations.map(({ scenario, expectedStageIdentity, stageBefore }) => {
        if (scenario === 'unknown-stage') {
          return {
            scenario,
            kind: stageBefore.state === 'present' ? stageBefore.kind : undefined,
            hasJournaledAuthority: false,
            matchesJournaledIdentity: undefined,
            matchesJournaledMode: undefined,
          };
        }
        if (stageBefore.state !== 'present' || expectedStageIdentity === undefined) {
          throw new Error('mismatched credential stage was not preserved for inspection');
        }
        return {
          scenario,
          kind: stageBefore.kind,
          hasJournaledAuthority: true,
          matchesJournaledIdentity:
            stageBefore.identity.device === expectedStageIdentity.identity.device &&
            stageBefore.identity.inode === expectedStageIdentity.identity.inode,
          matchesJournaledMode: stageBefore.mode === expectedStageIdentity.mode,
        };
      }),
    ).toEqual([
      {
        scenario: 'unknown-stage',
        kind: 'file',
        hasJournaledAuthority: false,
        matchesJournaledIdentity: undefined,
        matchesJournaledMode: undefined,
      },
      {
        scenario: 'replacement-stage',
        kind: 'file',
        hasJournaledAuthority: true,
        matchesJournaledIdentity: false,
        matchesJournaledMode: true,
      },
      {
        scenario: 'wrong-kind-stage',
        kind: 'directory',
        hasJournaledAuthority: true,
        matchesJournaledIdentity: false,
        matchesJournaledMode: true,
      },
      {
        scenario: 'mode-mismatch-stage',
        kind: 'file',
        hasJournaledAuthority: true,
        matchesJournaledIdentity: true,
        matchesJournaledMode: false,
      },
    ]);
    expect(
      observations.map(({ credentialAfter, registryAfter, manifestAfter }) => ({
        credentialAfter,
        registryAfter,
        manifestAfter,
      })),
    ).toEqual(
      scenarios.map(() => ({
        credentialAfter: { state: 'absent', code: 'ENOENT' },
        registryAfter: { state: 'absent', code: 'ENOENT' },
        manifestAfter: { state: 'absent', code: 'ENOENT' },
      })),
    );
  });

  it('recovers setup directory and credential commit authority in a bounded fresh process', async () => {
    const item = await fixture();
    const prepared = await prepareSetupCommitRecoveryFixture(
      item,
      'directory-commit-recovery',
      'directory-commit-install',
    );
    const canaries = credentialCanaries(prepared.credentialToken, prepared.credentialContent);
    const registryPath = join(item.root, 'credential-authorities.v1.json');
    const parsedWal = parseWalRecordJsonV2(prepared.wal);
    const credentialMutation = parsedWal.mutations.find(
      (mutation) => mutation.kind === 'credential' && mutation.path === prepared.credentialPath,
    );
    if (credentialMutation === undefined || credentialMutation.kind !== 'credential') {
      throw new Error('commit WAL credential authority is absent');
    }
    expect({
      operation: parsedWal.operation,
      direction: parsedWal.direction,
      phase: parsedWal.phase,
      cursor: parsedWal.cursor,
      credentialMutation,
    }).toEqual({
      operation: 'setup',
      direction: 'commit',
      phase: 'commit-decided',
      cursor: 3,
      credentialMutation: {
        step: 1,
        kind: 'credential',
        projectId: 'project-recovery',
        path: prepared.credentialPath,
        mode: prepared.credential.mode,
        stagingPath: prepared.credentialStagingPath,
        stagingIdentity: prepared.credential.identity,
        targetIdentity: prepared.credential.identity,
      },
    });
    expect(
      await durableNonCredentialAuthorityLeaks(
        [
          item.lockPath,
          item.walPath,
          item.manifestPath,
          ...parsedWal.mutations.flatMap((mutation) =>
            mutation.kind === 'ordinary'
              ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
              : [],
          ),
        ],
        canaries,
      ),
    ).toEqual([]);

    const beforeAuthority = await snapshotRecoveryAuthorityTree({
      ...item,
      registryPath,
      credentialPath: prepared.credentialPath,
      credentialStagingPath: prepared.credentialStagingPath,
    });
    const manifestStageBefore = recoveryAuthoritySnapshot(beforeAuthority, prepared.manifestStage);
    if (
      manifestStageBefore.state !== 'present' ||
      manifestStageBefore.kind !== 'file' ||
      manifestStageBefore.contents !== prepared.manifestJson
    ) {
      throw new Error('commit recovery fixture did not preserve its staged manifest authority');
    }
    expect(await runRecoveryChild(item)).toEqual({ state: 'active' });
    const afterAuthority = await snapshotRecoveryAuthorityTree({
      ...item,
      registryPath,
      credentialPath: prepared.credentialPath,
      credentialStagingPath: prepared.credentialStagingPath,
      authorityPaths: beforeAuthority.walAuthorities.map(({ path }) => path),
    });
    expectRecoveryAuthorityTreeDelta(
      beforeAuthority,
      afterAuthority,
      new Map([
        [item.walPath, absentRecoveryPath()],
        [item.manifestPath, manifestStageBefore],
        [prepared.manifestStage, absentRecoveryPath()],
      ]),
    );
    expect(await identity(prepared.targetPath)).toEqual(prepared.directory);
    expect(await identity(prepared.credentialPath)).toEqual(prepared.credential);
    expect(await readFile(prepared.credentialPath, 'utf8')).toBe(prepared.credentialContent);
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.manifestPath, 'utf8')).resolves.toBe(prepared.manifestJson);
    expect(
      await durableNonCredentialAuthorityLeaks(
        [
          item.lockPath,
          item.walPath,
          item.manifestPath,
          ...parsedWal.mutations.flatMap((mutation) =>
            mutation.kind === 'ordinary'
              ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
              : [],
          ),
        ],
        canaries,
      ),
    ).toEqual([]);
  });
  it('refuses each independent setup directory and credential authority mismatch in a bounded fresh process', async () => {
    const cases = [
      { authority: 'directory' as const, replacement: 'same-mode-new-inode' as const },
      { authority: 'directory' as const, replacement: 'same-inode-new-mode' as const },
      { authority: 'credential' as const, replacement: 'same-mode-new-inode' as const },
      { authority: 'credential' as const, replacement: 'same-inode-new-mode' as const },
    ];

    const observations: Array<{
      readonly scenario: (typeof cases)[number];
      readonly original: IdentityWithMode;
      readonly replaced: IdentityWithMode;
      readonly before: Record<string, RecoveryPathSnapshot>;
      readonly result: RecoveryChildDetailedResult;
      readonly after: Record<string, RecoveryPathSnapshot>;
      readonly walBefore: string;
      readonly walAfter: string;
    }> = [];
    for (const scenario of cases) {
      const item = await fixture();
      const prepared = await prepareSetupCommitRecoveryFixture(
        item,
        `${scenario.authority}-${scenario.replacement}-commit-recovery`,
        `${scenario.authority}-${scenario.replacement}-commit-install`,
      );
      const canaries = credentialCanaries(prepared.credentialToken, prepared.credentialContent);
      const preparedWal = parseWalRecordJsonV2(prepared.wal);
      const durableNonCredentialPaths = [
        item.lockPath,
        item.walPath,
        item.manifestPath,
        ...preparedWal.mutations.flatMap((mutation) =>
          mutation.kind === 'ordinary'
            ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
            : [],
        ),
      ];
      const original =
        scenario.authority === 'directory' ? prepared.directory : prepared.credential;
      const path =
        scenario.authority === 'directory' ? prepared.targetPath : prepared.credentialPath;

      if (scenario.authority === 'directory') {
        if (scenario.replacement === 'same-mode-new-inode') {
          await rm(path, { force: true, recursive: true });
          await mkdir(path, { mode: original.mode });
          await chmod(path, original.mode);
        } else {
          await chmod(path, original.mode === 0o700 ? 0o755 : 0o700);
        }
      } else if (scenario.replacement === 'same-mode-new-inode') {
        const replacementPath = `${path}.replacement`;
        await writeFile(replacementPath, prepared.credentialContent, { mode: original.mode });
        await chmod(replacementPath, original.mode);
        await rename(replacementPath, path);
      } else {
        await chmod(path, original.mode === 0o600 ? 0o640 : 0o600);
      }

      const replaced = await identity(path);
      const before = await snapshotRecoveryAuthorityState(item, prepared);
      const walBefore = before.wal;
      if (
        walBefore === undefined ||
        walBefore.state !== 'present' ||
        walBefore.kind !== 'file' ||
        walBefore.contents === undefined
      ) {
        throw new Error('expected a readable WAL file before recovery');
      }
      expect(await durableNonCredentialAuthorityLeaks(durableNonCredentialPaths, canaries)).toEqual(
        [],
      );
      const [result, repeatedResult] = await recoverFailClosedPreservingFilesystem({
        ...item,
        root: item.root,
      });
      expect(repeatedResult).toEqual(result);
      const after = await snapshotRecoveryAuthorityState(item, prepared);
      const walAfter = after.wal;
      if (
        walAfter === undefined ||
        walAfter.state !== 'present' ||
        walAfter.kind !== 'file' ||
        walAfter.contents === undefined
      ) {
        throw new Error('expected a readable WAL file after failed recovery');
      }
      expect(await durableNonCredentialAuthorityLeaks(durableNonCredentialPaths, canaries)).toEqual(
        [],
      );
      observations.push({
        scenario,
        original,
        replaced,
        before,
        result,
        after,
        walBefore: walBefore.contents,
        walAfter: walAfter.contents,
      });
    }

    expect(
      observations.map(({ scenario, original, replaced }) => ({
        scenario,
        sameIdentity:
          replaced.identity.device === original.identity.device &&
          replaced.identity.inode === original.identity.inode,
        sameMode: replaced.mode === original.mode,
      })),
    ).toEqual([
      { scenario: cases[0], sameIdentity: false, sameMode: true },
      { scenario: cases[1], sameIdentity: true, sameMode: false },
      { scenario: cases[2], sameIdentity: false, sameMode: true },
      { scenario: cases[3], sameIdentity: true, sameMode: false },
    ]);
    expect(observations.map(({ result }) => result)).toEqual(
      cases.map(() => ({
        state: 'recovery-required',
        failures: [{ stage: 'third-state' }],
      })),
    );
    expect(observations.map(({ walAfter }) => walAfter)).toEqual(
      observations.map(({ walBefore }) => walBefore),
    );
    expect(observations.map(({ after }) => after)).toEqual(
      observations.map(({ before }) => before),
    );
  });
  it('rejects manifest-stage and uninstall-private-source identity, mode, and content replacements in fresh processes', async () => {
    const mismatches = ['identity', 'mode', 'content'] as const;
    const observations: Array<{
      readonly surface: 'manifest-stage' | 'uninstall-private-source';
      readonly mismatch: ExactFileAuthorityMismatch;
      readonly original: RecoveryFileSnapshot;
      readonly replacement: RecoveryFileSnapshot;
      readonly result: RecoveryChildDetailedResult;
      readonly treeBefore: ReadonlyMap<string, RecoveryPathSnapshot>;
      readonly treeAfter: ReadonlyMap<string, RecoveryPathSnapshot>;
      readonly walBefore: string;
      readonly walAfter: string;
    }> = [];

    for (const surface of ['manifest-stage', 'uninstall-private-source'] as const) {
      for (const mismatch of mismatches) {
        const item = await fixture();
        let authorityPath: string;
        if (surface === 'manifest-stage') {
          const prepared = await prepareSetupCommitRecoveryFixture(
            item,
            `manifest-${mismatch}-commit-recovery`,
            `manifest-${mismatch}-commit-install`,
          );
          authorityPath = prepared.manifestStage;
        } else {
          const targetPath = join(item.root, 'uninstall-private-target');
          const operationId = `uninstall-private-${mismatch}-operation`;
          const sourcePath = `${targetPath}.scene-glass-${operationId}-0.rollback`;
          const receiptSourcePath = `${item.receiptPath}.scene-glass-${operationId}-1.rollback`;
          const receiptStagingPath = `${item.receiptPath}.scene-glass-${operationId}-1.stage`;
          const manifestSourcePath = `${item.manifestPath}.scene-glass-${operationId}-2.rollback`;
          const manifestStagingPath = `${item.manifestPath}.scene-glass-${operationId}-2.stage`;
          const manifest = activeManifest(`uninstall-private-${mismatch}-install`);
          const manifestJson = serializeSetupManifestV1(manifest);
          const sourceBytes = Buffer.from('uninstall-private-source-bytes\n', 'utf8');
          const receipt = serializeLifecycleReceiptV1({
            schemaVersion: 1,
            kind: 'scene-glass-lifecycle-receipt',
            operationId,
            installId: manifest.installId,
            terminalState: 'uninstalled',
            manifestFingerprint: `sha256:${createHash('sha256').update(manifestJson).digest('hex')}`,
          });
          await Promise.all([
            writeFile(sourcePath, sourceBytes, { mode: 0o600 }),
            writeFile(item.manifestPath, manifestJson, { mode: 0o600 }),
            writeFile(receiptStagingPath, receipt, { mode: 0o600 }),
          ]);
          const [sourceIdentity, manifestIdentity, receiptStagingIdentity] = await Promise.all([
            identity(sourcePath),
            identity(item.manifestPath),
            identity(receiptStagingPath),
          ]);
          await writeFile(
            item.walPath,
            bindWal({
              schemaVersion: 2,
              kind: 'scene-glass-lifecycle-wal',
              operationId,
              installId: manifest.installId,
              operation: 'uninstall',
              direction: 'commit',
              phase: 'commit-decided',
              lockPath: item.lockPath,
              manifestPath: item.manifestPath,
              receiptPath: item.receiptPath,
              manifest,
              cursor: 3,
              preimages: [
                {
                  path: item.manifestPath,
                  kind: 'file',
                  identity: manifestIdentity.identity,
                  mode: manifestIdentity.mode,
                  bytes: Buffer.from(manifestJson, 'utf8').toString('base64'),
                },
                {
                  path: targetPath,
                  kind: 'file',
                  identity: sourceIdentity.identity,
                  mode: sourceIdentity.mode,
                  bytes: sourceBytes.toString('base64'),
                },
                { path: item.receiptPath, kind: 'absent' },
              ],
              mutations: [
                {
                  step: 0,
                  kind: 'ordinary',
                  targetPath,
                  sourcePath,
                  stagingPath: `${targetPath}.scene-glass-${operationId}-0.stage`,
                  preimage: 1,
                  result: { kind: 'absent' },
                },
                {
                  step: 1,
                  kind: 'ordinary',
                  targetPath: item.receiptPath,
                  sourcePath: receiptSourcePath,
                  stagingPath: receiptStagingPath,
                  preimage: 2,
                  result: {
                    kind: 'file',
                    identity: receiptStagingIdentity.identity,
                    mode: receiptStagingIdentity.mode,
                    bytes: Buffer.from(receipt, 'utf8').toString('base64'),
                  },
                },
                {
                  step: 2,
                  kind: 'ordinary',
                  targetPath: item.manifestPath,
                  sourcePath: manifestSourcePath,
                  stagingPath: manifestStagingPath,
                  preimage: 0,
                  result: { kind: 'absent' },
                },
              ],
            }),
            { mode: 0o600 },
          );
          authorityPath = sourcePath;
        }

        const { original, replacement } = await tamperExactFileAuthority(
          authorityPath,
          mismatch,
          `${surface}-${mismatch}-corrupted-bytes\n`,
        );
        const treeBefore = await snapshotRecoveryFilesystemTree(item.root);
        const walBefore = await readFile(item.walPath, 'utf8');
        const [result, repeatedResult] = await recoverFailClosedPreservingFilesystem({
          ...item,
          root: item.root,
        });
        expect(repeatedResult).toEqual(result);
        const treeAfter = await snapshotRecoveryFilesystemTree(item.root);
        const walAfter = await readFile(item.walPath, 'utf8');
        observations.push({
          surface,
          mismatch,
          original,
          replacement,
          result,
          treeBefore,
          treeAfter,
          walBefore,
          walAfter,
        });
      }
    }

    expect(
      observations.map(({ surface, mismatch, original, replacement }) => ({
        surface,
        mismatch,
        sameIdentity:
          original.identity.device === replacement.identity.device &&
          original.identity.inode === replacement.identity.inode,
        sameMode: original.mode === replacement.mode,
        sameContents: original.contents === replacement.contents,
      })),
    ).toEqual([
      {
        surface: 'manifest-stage',
        mismatch: 'identity',
        sameIdentity: false,
        sameMode: true,
        sameContents: true,
      },
      {
        surface: 'manifest-stage',
        mismatch: 'mode',
        sameIdentity: true,
        sameMode: false,
        sameContents: true,
      },
      {
        surface: 'manifest-stage',
        mismatch: 'content',
        sameIdentity: true,
        sameMode: true,
        sameContents: false,
      },
      {
        surface: 'uninstall-private-source',
        mismatch: 'identity',
        sameIdentity: false,
        sameMode: true,
        sameContents: true,
      },
      {
        surface: 'uninstall-private-source',
        mismatch: 'mode',
        sameIdentity: true,
        sameMode: false,
        sameContents: true,
      },
      {
        surface: 'uninstall-private-source',
        mismatch: 'content',
        sameIdentity: true,
        sameMode: true,
        sameContents: false,
      },
    ]);
    expect(observations.map(({ result }) => result)).toEqual(
      observations.map(() => ({
        state: 'recovery-required',
        failures: [{ stage: 'third-state' }],
      })),
    );
    expect(observations.map(({ walAfter }) => walAfter)).toEqual(
      observations.map(({ walBefore }) => walBefore),
    );
    expect(observations.map(({ treeAfter }) => treeAfter)).toEqual(
      observations.map(({ treeBefore }) => treeBefore),
    );
  });
  it('recovers prepared rollback and commit-decided uninstall WALs in fresh Node processes', async () => {
    const rollback = await fixture();
    const rollbackTarget = join(rollback.root, 'rollback-owned.txt');
    const rollbackSource = join(rollback.root, '.rollback-owned.source');
    const rollbackBytes = Buffer.from('rollback-owned-bytes\n', 'utf8');
    const rollbackFingerprint = `sha256:${createHash('sha256').update(rollbackBytes).digest('hex')}`;
    const rollbackManifest = {
      ...activeManifest('fresh-rollback-install'),
      artifacts: [
        {
          path: rollbackTarget,
          kind: 'file',
          fingerprint: rollbackFingerprint,
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: rollbackTarget,
            expectedFingerprint: rollbackFingerprint,
          },
        },
      ],
    };
    await writeFile(rollbackSource, rollbackBytes, { mode: 0o600 });
    const rollbackManifestJson = serializeSetupManifestV1(rollbackManifest);
    await writeFile(rollback.manifestPath, rollbackManifestJson, { mode: 0o600 });
    await chmod(rollback.manifestPath, 0o600);
    const [rollbackSourceIdentity, rollbackManifestIdentity] = await Promise.all([
      identity(rollbackSource),
      identity(rollback.manifestPath),
    ]);
    await writeFile(
      rollback.walPath,
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'fresh-rollback-operation',
        installId: rollbackManifest.installId,
        operation: 'uninstall',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: rollback.lockPath,
        manifestPath: rollback.manifestPath,
        receiptPath: rollback.receiptPath,
        manifest: rollbackManifest,
        cursor: 1,
        preimages: [
          {
            path: rollback.manifestPath,
            kind: 'file',
            identity: rollbackManifestIdentity.identity,
            mode: rollbackManifestIdentity.mode,
            bytes: Buffer.from(rollbackManifestJson, 'utf8').toString('base64'),
          },
          {
            path: rollbackTarget,
            kind: 'file',
            identity: rollbackSourceIdentity.identity,
            mode: rollbackSourceIdentity.mode,
            bytes: rollbackBytes.toString('base64'),
          },
          {
            path: rollback.receiptPath,
            kind: 'absent',
          },
        ],
        mutations: [
          {
            step: 0,
            kind: 'ordinary',
            targetPath: rollbackTarget,
            sourcePath: rollbackSource,
            stagingPath: join(rollback.root, '.rollback-owned.stage'),
            preimage: 1,
            result: { kind: 'absent' },
          },
        ],
      }),
      { mode: 0o600 },
    );

    expect(await runRecoveryChild(rollback)).toEqual({ state: 'active' });
    expect(await readFile(rollbackTarget)).toEqual(rollbackBytes);
    await expect(readFile(rollbackSource)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(rollback.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(rollback.receiptPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(rollback.manifestPath, 'utf8')).resolves.toBe(
      serializeSetupManifestV1(rollbackManifest),
    );

    const commit = await fixture();
    const commitTarget = join(commit.root, 'commit-owned.txt');
    const commitTargetSource = join(commit.root, '.commit-owned.source');
    const commitReceiptSource = join(commit.root, '.commit-receipt.source');
    const commitManifestSource = join(commit.root, '.commit-manifest.source');
    const commitBytes = Buffer.from('commit-owned-bytes\n', 'utf8');
    const commitFingerprint = `sha256:${createHash('sha256').update(commitBytes).digest('hex')}`;
    const commitManifest = {
      ...activeManifest('fresh-commit-install'),
      artifacts: [
        {
          path: commitTarget,
          kind: 'file',
          fingerprint: commitFingerprint,
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: commitTarget,
            expectedFingerprint: commitFingerprint,
          },
        },
      ],
    };
    const commitManifestJson = serializeSetupManifestV1(commitManifest);
    const staleReceipt = serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'stale-commit-receipt',
      installId: 'retired-install',
      terminalState: 'uninstalled',
      manifestFingerprint: ZERO_FINGERPRINT,
    });
    const commitReceipt = serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'fresh-commit-operation',
      installId: commitManifest.installId,
      terminalState: 'uninstalled',
      manifestFingerprint: `sha256:${createHash('sha256').update(commitManifestJson).digest('hex')}`,
    });
    await Promise.all([
      writeFile(commitTargetSource, commitBytes, { mode: 0o600 }),
      writeFile(commitReceiptSource, staleReceipt, { mode: 0o600 }),
      writeFile(commit.receiptPath, commitReceipt, { mode: 0o600 }),
      writeFile(commitManifestSource, commitManifestJson, { mode: 0o600 }),
    ]);
    await Promise.all([
      chmod(commitTargetSource, 0o600),
      chmod(commitReceiptSource, 0o600),
      chmod(commit.receiptPath, 0o600),
      chmod(commitManifestSource, 0o600),
    ]);
    const [
      commitTargetIdentity,
      commitReceiptPreimageIdentity,
      commitReceiptIdentity,
      commitManifestIdentity,
    ] = await Promise.all([
      identity(commitTargetSource),
      identity(commitReceiptSource),
      identity(commit.receiptPath),
      identity(commitManifestSource),
    ]);
    await writeFile(
      commit.walPath,
      bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: 'fresh-commit-operation',
        installId: commitManifest.installId,
        operation: 'uninstall',
        direction: 'commit',
        phase: 'commit-decided',
        lockPath: commit.lockPath,
        manifestPath: commit.manifestPath,
        receiptPath: commit.receiptPath,
        manifest: commitManifest,
        cursor: 3,
        preimages: [
          {
            path: commit.manifestPath,
            kind: 'file',
            identity: commitManifestIdentity.identity,
            mode: commitManifestIdentity.mode,
            bytes: Buffer.from(commitManifestJson, 'utf8').toString('base64'),
          },
          {
            path: commitTarget,
            kind: 'file',
            identity: commitTargetIdentity.identity,
            mode: commitTargetIdentity.mode,
            bytes: commitBytes.toString('base64'),
          },
          {
            path: commit.receiptPath,
            kind: 'file',
            identity: commitReceiptPreimageIdentity.identity,
            mode: commitReceiptPreimageIdentity.mode,
            bytes: Buffer.from(staleReceipt, 'utf8').toString('base64'),
          },
        ],
        mutations: [
          {
            step: 0,
            kind: 'ordinary',
            targetPath: commitTarget,
            sourcePath: commitTargetSource,
            stagingPath: join(commit.root, '.commit-owned.stage'),
            preimage: 1,
            result: { kind: 'absent' },
          },
          {
            step: 1,
            kind: 'ordinary',
            targetPath: commit.receiptPath,
            sourcePath: commitReceiptSource,
            stagingPath: join(commit.root, '.commit-receipt.stage'),
            preimage: 2,
            result: {
              kind: 'file',
              identity: commitReceiptIdentity.identity,
              mode: commitReceiptIdentity.mode,
              bytes: Buffer.from(commitReceipt, 'utf8').toString('base64'),
            },
          },
          {
            step: 2,
            kind: 'ordinary',
            targetPath: commit.manifestPath,
            sourcePath: commitManifestSource,
            stagingPath: join(commit.root, '.commit-manifest.stage'),
            preimage: 0,
            result: { kind: 'absent' },
          },
        ],
      }),
      { mode: 0o600 },
    );

    expect(await runRecoveryChild(commit)).toEqual({ state: 'uninstalled' });
    await expect(readFile(commitTarget)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commitTargetSource)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commitReceiptSource)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commitManifestSource)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commit.manifestPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commit.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(commit.receiptPath, 'utf8')).resolves.toBe(commitReceipt);
  });
  it('recovers credential transactions killed after credential publication and commit decision in second fresh processes', async () => {
    type CredentialMutation = Extract<
      ReturnType<typeof parseWalRecordJsonV2>['mutations'][number],
      { readonly kind: 'credential' }
    >;
    type KilledCredentialRecoveryObservation = {
      readonly boundary: 'credential-publication' | 'commit-decision';
      readonly operationId: string;
      readonly installId: string;
      readonly credentialPath: string;
      readonly credentialStagingPath: string;
      readonly credentialContent: string;
      readonly credentialMutation: CredentialMutation;
      readonly wal: ReturnType<typeof parseWalRecordJsonV2>;
      readonly credentialBefore: IdentityWithMode;
      readonly credentialContentsBefore: string;
      readonly credentialStagingBefore: RecoveryPathSnapshot;
      readonly registryBefore: RecoveryPathSnapshot;
      readonly manifestBefore: RecoveryPathSnapshot;
      readonly expectedManifest: string | undefined;
      readonly recovery: RecoveryChildResult;
      readonly walAfter: RecoveryPathSnapshot;
      readonly credentialAfter: RecoveryPathSnapshot;
      readonly credentialIdentityAfter: IdentityWithMode | undefined;
      readonly credentialContentsAfter: string | undefined;
      readonly credentialStagingAfter: RecoveryPathSnapshot;
      readonly registryAfter: RecoveryPathSnapshot;
      readonly manifestAfter: RecoveryPathSnapshot;
    };
    const observations: KilledCredentialRecoveryObservation[] = [];

    for (const boundary of ['credential-publication', 'commit-decision'] as const) {
      const item = await fixture();
      const operationId = `producer-${boundary}-operation`;
      const installId = `producer-${boundary}-install`;
      const credentialPath = join(item.root, `${boundary}-producer-credential`);
      const credentialStagingPath = join(item.root, `.${boundary}-producer-credential.stage`);
      const registryPath = join(item.root, `${boundary}-credential-authorities.v1.json`);
      const token = 'producer-crash-token-never-in-authority';
      const credentialContent = credentialEnvelope('producer-credential-project', token);
      const canaries = credentialCanaries(token, credentialContent);

      await runProducerAndKill({
        ...item,
        root: item.root,
        boundary,
        operationId,
        installId,
        credentialPath,
        credentialStagingPath,
        registryPath,
        credentialContent,
      });

      const wal = parseWalRecordJsonV2(await readFile(item.walPath, 'utf8'));
      const credentialMutation = wal.mutations.find(
        (mutation) => mutation.kind === 'credential' && mutation.path === credentialPath,
      );
      if (credentialMutation === undefined || credentialMutation.kind !== 'credential') {
        throw new Error('killed producer WAL did not retain credential authority');
      }
      const beforeAuthority = await snapshotRecoveryAuthorityTree({
        ...item,
        registryPath,
        credentialPath,
        credentialStagingPath,
      });
      const credentialBefore = await identity(credentialPath);
      const credentialContentsBefore = await readFile(credentialPath, 'utf8');
      const credentialStagingBefore = beforeAuthority.credentialStaging;
      const registryBefore = beforeAuthority.registry;
      const manifestBefore = beforeAuthority.manifest;
      const publicStatePaths = [
        item.lockPath,
        item.walPath,
        item.manifestPath,
        registryPath,
        ...wal.mutations.flatMap((mutation) =>
          mutation.kind === 'ordinary'
            ? [mutation.targetPath, mutation.sourcePath, mutation.stagingPath]
            : [],
        ),
      ];
      const expectedRegistryPostimage = {
        schemaVersion: 1 as const,
        projects: [
          {
            projectId: 'producer-credential-project',
            tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
            canonicalRoot: item.root,
            credentialPath,
            device: credentialBefore.identity.device,
            inode: credentialBefore.identity.inode,
          },
        ],
      };
      const expectedRegistryFingerprint = `sha256:${createHash('sha256')
        .update(serializeCredentialAuthorityRegistryV1(expectedRegistryPostimage), 'utf8')
        .digest('hex')}`;
      const expectedManifest =
        boundary === 'commit-decision'
          ? serializeSetupManifestV1({
              schemaVersion: 1,
              kind: 'scene-glass-setup-manifest',
              installId,
              state: 'active',
              artifacts: [
                {
                  path: credentialPath,
                  kind: 'credential',
                  ownership: 'setup-created',
                  projectId: 'producer-credential-project',
                  identity: credentialBefore.identity,
                  mode: 0o600,
                  linkCount: 1,
                  inverse: {
                    kind: 'delete-created-credential',
                    path: credentialPath,
                    projectId: 'producer-credential-project',
                    identity: credentialBefore.identity,
                    mode: 0o600,
                    linkCount: 1,
                  },
                },
                {
                  path: registryPath,
                  kind: 'credential-authority-registry',
                  fingerprint: expectedRegistryFingerprint,
                  preimage: { schemaVersion: 1, projects: [] },
                  postimage: expectedRegistryPostimage,
                  inverse: {
                    kind: 'restore-credential-authority-registry-entry',
                    path: registryPath,
                    preimage: { schemaVersion: 1, projects: [] },
                    postimage: expectedRegistryPostimage,
                  },
                },
              ],
            })
          : undefined;
      const manifestAuthorityPath = `${item.manifestPath}.scene-glass-${operationId}.manifest-authority`;
      const manifestStagingPath = `${manifestAuthorityPath}.scene-glass-${operationId}-2.stage`;
      const manifestStageBefore =
        boundary === 'commit-decision'
          ? recoveryAuthoritySnapshot(beforeAuthority, manifestStagingPath)
          : undefined;
      if (
        manifestStageBefore !== undefined &&
        (manifestStageBefore.state !== 'present' ||
          manifestStageBefore.kind !== 'file' ||
          manifestStageBefore.contents !== expectedManifest)
      ) {
        throw new Error(
          'commit-decision recovery fixture did not preserve the exact manifest stage',
        );
      }
      let expectedRecoveryDelta: ReadonlyMap<string, RecoveryPathSnapshot>;
      if (boundary === 'credential-publication') {
        expectedRecoveryDelta = new Map([
          [item.walPath, absentRecoveryPath()],
          [item.manifestPath, absentRecoveryPath()],
          [registryPath, absentRecoveryPath()],
          [credentialPath, absentRecoveryPath()],
          [credentialStagingPath, absentRecoveryPath()],
        ]);
      } else {
        if (manifestStageBefore === undefined) {
          throw new Error('commit-decision recovery fixture did not retain a manifest stage');
        }
        expectedRecoveryDelta = new Map([
          [item.walPath, absentRecoveryPath()],
          [item.manifestPath, manifestStageBefore],
          [manifestStagingPath, absentRecoveryPath()],
        ]);
      }
      expect(await durableNonCredentialAuthorityLeaks(publicStatePaths, canaries)).toEqual([]);
      const recovery = await runRecoveryChild(item);
      const afterAuthority = await snapshotRecoveryAuthorityTree({
        ...item,
        registryPath,
        credentialPath,
        credentialStagingPath,
        authorityPaths: beforeAuthority.walAuthorities.map(({ path }) => path),
      });
      expectRecoveryAuthorityTreeDelta(beforeAuthority, afterAuthority, expectedRecoveryDelta);
      const walAfter = afterAuthority.wal;
      const credentialAfter = afterAuthority.credential;
      const credentialIdentityAfter =
        credentialAfter.state === 'present' ? await identity(credentialPath) : undefined;
      const credentialContentsAfter =
        credentialAfter.state === 'present' ? await readFile(credentialPath, 'utf8') : undefined;
      const credentialStagingAfter = afterAuthority.credentialStaging;
      const registryAfter = afterAuthority.registry;
      const manifestAfter = afterAuthority.manifest;
      expect(await durableNonCredentialAuthorityLeaks(publicStatePaths, canaries)).toEqual([]);
      observations.push({
        boundary,
        operationId,
        installId,
        credentialPath,
        credentialStagingPath,
        credentialContent,
        credentialMutation,
        wal,
        credentialBefore,
        credentialContentsBefore,
        credentialStagingBefore,
        registryBefore,
        manifestBefore,
        expectedManifest,
        recovery,
        walAfter,
        credentialAfter,
        credentialIdentityAfter,
        credentialContentsAfter,
        credentialStagingAfter,
        registryAfter,
        manifestAfter,
      });
    }

    const [published, committed] = observations;
    if (published === undefined || committed === undefined) {
      throw new Error('credential crash-boundary observations are incomplete');
    }

    expect({
      boundary: published.boundary,
      operationId: published.operationId,
      installId: published.installId,
      wal: {
        operation: published.wal.operation,
        direction: published.wal.direction,
        phase: published.wal.phase,
        cursor: published.wal.cursor,
        credentialMutations: published.wal.mutations.filter(
          (mutation) => mutation.kind === 'credential',
        ).length,
        credentialStep: published.credentialMutation.step,
        credentialMode: published.credentialMutation.mode,
      },
      credential: {
        matchesWalIdentity:
          published.credentialBefore.identity.device ===
            published.credentialMutation.targetIdentity.device &&
          published.credentialBefore.identity.inode ===
            published.credentialMutation.targetIdentity.inode,
        mode: published.credentialBefore.mode,
        contents: published.credentialContentsBefore,
        staging: published.credentialStagingBefore,
      },
      registryBefore: published.registryBefore,
      manifestBefore: published.manifestBefore,
      recovery: published.recovery,
      walAfter: published.walAfter,
      credentialAfter: published.credentialAfter,
      credentialStagingAfter: published.credentialStagingAfter,
      registryAfter: published.registryAfter,
      manifestAfter: published.manifestAfter,
    }).toEqual({
      boundary: 'credential-publication',
      operationId: 'producer-credential-publication-operation',
      installId: 'producer-credential-publication-install',
      wal: {
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        cursor: 1,
        credentialMutations: 1,
        credentialStep: 0,
        credentialMode: 0o600,
      },
      credential: {
        matchesWalIdentity: true,
        mode: 0o600,
        contents: credentialEnvelope(
          'producer-credential-project',
          'producer-crash-token-never-in-authority',
        ),
        staging: { state: 'absent', code: 'ENOENT' },
      },
      registryBefore: { state: 'absent', code: 'ENOENT' },
      manifestBefore: { state: 'absent', code: 'ENOENT' },
      recovery: { state: 'never-installed' },
      walAfter: { state: 'absent', code: 'ENOENT' },
      credentialAfter: { state: 'absent', code: 'ENOENT' },
      credentialStagingAfter: { state: 'absent', code: 'ENOENT' },
      registryAfter: { state: 'absent', code: 'ENOENT' },
      manifestAfter: { state: 'absent', code: 'ENOENT' },
    });
    expect(published.credentialMutation).toEqual({
      step: 0,
      kind: 'credential',
      projectId: 'producer-credential-project',
      path: published.credentialPath,
      mode: 0o600,
      stagingPath: published.credentialStagingPath,
      stagingIdentity: published.credentialBefore.identity,
      targetIdentity: published.credentialBefore.identity,
    });
    expect({
      boundary: committed.boundary,
      operationId: committed.operationId,
      installId: committed.installId,
      wal: {
        operation: committed.wal.operation,
        direction: committed.wal.direction,
        phase: committed.wal.phase,
        credentialMutations: committed.wal.mutations.filter(
          (mutation) => mutation.kind === 'credential',
        ).length,
        credentialStep: committed.credentialMutation.step,
        credentialMode: committed.credentialMutation.mode,
      },
      credential: {
        matchesWalIdentity:
          committed.credentialBefore.identity.device ===
            committed.credentialMutation.targetIdentity.device &&
          committed.credentialBefore.identity.inode ===
            committed.credentialMutation.targetIdentity.inode,
        mode: committed.credentialBefore.mode,
        contents: committed.credentialContentsBefore,
        staging: committed.credentialStagingBefore,
        identityAfter: committed.credentialIdentityAfter,
        contentsAfter: committed.credentialContentsAfter,
        stagingAfter: committed.credentialStagingAfter,
      },
      manifestBefore: committed.manifestBefore,
      recovery: committed.recovery,
      walAfter: committed.walAfter,
    }).toEqual({
      boundary: 'commit-decision',
      operationId: 'producer-commit-decision-operation',
      installId: 'producer-commit-decision-install',
      wal: {
        operation: 'setup',
        direction: 'commit',
        phase: 'commit-decided',
        credentialMutations: 1,
        credentialStep: 0,
        credentialMode: 0o600,
      },
      credential: {
        matchesWalIdentity: true,
        mode: 0o600,
        contents: credentialEnvelope(
          'producer-credential-project',
          'producer-crash-token-never-in-authority',
        ),
        staging: { state: 'absent', code: 'ENOENT' },
        identityAfter: committed.credentialBefore,
        contentsAfter: credentialEnvelope(
          'producer-credential-project',
          'producer-crash-token-never-in-authority',
        ),
        stagingAfter: { state: 'absent', code: 'ENOENT' },
      },
      manifestBefore: { state: 'absent', code: 'ENOENT' },
      recovery: { state: 'active' },
      walAfter: { state: 'absent', code: 'ENOENT' },
    });
    expect(committed.credentialMutation).toEqual({
      step: 0,
      kind: 'credential',
      projectId: 'producer-credential-project',
      path: committed.credentialPath,
      mode: 0o600,
      stagingPath: committed.credentialStagingPath,
      stagingIdentity: committed.credentialBefore.identity,
      targetIdentity: committed.credentialBefore.identity,
    });
    if (
      committed.registryBefore.state !== 'present' ||
      committed.registryBefore.kind !== 'file' ||
      committed.registryBefore.contents === undefined
    ) {
      throw new Error('commit-decision boundary did not persist a readable credential registry');
    }
    expect({
      kind: committed.registryBefore.kind,
      mode: committed.registryBefore.mode,
      contents: JSON.parse(committed.registryBefore.contents),
    }).toEqual({
      kind: 'file',
      mode: 0o600,
      contents: {
        schemaVersion: 1,
        projects: [
          {
            projectId: 'producer-credential-project',
            tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
            canonicalRoot: committed.credentialPath.slice(
              0,
              committed.credentialPath.lastIndexOf('/'),
            ),
            credentialPath: committed.credentialPath,
            device: committed.credentialBefore.identity.device,
            inode: committed.credentialBefore.identity.inode,
          },
        ],
      },
    });
    expect(committed.registryAfter).toEqual(committed.registryBefore);
    if (
      committed.manifestAfter.state !== 'present' ||
      committed.manifestAfter.kind !== 'file' ||
      committed.manifestAfter.contents === undefined
    ) {
      throw new Error('commit-decision recovery did not persist a readable setup manifest');
    }
    expect({
      kind: committed.manifestAfter.kind,
      mode: committed.manifestAfter.mode,
      contents: committed.manifestAfter.contents,
    }).toEqual({
      kind: 'file',
      mode: 0o600,
      contents: committed.expectedManifest,
    });
  });
  it('preserves a self-consistent independently placed WAL stage with mismatched lineage inode', async () => {
    const item = await fixture();
    const operationId = 'foreign-self-consistent-stage';
    const installId = 'foreign-self-consistent-stage-install';
    const targetPath = join(item.root, 'foreign-self-consistent-target');
    const sourcePath = join(item.root, '.foreign-self-consistent-source');
    const stagingPath = join(item.root, '.foreign-self-consistent-target.stage');
    const stagePath = `${item.walPath}.scene-glass-wal.stage`;
    const stagedWal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId,
      installId,
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      cursor: 0,
      preimages: [{ path: targetPath, kind: 'absent' }],
      mutations: [
        {
          step: 0,
          kind: 'ordinary',
          targetPath,
          sourcePath,
          stagingPath,
          preimage: 0,
          result: { kind: 'absent' },
        },
      ],
    });
    await writeFile(stagePath, stagedWal, { mode: 0o600 });
    const stagedIdentity = await identity(stagePath);
    const stagedRecord = parseWalRecordJsonV2(stagedWal);
    const currentWal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId,
      installId,
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      cursor: 0,
      preimages: [{ path: targetPath, kind: 'absent' }],
      mutations: [
        {
          step: 0,
          kind: 'ordinary',
          targetPath,
          sourcePath,
          stagingPath,
          preimage: 0,
          result: { kind: 'absent' },
        },
      ],
      replacedWalStage: {
        identity: {
          device: stagedIdentity.identity.device,
          inode: (BigInt(stagedIdentity.identity.inode) + 1n).toString(10),
        },
        mode: stagedIdentity.mode,
        authorityFingerprint: stagedRecord.authorityFingerprint,
      },
    });
    await writeFile(item.walPath, currentWal, { mode: 0o600 });
    const treeBefore = await snapshotRecoveryFilesystemTree(item.root);

    const [first, second] = await recoverFailClosedPreservingFilesystem({
      ...item,
      root: item.root,
    });

    expect([first, second]).toEqual([
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
    ]);
    expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(treeBefore);
    await expect(readFile(stagePath, 'utf8')).resolves.toBe(stagedWal);
    expect(await identity(stagePath)).toEqual(stagedIdentity);
    await expect(readFile(item.walPath, 'utf8')).resolves.toBe(currentWal);
  });
  it('preserves a foreign deterministic WAL stage byte-for-byte when the primary WAL is absent', async () => {
    const item = await fixture();
    const stagePath = `${item.walPath}.scene-glass-wal.stage`;
    const foreign = '{"foreign":"fixed-wal-stage"}\n';
    await writeFile(stagePath, foreign, { mode: 0o600 });
    await chmod(stagePath, 0o600);
    const before = await identity(stagePath);

    await expect(
      recoverLifecycle({
        ...item,
        port: createNodeLifecycleTransactionPort(),
      }),
    ).resolves.toEqual({
      state: 'recovery-required',
      failures: [{ stage: 'wal-authority' }],
    });

    expect(await readFile(stagePath, 'utf8')).toBe(foreign);
    expect(await identity(stagePath)).toEqual(before);
    await expect(readFile(item.walPath, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('retains an orphaned replacement WAL stage when the primary WAL is absent', async () => {
    const item = await fixture();
    const stagePath = `${item.walPath}.scene-glass-wal.stage`;
    const stagedWal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'orphaned-replacement-stage',
      installId: 'orphaned-replacement-install',
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      cursor: 0,
      preimages: [],
      mutations: [],
      replacedWalStage: {
        identity: { device: '1', inode: '1' },
        mode: 0o600,
        authorityFingerprint: ZERO_FINGERPRINT,
      },
    });
    await writeFile(stagePath, stagedWal, { mode: 0o600 });
    await chmod(stagePath, 0o600);
    const before = await snapshotRecoveryFilesystemTree(item.root);
    const stageIdentity = await identity(stagePath);

    const first = await runRecoveryChildDetailed(item);
    const second = await runRecoveryChildDetailed(item);

    expect([first, second]).toEqual([
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
      { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
    ]);
    expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(before);
    await expect(readFile(stagePath, 'utf8')).resolves.toBe(stagedWal);
    expect(await identity(stagePath)).toEqual(stageIdentity);
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('recovers deterministic WAL stage residue and rejects legacy residue from bounded fresh producers', async () => {
    const maximumScannedLegacyStageStep = 64;
    for (const scenario of [
      {
        name: 'initial-wal-stage',
        kind: 'deterministic' as const,
        boundary: 'initial-publication' as const,
      },
      {
        name: 'replacement-wal-stage',
        kind: 'deterministic' as const,
        boundary: 'replacement' as const,
      },
      { name: 'legacy-first-stage', kind: 'legacy' as const, step: 0 },
      {
        name: 'legacy-maximum-stage',
        kind: 'legacy' as const,
        step: maximumScannedLegacyStageStep,
      },
    ] as const) {
      const item = await fixture();
      const operationId = `residue-${scenario.name}-operation`;
      const installId = `residue-${scenario.name}-install`;
      const credentialPath = join(item.root, `${scenario.name}-credential`);
      const credentialStagingPath = join(item.root, `.${scenario.name}-credential.stage`);
      const registryPath = join(item.root, `${scenario.name}-registry.v1.json`);
      const deterministicStagePath = `${item.walPath}.scene-glass-wal.stage`;
      const legacyStagePath =
        scenario.kind === 'legacy'
          ? `${item.walPath}.scene-glass-${operationId}-${scenario.step}.stage`
          : join(item.root, `.${scenario.name}.legacy-stage.absent`);

      if (scenario.kind === 'deterministic') {
        await runWalStageProducerAndKill({
          ...item,
          root: item.root,
          boundary: scenario.boundary,
          operationId,
          installId,
          credentialPath,
          credentialStagingPath,
        });
      } else {
        await runProducerAndKill({
          ...item,
          root: item.root,
          boundary: 'prepared-before-stage',
          operationId,
          installId,
          credentialPath,
          credentialStagingPath,
          registryPath,
          credentialContent: credentialEnvelope(
            'producer-credential-project',
            `${scenario.name}-token`,
          ),
        });
        await writeFile(legacyStagePath, `legacy-${scenario.step}-stage-residue\n`, {
          mode: 0o600,
        });
        await chmod(legacyStagePath, 0o600);
      }

      const before = await snapshotWalResidueRecoveryState({
        ...item,
        root: item.root,
        targetPath: credentialPath,
        targetStagingPath: credentialStagingPath,
        deterministicStagePath,
        legacyStagePath,
      });
      const stage =
        scenario.kind === 'deterministic' ? before.deterministicStage : before.legacyStage;
      if (!isExactRecoveryFileSnapshot(stage)) {
        throw new Error('bounded producer did not leave an inspectable WAL stage residue');
      }
      expectWalResidueStageSnapshot(scenario, stage, before);

      const firstRecovery = await runRecoveryChildDetailed({ ...item });
      const afterFirstRecovery = await snapshotWalResidueRecoveryState({
        ...item,
        root: item.root,
        targetPath: credentialPath,
        targetStagingPath: credentialStagingPath,
        deterministicStagePath,
        legacyStagePath,
      });
      const secondRecovery = await runRecoveryChildDetailed({ ...item });
      const afterSecondRecovery = await snapshotWalResidueRecoveryState({
        ...item,
        root: item.root,
        targetPath: credentialPath,
        targetStagingPath: credentialStagingPath,
        deterministicStagePath,
        legacyStagePath,
      });

      const recoveries = [firstRecovery, secondRecovery];
      const observed =
        scenario.kind === 'deterministic'
          ? {
              recoveries,
              roots: [afterFirstRecovery.root, afterSecondRecovery.root],
              locks: [afterFirstRecovery.lock, afterSecondRecovery.lock],
              repeatedTree:
                JSON.stringify(normalizeRecoveryFilesystemTree(afterFirstRecovery.tree)) ===
                JSON.stringify(normalizeRecoveryFilesystemTree(afterSecondRecovery.tree)),
              residues: [afterFirstRecovery, afterSecondRecovery].map((state) => ({
                wal: state.wal,
                manifest: state.manifest,
                receipt: state.receipt,
                target: state.target,
                targetStaging: state.targetStaging,
                deterministicStage: state.deterministicStage,
                legacyStage: state.legacyStage,
              })),
            }
          : { recoveries, snapshots: [afterFirstRecovery, afterSecondRecovery] };
      const absent = { state: 'absent' as const, code: 'ENOENT' };
      const expected =
        scenario.kind === 'deterministic'
          ? {
              recoveries: [
                { state: 'never-installed', failures: [] },
                { state: 'never-installed', failures: [] },
              ],
              roots: [before.root, before.root],
              locks: [before.lock, before.lock],
              repeatedTree: true,
              residues: [
                {
                  wal: absent,
                  manifest: absent,
                  receipt: absent,
                  target: absent,
                  targetStaging: absent,
                  deterministicStage: absent,
                  legacyStage: absent,
                },
                {
                  wal: absent,
                  manifest: absent,
                  receipt: absent,
                  target: absent,
                  targetStaging: absent,
                  deterministicStage: absent,
                  legacyStage: absent,
                },
              ],
            }
          : {
              recoveries: [
                { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
                { state: 'recovery-required', failures: [{ stage: 'wal-authority' }] },
              ],
              snapshots: [before, before],
            };
      expect(observed).toEqual(expected);
    }
  });

  it('recovers fresh-process uninstall producers killed at durable rollback and commit decisions', async () => {
    for (const boundary of ['rollback-prepared', 'commit-decided'] as const) {
      const item = await fixture();
      const operationId = `uninstall-${boundary}-operation`;
      const installId = `uninstall-${boundary}-install`;
      const targetPath = join(item.root, `${boundary}-owned.txt`);
      const credentialPath = join(item.root, `${boundary}-credential`);
      const registryPath = join(item.root, `${boundary}-registry.v1.json`);
      const targetContents = `${boundary}-owned-bytes\n`;
      const targetFingerprint = `sha256:${createHash('sha256')
        .update(targetContents, 'utf8')
        .digest('hex')}`;
      const credentialToken = `${boundary}-credential-token`;
      const credentialContents = credentialEnvelope(
        `uninstall-${boundary}-project`,
        credentialToken,
      );

      await Promise.all([
        writeFile(targetPath, targetContents, { mode: 0o600 }),
        writeFile(credentialPath, credentialContents, { mode: 0o600 }),
      ]);
      await Promise.all([chmod(targetPath, 0o600), chmod(credentialPath, 0o600)]);
      const credentialIdentity = await identity(credentialPath);
      const registryPreimage = { schemaVersion: 1 as const, projects: [] };
      const registryPostimage = {
        schemaVersion: 1 as const,
        projects: [
          {
            projectId: `uninstall-${boundary}-project`,
            tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
            canonicalRoot: item.root,
            credentialPath,
            device: credentialIdentity.identity.device,
            inode: credentialIdentity.identity.inode,
          },
        ],
      };
      const registryPostimageJson = serializeCredentialAuthorityRegistryV1(registryPostimage);
      const registryFingerprint = `sha256:${createHash('sha256')
        .update(registryPostimageJson, 'utf8')
        .digest('hex')}`;
      const manifest = {
        ...activeManifest(installId),
        artifacts: [
          {
            path: targetPath,
            kind: 'file' as const,
            fingerprint: targetFingerprint,
            hunks: [],
            inverse: {
              kind: 'delete-created-file' as const,
              path: targetPath,
              expectedFingerprint: targetFingerprint,
            },
          },
          {
            path: credentialPath,
            kind: 'credential' as const,
            ownership: 'setup-created' as const,
            projectId: `uninstall-${boundary}-project`,
            identity: credentialIdentity.identity,
            mode: credentialIdentity.mode,
            linkCount: 1 as const,
            inverse: {
              kind: 'delete-created-credential' as const,
              path: credentialPath,
              projectId: `uninstall-${boundary}-project`,
              identity: credentialIdentity.identity,
              mode: credentialIdentity.mode,
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
        ],
      };
      const manifestJson = serializeSetupManifestV1(manifest);
      const registryPreimageJson = serializeCredentialAuthorityRegistryV1(registryPreimage);
      await Promise.all([
        writeFile(item.manifestPath, manifestJson, { mode: 0o600 }),
        writeFile(registryPath, registryPostimageJson, { mode: 0o600 }),
      ]);
      await Promise.all([chmod(item.manifestPath, 0o600), chmod(registryPath, 0o600)]);
      const [manifestIdentity, targetIdentity, registryIdentity] = await Promise.all([
        identity(item.manifestPath),
        identity(targetPath),
        identity(registryPath),
      ]);
      const preflight = validateUninstallPreflight({
        manifest,
        observed: [
          {
            path: targetPath,
            fingerprint: targetFingerprint,
            hunks: [],
            semanticConfig: undefined,
          },
          { path: credentialPath, fingerprint: undefined, hunks: [], semanticConfig: undefined },
          {
            path: registryPath,
            fingerprint: registryFingerprint,
            hunks: [],
            semanticConfig: undefined,
            semanticCredentialAuthorityRegistry: registryPostimage,
          },
        ],
      });
      const [targetInverse, credentialInverse, registryInverse] = preflight.inverse;
      if (
        !preflight.canUninstall ||
        targetInverse?.kind !== 'delete-created-file' ||
        credentialInverse?.kind !== 'delete-created-credential' ||
        registryInverse?.kind !== 'restore-credential-authority-registry-entry'
      ) {
        throw new Error('uninstall fixture preflight did not expose its ordered inverse plan');
      }
      const receipt = serializeLifecycleReceiptV1({
        schemaVersion: 1,
        kind: 'scene-glass-lifecycle-receipt',
        operationId,
        installId,
        terminalState: 'uninstalled',
        manifestFingerprint: `sha256:${createHash('sha256').update(manifestJson).digest('hex')}`,
      });
      const expectedTargetMutation = {
        step: 0,
        kind: 'ordinary' as const,
        targetPath: targetInverse.path,
        sourcePath: `${targetInverse.path}.scene-glass-${operationId}-0.rollback`,
        stagingPath: `${targetInverse.path}.scene-glass-${operationId}-0.stage`,
        preimage: 1,
        result: { kind: 'absent' as const },
      };
      const expectedRegistryMutation = {
        step: 1,
        kind: 'ordinary' as const,
        targetPath: registryInverse.path,
        sourcePath: `${registryInverse.path}.scene-glass-${operationId}-1.rollback`,
        stagingPath: `${registryInverse.path}.scene-glass-${operationId}-1.stage`,
        preimage: 3,
        result: {
          kind: 'file' as const,
          mode: registryIdentity.mode,
          bytes: Buffer.from(
            serializeCredentialAuthorityRegistryV1(registryInverse.preimage),
            'utf8',
          ).toString('base64'),
        },
      };
      const expectedReceiptMutation = {
        step: 2,
        kind: 'ordinary' as const,
        targetPath: item.receiptPath,
        sourcePath: `${item.receiptPath}.scene-glass-${operationId}-2.rollback`,
        stagingPath: `${item.receiptPath}.scene-glass-${operationId}-2.stage`,
        preimage: 4,
        result: {
          kind: 'file' as const,
          mode: 0o600,
          bytes: Buffer.from(receipt, 'utf8').toString('base64'),
        },
      };
      const expectedManifestMutation = {
        step: 3,
        kind: 'ordinary' as const,
        targetPath: item.manifestPath,
        sourcePath: `${item.manifestPath}.scene-glass-${operationId}-3.rollback`,
        stagingPath: `${item.manifestPath}.scene-glass-${operationId}-3.stage`,
        preimage: 0,
        result: { kind: 'absent' as const },
      };
      const expectedMutationCount = 4;
      const expectedPreimages = [
        {
          path: item.manifestPath,
          kind: 'file' as const,
          identity: manifestIdentity.identity,
          mode: manifestIdentity.mode,
          bytes: Buffer.from(manifestJson, 'utf8').toString('base64'),
        },
        {
          path: targetInverse.path,
          kind: 'file' as const,
          identity: targetIdentity.identity,
          mode: targetIdentity.mode,
          bytes: Buffer.from(targetContents, 'utf8').toString('base64'),
        },
        {
          path: credentialInverse.path,
          kind: 'credential' as const,
          identity: credentialIdentity.identity,
          mode: credentialIdentity.mode,
        },
        {
          path: registryInverse.path,
          kind: 'file' as const,
          identity: registryIdentity.identity,
          mode: registryIdentity.mode,
          bytes: Buffer.from(
            serializeCredentialAuthorityRegistryV1(registryInverse.postimage),
            'utf8',
          ).toString('base64'),
        },
        { path: item.receiptPath, kind: 'absent' as const },
      ] as const;

      const before = await snapshotUninstallRecoveryState({
        ...item,
        root: item.root,
        targetPath,
        credentialPath,
        registryPath,
      });
      await runUninstallProducerAndKill({
        ...item,
        root: item.root,
        boundary,
        operationId,
        manifestJson,
        targetPath,
        targetFingerprint,
        credentialPath,
        registryPath,
        registryPostimage,
        registryFingerprint,
        expectedMutationCount,
        receipt,
      });
      const crashed = await snapshotUninstallRecoveryState({
        ...item,
        root: item.root,
        targetPath,
        credentialPath,
        registryPath,
      });
      if (!isExactRecoveryFileSnapshot(crashed.wal)) {
        throw new Error('killed uninstall producer did not retain its durable WAL');
      }
      const registryMutationResultPath = expectedRegistryMutation.targetPath;
      const registryMutationResult = crashed.tree.get(registryMutationResultPath);
      if (
        registryMutationResult === undefined ||
        !isExactRecoveryFileSnapshot(registryMutationResult)
      ) {
        throw new Error('killed uninstall producer did not retain the registry mutation result');
      }
      expect({
        path: registryMutationResultPath,
        mode: registryMutationResult.mode,
        contents: registryMutationResult.contents,
      }).toEqual({
        path: registryMutationResultPath,
        mode: registryIdentity.mode,
        contents: registryPreimageJson,
      });
      const receiptMutationResultPath = expectedReceiptMutation.targetPath;
      const receiptMutationResult = crashed.tree.get(receiptMutationResultPath);
      if (
        receiptMutationResult === undefined ||
        !isExactRecoveryFileSnapshot(receiptMutationResult)
      ) {
        throw new Error('killed uninstall producer did not retain the receipt mutation result');
      }
      expect({
        path: receiptMutationResultPath,
        mode: receiptMutationResult.mode,
        contents: receiptMutationResult.contents,
      }).toEqual({
        path: receiptMutationResultPath,
        mode: 0o600,
        contents: receipt,
      });
      const expectedMutationPlan = [
        expectedTargetMutation,
        {
          ...expectedRegistryMutation,
          result: {
            ...expectedRegistryMutation.result,
            identity: registryMutationResult.identity,
          },
        },
        {
          ...expectedReceiptMutation,
          result: {
            ...expectedReceiptMutation.result,
            identity: receiptMutationResult.identity,
          },
        },
        expectedManifestMutation,
      ] as const;
      const crashedWal = parseWalRecordJsonV2(crashed.wal.contents);
      if (crashedWal.operation !== 'uninstall') {
        throw new Error('killed uninstall producer did not retain an uninstall WAL');
      }
      expect(crashedWal.preimages).toEqual(expectedPreimages);
      expect(crashedWal.mutations).toHaveLength(expectedMutationCount);
      expect(crashedWal.mutations).toEqual(expectedMutationPlan);
      expect({
        boundary,
        schemaVersion: crashedWal.schemaVersion,
        kind: crashedWal.kind,
        operationId: crashedWal.operationId,
        installId: crashedWal.installId,
        operation: crashedWal.operation,
        direction: crashedWal.direction,
        phase: crashedWal.phase,
        cursor: crashedWal.cursor,
        lockPath: crashedWal.lockPath,
        manifestPath: crashedWal.manifestPath,
        receiptPath: crashedWal.receiptPath,
        manifest: crashedWal.manifest,
        walStage: crashed.walStage,
      }).toEqual(
        boundary === 'rollback-prepared'
          ? {
              boundary: 'rollback-prepared',
              schemaVersion: 2,
              kind: 'scene-glass-lifecycle-wal',
              operationId,
              installId,
              operation: 'uninstall',
              direction: 'rollback',
              phase: 'prepared',
              cursor: expectedMutationCount,
              lockPath: item.lockPath,
              manifestPath: item.manifestPath,
              receiptPath: item.receiptPath,
              manifest,
              walStage: { state: 'absent', code: 'ENOENT' },
            }
          : {
              boundary: 'commit-decided',
              schemaVersion: 2,
              kind: 'scene-glass-lifecycle-wal',
              operationId,
              installId,
              operation: 'uninstall',
              direction: 'commit',
              phase: 'commit-decided',
              cursor: expectedMutationCount,
              lockPath: item.lockPath,
              manifestPath: item.manifestPath,
              receiptPath: item.receiptPath,
              manifest,
              walStage: { state: 'absent', code: 'ENOENT' },
            },
      );

      const recovery = await runRecoveryChild(item);
      const after = await snapshotUninstallRecoveryState({
        ...item,
        root: item.root,
        targetPath,
        credentialPath,
        registryPath,
      });
      const canaries = credentialCanaries(credentialToken, credentialContents);
      expect(
        await durableNonCredentialAuthorityLeaks(
          [...after.tree.keys()].filter((path) => path !== credentialPath),
          canaries,
        ),
      ).toEqual([]);

      expectUninstallRecoveryOutcome({
        after,
        before,
        boundary,
        lockPath: item.lockPath,
        receipt,
        receiptPath: item.receiptPath,
        recovery,
        registryPath,
        registryPreimageJson,
        rootPath: item.root,
      });
    }
  });
  it('retains rollback authority when untouched credential, directory, or file preimages are tampered', async () => {
    for (const scenario of ['credential', 'directory', 'file'] as const) {
      const item = await fixture();
      const credentialPath = join(item.root, `${scenario}-credential`);
      const directoryPath = join(item.root, `${scenario}-directory`);
      const filePath = join(item.root, `${scenario}-preimage.txt`);
      const manifest = activeManifest(`untouched-${scenario}-install`);
      const manifestJson = serializeSetupManifestV1(manifest);
      const fileBytes = Buffer.from(`${scenario} exact preimage\n`, 'utf8');
      await mkdir(directoryPath, { mode: 0o700 });
      await Promise.all([
        writeFile(item.manifestPath, manifestJson, { mode: 0o600 }),
        writeFile(credentialPath, `${scenario}-credential\n`, { mode: 0o600 }),
        writeFile(filePath, fileBytes, { mode: 0o600 }),
      ]);
      await Promise.all([
        chmod(directoryPath, 0o700),
        chmod(item.manifestPath, 0o600),
        chmod(credentialPath, 0o600),
        chmod(filePath, 0o600),
      ]);
      const [manifestIdentity, credentialIdentity, directoryIdentity, fileIdentity] =
        await Promise.all([
          identity(item.manifestPath),
          identity(credentialPath),
          identity(directoryPath),
          identity(filePath),
        ]);
      const wal = bindWal({
        schemaVersion: 2,
        kind: 'scene-glass-lifecycle-wal',
        operationId: `untouched-${scenario}-rollback`,
        installId: manifest.installId,
        operation: 'uninstall',
        direction: 'rollback',
        phase: 'prepared',
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
        manifest,
        cursor: 0,
        preimages: [
          {
            path: item.manifestPath,
            kind: 'file',
            identity: manifestIdentity.identity,
            mode: manifestIdentity.mode,
            bytes: Buffer.from(manifestJson, 'utf8').toString('base64'),
          },
          {
            path: credentialPath,
            kind: 'credential',
            identity: credentialIdentity.identity,
            mode: credentialIdentity.mode,
          },
          {
            path: directoryPath,
            kind: 'directory',
            identity: directoryIdentity.identity,
            mode: directoryIdentity.mode,
          },
          {
            path: filePath,
            kind: 'file',
            identity: fileIdentity.identity,
            mode: fileIdentity.mode,
            bytes: fileBytes.toString('base64'),
          },
          { path: item.receiptPath, kind: 'absent' },
        ],
        mutations: [],
      });
      await writeFile(item.walPath, wal, { mode: 0o600 });
      await chmod(item.walPath, 0o600);

      if (scenario === 'credential') {
        await tamperExactFileAuthority(credentialPath, 'identity', `${scenario}-credential\n`);
      } else if (scenario === 'directory') {
        await rm(directoryPath, { recursive: true });
        await mkdir(directoryPath, { mode: directoryIdentity.mode });
        await chmod(directoryPath, directoryIdentity.mode);
        const recreated = (await identity(directoryPath)).identity;
        if (
          recreated.device === directoryIdentity.identity.device &&
          recreated.inode === directoryIdentity.identity.inode
        ) {
          throw new Error('recreated directory fixture retained its original identity');
        }
      } else {
        await tamperExactFileAuthority(filePath, 'content', `${scenario} replacement\n`);
      }

      const treeBefore = await snapshotRecoveryFilesystemTree(item.root);
      const first = await recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
      });
      const treeAfterFirst = await snapshotRecoveryFilesystemTree(item.root);
      const second = await recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
      });
      const treeAfterSecond = await snapshotRecoveryFilesystemTree(item.root);

      expect([first, second]).toEqual([
        { state: 'recovery-required', failures: [{ stage: 'third-state' }] },
        { state: 'recovery-required', failures: [{ stage: 'third-state' }] },
      ]);
      expect([treeAfterFirst, treeAfterSecond]).toEqual([treeBefore, treeBefore]);
      await expect(readFile(item.walPath, 'utf8')).resolves.toBe(wal);
    }
  });
  it('keeps a restored different-install stale receipt active across repeated fresh recovery', async () => {
    const item = await fixture();
    const operationId = 'stale-receipt-rollback';
    const manifest = activeManifest('stale-receipt-current-install');
    const manifestJson = serializeSetupManifestV1(manifest);
    const sourcePath = join(item.root, '.stale-receipt.rollback');
    const stagingPath = join(item.root, '.stale-receipt.stage');
    const staleReceipt = serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'retired-uninstall',
      installId: 'stale-receipt-retired-install',
      terminalState: 'uninstalled',
      manifestFingerprint: ZERO_FINGERPRINT,
    });
    const uninstalledReceipt = serializeLifecycleReceiptV1({
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId,
      installId: manifest.installId,
      terminalState: 'uninstalled',
      manifestFingerprint: `sha256:${createHash('sha256').update(manifestJson).digest('hex')}`,
    });
    await Promise.all([
      writeFile(item.manifestPath, manifestJson, { mode: 0o600 }),
      writeFile(sourcePath, staleReceipt, { mode: 0o600 }),
      writeFile(item.receiptPath, uninstalledReceipt, { mode: 0o600 }),
    ]);
    await Promise.all([
      chmod(item.manifestPath, 0o600),
      chmod(sourcePath, 0o600),
      chmod(item.receiptPath, 0o600),
    ]);
    const [manifestIdentity, staleReceiptIdentity, uninstalledReceiptIdentity] = await Promise.all([
      identity(item.manifestPath),
      identity(sourcePath),
      identity(item.receiptPath),
    ]);
    const wal = bindWal({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId,
      installId: manifest.installId,
      operation: 'uninstall',
      direction: 'rollback',
      phase: 'prepared',
      lockPath: item.lockPath,
      manifestPath: item.manifestPath,
      receiptPath: item.receiptPath,
      manifest,
      cursor: 1,
      preimages: [
        {
          path: item.manifestPath,
          kind: 'file',
          identity: manifestIdentity.identity,
          mode: manifestIdentity.mode,
          bytes: Buffer.from(manifestJson, 'utf8').toString('base64'),
        },
        {
          path: item.receiptPath,
          kind: 'file',
          identity: staleReceiptIdentity.identity,
          mode: staleReceiptIdentity.mode,
          bytes: Buffer.from(staleReceipt, 'utf8').toString('base64'),
        },
      ],
      mutations: [
        {
          step: 0,
          kind: 'ordinary',
          targetPath: item.receiptPath,
          sourcePath,
          stagingPath,
          preimage: 1,
          result: {
            kind: 'file',
            identity: uninstalledReceiptIdentity.identity,
            mode: uninstalledReceiptIdentity.mode,
            bytes: Buffer.from(uninstalledReceipt, 'utf8').toString('base64'),
          },
        },
      ],
    });
    await writeFile(item.walPath, wal, { mode: 0o600 });
    await chmod(item.walPath, 0o600);

    expect(await runRecoveryChildDetailed(item)).toEqual({ state: 'active', failures: [] });
    await expect(readFile(item.receiptPath, 'utf8')).resolves.toBe(staleReceipt);
    await expect(readFile(sourcePath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(item.walPath)).rejects.toMatchObject({ code: 'ENOENT' });
    const afterFirst = await snapshotRecoveryFilesystemTree(item.root);

    expect(await runRecoveryChildDetailed(item)).toEqual({ state: 'active', failures: [] });
    expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(afterFirst);
  });
  it('rejects same-install, conflicting, and malformed receipts beside an active manifest', async () => {
    for (const scenario of ['same-install', 'conflicting', 'malformed'] as const) {
      const item = await fixture();
      const manifest = activeManifest(`terminal-${scenario}-install`);
      const manifestJson = serializeSetupManifestV1(manifest);
      let receipt: string;
      if (scenario === 'malformed') {
        receipt = 'malformed receipt\n';
      } else {
        receipt = serializeLifecycleReceiptV1({
          schemaVersion: 1,
          kind: 'scene-glass-lifecycle-receipt',
          operationId: `terminal-${scenario}-receipt`,
          installId: scenario === 'same-install' ? manifest.installId : 'conflicting-install',
          terminalState: scenario === 'same-install' ? 'uninstalled' : 'active',
          manifestFingerprint: ZERO_FINGERPRINT,
        });
      }
      await Promise.all([
        writeFile(item.manifestPath, manifestJson, { mode: 0o600 }),
        writeFile(item.receiptPath, receipt, { mode: 0o600 }),
      ]);
      await Promise.all([chmod(item.manifestPath, 0o600), chmod(item.receiptPath, 0o600)]);
      const before = await snapshotRecoveryFilesystemTree(item.root);

      const first = await recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
      });
      const second = await recoverLifecycle({
        port: createNodeLifecycleTransactionPort(),
        walPath: item.walPath,
        lockPath: item.lockPath,
        manifestPath: item.manifestPath,
        receiptPath: item.receiptPath,
      });

      expect([first, second]).toEqual([
        { state: 'recovery-required', failures: [{ stage: 'terminal-authority' }] },
        { state: 'recovery-required', failures: [{ stage: 'terminal-authority' }] },
      ]);
      expect(await snapshotRecoveryFilesystemTree(item.root)).toEqual(before);
    }
  });
});

interface RecoveryChildInput {
  readonly walPath: string;
  readonly lockPath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly includeFailures?: boolean;
}
interface IdentityWithMode {
  readonly identity: { readonly device: string; readonly inode: string };
  readonly mode: number;
}

interface SetupCommitRecoveryFixture {
  readonly targetPath: string;
  readonly directoryStagingPath: string;
  readonly credentialPath: string;
  readonly credentialStagingPath: string;
  readonly credentialContent: string;
  readonly credentialToken: string;
  readonly manifestStage: string;
  readonly manifestAuthorityPath: string;
  readonly directory: IdentityWithMode;
  readonly credential: IdentityWithMode;
  readonly wal: string;
  readonly manifestJson: string;
}

async function prepareSetupCommitRecoveryFixture(
  item: RecoveryChildInput & { readonly root: string },
  operationId: string,
  installId: string,
): Promise<SetupCommitRecoveryFixture> {
  const targetPath = join(item.root, 'setup');
  const directoryStagingPath = join(item.root, '.setup.stage');
  const credentialPath = join(item.root, 'credential');
  const credentialStagingPath = join(item.root, '.credential.stage');
  const manifestStage = join(item.root, '.manifest.stage');
  const manifestAuthorityPath = `${item.manifestPath}.scene-glass-${operationId}.manifest-authority`;
  const manifest = activeManifest(installId);
  const manifestJson = serializeSetupManifestV1(manifest);
  const manifestBytes = Buffer.from(manifestJson, 'utf8');
  const credentialToken = 'commit-recovery-token-never-in-authority';
  const credentialContent = credentialEnvelope('project-recovery', credentialToken);
  await mkdir(targetPath, { mode: 0o700 });
  await chmod(targetPath, 0o700);
  await writeFile(credentialPath, credentialContent, { mode: 0o600 });
  await chmod(credentialPath, 0o600);
  await writeFile(manifestStage, manifestBytes, { mode: 0o600 });
  await chmod(manifestStage, 0o600);
  const directory = await identity(targetPath);
  const credential = await identity(credentialPath);
  const stagedManifest = await identity(manifestStage);
  const wal = bindWal({
    schemaVersion: 2,
    kind: 'scene-glass-lifecycle-wal',
    operationId,
    installId,
    operation: 'setup',
    direction: 'commit',
    phase: 'commit-decided',
    lockPath: item.lockPath,
    manifestPath: item.manifestPath,
    cursor: 3,
    preimages: [
      { path: targetPath, kind: 'absent' },
      { path: credentialPath, kind: 'absent' },
      { path: manifestAuthorityPath, kind: 'absent' },
    ],
    mutations: [
      {
        step: 0,
        kind: 'ordinary',
        targetPath,
        sourcePath: join(item.root, '.setup.rollback'),
        stagingPath: directoryStagingPath,
        preimage: 0,
        result: { kind: 'directory', identity: directory.identity, mode: directory.mode },
      },
      {
        step: 1,
        kind: 'credential',
        projectId: 'project-recovery',
        path: credentialPath,
        mode: credential.mode,
        stagingPath: credentialStagingPath,
        stagingIdentity: credential.identity,
        targetIdentity: credential.identity,
      },
      {
        step: 2,
        kind: 'ordinary',
        targetPath: manifestAuthorityPath,
        sourcePath: join(item.root, '.manifest.rollback'),
        stagingPath: manifestStage,
        preimage: 2,
        result: {
          kind: 'file',
          identity: stagedManifest.identity,
          mode: stagedManifest.mode,
          bytes: manifestBytes.toString('base64'),
        },
      },
    ],
  });
  manifestBytes.fill(0);
  await writeFile(item.walPath, wal, { mode: 0o600 });
  return {
    targetPath,
    directoryStagingPath,
    credentialPath,
    credentialStagingPath,
    credentialContent,
    credentialToken,
    manifestStage,
    manifestAuthorityPath,
    directory,
    credential,
    wal,
    manifestJson,
  };
}
async function snapshotRecoveryAuthorityState(
  item: RecoveryChildInput & { readonly root: string },
  prepared: SetupCommitRecoveryFixture,
): Promise<Record<string, RecoveryPathSnapshot>> {
  return {
    root: await snapshotRecoveryPath(item.root),
    lock: await snapshotRecoveryPath(item.lockPath),
    wal: await snapshotRecoveryPath(item.walPath),
    manifest: await snapshotRecoveryPath(item.manifestPath),
    receipt: await snapshotRecoveryPath(item.receiptPath),
    target: await snapshotRecoveryPath(prepared.targetPath),
    directoryStaging: await snapshotRecoveryPath(prepared.directoryStagingPath),
    credential: await snapshotRecoveryPath(prepared.credentialPath),
    credentialStaging: await snapshotRecoveryPath(prepared.credentialStagingPath),
    manifestStage: await snapshotRecoveryPath(prepared.manifestStage),
    manifestAuthority: await snapshotRecoveryPath(prepared.manifestAuthorityPath),
  };
}
type NormalizedRecoveryPathSnapshot =
  | {
      readonly state: 'absent';
      readonly code: string | undefined;
    }
  | {
      readonly state: 'present';
      readonly kind: 'directory' | 'file' | 'other';
      readonly mode: number;
      readonly contents: string | undefined;
    };

function normalizeRecoveryPathSnapshot(
  snapshot: RecoveryPathSnapshot,
): NormalizedRecoveryPathSnapshot {
  if (snapshot.state === 'absent') {
    return { state: snapshot.state, code: snapshot.code };
  }
  return {
    state: snapshot.state,
    kind: snapshot.kind,
    mode: snapshot.mode,
    contents: snapshot.contents,
  };
}

function normalizeRecoveryFilesystemTree(
  tree: ReadonlyMap<string, RecoveryPathSnapshot>,
): readonly { readonly path: string; readonly snapshot: NormalizedRecoveryPathSnapshot }[] {
  return [...tree]
    .map(([path, snapshot]) => ({ path, snapshot: normalizeRecoveryPathSnapshot(snapshot) }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

interface WalResidueRecoveryState {
  readonly root: RecoveryPathSnapshot;
  readonly lock: RecoveryPathSnapshot;
  readonly wal: RecoveryPathSnapshot;
  readonly manifest: RecoveryPathSnapshot;
  readonly receipt: RecoveryPathSnapshot;
  readonly target: RecoveryPathSnapshot;
  readonly targetStaging: RecoveryPathSnapshot;
  readonly deterministicStage: RecoveryPathSnapshot;
  readonly legacyStage: RecoveryPathSnapshot;
  readonly tree: ReadonlyMap<string, RecoveryPathSnapshot>;
}

async function snapshotWalResidueRecoveryState(
  input: RecoveryChildInput & {
    readonly root: string;
    readonly targetPath: string;
    readonly targetStagingPath: string;
    readonly deterministicStagePath: string;
    readonly legacyStagePath: string;
  },
): Promise<WalResidueRecoveryState> {
  const [
    root,
    lock,
    wal,
    manifest,
    receipt,
    target,
    targetStaging,
    deterministicStage,
    legacyStage,
    tree,
  ] = await Promise.all([
    snapshotRecoveryPath(input.root),
    snapshotRecoveryPath(input.lockPath),
    snapshotRecoveryPath(input.walPath),
    snapshotRecoveryPath(input.manifestPath),
    snapshotRecoveryPath(input.receiptPath),
    snapshotRecoveryPath(input.targetPath),
    snapshotRecoveryPath(input.targetStagingPath),
    snapshotRecoveryPath(input.deterministicStagePath),
    snapshotRecoveryPath(input.legacyStagePath),
    snapshotRecoveryFilesystemTree(input.root),
  ]);
  return {
    root,
    lock,
    wal,
    manifest,
    receipt,
    target,
    targetStaging,
    deterministicStage,
    legacyStage,
    tree,
  };
}

interface UninstallRecoveryState {
  readonly root: RecoveryPathSnapshot;
  readonly lock: RecoveryPathSnapshot;
  readonly wal: RecoveryPathSnapshot;
  readonly walStage: RecoveryPathSnapshot;
  readonly manifest: RecoveryPathSnapshot;
  readonly receipt: RecoveryPathSnapshot;
  readonly target: RecoveryPathSnapshot;
  readonly credential: RecoveryPathSnapshot;
  readonly registry: RecoveryPathSnapshot;
  readonly tree: ReadonlyMap<string, RecoveryPathSnapshot>;
}

async function snapshotUninstallRecoveryState(
  input: RecoveryChildInput & {
    readonly root: string;
    readonly targetPath: string;
    readonly credentialPath: string;
    readonly registryPath: string;
  },
): Promise<UninstallRecoveryState> {
  const [root, lock, wal, walStage, manifest, receipt, target, credential, registry, tree] =
    await Promise.all([
      snapshotRecoveryPath(input.root),
      snapshotRecoveryPath(input.lockPath),
      snapshotRecoveryPath(input.walPath),
      snapshotRecoveryPath(`${input.walPath}.scene-glass-wal.stage`),
      snapshotRecoveryPath(input.manifestPath),
      snapshotRecoveryPath(input.receiptPath),
      snapshotRecoveryPath(input.targetPath),
      snapshotRecoveryPath(input.credentialPath),
      snapshotRecoveryPath(input.registryPath),
      snapshotRecoveryFilesystemTree(input.root),
    ]);
  return {
    root,
    lock,
    wal,
    walStage,
    manifest,
    receipt,
    target,
    credential,
    registry,
    tree,
  };
}
interface WalResidueScenario {
  readonly kind: 'deterministic' | 'legacy';
  readonly boundary?: 'initial-publication' | 'replacement';
  readonly step?: number;
}

function expectWalResidueStageSnapshot(
  scenario: WalResidueScenario,
  stage: RecoveryFileSnapshot,
  before: WalResidueRecoveryState,
): void {
  let actual: Record<string, unknown>;
  let expected: Record<string, unknown>;
  if (scenario.kind === 'deterministic') {
    if (scenario.boundary !== 'initial-publication' && scenario.boundary !== 'replacement') {
      throw new Error('deterministic WAL stage scenario omitted its boundary');
    }
    const stagedWal = parseWalRecordJsonV2(stage.contents);
    const stagedTransport = JSON.parse(stage.contents) as {
      readonly replacedWalStage?: unknown;
    };
    let replacementWal: RecoveryFileSnapshot | undefined;
    let replacementRecord: ReturnType<typeof parseWalRecordJsonV2> | undefined;
    if (scenario.boundary === 'replacement') {
      const candidate = before.wal;
      if (!isExactRecoveryFileSnapshot(candidate)) {
        throw new Error('replacement WAL stage fixture did not retain its primary WAL authority');
      }
      replacementWal = candidate;
      replacementRecord = parseWalRecordJsonV2(candidate.contents);
    }
    actual = {
      boundary: scenario.boundary,
      operation: stagedWal.operation,
      direction: stagedWal.direction,
      phase: stagedWal.phase,
      cursor: stagedWal.cursor,
      mutations: stagedWal.mutations.length,
      creationIntents: stagedWal.creationIntents?.length ?? 0,
      replacedWalStage: stagedTransport.replacedWalStage,
      walState: before.wal.state,
    };
    if (scenario.boundary === 'initial-publication') {
      expected = {
        boundary: 'initial-publication',
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        cursor: 0,
        mutations: 0,
        creationIntents: 1,
        replacedWalStage: undefined,
        walState: 'absent',
      };
    } else {
      if (replacementWal === undefined || replacementRecord === undefined) {
        throw new Error('replacement WAL stage fixture lost its primary WAL authority');
      }
      expected = {
        boundary: 'replacement',
        operation: 'setup',
        direction: 'rollback',
        phase: 'prepared',
        cursor: 0,
        mutations: 1,
        creationIntents: 0,
        replacedWalStage: {
          identity: replacementWal.identity,
          mode: replacementWal.mode,
          authorityFingerprint: replacementRecord.authorityFingerprint,
        },
        walState: 'present',
      };
    }
  } else {
    if (scenario.step === undefined) {
      throw new Error('legacy WAL stage scenario omitted its stage step');
    }
    const durableWal = before.wal;
    if (!isExactRecoveryFileSnapshot(durableWal)) {
      throw new Error('legacy stage fixture did not retain its producer WAL');
    }
    const parsed = parseWalRecordJsonV2(durableWal.contents);
    actual = {
      step: scenario.step,
      operation: parsed.operation,
      direction: parsed.direction,
      phase: parsed.phase,
      cursor: parsed.cursor,
      mutations: parsed.mutations.length,
      deterministicStage: before.deterministicStage,
    };
    expected = {
      step: scenario.step,
      operation: 'setup',
      direction: 'rollback',
      phase: 'prepared',
      cursor: 0,
      mutations: 0,
      deterministicStage: { state: 'absent', code: 'ENOENT' },
    };
  }
  expect(actual).toEqual(expected);
}

interface UninstallRecoveryOutcomeInput {
  readonly after: UninstallRecoveryState;
  readonly before: UninstallRecoveryState;
  readonly boundary: 'rollback-prepared' | 'commit-decided';
  readonly lockPath: string;
  readonly receipt: string;
  readonly receiptPath: string;
  readonly recovery: RecoveryChildResult;
  readonly registryPath: string;
  readonly registryPreimageJson: string;
  readonly rootPath: string;
}

function expectUninstallRecoveryOutcome(input: UninstallRecoveryOutcomeInput): void {
  const actual =
    input.boundary === 'rollback-prepared'
      ? { recovery: input.recovery, after: input.after }
      : {
          recovery: input.recovery,
          lock: input.after.lock,
          manifest: input.after.manifest,
          credential: input.after.credential,
          target: input.after.target,
          wal: input.after.wal,
          walStage: input.after.walStage,
          receipt: normalizeRecoveryPathSnapshot(input.after.receipt),
          registry: normalizeRecoveryPathSnapshot(input.after.registry),
          tree: normalizeRecoveryFilesystemTree(input.after.tree),
        };
  const expected =
    input.boundary === 'rollback-prepared'
      ? { recovery: { state: 'active' }, after: input.before }
      : {
          recovery: { state: 'uninstalled' },
          lock: input.before.lock,
          manifest: { state: 'absent', code: 'ENOENT' },
          credential: { state: 'absent', code: 'ENOENT' },
          target: { state: 'absent', code: 'ENOENT' },
          wal: { state: 'absent', code: 'ENOENT' },
          walStage: { state: 'absent', code: 'ENOENT' },
          receipt: {
            state: 'present',
            kind: 'file',
            mode: 0o600,
            contents: input.receipt,
          },
          registry: {
            state: 'present',
            kind: 'file',
            mode: 0o600,
            contents: input.registryPreimageJson,
          },
          tree: [
            { path: input.rootPath, snapshot: normalizeRecoveryPathSnapshot(input.before.root) },
            { path: input.lockPath, snapshot: normalizeRecoveryPathSnapshot(input.before.lock) },
            {
              path: input.receiptPath,
              snapshot: {
                state: 'present',
                kind: 'file',
                mode: 0o600,
                contents: input.receipt,
              },
            },
            {
              path: input.registryPath,
              snapshot: {
                state: 'present',
                kind: 'file',
                mode: 0o600,
                contents: input.registryPreimageJson,
              },
            },
          ].sort((left, right) => left.path.localeCompare(right.path)),
        };
  expect(actual).toEqual(expected);
}

interface RecoveryChildResult {
  readonly state: 'active' | 'uninstalled' | 'never-installed' | 'recovery-required';
}
interface RecoveryChildDetailedResult extends RecoveryChildResult {
  readonly failures: readonly { readonly stage: string }[];
}

function isRecoveryChildDetailedResult(value: unknown): value is RecoveryChildDetailedResult {
  return (
    isRecoveryChildResult(value) &&
    'failures' in value &&
    Array.isArray(value.failures) &&
    value.failures.every(
      (failure) =>
        failure !== null &&
        typeof failure === 'object' &&
        !Array.isArray(failure) &&
        Object.keys(failure).length === 1 &&
        'stage' in failure &&
        typeof failure.stage === 'string',
    )
  );
}

function isRecoveryChildResult(value: unknown): value is RecoveryChildResult {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    'state' in value &&
    (value.state === 'active' ||
      value.state === 'uninstalled' ||
      value.state === 'never-installed' ||
      value.state === 'recovery-required')
  );
}

function recoveryChildScript(): string {
  const transactionModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/transaction.ts', import.meta.url).href,
  );
  const portModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/node-transaction-port.ts', import.meta.url)
      .href,
  );
  return [
    `import { recoverLifecycle } from ${transactionModule};`,
    `import { createNodeLifecycleTransactionPort } from ${portModule};`,
    'const main = async () => {',
    "const input = JSON.parse(process.env.SCG_RECOVERY_CHILD_INPUT ?? '');",
    'const result = await recoverLifecycle({',
    '  port: createNodeLifecycleTransactionPort(),',
    '  walPath: input.walPath,',
    '  lockPath: input.lockPath,',
    '  manifestPath: input.manifestPath,',
    '  receiptPath: input.receiptPath,',
    '});',
    'process.stdout.write(JSON.stringify(input.includeFailures === true ? { state: result.state, failures: result.failures.map(({ stage }) => ({ stage })) } : { state: result.state }) + "\\n");',
    '};',
    'void main().catch(() => { process.exitCode = 1; });',
  ].join('\n');
}

async function runRecoveryChild(input: RecoveryChildInput): Promise<RecoveryChildResult> {
  return new Promise((resolveChild, rejectChild) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', '--input-type=module', '--eval', recoveryChildScript()],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SCG_RECOVERY_CHILD_INPUT: JSON.stringify({
            walPath: input.walPath,
            lockPath: input.lockPath,
            manifestPath: input.manifestPath,
            receiptPath: input.receiptPath,
            includeFailures: input.includeFailures === true,
          }),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const maximumOutputBytes = 4096;
    let stdout = '';
    let stderr = '';
    let settled = false;
    const clearChildTimeout = (): void => {
      clearTimeout(timeout);
    };
    const fail = (message: string): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearChildTimeout();
      child.kill('SIGKILL');
      rejectChild(new Error(message));
    };
    const timeout = setTimeout(() => {
      fail('fresh recovery child timed out');
    }, 5_000);
    const append = (stream: 'stdout' | 'stderr', chunk: string): void => {
      const current = stream === 'stdout' ? stdout : stderr;
      if (
        Buffer.byteLength(current, 'utf8') + Buffer.byteLength(chunk, 'utf8') >
        maximumOutputBytes
      ) {
        fail(`fresh recovery child emitted unbounded ${stream}`);
        return;
      }
      if (stream === 'stdout') {
        stdout += chunk;
      } else {
        stderr += chunk;
      }
    };
    child.once('error', () => {
      fail('fresh recovery child could not start');
    });
    if (child.stdout === null || child.stderr === null) {
      fail('fresh recovery child did not expose bounded output streams');
      return;
    }
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      append('stdout', chunk);
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      append('stderr', chunk);
    });
    child.once('close', (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearChildTimeout();
      if (stderr !== '') {
        rejectChild(new Error('fresh recovery child wrote to stderr'));
        return;
      }
      if (code !== 0) {
        rejectChild(new Error('fresh recovery child did not exit successfully'));
        return;
      }
      const lines = stdout.trim().split('\n');
      if (lines.length !== 1 || lines[0] === undefined) {
        rejectChild(new Error('fresh recovery child did not produce one bounded JSON result'));
        return;
      }
      try {
        const result: unknown = JSON.parse(lines[0]);
        if (!isRecoveryChildResult(result)) {
          rejectChild(
            new Error('fresh recovery child result did not satisfy the recovery contract'),
          );
          return;
        }
        resolveChild(result);
      } catch {
        rejectChild(new Error('fresh recovery child produced invalid JSON'));
      }
    });
  });
}
async function runRecoveryChildDetailed(
  input: RecoveryChildInput,
): Promise<RecoveryChildDetailedResult> {
  const result = await runRecoveryChild({ ...input, includeFailures: true });
  if (!isRecoveryChildDetailedResult(result)) {
    throw new Error('fresh recovery child did not produce exact failure stages');
  }
  return result;
}
interface ProducerChildInput extends RecoveryChildInput {
  readonly root: string;
  readonly boundary:
    | 'prepared-before-stage'
    | 'credential-staged-before-publication'
    | 'credential-publication'
    | 'commit-decision';
  readonly operationId: string;
  readonly installId: string;
  readonly credentialPath: string;
  readonly credentialStagingPath: string;
  readonly registryPath: string;
  readonly credentialContent: string;
}
interface WalStageProducerChildInput extends RecoveryChildInput {
  readonly root: string;
  readonly boundary: 'initial-publication' | 'replacement';
  readonly operationId: string;
  readonly installId: string;
  readonly credentialPath: string;
  readonly credentialStagingPath: string;
}

interface UninstallProducerChildInput extends RecoveryChildInput {
  readonly root: string;
  readonly boundary: 'rollback-prepared' | 'commit-decided';
  readonly operationId: string;
  readonly manifestJson: string;
  readonly receipt: string;
  readonly targetPath: string;
  readonly targetFingerprint: string;
  readonly credentialPath: string;
  readonly registryPath: string;
  readonly registryPostimage: unknown;
  readonly registryFingerprint: string;
  readonly expectedMutationCount: number;
}

function producerChildScript(): string {
  const transactionModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/transaction.ts', import.meta.url).href,
  );
  const portModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/node-transaction-port.ts', import.meta.url)
      .href,
  );
  const credentialAuthorityModule = JSON.stringify(
    new URL('../../packages/onboarding/src/credential-authority.ts', import.meta.url).href,
  );
  return [
    "import { createHash } from 'node:crypto';",
    "import { readFile } from 'node:fs/promises';",
    `import { applySetupTransaction, openSetupTransactionAuthority, publishSetupTransaction } from ${transactionModule};`,
    `import { createNodeLifecycleTransactionPort } from ${portModule};`,
    `import { serializeCredentialAuthorityRegistryV1 } from ${credentialAuthorityModule};`,
    'const main = async () => {',
    "const input = JSON.parse(process.env.SCG_PRODUCER_CHILD_INPUT ?? '');",
    'const port = createNodeLifecycleTransactionPort();',
    'const waitAtDurableBoundary = async () => {',
    '  await new Promise((resolve, reject) => {',
    "    process.stdout.write('durable\\n', (error) => {",
    '      if (error === undefined || error === null) resolve();',
    '      else reject(error);',
    '    });',
    '  });',
    '  return new Promise(() => undefined);',
    '};',
    'const fsyncParent = port.fsyncParent.bind(port);',
    'port.fsyncParent = async (request) => {',
    '  await fsyncParent(request);',
    '  if (request.path !== input.walPath) return;',
    "  const wal = JSON.parse(await readFile(input.walPath, 'utf8'));",
    "  const credential = wal.mutations.find((mutation) => mutation.kind === 'credential' && mutation.path === input.credentialPath);",
    "  const durable = input.boundary === 'prepared-before-stage'",
    "    ? wal.direction === 'rollback' && wal.phase === 'prepared' && wal.cursor === 0 && wal.mutations.length === 0",
    "    : input.boundary === 'credential-publication'",
    "      ? wal.direction === 'rollback' && wal.phase === 'prepared' && credential !== undefined && wal.cursor === credential.step + 1",
    "      : wal.direction === 'commit' && wal.phase === 'commit-decided';",
    '  if (!durable) return;',
    '  await waitAtDurableBoundary();',
    '};',
    'const writeReservedStagedWrite = port.writeReservedStagedWrite.bind(port);',
    'port.writeReservedStagedWrite = async (request) => {',
    '  await writeReservedStagedWrite(request);',
    "  if (input.boundary !== 'credential-staged-before-publication') return;",
    "  const wal = JSON.parse(await readFile(input.walPath, 'utf8'));",
    "  const credential = wal.mutations.find((mutation) => mutation.kind === 'credential' && mutation.path === input.credentialPath);",
    "  const durable = wal.direction === 'rollback' && wal.phase === 'prepared' && credential !== undefined && wal.cursor === credential.step;",
    "  if (!durable) throw new Error('credential stage was not durably journaled before publication');",
    '  await waitAtDurableBoundary();',
    '};',
    'const authority = await openSetupTransactionAuthority({',
    '  operationId: input.operationId,',
    '  installId: input.installId,',
    '  port,',
    '  lockPath: input.lockPath,',
    '  walPath: input.walPath,',
    '  manifestPath: input.manifestPath,',
    "  preimages: [{ path: input.credentialPath, state: 'absent' }],",
    '  credential: {',
    "    projectId: 'producer-credential-project',",
    '    path: input.credentialPath,',
    '    stagingPath: input.credentialStagingPath,',
    '    mode: 0o600,',
    '  },',
    '});',
    'const reservedCreatedCredential = authority.reservedCreatedCredential;',
    "if (reservedCreatedCredential === undefined) throw new Error('producer did not reserve credential authority');",
    "if (reservedCreatedCredential.projectId !== 'producer-credential-project' || reservedCreatedCredential.path !== input.credentialPath || reservedCreatedCredential.mode !== 0o600) throw new Error('producer reserved credential authority differs from its candidate');",
    'const registryPreimage = { schemaVersion: 1, projects: [] };',
    'const registryPostimage = {',
    '  schemaVersion: 1,',
    '  projects: [{',
    '    projectId: reservedCreatedCredential.projectId,',
    "    tokenEnv: 'SCENE_GLASS_HOST_TOKEN',",
    '    canonicalRoot: input.root,',
    '    credentialPath: reservedCreatedCredential.path,',
    '    device: reservedCreatedCredential.identity.device,',
    '    inode: reservedCreatedCredential.identity.inode,',
    '  }],',
    '};',
    "const registryFingerprint = `sha256:${createHash('sha256').update(serializeCredentialAuthorityRegistryV1(registryPostimage), 'utf8').digest('hex')}`;",
    'const finalization = Object.freeze({',
    '  manifest: {',
    "    schemaVersion: 1, kind: 'scene-glass-setup-manifest', installId: input.installId, state: 'active',",
    '    artifacts: [',
    "      { path: reservedCreatedCredential.path, kind: 'credential', ownership: 'setup-created', projectId: reservedCreatedCredential.projectId, identity: reservedCreatedCredential.identity, mode: reservedCreatedCredential.mode, linkCount: reservedCreatedCredential.linkCount, inverse: { kind: 'delete-created-credential', path: reservedCreatedCredential.path, projectId: reservedCreatedCredential.projectId, identity: reservedCreatedCredential.identity, mode: reservedCreatedCredential.mode, linkCount: reservedCreatedCredential.linkCount } },",
    "      { path: input.registryPath, kind: 'credential-authority-registry', fingerprint: registryFingerprint, preimage: registryPreimage, postimage: registryPostimage, inverse: { kind: 'restore-credential-authority-registry-entry', path: input.registryPath, preimage: registryPreimage, postimage: registryPostimage } },",
    '    ],',
    '  },',
    "  operations: Object.freeze([{ kind: 'apply-credential-authority-registry', path: input.registryPath, preimage: registryPreimage, postimage: registryPostimage, fingerprint: registryFingerprint, mode: 0o600 }]),",
    "  preimages: Object.freeze([{ path: input.registryPath, state: 'absent' }]),",
    '});',
    'const applied = await applySetupTransaction({',
    '  authority,',
    '  operationId: input.operationId,',
    '  installId: input.installId,',
    '  credential: {',
    "    projectId: 'producer-credential-project',",
    '    path: input.credentialPath,',
    '    stagingPath: input.credentialStagingPath,',
    '    mode: 0o600,',
    '    contentBytes: new TextEncoder().encode(input.credentialContent),',
    '  },',
    '  finalization,',
    '});',
    "if (!('manifest' in applied)) throw new Error('producer setup did not apply');",
    "if (input.boundary === 'commit-decision') await publishSetupTransaction(applied);",
    "throw new Error('producer passed its durable boundary');",
    '};',
    'void main().catch(() => { process.exitCode = 1; });',
  ].join('\n');
}

function walStageProducerChildScript(): string {
  const transactionModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/transaction.ts', import.meta.url).href,
  );
  const portModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/node-transaction-port.ts', import.meta.url)
      .href,
  );
  return [
    `import { openSetupTransactionAuthority } from ${transactionModule};`,
    `import { createNodeLifecycleTransactionPort } from ${portModule};`,
    'const main = async () => {',
    "const input = JSON.parse(process.env.SCG_WAL_STAGE_PRODUCER_CHILD_INPUT ?? '');",
    'const port = createNodeLifecycleTransactionPort();',
    'const waitAtDurableBoundary = async () => {',
    '  await new Promise((resolve, reject) => {',
    "    process.stdout.write('durable\\n', (error) => {",
    '      if (error === undefined || error === null) resolve();',
    '      else reject(error);',
    '    });',
    '  });',
    '  return new Promise(() => undefined);',
    '};',
    "const walStagePath = input.walPath + '.scene-glass-wal.stage';",
    'const stageWrite = port.stageWrite.bind(port);',
    'port.stageWrite = async (request) => {',
    '  const staged = await stageWrite(request);',
    '  if (request.stagingPath !== walStagePath) return staged;',
    '  const wal = JSON.parse(new TextDecoder().decode(request.bytes));',
    "  const durable = input.boundary === 'initial-publication'",
    "    ? wal.operation === 'setup' && wal.direction === 'rollback' && wal.phase === 'prepared' && wal.cursor === 0 && wal.mutations.length === 0 && Array.isArray(wal.creationIntents) && wal.creationIntents.length === 1",
    "    : wal.operation === 'setup' && wal.direction === 'rollback' && wal.phase === 'prepared' && wal.cursor === 0 && wal.mutations.length === 1 && !('creationIntents' in wal);",
    '  if (durable) await waitAtDurableBoundary();',
    '  return staged;',
    '};',
    'await openSetupTransactionAuthority({',
    '  operationId: input.operationId,',
    '  installId: input.installId,',
    '  port,',
    '  lockPath: input.lockPath,',
    '  walPath: input.walPath,',
    '  manifestPath: input.manifestPath,',
    "  preimages: [{ path: input.credentialPath, state: 'absent' }],",
    '  credential: {',
    "    projectId: 'wal-stage-producer-project',",
    '    path: input.credentialPath,',
    '    stagingPath: input.credentialStagingPath,',
    '    mode: 0o600,',
    '  },',
    '});',
    "throw new Error('wal stage producer passed its durable boundary');",
    '};',
    'void main().catch(() => { process.exitCode = 1; });',
  ].join('\n');
}

function uninstallProducerChildScript(): string {
  const transactionModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/transaction.ts', import.meta.url).href,
  );
  const portModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/node-transaction-port.ts', import.meta.url)
      .href,
  );
  const provenanceModule = JSON.stringify(
    new URL('../../packages/onboarding/src/lifecycle/provenance.ts', import.meta.url).href,
  );
  return [
    "import { Buffer } from 'node:buffer';",
    "import { readFile } from 'node:fs/promises';",
    `import { applyUninstallTransaction } from ${transactionModule};`,
    `import { createNodeLifecycleTransactionPort } from ${portModule};`,
    `import { validateUninstallPreflight } from ${provenanceModule};`,
    'const main = async () => {',
    "const input = JSON.parse(process.env.SCG_UNINSTALL_PRODUCER_CHILD_INPUT ?? '');",
    'const port = createNodeLifecycleTransactionPort();',
    'const waitAtDurableBoundary = async () => {',
    '  await new Promise((resolve, reject) => {',
    "    process.stdout.write('durable\\n', (error) => {",
    '      if (error === undefined || error === null) resolve();',
    '      else reject(error);',
    '    });',
    '  });',
    '  return new Promise(() => undefined);',
    '};',
    'const hasTerminalMutationAuthority = (wal) => {',
    "  const receiptMutations = wal.mutations.filter((mutation) => mutation.kind === 'ordinary' && mutation.targetPath === input.receiptPath);",
    "  const manifestMutations = wal.mutations.filter((mutation) => mutation.kind === 'ordinary' && mutation.targetPath === input.manifestPath);",
    '  const receiptMutation = receiptMutations[0];',
    '  const manifestMutation = manifestMutations[0];',
    '  const receiptPreimage = receiptMutation === undefined ? undefined : wal.preimages[receiptMutation.preimage];',
    '  const manifestPreimage = manifestMutation === undefined ? undefined : wal.preimages[manifestMutation.preimage];',
    '  return (',
    '    receiptMutations.length === 1 &&',
    '    manifestMutations.length === 1 &&',
    '    receiptMutation !== undefined &&',
    '    manifestMutation !== undefined &&',
    "    receiptMutation.result.kind === 'file' &&",
    '    receiptMutation.result.mode === 0o600 &&',
    "    receiptMutation.result.bytes === Buffer.from(input.receipt, 'utf8').toString('base64') &&",
    "    manifestMutation.result.kind === 'absent' &&",
    '    receiptPreimage !== undefined &&',
    "    receiptPreimage.kind === 'absent' &&",
    '    manifestPreimage !== undefined &&',
    "    manifestPreimage.kind === 'file' &&",
    "    Buffer.from(manifestPreimage.bytes, 'base64').toString('utf8') === input.manifestJson &&",
    '    JSON.stringify(wal.manifest) === JSON.stringify(JSON.parse(input.manifestJson))',
    '  );',
    '};',
    'const replaceExactWal = port.replaceExactWal.bind(port);',
    'port.replaceExactWal = async (request) => {',
    '  const result = await replaceExactWal(request);',
    "  const wal = JSON.parse(await readFile(input.walPath, 'utf8'));",
    "  const rollbackReady = wal.operation === 'uninstall' && wal.direction === 'rollback' && wal.phase === 'prepared' && wal.cursor === input.expectedMutationCount && wal.mutations.length === input.expectedMutationCount && wal.creationIntents === undefined && hasTerminalMutationAuthority(wal);",
    "  const commitReady = wal.operation === 'uninstall' && wal.direction === 'commit' && wal.phase === 'commit-decided' && wal.cursor === input.expectedMutationCount && wal.mutations.length === input.expectedMutationCount && hasTerminalMutationAuthority(wal);",
    "  if ((input.boundary === 'rollback-prepared' && rollbackReady) || (input.boundary === 'commit-decided' && commitReady)) await waitAtDurableBoundary();",
    '  return result;',
    '};',
    'const manifest = JSON.parse(input.manifestJson);',
    'const preflight = validateUninstallPreflight({',
    '  manifest,',
    '  observed: [',
    '    { path: input.targetPath, fingerprint: input.targetFingerprint, hunks: [], semanticConfig: undefined },',
    '    { path: input.credentialPath, fingerprint: undefined, hunks: [], semanticConfig: undefined },',
    '    { path: input.registryPath, fingerprint: input.registryFingerprint, hunks: [], semanticConfig: undefined, semanticCredentialAuthorityRegistry: input.registryPostimage },',
    '  ],',
    '});',
    "if (!preflight.canUninstall) throw new Error('uninstall producer preflight was not accepted');",
    'await applyUninstallTransaction({',
    '  manifest,',
    '  operationId: input.operationId,',
    '  preflight,',
    '  walPath: input.walPath,',
    '  manifestPath: input.manifestPath,',
    '  receiptPath: input.receiptPath,',
    '  lockPath: input.lockPath,',
    '  port,',
    '});',
    "throw new Error('uninstall producer passed its durable boundary');",
    '};',
    'void main().catch(() => { process.exitCode = 1; });',
  ].join('\n');
}

interface BoundedProducerChildInput {
  readonly script: string;
  readonly environment: string;
  readonly input: unknown;
  readonly label: string;
}

async function runBoundedProducerAndKill(input: BoundedProducerChildInput): Promise<void> {
  return new Promise((resolveChild, rejectChild) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', '--input-type=module', '--eval', input.script],
      {
        cwd: process.cwd(),
        env: { ...process.env, [input.environment]: JSON.stringify(input.input) },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const maximumOutputBytes = 4096;
    let stdout = '';
    let stderr = '';
    let killed = false;
    let settled = false;
    const finish = (error: Error | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error === undefined) resolveChild();
      else rejectChild(error);
    };
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error(`${input.label} did not reach its durable boundary`));
    }, 5_000);
    const append = (stream: 'stdout' | 'stderr', chunk: string): void => {
      const current = stream === 'stdout' ? stdout : stderr;
      if (
        Buffer.byteLength(current, 'utf8') + Buffer.byteLength(chunk, 'utf8') >
        maximumOutputBytes
      ) {
        child.kill('SIGKILL');
        finish(new Error(`${input.label} emitted unbounded ${stream}`));
        return;
      }
      if (stream === 'stdout') stdout += chunk;
      else stderr += chunk;
    };
    child.once('error', () => finish(new Error(`${input.label} could not start`)));
    if (child.stdout === null || child.stderr === null) {
      child.kill('SIGKILL');
      finish(new Error(`${input.label} did not expose bounded output streams`));
      return;
    }
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      append('stdout', chunk);
      if (!killed && stdout === 'durable\n') {
        killed = child.kill('SIGKILL');
        if (!killed) finish(new Error(`${input.label} could not be terminated`));
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => append('stderr', chunk));
    child.once('close', (code, signal) => {
      if (settled) return;
      if (stderr !== '') {
        finish(new Error(`${input.label} wrote to stderr`));
        return;
      }
      if (!killed || signal !== 'SIGKILL' || code !== null || stdout !== 'durable\n') {
        finish(new Error(`${input.label} did not terminate at its durable boundary`));
        return;
      }
      finish(undefined);
    });
  });
}

async function runProducerAndKill(input: ProducerChildInput): Promise<void> {
  return runBoundedProducerAndKill({
    script: producerChildScript(),
    environment: 'SCG_PRODUCER_CHILD_INPUT',
    input,
    label: `producer child (${input.boundary})`,
  });
}

async function runWalStageProducerAndKill(input: WalStageProducerChildInput): Promise<void> {
  return runBoundedProducerAndKill({
    script: walStageProducerChildScript(),
    environment: 'SCG_WAL_STAGE_PRODUCER_CHILD_INPUT',
    input,
    label: 'WAL stage producer child',
  });
}

async function runUninstallProducerAndKill(input: UninstallProducerChildInput): Promise<void> {
  return runBoundedProducerAndKill({
    script: uninstallProducerChildScript(),
    environment: 'SCG_UNINSTALL_PRODUCER_CHILD_INPUT',
    input,
    label: 'uninstall producer child',
  });
}
