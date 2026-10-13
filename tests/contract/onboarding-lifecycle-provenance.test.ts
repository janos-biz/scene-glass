import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';
import { reconstructOwnedStaticFilePreimage } from '../../packages/onboarding/src/lifecycle/node-transaction-port.js';
import { STATIC_LOADER_MARKER } from '../../packages/onboarding/src/lifecycle/host-plan.js';
import {
  VITE_SNAPSHOT_COMMITMENT_DIRECTORY,
  VITE_SNAPSHOT_COMMITMENT_MAX_BYTES,
  VITE_SNAPSHOT_ROOT_DIRECTORY,
} from '../../packages/onboarding/src/vite/index.js';
import {
  assertLifecycleTarget,
  finalizeSetupManifestV1,
  parseHostWalRecordV3,
  parseHostSetupManifestV2,
  parseLifecycleReceiptJsonV1,
  parseSetupManifestV1,
  parseSetupManifestJsonV1,
  parseWalRecord,
  parseWalRecordJson,
  parseWalRecordJsonV2,
  parseWalRecordV2,
  serializeHostWalRecordV3,
  serializeHostLifecycleReceiptV2,
  serializeHostSetupManifestV2,
  serializeLifecycleReceiptV1,
  serializeSetupManifestV1,
  serializeWalRecord,
  serializeWalRecordV1,
  serializeWalRecordV2,
  translateLegacyWalV2ToHostV3,
  validateOwnedArtifacts,
  validateUninstallPreflight,
} from '../../packages/onboarding/src/lifecycle/provenance.js';

const FINGERPRINT_A = `sha256:${'a'.repeat(64)}`;
const FINGERPRINT_B = `sha256:${'b'.repeat(64)}`;
const WAL_IDENTITY = { device: '11', inode: '12' } as const;
const HOST_CONTEXT = {
  hostRoot: '/host',
  checkoutRoot: '/checkout',
  homeDir: '/home/test',
  selectedConfigDir: '/state',
  installId: 'install-alpha',
} as const;
const CONFIG_PATH = '/state/config.json';
const PROJECT = {
  projectId: 'alpha',
  root: '/srv/alpha',
  allowedOrigins: ['https://alpha.example.test'],
  tokenEnv: 'SCG_ALPHA_TOKEN',
  framework: 'react',
} as const;
const HUNK = {
  id: 'project-alpha',
  fingerprint: FINGERPRINT_A,
  operation: 'insert',
  subject: 'alpha',
} as const;
const PREIMAGE = { schemaVersion: 1, projects: [] } as const;
const POSTIMAGE = { schemaVersion: 1, projects: [PROJECT] } as const;
const CONFIG_ARTIFACT = {
  path: CONFIG_PATH,
  kind: 'config',
  fingerprint: FINGERPRINT_A,
  hunks: [HUNK],
  preimage: PREIMAGE,
  postimage: POSTIMAGE,
  inverse: {
    kind: 'remove-config-hunks',
    path: CONFIG_PATH,
    hunks: [HUNK],
    preimage: PREIMAGE,
    postimage: POSTIMAGE,
  },
} as const;
const REGISTRY_PATH = '/state/credential-authorities.v1.json';
const CREATED_CREDENTIAL = {
  path: REGISTRY_PATH,
  kind: 'credential',
  ownership: 'setup-created',
  projectId: 'alpha',
  identity: WAL_IDENTITY,
  mode: 0o600,
  linkCount: 1,
  inverse: {
    kind: 'delete-created-credential',
    path: REGISTRY_PATH,
    projectId: 'alpha',
    identity: WAL_IDENTITY,
    mode: 0o600,
    linkCount: 1,
  },
} as const;
const REGISTRY_ALPHA = {
  projectId: 'alpha',
  tokenEnv: 'SCG_ALPHA_TOKEN',
  canonicalRoot: '/srv/alpha',
  credentialPath: '/srv/alpha/.scene-glass/credential',
  device: '11',
  inode: '12',
} as const;
const REGISTRY_ALPHA_UPDATED = {
  ...REGISTRY_ALPHA,
  tokenEnv: 'SCG_ALPHA_ROTATED_TOKEN',
  credentialPath: '/srv/alpha/.scene-glass/credential-rotated',
  inode: '13',
} as const;
const REGISTRY_BETA = {
  projectId: 'beta',
  tokenEnv: 'SCG_BETA_TOKEN',
  canonicalRoot: '/srv/beta',
  credentialPath: '/srv/beta/.scene-glass/credential',
  device: '21',
  inode: '22',
} as const;
const REGISTRY_EMPTY = { schemaVersion: 1, projects: [] } as const;
const REGISTRY_ALPHA_IMAGE = { schemaVersion: 1, projects: [REGISTRY_ALPHA] } as const;
const REGISTRY_ALPHA_UPDATED_IMAGE = {
  schemaVersion: 1,
  projects: [REGISTRY_ALPHA_UPDATED],
} as const;
const REGISTRY_ALPHA_FINGERPRINT =
  'sha256:0a4496203ec26a1c2692a69d3a70718859cbb02e5aef780c8ce5427acf4ad07a';
const REGISTRY_ALPHA_UPDATED_FINGERPRINT =
  'sha256:6e3cc6e654a78af498959fa6dd6c7c6a60e780aa0ddde8d1f619676cc18c6abc';
const REGISTRY_EMPTY_FINGERPRINT =
  'sha256:211a77112c07ac15538b81d8de7148b52d12d9160aac0240334cdc1a00c4306f';
const REGISTRY_ALPHA_UPDATED_WITH_BETA_FINGERPRINT =
  'sha256:463865c95e848950f7d7a89198a9bc02034f1ca526545c18909aa8417be02d65';
function registryArtifact(preimage: unknown, postimage: unknown, fingerprint: string) {
  return {
    path: REGISTRY_PATH,
    kind: 'credential-authority-registry' as const,
    fingerprint,
    preimage,
    postimage,
    inverse: {
      kind: 'restore-credential-authority-registry-entry' as const,
      path: REGISTRY_PATH,
      preimage,
      postimage,
    },
  };
}
const MANIFEST = {
  schemaVersion: 1,
  kind: 'scene-glass-setup-manifest',
  installId: 'install-alpha',
  state: 'active',
  artifacts: [CONFIG_ARTIFACT, CREATED_CREDENTIAL],
} as const;

function observedConfig(
  overrides: Partial<{
    hunks: readonly { readonly id: string; readonly fingerprint: string }[];
    semanticConfig: unknown;
  }> = {},
) {
  return {
    path: CONFIG_PATH,
    fingerprint: FINGERPRINT_B,
    hunks: [HUNK],
    semanticConfig: { schemaVersion: 1, projects: [PROJECT] },
    ...overrides,
  };
}

function observedCredential() {
  return {
    path: REGISTRY_PATH,
    fingerprint: undefined,
    hunks: [],
    semanticConfig: undefined,
  };
}
const WAL_RESULT_IDENTITY = { device: '11', inode: '13' } as const;
const WAL_DIRECTORY_RESULT = {
  kind: 'directory',
  identity: WAL_RESULT_IDENTITY,
  mode: 0o700,
};

const WAL_V2_MANIFEST = {
  schemaVersion: 1,
  kind: 'scene-glass-setup-manifest',
  installId: 'install-alpha',
  state: 'active',
  artifacts: [
    {
      path: '/state/config.json',
      kind: 'file',
      fingerprint: FINGERPRINT_A,
      hunks: [],
      inverse: {
        kind: 'delete-created-file',
        path: '/state/config.json',
        expectedFingerprint: FINGERPRINT_A,
      },
    },
    {
      path: '/state/credential',
      kind: 'credential',
      ownership: 'setup-created',
      projectId: 'alpha',
      identity: WAL_IDENTITY,
      mode: 0o600,
      linkCount: 1,
      inverse: {
        kind: 'delete-created-credential',
        path: '/state/credential',
        projectId: 'alpha',
        identity: WAL_IDENTITY,
        mode: 0o600,
        linkCount: 1,
      },
    },
  ],
} as const;
const WAL_V2_RECEIPT_BYTES =
  'ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1saWZlY3ljbGUtcmVjZWlwdCIsCiAgIm9wZXJhdGlvbklkIjogIm9wZXJhdGlvbi1hbHBoYSIsCiAgImluc3RhbGxJZCI6ICJpbnN0YWxsLWFscGhhIiwKICAidGVybWluYWxTdGF0ZSI6ICJ1bmluc3RhbGxlZCIsCiAgIm1hbmlmZXN0RmluZ2VycHJpbnQiOiAic2hhMjU2OmI5MjdkYjVhY2I3Y2JjM2QxMGIwNTE4NTc0ZGY3ZWU2MmNkMDEwZDdlMDcxOTJhMmNjYTMzZWZhMDg5NzYwMjUiCn0K';

const GOLDEN_MANIFEST_JSON = `{
  "schemaVersion": 1,
  "kind": "scene-glass-setup-manifest",
  "installId": "golden-install",
  "state": "active",
  "artifacts": []
}
`;
const GOLDEN_RECEIPT_JSON = `{
  "schemaVersion": 1,
  "kind": "scene-glass-lifecycle-receipt",
  "operationId": "golden-receipt-operation",
  "installId": "golden-install",
  "terminalState": "uninstalled",
  "manifestFingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
`;
const GOLDEN_SETUP_PREPARED_WAL_JSON = `{
  "schemaVersion": 2,
  "kind": "scene-glass-lifecycle-wal",
  "operationId": "golden-setup-prepared",
  "installId": "golden-install",
  "operation": "setup",
  "direction": "rollback",
  "phase": "prepared",
  "lockPath": "/golden/lifecycle.lock",
  "manifestPath": "/golden/manifest.json",
  "cursor": 0,
  "preimages": [],
  "mutations": [],
  "authorityFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
`;
const GOLDEN_SETUP_FINALIZED_WAL_JSON = `{
  "schemaVersion": 2,
  "kind": "scene-glass-lifecycle-wal",
  "operationId": "golden-setup-finalized",
  "installId": "golden-install",
  "operation": "setup",
  "direction": "rollback",
  "phase": "finalized",
  "lockPath": "/golden/lifecycle.lock",
  "manifestPath": "/golden/manifest.json",
  "cursor": 0,
  "preimages": [],
  "mutations": [],
  "authorityFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
`;
const GOLDEN_SETUP_COMMITTED_WAL_JSON = `{
  "schemaVersion": 2,
  "kind": "scene-glass-lifecycle-wal",
  "operationId": "golden-setup-committed",
  "installId": "golden-install",
  "operation": "setup",
  "direction": "commit",
  "phase": "commit-decided",
  "lockPath": "/golden/lifecycle.lock",
  "manifestPath": "/golden/manifest.json",
  "cursor": 0,
  "preimages": [],
  "mutations": [],
  "authorityFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
`;
const GOLDEN_UNINSTALL_PREPARED_WAL_JSON = `{
  "schemaVersion": 2,
  "kind": "scene-glass-lifecycle-wal",
  "operationId": "golden-uninstall-prepared",
  "installId": "golden-install",
  "operation": "uninstall",
  "direction": "rollback",
  "phase": "prepared",
  "lockPath": "/golden/lifecycle.lock",
  "manifestPath": "/golden/manifest.json",
  "cursor": 0,
  "preimages": [
    {
      "path": "/golden/manifest.json",
      "kind": "file",
      "identity": {
        "device": "11",
        "inode": "12"
      },
      "mode": 384,
      "bytes": "ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1zZXR1cC1tYW5pZmVzdCIsCiAgImluc3RhbGxJZCI6ICJnb2xkZW4taW5zdGFsbCIsCiAgInN0YXRlIjogImFjdGl2ZSIsCiAgImFydGlmYWN0cyI6IFtdCn0K"
    },
    {
      "path": "/golden/receipt.json",
      "kind": "absent"
    }
  ],
  "mutations": [],
  "authorityFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "receiptPath": "/golden/receipt.json",
  "manifest": {
    "schemaVersion": 1,
    "kind": "scene-glass-setup-manifest",
    "installId": "golden-install",
    "state": "active",
    "artifacts": []
  }
}
`;
const GOLDEN_UNINSTALL_COMMITTED_WAL_JSON = `{
  "schemaVersion": 2,
  "kind": "scene-glass-lifecycle-wal",
  "operationId": "golden-uninstall-committed",
  "installId": "golden-install",
  "operation": "uninstall",
  "direction": "commit",
  "phase": "commit-decided",
  "lockPath": "/golden/lifecycle.lock",
  "manifestPath": "/golden/manifest.json",
  "cursor": 2,
  "preimages": [
    {
      "path": "/golden/manifest.json",
      "kind": "file",
      "identity": {
        "device": "11",
        "inode": "12"
      },
      "mode": 384,
      "bytes": "ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1zZXR1cC1tYW5pZmVzdCIsCiAgImluc3RhbGxJZCI6ICJnb2xkZW4taW5zdGFsbCIsCiAgInN0YXRlIjogImFjdGl2ZSIsCiAgImFydGlmYWN0cyI6IFtdCn0K"
    },
    {
      "path": "/golden/receipt.json",
      "kind": "absent"
    }
  ],
  "mutations": [
    {
      "step": 0,
      "kind": "ordinary",
      "targetPath": "/golden/receipt.json",
      "sourcePath": "/golden/receipt-source.json",
      "stagingPath": "/golden/.receipt.stage",
      "preimage": 1,
      "result": {
        "kind": "file",
        "identity": {
          "device": "11",
          "inode": "13"
        },
        "mode": 384,
        "bytes": "ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1saWZlY3ljbGUtcmVjZWlwdCIsCiAgIm9wZXJhdGlvbklkIjogImdvbGRlbi11bmluc3RhbGwtY29tbWl0dGVkIiwKICAiaW5zdGFsbElkIjogImdvbGRlbi1pbnN0YWxsIiwKICAidGVybWluYWxTdGF0ZSI6ICJ1bmluc3RhbGxlZCIsCiAgIm1hbmlmZXN0RmluZ2VycHJpbnQiOiAic2hhMjU2OmJjNzA5NzVmNzUyZGM0MGYzYTg0YzJmMjBmODkwMDIzY2UyYjlhODc3YjRlNjFkY2NhZjRmYjdhODllNDMwYmQiCn0K"
      }
    },
    {
      "step": 1,
      "kind": "ordinary",
      "targetPath": "/golden/manifest.json",
      "sourcePath": "/golden/manifest-source.json",
      "stagingPath": "/golden/.manifest.stage",
      "preimage": 0,
      "result": {
        "kind": "absent"
      }
    }
  ],
  "authorityFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "receiptPath": "/golden/receipt.json",
  "manifest": {
    "schemaVersion": 1,
    "kind": "scene-glass-setup-manifest",
    "installId": "golden-install",
    "state": "active",
    "artifacts": []
  }
}
`;
function setupWalV2(
  phase: 'prepared' | 'finalized' | 'commit-decided' = 'prepared',
  direction: 'rollback' | 'commit' = 'rollback',
  cursor: number = 0,
) {
  return {
    schemaVersion: 2,
    kind: 'scene-glass-lifecycle-wal',
    operationId: 'operation-alpha',
    installId: 'install-alpha',
    operation: 'setup',
    direction,
    phase,
    lockPath: '/state/lifecycle.lock',
    manifestPath: '/state/manifest.json',
    cursor,
    preimages: [
      { path: '/state/config.json', kind: 'absent' },
      { path: '/state/credential', kind: 'absent' },
    ],
    mutations: [
      {
        step: 0,
        kind: 'ordinary',
        targetPath: '/state/config.json',
        sourcePath: '/state/config-source.json',
        stagingPath: '/state/.config.stage',
        preimage: 0,
        result: {
          kind: 'file',
          identity: WAL_RESULT_IDENTITY,
          mode: 0o600,
          bytes: 'Y29uZmlnCg==',
        },
      },
      {
        step: 1,
        kind: 'credential',
        projectId: 'alpha',
        path: '/state/credential',
        mode: 0o600,
        stagingPath: '/state/.credential.stage',
        stagingIdentity: WAL_IDENTITY,
        targetIdentity: WAL_IDENTITY,
      },
    ],
    authorityFingerprint: FINGERPRINT_A,
  };
}
function setupWalV2WithCreationIntent(validationToken = '0'.repeat(32)) {
  const record = setupWalV2();
  return {
    schemaVersion: record.schemaVersion,
    kind: record.kind,
    operationId: record.operationId,
    installId: record.installId,
    operation: record.operation,
    direction: record.direction,
    phase: record.phase,
    lockPath: record.lockPath,
    manifestPath: record.manifestPath,
    cursor: record.mutations.length,
    preimages: [
      ...record.preimages,
      { path: '/state/new-credential', kind: 'absent' },
      { path: '/state/.new-credential.stage', kind: 'absent' },
    ],
    mutations: record.mutations,
    creationIntents: [
      {
        step: record.mutations.length,
        kind: 'credential',
        targetPath: '/state/new-credential',
        stagingPath: '/state/.new-credential.stage',
        mode: 0o600,
        validationToken,
        targetPreimage: 2,
        stagingPreimage: 3,
      },
    ],
    authorityFingerprint: record.authorityFingerprint,
  };
}

function setupWalV2WithDirectoryResult(
  phase: 'prepared' | 'finalized' | 'commit-decided' = 'prepared',
  direction: 'rollback' | 'commit' = 'rollback',
  cursor: number = 0,
  result: unknown = WAL_DIRECTORY_RESULT,
) {
  const record = setupWalV2(phase, direction, cursor);
  return {
    ...record,
    mutations: record.mutations.map((mutation, index) =>
      index === 0 ? { ...mutation, result } : mutation,
    ),
  };
}

function uninstallWalV2(
  phase: 'prepared' | 'commit-decided' = 'prepared',
  direction: 'rollback' | 'commit' = 'rollback',
  cursor: number = 0,
) {
  const terminalMutations =
    phase === 'commit-decided' && direction === 'commit'
      ? [
          {
            step: 1,
            kind: 'ordinary',
            targetPath: '/state/receipt.json',
            sourcePath: '/state/receipt-source.json',
            stagingPath: '/state/.receipt.stage',
            preimage: 3,
            result: {
              kind: 'file',
              identity: WAL_RESULT_IDENTITY,
              mode: 0o600,
              bytes: WAL_V2_RECEIPT_BYTES,
            },
          },
          {
            step: 2,
            kind: 'ordinary',
            targetPath: '/state/manifest.json',
            sourcePath: '/state/manifest-source.json',
            stagingPath: '/state/.manifest.stage',
            preimage: 0,
            result: { kind: 'absent' },
          },
        ]
      : [];
  return {
    schemaVersion: 2,
    kind: 'scene-glass-lifecycle-wal',
    operationId: 'operation-alpha',
    installId: 'install-alpha',
    operation: 'uninstall',
    direction,
    phase,
    lockPath: '/state/lifecycle.lock',
    manifestPath: '/state/manifest.json',
    cursor,
    preimages: [
      {
        path: '/state/manifest.json',
        kind: 'file',
        identity: WAL_IDENTITY,
        mode: 0o600,
        bytes: Buffer.from(serializeSetupManifestV1(WAL_V2_MANIFEST), 'utf8').toString('base64'),
      },
      { path: '/state/config.json', kind: 'absent' },
      {
        path: '/state/credential',
        kind: 'credential',
        identity: WAL_RESULT_IDENTITY,
        mode: 0o600,
      },
      { path: '/state/receipt.json', kind: 'absent' },
    ],
    mutations: [
      {
        step: 0,
        kind: 'ordinary',
        targetPath: '/state/config.json',
        sourcePath: '/state/config-source.json',
        stagingPath: '/state/.config.stage',
        preimage: 1,
        result: { kind: 'absent' },
      },
      ...terminalMutations,
    ],
    authorityFingerprint: FINGERPRINT_A,
    receiptPath: '/state/receipt.json',
    manifest: WAL_V2_MANIFEST,
  };
}
function hostUninstallWalV3() {
  const v2 = uninstallWalV2('commit-decided', 'commit', 3);
  const manifest = {
    schemaVersion: 2,
    kind: 'scene-glass-host-setup-manifest',
    installId: 'install-alpha',
    state: 'active',
    hostRoot: '/host',
    stateRoot: '/host/.scg/onboarding',
    artifacts: WAL_V2_MANIFEST.artifacts,
  } as const;
  const manifestBytes = serializeHostSetupManifestV2(manifest);
  const receiptBytes = serializeHostLifecycleReceiptV2({
    schemaVersion: 2,
    kind: 'scene-glass-host-lifecycle-receipt',
    operationId: v2.operationId,
    installId: v2.installId,
    terminalState: 'uninstalled',
    hostRoot: manifest.hostRoot,
    stateRoot: manifest.stateRoot,
    manifestFingerprint: `sha256:${createHash('sha256').update(manifestBytes).digest('hex')}`,
  });
  return {
    ...v2,
    schemaVersion: 3,
    kind: 'scene-glass-host-lifecycle-wal',
    lockPath: '/home/test/.scg/onboarding/lifecycle.lock',
    manifestPath: '/host/.scg/onboarding/manifest.v2.json',
    receiptPath: '/host/.scg/onboarding/receipt.v2.json',
    preimages: v2.preimages.map((preimage, index) =>
      index === 0
        ? {
            ...preimage,
            path: '/host/.scg/onboarding/manifest.v2.json',
            bytes: Buffer.from(manifestBytes, 'utf8').toString('base64'),
          }
        : index === 3
          ? { ...preimage, path: '/host/.scg/onboarding/receipt.v2.json' }
          : preimage,
    ),
    mutations: v2.mutations.map((mutation, index) =>
      index === 1 && mutation.kind === 'ordinary'
        ? {
            ...mutation,
            targetPath: '/host/.scg/onboarding/receipt.v2.json',
            result: {
              ...mutation.result,
              bytes: Buffer.from(receiptBytes, 'utf8').toString('base64'),
            },
          }
        : index === 2
          ? { ...mutation, targetPath: '/host/.scg/onboarding/manifest.v2.json' }
          : mutation,
    ),
    manifest,
    hostRoot: '/host',
    stateRoot: '/host/.scg/onboarding',
  };
}

describe('onboarding lifecycle provenance', () => {
  it('parses independent canonical manifest and receipt golden bytes', () => {
    const expectedManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'golden-install',
      state: 'active',
      artifacts: [],
    };
    const expectedReceipt = {
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-receipt',
      operationId: 'golden-receipt-operation',
      installId: 'golden-install',
      terminalState: 'uninstalled',
      manifestFingerprint: `sha256:${'a'.repeat(64)}`,
    };

    expect(parseSetupManifestJsonV1(GOLDEN_MANIFEST_JSON)).toEqual(expectedManifest);
    expect(parseLifecycleReceiptJsonV1(GOLDEN_RECEIPT_JSON)).toEqual(expectedReceipt);
    expect(serializeSetupManifestV1(expectedManifest)).toBe(GOLDEN_MANIFEST_JSON);
    expect(serializeLifecycleReceiptV1(expectedReceipt)).toBe(GOLDEN_RECEIPT_JSON);
    expect(() =>
      parseSetupManifestJsonV1(
        GOLDEN_MANIFEST_JSON.replace('\n  "schemaVersion"', '\n\t"schemaVersion"'),
      ),
    ).toThrow('canonical two-space LF serialization');
  });

  it('rejects non-own keys, raw token fields, and token-digest fields', () => {
    const inherited = Object.create({ schemaVersion: 1 });
    Object.assign(inherited, { ...MANIFEST });
    const rawToken = {
      ...MANIFEST,
      artifacts: [{ ...CONFIG_ARTIFACT, token: 'raw-secret-value' }],
    };
    const tokenDigest = {
      ...MANIFEST,
      artifacts: [{ ...CONFIG_ARTIFACT, tokenDigest: FINGERPRINT_A }],
    };

    expect(() => parseSetupManifestV1(inherited)).toThrow('ordinary object');
    expect(() => parseSetupManifestV1(rawToken)).toThrow('exact canonical own keys');
    expect(() => parseSetupManifestV1(tokenDigest)).toThrow('exact canonical own keys');
  });

  it('requires exactly one matching owned hunk rather than accepting a conflict', () => {
    const validation = validateOwnedArtifacts({
      artifacts: parseSetupManifestV1(MANIFEST).artifacts,
      observed: [observedConfig({ hunks: [HUNK, HUNK] }), observedCredential()],
    });

    expect(validation.valid).toBe(false);
    expect(validation.issues).toContainEqual({
      code: 'hunk-duplicate',
      path: CONFIG_PATH,
      hunkId: 'project-alpha',
    });
  });

  it('tolerates unrelated config edits while preserving the owned hunk and semantic project', () => {
    const validation = validateOwnedArtifacts({
      artifacts: parseSetupManifestV1(MANIFEST).artifacts,
      observed: [
        observedConfig({
          hunks: [HUNK, { ...HUNK, id: 'unrelated-project', fingerprint: FINGERPRINT_B }],
          semanticConfig: {
            schemaVersion: 1,
            projects: [
              PROJECT,
              {
                projectId: 'beta',
                root: '/srv/beta',
                allowedOrigins: ['https://beta.example.test'],
                tokenEnv: 'SCG_BETA_TOKEN',
                framework: 'react',
              },
            ],
          },
        }),
        observedCredential(),
      ],
    });

    expect(validation).toEqual({ valid: true, issues: [] });
  });

  it('models created and adopted credentials separately and forbids deletion of adopted authority', () => {
    const adopted = {
      ...MANIFEST,
      artifacts: [
        CONFIG_ARTIFACT,
        {
          path: REGISTRY_PATH,
          kind: 'credential',
          ownership: 'adopted',
          inverse: { kind: 'none' },
        },
      ],
    } as const;
    const invalidAdoptedDelete = {
      ...adopted,
      artifacts: [
        CONFIG_ARTIFACT,
        {
          path: REGISTRY_PATH,
          kind: 'credential',
          ownership: 'adopted',
          inverse: {
            kind: 'delete-created-credential',
            path: REGISTRY_PATH,
            projectId: 'alpha',
            identity: WAL_IDENTITY,
            mode: 0o600,
            linkCount: 1,
          },
        },
      ],
    } as const;

    const parsedCreated = parseSetupManifestV1(MANIFEST);
    const parsedAdopted = parseSetupManifestV1(adopted);
    expect(parsedCreated.artifacts[1]?.inverse.kind).toBe('delete-created-credential');
    expect(parsedAdopted.artifacts[1]?.inverse.kind).toBe('none');
    expect(() => parseSetupManifestV1(invalidAdoptedDelete)).toThrow(
      'adopted credential must not have a delete inverse',
    );
  });
  it('records only directional selected-entry registry transitions', () => {
    const transitions = [
      {
        preimage: REGISTRY_EMPTY,
        postimage: REGISTRY_ALPHA_IMAGE,
        fingerprint: REGISTRY_ALPHA_FINGERPRINT,
      },
      {
        preimage: REGISTRY_ALPHA_IMAGE,
        postimage: REGISTRY_ALPHA_UPDATED_IMAGE,
        fingerprint: REGISTRY_ALPHA_UPDATED_FINGERPRINT,
      },
      {
        preimage: REGISTRY_ALPHA_UPDATED_IMAGE,
        postimage: REGISTRY_EMPTY,
        fingerprint: REGISTRY_EMPTY_FINGERPRINT,
      },
    ];
    for (const { preimage, postimage, fingerprint } of transitions) {
      const artifact = registryArtifact(preimage, postimage, fingerprint);
      const parsed = parseSetupManifestV1({
        ...MANIFEST,
        artifacts: [artifact],
      });

      expect(parsed.artifacts).toEqual([
        expect.objectContaining({
          kind: 'credential-authority-registry',
          preimage,
          postimage,
          fingerprint,
          inverse: {
            kind: 'restore-credential-authority-registry-entry',
            path: REGISTRY_PATH,
            preimage,
            postimage,
          },
        }),
      ]);
    }
  });

  it('permits unrelated registry entries while requiring the selected postimage', () => {
    const artifact = registryArtifact(
      REGISTRY_ALPHA_IMAGE,
      REGISTRY_ALPHA_UPDATED_IMAGE,
      REGISTRY_ALPHA_UPDATED_WITH_BETA_FINGERPRINT,
    );
    const preflight = validateUninstallPreflight({
      manifest: { ...MANIFEST, artifacts: [artifact] },
      observed: [
        {
          path: REGISTRY_PATH,
          fingerprint: REGISTRY_ALPHA_UPDATED_WITH_BETA_FINGERPRINT,
          hunks: [],
          semanticConfig: undefined,
          semanticCredentialAuthorityRegistry: {
            schemaVersion: 1,
            projects: [REGISTRY_ALPHA_UPDATED, REGISTRY_BETA],
          },
        },
      ],
    });

    expect(preflight).toEqual({
      canUninstall: true,
      writes: [],
      inverse: [artifact.inverse],
      issues: [],
    });
  });

  it('creates but never records a Scene Glass root directory as lifecycle-owned', () => {
    const manifest = finalizeSetupManifestV1({
      manifest: {
        schemaVersion: 1,
        kind: 'scene-glass-setup-manifest',
        installId: 'install-directory-root',
        state: 'active',
        artifacts: [],
      },
      operations: [],
      credential: undefined,
      directories: [
        {
          path: '/srv/alpha/.scene-glass',
          identity: WAL_IDENTITY,
          mode: 0o700,
        },
      ],
    });

    expect(manifest.artifacts).toEqual([]);
  });
  it('requires canonical owned paths and does not claim checkout or annotation roots as owned artifacts', () => {
    const checkout = {
      ...MANIFEST,
      artifacts: [
        {
          path: '/srv/alpha/.scene-glass',
          kind: 'file',
          fingerprint: FINGERPRINT_A,
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: '/srv/alpha/.scene-glass',
            expectedFingerprint: FINGERPRINT_A,
          },
        },
      ],
    } as const;
    const annotations = {
      ...MANIFEST,
      artifacts: [
        {
          path: '/srv/alpha/.scg/annotations',
          kind: 'file',
          fingerprint: FINGERPRINT_A,
          hunks: [],
          inverse: {
            kind: 'delete-created-file',
            path: '/srv/alpha/.scg/annotations',
            expectedFingerprint: FINGERPRINT_A,
          },
        },
      ],
    } as const;
    const noncanonical = {
      ...MANIFEST,
      artifacts: [{ ...CONFIG_ARTIFACT, path: '~/.scg/config.json' }],
    } as const;

    expect(() => parseSetupManifestV1(noncanonical)).toThrow('canonical absolute normalized path');
    expect(() => parseSetupManifestV1(checkout)).toThrow('never lifecycle-owned');
    expect(() => parseSetupManifestV1(annotations)).toThrow('never lifecycle-owned');
  });

  it('performs a full no-write preflight and only exposes inverses after every target passes', () => {
    const missingAndChanged = validateUninstallPreflight({
      manifest: MANIFEST,
      observed: [observedConfig({ hunks: [{ ...HUNK, fingerprint: FINGERPRINT_B }] })],
    });
    const absent = validateUninstallPreflight({ manifest: undefined, observed: [] });
    const valid = validateUninstallPreflight({
      manifest: MANIFEST,
      observed: [observedConfig(), observedCredential()],
    });

    expect(missingAndChanged.canUninstall).toBe(false);
    expect(missingAndChanged.writes).toEqual([]);
    expect(missingAndChanged.inverse).toEqual([]);
    expect(missingAndChanged.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'hunk-changed' }),
        expect.objectContaining({
          code: 'target-missing',
          path: REGISTRY_PATH,
        }),
      ]),
    );
    expect(absent).toMatchObject({ canUninstall: false, writes: [], inverse: [] });
    expect(absent.issues).toContainEqual({
      code: 'provenance-absent',
      path: undefined,
      hunkId: undefined,
    });
    expect(valid.canUninstall).toBe(true);
    expect(valid.writes).toEqual([]);
    expect(valid.inverse).toHaveLength(2);
  });
  it('matches hand-authored golden bytes for every legal disk-authoritative WAL v2 phase', () => {
    const authorityFingerprint = `sha256:${'0'.repeat(64)}`;
    const expected = (
      operationId: string,
      operation: 'setup' | 'uninstall',
      direction: 'rollback' | 'commit',
      phase: 'prepared' | 'finalized' | 'commit-decided',
    ) => ({
      schemaVersion: 2,
      kind: 'scene-glass-lifecycle-wal',
      operationId,
      installId: 'golden-install',
      operation,
      direction,
      phase,
      lockPath: '/golden/lifecycle.lock',
      manifestPath: '/golden/manifest.json',
      cursor: 0,
      preimages: [],
      mutations: [],
      authorityFingerprint,
    });
    const uninstallManifest = {
      schemaVersion: 1,
      kind: 'scene-glass-setup-manifest',
      installId: 'golden-install',
      state: 'active',
      artifacts: [],
    };
    const uninstallPreimages = [
      {
        path: '/golden/manifest.json',
        kind: 'file',
        identity: WAL_IDENTITY,
        mode: 0o600,
        bytes:
          'ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1zZXR1cC1tYW5pZmVzdCIsCiAgImluc3RhbGxJZCI6ICJnb2xkZW4taW5zdGFsbCIsCiAgInN0YXRlIjogImFjdGl2ZSIsCiAgImFydGlmYWN0cyI6IFtdCn0K',
      },
      { path: '/golden/receipt.json', kind: 'absent' },
    ];
    const committedUninstallMutations = [
      {
        step: 0,
        kind: 'ordinary',
        targetPath: '/golden/receipt.json',
        sourcePath: '/golden/receipt-source.json',
        stagingPath: '/golden/.receipt.stage',
        preimage: 1,
        result: {
          kind: 'file',
          identity: WAL_RESULT_IDENTITY,
          mode: 0o600,
          bytes:
            'ewogICJzY2hlbWFWZXJzaW9uIjogMSwKICAia2luZCI6ICJzY2VuZS1nbGFzcy1saWZlY3ljbGUtcmVjZWlwdCIsCiAgIm9wZXJhdGlvbklkIjogImdvbGRlbi11bmluc3RhbGwtY29tbWl0dGVkIiwKICAiaW5zdGFsbElkIjogImdvbGRlbi1pbnN0YWxsIiwKICAidGVybWluYWxTdGF0ZSI6ICJ1bmluc3RhbGxlZCIsCiAgIm1hbmlmZXN0RmluZ2VycHJpbnQiOiAic2hhMjU2OmJjNzA5NzVmNzUyZGM0MGYzYTg0YzJmMjBmODkwMDIzY2UyYjlhODc3YjRlNjFkY2NhZjRmYjdhODllNDMwYmQiCn0K',
        },
      },
      {
        step: 1,
        kind: 'ordinary',
        targetPath: '/golden/manifest.json',
        sourcePath: '/golden/manifest-source.json',
        stagingPath: '/golden/.manifest.stage',
        preimage: 0,
        result: { kind: 'absent' },
      },
    ];
    const goldens = [
      {
        json: GOLDEN_SETUP_PREPARED_WAL_JSON,
        record: expected('golden-setup-prepared', 'setup', 'rollback', 'prepared'),
      },
      {
        json: GOLDEN_SETUP_FINALIZED_WAL_JSON,
        record: expected('golden-setup-finalized', 'setup', 'rollback', 'finalized'),
      },
      {
        json: GOLDEN_SETUP_COMMITTED_WAL_JSON,
        record: expected('golden-setup-committed', 'setup', 'commit', 'commit-decided'),
      },
      {
        json: GOLDEN_UNINSTALL_PREPARED_WAL_JSON,
        record: {
          ...expected('golden-uninstall-prepared', 'uninstall', 'rollback', 'prepared'),
          preimages: uninstallPreimages,
          receiptPath: '/golden/receipt.json',
          manifest: uninstallManifest,
        },
      },
      {
        json: GOLDEN_UNINSTALL_COMMITTED_WAL_JSON,
        record: {
          ...expected('golden-uninstall-committed', 'uninstall', 'commit', 'commit-decided'),
          cursor: 2,
          preimages: uninstallPreimages,
          mutations: committedUninstallMutations,
          receiptPath: '/golden/receipt.json',
          manifest: uninstallManifest,
        },
      },
    ] as const;

    for (const { json, record } of goldens) {
      const parsed = parseWalRecordJsonV2(json);
      expect(parsed).toEqual(record);
      expect(serializeWalRecordV2(record)).toBe(json);
      expect(serializeWalRecord(parsed)).toBe(json);
      expect(parseWalRecordJson(json)).toEqual({
        classification: 'v2-recovery-authority',
        record: parsed,
      });
      expect(() =>
        parseWalRecordJsonV2(json.replace('\n  "schemaVersion"', '\n\t"schemaVersion"')),
      ).toThrow('canonical two-space LF serialization');
    }
  });
  it('replaces at most one prior terminal receipt file with exact terminal authority', () => {
    const base = uninstallWalV2('commit-decided', 'commit', 3);
    const receiptPreimageIndex = 3;
    const receiptMutationIndex = 1;
    const receiptPreimage = {
      path: base.receiptPath,
      kind: 'file',
      identity: WAL_IDENTITY,
      mode: 0o600,
      bytes: Buffer.from(
        serializeLifecycleReceiptV1({
          schemaVersion: 1,
          kind: 'scene-glass-lifecycle-receipt',
          operationId: 'prior-receipt',
          installId: 'prior-install',
          terminalState: 'uninstalled',
          manifestFingerprint: FINGERPRINT_A,
        }),
        'utf8',
      ).toString('base64'),
    };
    const bound = {
      ...base,
      preimages: base.preimages.map((preimage, index) =>
        index === receiptPreimageIndex ? receiptPreimage : preimage,
      ),
    };
    const json = serializeWalRecordV2(bound);
    const parsed = parseWalRecordJsonV2(json);

    expect(parseWalRecordV2(base).preimages[receiptPreimageIndex]).toEqual({
      path: base.receiptPath,
      kind: 'absent',
    });
    expect(serializeWalRecordV2(parsed)).toBe(json);
    expect(parsed.preimages[receiptPreimageIndex]).toEqual(receiptPreimage);
    expect(parsed.mutations[receiptMutationIndex]).toEqual({
      step: 1,
      kind: 'ordinary',
      targetPath: base.receiptPath,
      sourcePath: '/state/receipt-source.json',
      stagingPath: '/state/.receipt.stage',
      preimage: receiptPreimageIndex,
      result: {
        kind: 'file',
        identity: WAL_RESULT_IDENTITY,
        mode: 0o600,
        bytes: WAL_V2_RECEIPT_BYTES,
      },
    });
    expect(parsed.mutations[2]).toEqual({
      step: 2,
      kind: 'ordinary',
      targetPath: base.manifestPath,
      sourcePath: '/state/manifest-source.json',
      stagingPath: '/state/.manifest.stage',
      preimage: 0,
      result: { kind: 'absent' },
    });
    expect(() =>
      parseWalRecordV2({
        ...bound,
        mutations: bound.mutations.map((mutation, index) =>
          index === receiptMutationIndex ? { ...mutation, result: { kind: 'absent' } } : mutation,
        ),
      }),
    ).toThrow('uninstall WAL v2 terminal receipt mutation lacks exact authority');
    expect(() =>
      parseWalRecordV2({
        ...base,
        preimages: base.preimages.map((preimage, index) =>
          index === receiptPreimageIndex
            ? {
                path: base.receiptPath,
                kind: 'credential',
                identity: WAL_IDENTITY,
                mode: 0o600,
              }
            : preimage,
        ),
      }),
    ).toThrow('ordinary WAL v2 mutation must reference its exact noncredential preimage');
    expect(() =>
      parseWalRecordV2({ ...bound, preimages: [...bound.preimages, receiptPreimage] }),
    ).toThrow('uninstall WAL v2 receipt preimage must be unique');
    expect(() =>
      parseWalRecordV2({
        ...bound,
        mutations: bound.mutations.map((mutation, index) =>
          index === 0 ? { ...mutation, sourcePath: base.receiptPath } : mutation,
        ),
      }),
    ).toThrow('path collision');
  });

  it('canonically round-trips identity-only directory WAL v2 authority', () => {
    const json = serializeWalRecordV2(setupWalV2WithDirectoryResult());
    const parsed = parseWalRecordJsonV2(json);
    const mutation = parsed.mutations[0];

    if (
      mutation === undefined ||
      mutation.kind !== 'ordinary' ||
      mutation.result.kind !== 'directory'
    ) {
      throw new Error('directory WAL v2 fixture did not parse as directory authority');
    }

    expect(mutation.result).toEqual(WAL_DIRECTORY_RESULT);
    expect(serializeWalRecordV2(parsed)).toBe(json);
  });

  it('rejects noncanonical and content-bearing directory WAL v2 results', () => {
    const reorderedDirectoryResult = {
      identity: WAL_RESULT_IDENTITY,
      kind: 'directory',
      mode: 0o700,
    };

    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, reorderedDirectoryResult),
      ),
    ).toThrow('exact canonical own keys');
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          extra: true,
        }),
      ),
    ).toThrow('exact canonical own keys');
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          bytes: 'Y29uZmlnCg==',
        }),
      ),
    ).toThrow('exact canonical own keys');
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          fingerprint: FINGERPRINT_A,
        }),
      ),
    ).toThrow('exact canonical own keys');
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          digest: FINGERPRINT_A,
        }),
      ),
    ).toThrow('exact canonical own keys');
  });

  it('requires canonical directory identity and mode', () => {
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          identity: { device: '01', inode: '13' },
        }),
      ),
    ).toThrow('canonical decimal identity');
    expect(() =>
      parseWalRecordV2(
        setupWalV2WithDirectoryResult('prepared', 'rollback', 0, {
          ...WAL_DIRECTORY_RESULT,
          mode: 0o1000,
        }),
      ),
    ).toThrow('canonical permission mode');
  });

  it('requires directory WAL v2 authority to have an exact absent preimage', () => {
    const record = setupWalV2WithDirectoryResult();
    const filePreimage = {
      path: '/state/config.json',
      kind: 'file',
      identity: WAL_IDENTITY,
      mode: 0o600,
      bytes: 'Y29uZmlnCg==',
    };
    const credentialPreimage = {
      path: '/state/config.json',
      kind: 'credential',
      identity: WAL_IDENTITY,
      mode: 0o600,
    };

    expect(() =>
      parseWalRecordV2({
        ...record,
        preimages: [filePreimage, record.preimages[1]],
      }),
    ).toThrow('exact absent preimage');
    expect(() =>
      parseWalRecordV2({
        ...record,
        preimages: [credentialPreimage, record.preimages[1]],
      }),
    ).toThrow('exact absent preimage');
  });
  it('requires setup credential WAL authority to use an absent preimage and one identity', () => {
    const record = setupWalV2();
    const credentialPreimage = {
      path: '/state/credential',
      kind: 'credential',
      identity: WAL_IDENTITY,
      mode: 0o600,
    };
    const parsed = parseWalRecordV2(record);
    const credentialMutation = parsed.mutations[1];

    if (credentialMutation === undefined || credentialMutation.kind !== 'credential') {
      throw new Error('WAL v2 fixture did not preserve credential authority');
    }

    expect(parsed.preimages[1]).toEqual({ path: '/state/credential', kind: 'absent' });
    expect(credentialMutation.stagingIdentity).toEqual(credentialMutation.targetIdentity);
    expect(() =>
      parseWalRecordV2({ ...record, preimages: [record.preimages[0], credentialPreimage] }),
    ).toThrow('credential WAL v2 mutation must create one exact credential identity');
    expect(() =>
      parseWalRecordV2({
        ...record,
        mutations: record.mutations.map((mutation, index) =>
          index === 1 ? { ...mutation, targetIdentity: WAL_RESULT_IDENTITY } : mutation,
        ),
      }),
    ).toThrow('credential WAL v2 mutation must create one exact credential identity');
  });

  it('preserves directory target, preimage, source, and stage collision detection', () => {
    const record = setupWalV2WithDirectoryResult();
    const sourceCollision = {
      ...record,
      mutations: record.mutations.map((mutation, index) =>
        index === 0 ? { ...mutation, sourcePath: '/state/config.json' } : mutation,
      ),
    };
    const stageCollision = {
      ...record,
      mutations: record.mutations.map((mutation, index) =>
        index === 0 ? { ...mutation, stagingPath: '/state/config.json' } : mutation,
      ),
    };

    expect(() => parseWalRecordV2(sourceCollision)).toThrow(
      'ordinary WAL v2 mutation targets must be unique',
    );
    expect(() => parseWalRecordV2(stageCollision)).toThrow(
      'ordinary WAL v2 mutation targets must be unique',
    );
  });

  it('permits partial prepared setup cursors but rejects incomplete finalized and commit-decided cursors', () => {
    expect(
      parseWalRecordV2(setupWalV2WithDirectoryResult('prepared', 'rollback', 1)),
    ).toMatchObject({ cursor: 1 });
    expect(() =>
      parseWalRecordV2(setupWalV2WithDirectoryResult('finalized', 'rollback', 1)),
    ).toThrow('complete every mutation step');
    expect(() =>
      parseWalRecordV2(setupWalV2WithDirectoryResult('commit-decided', 'commit', 1)),
    ).toThrow('complete every mutation step');
  });

  it('accepts only native-compatible creation-intent validation tokens', () => {
    expect(parseWalRecordV2(setupWalV2WithCreationIntent()).creationIntents).toHaveLength(1);
    for (const validationToken of [
      '0'.repeat(31),
      '0'.repeat(33),
      'A'.repeat(32),
      '_'.repeat(32),
    ]) {
      expect(() => parseWalRecordV2(setupWalV2WithCreationIntent(validationToken))).toThrow(
        'validationToken must be exactly 32 lowercase hexadecimal characters',
      );
    }
  });
  it('classifies exact v1 WAL records as legacy-only without v2 mutation authority', () => {
    const legacyRecord = {
      schemaVersion: 1,
      kind: 'scene-glass-lifecycle-wal',
      operationId: 'operation-alpha',
      installId: 'install-alpha',
      operation: 'setup',
      phase: 'prepared',
      manifestFingerprint: FINGERPRINT_A,
    };
    const json = serializeWalRecordV1(legacyRecord);
    const parsed = parseWalRecordJson(json);

    expect(parseWalRecord(legacyRecord)).toEqual(parsed);
    expect(serializeWalRecord(legacyRecord)).toBe(json);
    expect(parsed.classification).toBe('legacy-v1-recovery-required');
    expect('mutations' in parsed.record).toBe(false);
    expect('direction' in parsed.record).toBe(false);
  });

  it('rejects invalid WAL v2 keys, inherited values, sparse arrays, and phase-direction pairs', () => {
    const inherited = Object.create({ authorityFingerprint: FINGERPRINT_A });
    Object.assign(inherited, setupWalV2());
    const sparsePreimages = new Array(2);
    sparsePreimages[0] = setupWalV2().preimages[0];
    const sparseDirectoryMutations = new Array(2);
    sparseDirectoryMutations[0] = setupWalV2WithDirectoryResult().mutations[0];
    const creationIntentRecord = setupWalV2WithCreationIntent();
    const creationIntent = creationIntentRecord.creationIntents[0];
    if (creationIntent === undefined) {
      throw new Error('creation intent fixture is incomplete');
    }
    const sparseCreationIntents = new Array(2);
    sparseCreationIntents[0] = creationIntent;
    const tooManyCreationIntents = Array.from({ length: 257 }, () => creationIntent);

    expect(() => parseWalRecordV2({ ...setupWalV2(), unexpected: true })).toThrow(
      'exact canonical own keys',
    );
    expect(() => parseWalRecordV2(inherited)).toThrow('ordinary object');
    expect(() => parseWalRecordV2({ ...setupWalV2(), preimages: sparsePreimages })).toThrow(
      'must not be sparse',
    );
    expect(() =>
      parseWalRecordV2({
        ...setupWalV2WithDirectoryResult(),
        mutations: sparseDirectoryMutations,
      }),
    ).toThrow('mutations must not be sparse');
    expect(() =>
      parseWalRecordV2({
        ...creationIntentRecord,
        creationIntents: sparseCreationIntents,
      }),
    ).toThrow('creationIntents must be a dense array');
    expect(() =>
      parseWalRecordV2({
        ...creationIntentRecord,
        creationIntents: tooManyCreationIntents,
      }),
    ).toThrow('creationIntents must be a bounded array');
    expect(() => parseWalRecordV2(setupWalV2('prepared', 'commit', 0))).toThrow(
      'phase and direction are incompatible',
    );
    expect(() => parseWalRecordV2(setupWalV2('finalized', 'commit', 2))).toThrow(
      'phase and direction are incompatible',
    );
    expect(() => parseWalRecordV2({ ...setupWalV2(), phase: 'applied' })).toThrow(
      'phase is unsupported',
    );
    const unordered = setupWalV2();
    const firstStep = unordered.mutations[0];
    const secondStep = unordered.mutations[1];
    if (firstStep === undefined || secondStep === undefined) {
      throw new Error('WAL v2 fixture is incomplete');
    }
    expect(() =>
      parseWalRecordV2({
        ...unordered,
        mutations: [{ ...firstStep, step: 1 }, secondStep],
      }),
    ).toThrow('contiguous and ordered');
    expect(() => parseWalRecordV2(setupWalV2('finalized', 'rollback', 1))).toThrow(
      'complete every mutation step',
    );
    expect(() => parseWalRecordV2({ ...uninstallWalV2(), phase: 'finalized' })).toThrow(
      'phase and direction are incompatible',
    );
    expect(() => parseWalRecordV2(uninstallWalV2('commit-decided', 'rollback', 1))).toThrow(
      'phase and direction are incompatible',
    );
  });

  it('rejects noncanonical, relative, and colliding WAL v2 paths', () => {
    const base = setupWalV2();
    const collidingMutations = base.mutations.map((mutation, index) =>
      index === 0 ? { ...mutation, stagingPath: '/state/config-source.json' } : mutation,
    );

    expect(() => parseWalRecordV2({ ...base, lockPath: '/state/../state/lifecycle.lock' })).toThrow(
      'canonical absolute normalized path',
    );
    expect(() => parseWalRecordV2({ ...base, manifestPath: 'state/manifest.json' })).toThrow(
      'canonical absolute normalized path',
    );
    expect(() => parseWalRecordV2({ ...base, mutations: collidingMutations })).toThrow(
      'path collision',
    );
    expect(() => parseWalRecordV2({ ...base, lockPath: '/state/config.json' })).toThrow(
      'path collision',
    );
  });

  it('enforces aggregate WAL v2 image and structural limits while accepting their exact boundaries', () => {
    const atStructuralEntryLimit = Array.from({ length: 256 }, (_, step) => ({
      step,
      kind: 'ordinary' as const,
      targetPath: `/state/structural-target-${step}`,
      sourcePath: `/state/structural-source-${step}`,
      stagingPath: `/state/.structural-stage-${step}`,
      preimage: step,
      result: { kind: 'absent' as const },
    }));
    const atStructuralPreimageLimit = Array.from({ length: 256 }, (_, step) => ({
      path: `/state/structural-target-${step}`,
      kind: 'absent' as const,
    }));
    const tooManyPreimages = Array.from({ length: 257 }, (_, index) => ({
      path: `/state/preimage-${index}`,
      kind: 'absent',
    }));
    const tooManyMutations = Array.from({ length: 257 }, (_, step) => ({
      step,
      kind: 'ordinary',
      targetPath: `/state/target-${step}`,
      sourcePath: `/state/source-${step}`,
      stagingPath: `/state/stage-${step}`,
      preimage: 0,
      result: { kind: 'absent' },
    }));
    const oversizedImage = Buffer.alloc(1024 * 1024 + 1).toString('base64');
    const maximumImage = Buffer.alloc(1024 * 1024).toString('base64');
    const aggregatePreimages = Array.from({ length: 17 }, (_, index) => ({
      path: `/state/preimage-image-${index}`,
      kind: 'file',
      identity: WAL_IDENTITY,
      mode: 0o600,
      bytes: maximumImage,
    }));
    const aggregateResultPreimages = Array.from({ length: 17 }, (_, step) => ({
      path: `/state/result-image-${step}`,
      kind: 'absent',
    }));
    const aggregateResultMutations = Array.from({ length: 17 }, (_, step) => ({
      step,
      kind: 'ordinary',
      targetPath: `/state/result-image-${step}`,
      sourcePath: `/state/result-source-${step}`,
      stagingPath: `/state/.result-stage-${step}`,
      preimage: step,
      result: {
        kind: 'file',
        identity: WAL_RESULT_IDENTITY,
        mode: 0o600,
        bytes: maximumImage,
      },
    }));
    const aggregateMixedPreimages = [
      ...Array.from({ length: 8 }, (_, index) => ({
        path: `/state/exact-preimage-image-${index}`,
        kind: 'file' as const,
        identity: WAL_IDENTITY,
        mode: 0o600,
        bytes: maximumImage,
      })),
      ...Array.from({ length: 8 }, (_, index) => ({
        path: `/state/exact-result-image-${index}`,
        kind: 'absent' as const,
      })),
    ];
    const aggregateMixedMutations = Array.from({ length: 8 }, (_, step) => ({
      step,
      kind: 'ordinary' as const,
      targetPath: `/state/exact-result-image-${step}`,
      sourcePath: `/state/exact-result-source-${step}`,
      stagingPath: `/state/.exact-result-stage-${step}`,
      preimage: step + 8,
      result: {
        kind: 'file' as const,
        identity: WAL_RESULT_IDENTITY,
        mode: 0o600,
        bytes: maximumImage,
      },
    }));
    const oversizedResultRecord = setupWalV2();
    const oversizedResultMutation = oversizedResultRecord.mutations[0];
    const credentialMutation = oversizedResultRecord.mutations[1];
    if (
      oversizedResultMutation === undefined ||
      oversizedResultMutation.kind !== 'ordinary' ||
      oversizedResultMutation.result === undefined ||
      oversizedResultMutation.result.kind !== 'file' ||
      credentialMutation === undefined ||
      credentialMutation.kind !== 'credential'
    ) {
      throw new Error('WAL v2 fixture lacks an ordinary file result');
    }
    const oversizedOrdinaryResult = oversizedResultMutation.result;

    const structuralAtLimit = parseWalRecordV2({
      ...setupWalV2(),
      cursor: 0,
      preimages: atStructuralPreimageLimit,
      mutations: atStructuralEntryLimit,
    });
    expect({
      preimages: structuralAtLimit.preimages.length,
      mutations: structuralAtLimit.mutations.length,
    }).toEqual({ preimages: 256, mutations: 256 });
    expect(
      parseWalRecordV2({
        ...setupWalV2(),
        cursor: 0,
        preimages: aggregateMixedPreimages,
        mutations: aggregateMixedMutations,
      }).preimages,
    ).toHaveLength(16);
    expect(() => parseWalRecordV2({ ...setupWalV2(), preimages: tooManyPreimages })).toThrow(
      'preimages must be a bounded array',
    );
    expect(() => parseWalRecordV2({ ...setupWalV2(), mutations: tooManyMutations })).toThrow(
      'mutations must be a bounded array',
    );
    expect(() =>
      parseWalRecordV2({
        ...oversizedResultRecord,
        mutations: [
          {
            ...oversizedResultMutation,
            result: { ...oversizedOrdinaryResult, bytes: oversizedImage },
          },
          credentialMutation,
        ],
      }),
    ).toThrow('ordinary mutation result bytes must be bounded canonical base64');
    expect(() =>
      parseWalRecordV2({
        ...setupWalV2(),
        preimages: aggregatePreimages,
        mutations: [],
        cursor: 0,
      }),
    ).toThrow('aggregate byte limit');
    expect(() =>
      parseWalRecordV2({
        ...setupWalV2(),
        preimages: aggregateResultPreimages,
        mutations: aggregateResultMutations,
        cursor: 0,
      }),
    ).toThrow('aggregate byte limit');
  });

  it('rejects malformed and noncanonical ordinary-image base64', () => {
    for (const bytes of ['YQ', 'YQ==\n', '_w==']) {
      expect(() =>
        parseWalRecordV2({
          ...setupWalV2(),
          preimages: [
            {
              path: '/state/config.json',
              kind: 'file',
              identity: WAL_IDENTITY,
              mode: 0o600,
              bytes,
            },
            { path: '/state/credential', kind: 'absent' },
          ],
        }),
      ).toThrow('canonical base64');
    }
  });

  it('rejects credential bytes, fingerprints, tokens, and token digests structurally', () => {
    for (const [field, value] of [
      ['bytes', 'Y3JlZGVudGlhbA=='],
      ['fingerprint', FINGERPRINT_A],
      ['token', 'credential-token'],
      ['tokenDigest', FINGERPRINT_A],
    ] as const) {
      const uninstall = uninstallWalV2();
      const setup = setupWalV2();
      const credentialPreimage = uninstall.preimages[2];
      const credentialMutation = setup.mutations[1];
      if (credentialPreimage === undefined || credentialMutation === undefined) {
        throw new Error('WAL v2 fixture is incomplete');
      }
      const credentialPreimageWithForbiddenField = {
        ...credentialPreimage,
        [field]: value,
      };
      const credentialMutationWithForbiddenField = {
        ...credentialMutation,
        [field]: value,
      };

      expect(() =>
        parseWalRecordV2({
          ...uninstall,
          preimages: uninstall.preimages.map((preimage, index) =>
            index === 2 ? credentialPreimageWithForbiddenField : preimage,
          ),
        }),
      ).toThrow('exact canonical own keys');
      expect(() =>
        parseWalRecordV2({
          ...setup,
          mutations: [setup.mutations[0], credentialMutationWithForbiddenField],
        }),
      ).toThrow('exact canonical own keys');
    }
  });

  it('deeply freezes parsed WAL v2 authority at every recovery boundary', () => {
    const parsedUninstall = parseWalRecordV2(uninstallWalV2('commit-decided', 'commit', 3));
    const parsedSetup = parseWalRecordV2(setupWalV2());
    if (parsedUninstall.operation !== 'uninstall' || parsedSetup.operation !== 'setup') {
      throw new Error('WAL v2 fixture did not preserve recovery authority');
    }
    const manifestPreimage = parsedUninstall.preimages[0];
    const credentialPreimage = parsedUninstall.preimages[2];
    const receiptPreimage = parsedUninstall.preimages[3];
    const credentialAbsentPreimage = parsedSetup.preimages[1];
    const ordinaryMutation = parsedUninstall.mutations[1];
    const credentialMutation = parsedSetup.mutations[1];
    if (
      manifestPreimage === undefined ||
      manifestPreimage.kind !== 'file' ||
      credentialPreimage === undefined ||
      credentialPreimage.kind !== 'credential' ||
      receiptPreimage === undefined ||
      receiptPreimage.kind !== 'absent' ||
      credentialAbsentPreimage === undefined ||
      credentialAbsentPreimage.kind !== 'absent' ||
      ordinaryMutation === undefined ||
      ordinaryMutation.kind !== 'ordinary' ||
      ordinaryMutation.result.kind !== 'file' ||
      credentialMutation === undefined ||
      credentialMutation.kind !== 'credential'
    ) {
      throw new Error('WAL v2 fixture did not preserve nested authority');
    }

    expect(Object.isFrozen(parsedUninstall)).toBe(true);
    expect(Object.isFrozen(parsedUninstall.preimages)).toBe(true);
    expect(Object.isFrozen(manifestPreimage)).toBe(true);
    expect(Object.isFrozen(manifestPreimage.identity)).toBe(true);
    expect(Object.isFrozen(credentialPreimage)).toBe(true);
    expect(Object.isFrozen(credentialPreimage.identity)).toBe(true);
    expect(Object.isFrozen(receiptPreimage)).toBe(true);
    expect(Object.isFrozen(parsedUninstall.mutations)).toBe(true);
    expect(Object.isFrozen(ordinaryMutation)).toBe(true);
    expect(Object.isFrozen(ordinaryMutation.result)).toBe(true);
    expect(Object.isFrozen(ordinaryMutation.result.identity)).toBe(true);
    expect(Object.isFrozen(parsedSetup)).toBe(true);
    expect(Object.isFrozen(parsedSetup.preimages)).toBe(true);
    expect(Object.isFrozen(credentialAbsentPreimage)).toBe(true);
    expect(Object.isFrozen(parsedSetup.mutations)).toBe(true);
    expect(Object.isFrozen(credentialMutation)).toBe(true);
    expect(Object.isFrozen(credentialMutation.stagingIdentity)).toBe(true);
    expect(Object.isFrozen(credentialMutation.targetIdentity)).toBe(true);
    expect(Object.isFrozen(parsedUninstall.manifest)).toBe(true);
    expect(Object.isFrozen(parsedUninstall.manifest.artifacts)).toBe(true);
    expect(Object.isFrozen(parsedUninstall.manifest.artifacts[0])).toBe(true);
  });
  it('requires paired canonical Vite authority in host manifests', () => {
    const manifest = {
      schemaVersion: 2,
      kind: 'scene-glass-host-setup-manifest',
      installId: 'install-alpha',
      state: 'active',
      hostRoot: '/host',
      stateRoot: '/host/.scg/onboarding',
      artifacts: [],
      compactViteAuthority: {
        syntheticRoot: `/host/${VITE_SNAPSHOT_ROOT_DIRECTORY}/install-alpha`,
        rootIdentity: WAL_IDENTITY,
        commitmentDigest: 'a'.repeat(64),
      },
      fullCommitmentBinding: {
        path: `/host/${VITE_SNAPSHOT_COMMITMENT_DIRECTORY}/install-alpha.json`,
        identity: WAL_IDENTITY,
        mode: 0o600,
        linkCount: 1,
        byteLength: VITE_SNAPSHOT_COMMITMENT_MAX_BYTES,
        sha256: FINGERPRINT_A,
      },
    };
    expect(parseHostSetupManifestV2(JSON.parse(serializeHostSetupManifestV2(manifest)))).toEqual(
      manifest,
    );
    expect(() =>
      parseHostSetupManifestV2({
        ...manifest,
        fullCommitmentBinding: {
          ...manifest.fullCommitmentBinding,
          byteLength: VITE_SNAPSHOT_COMMITMENT_MAX_BYTES + 1,
        },
      }),
    ).toThrow();
    expect(() =>
      parseHostSetupManifestV2({ ...manifest, fullCommitmentBinding: undefined }),
    ).toThrow();
  });
  it('round-trips context-bound host WAL v3 and rejects cross-version parser inputs', () => {
    const v2 = setupWalV2();
    const v3 = {
      ...v2,
      schemaVersion: 3,
      kind: 'scene-glass-host-lifecycle-wal',
      lockPath: '/home/test/.scg/onboarding/lifecycle.lock',
      manifestPath: '/host/.scg/onboarding/manifest.v2.json',
      hostRoot: '/host',
      stateRoot: '/host/.scg/onboarding',
    };
    const bytes = serializeHostWalRecordV3(v3, HOST_CONTEXT);
    expect(parseHostWalRecordV3(JSON.parse(bytes), HOST_CONTEXT)).toEqual(v3);
    expect(() => parseHostWalRecordV3(v3, { ...HOST_CONTEXT, hostRoot: '/other' })).toThrow();
    expect(() => parseHostWalRecordV3(v2, HOST_CONTEXT)).toThrow();
    expect(() => parseWalRecordV2(v3)).toThrow();
  });

  it('dispatches a schema-v2 WAL by content despite the historical v1 filename', () => {
    const historicalV1Filename = 'lifecycle.wal.v1.json';
    expect(historicalV1Filename).toBe('lifecycle.wal.v1.json');
    expect(parseWalRecordJson(serializeWalRecordV2(setupWalV2()))).toMatchObject({
      classification: 'v2-recovery-authority',
      record: { schemaVersion: 2 },
    });
  });

  it('rejects annotation and retained lifecycle containers as targets', () => {
    for (const path of [
      '/host/.scg/annotations',
      '/host/.scg/annotations/owned.json',
      '/host/.scg',
      '/host/.scg/onboarding',
    ]) {
      expect(() => assertLifecycleTarget(path)).toThrow();
    }
  });

  it('translates a deployed schema-v2-at-v1-filename WAL into a source-bound host-v3 migration image', () => {
    const record = parseWalRecordV2({
      ...setupWalV2(),
      lockPath: '/home/test/.scene-glass-onboarding.lock',
      manifestPath: '/checkout/.scene-glass/onboarding/manifest.v1.json',
    });
    const authorityEntries = [
      ...record.preimages.map((_, index) => ({
        sourceKind: 'preimage' as const,
        sourceIndex: index,
        destinationKind: 'preimage' as const,
        destinationIndex: index,
      })),
      ...record.mutations.map((_, index) => ({
        sourceKind: 'mutation' as const,
        sourceIndex: index,
        destinationKind: 'mutation' as const,
        destinationIndex: index,
      })),
    ];
    const sourceFileFacts = {
      path: '/checkout/.scene-glass/onboarding/lifecycle.wal.v1.json',
      identity: WAL_IDENTITY,
      owner: '501',
      mode: 0o600,
      byteLength: 512,
      sha256: FINGERPRINT_A,
      parserVersion: 'v2',
      authorityFingerprint: FINGERPRINT_A,
      authorityMap: { entries: authorityEntries, cursorTransitions: [] },
    };
    const image = translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, sourceFileFacts);
    expect(image).toMatchObject({
      schemaVersion: 3,
      operation: 'migration',
      phase: 'source-bound',
      sourceRecord: record,
      translatedRecord: {
        operation: 'migration',
        phase: 'source-bound',
        lockPath: '/home/test/.scg/onboarding/lifecycle.lock',
      },
    });
    expect(() =>
      translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, {
        ...sourceFileFacts,
        authorityMap: { entries: authorityEntries.slice(1), cursorTransitions: [] },
      }),
    ).toThrow();
  });
  it('validates host-v3 uninstall terminal authority with host-v2 bytes', () => {
    const record = hostUninstallWalV3();
    expect(parseHostWalRecordV3(record, HOST_CONTEXT)).toEqual(record);
    expect(() =>
      parseHostWalRecordV3(
        {
          ...record,
          mutations: record.mutations.map((mutation, index) =>
            index === 1 && mutation.kind === 'ordinary'
              ? { ...mutation, result: { ...mutation.result, bytes: WAL_V2_RECEIPT_BYTES } }
              : mutation,
          ),
        },
        HOST_CONTEXT,
      ),
    ).toThrow();
    expect(() =>
      parseHostWalRecordV3(
        {
          ...record,
          manifest: { ...record.manifest, artifacts: [] },
        },
        HOST_CONTEXT,
      ),
    ).toThrow();
  });

  it('requires dense deterministic authority and cursor maps for every translated authority kind', () => {
    const base = uninstallWalV2('prepared', 'rollback', 1);
    const manifestPreimage = base.preimages[0];
    const receiptPreimage = base.preimages[3];
    if (manifestPreimage === undefined || receiptPreimage === undefined) {
      throw new Error('uninstall fixture is incomplete');
    }
    const record = parseWalRecordV2({
      schemaVersion: base.schemaVersion,
      kind: base.kind,
      operationId: base.operationId,
      installId: base.installId,
      operation: base.operation,
      direction: base.direction,
      phase: base.phase,
      lockPath: '/home/test/.scene-glass-onboarding.lock',
      manifestPath: '/checkout/.scene-glass/onboarding/manifest.v1.json',
      cursor: base.cursor,
      preimages: [
        { ...manifestPreimage, path: '/checkout/.scene-glass/onboarding/manifest.v1.json' },
        ...base.preimages.slice(1, 3),
        { ...receiptPreimage, path: '/checkout/.scene-glass/onboarding/receipt.v1.json' },
        { path: '/state/new-file', kind: 'absent' as const },
        { path: '/state/.new-file.stage', kind: 'absent' as const },
      ],
      mutations: base.mutations,
      creationIntents: [
        {
          step: 1,
          kind: 'file' as const,
          targetPath: '/state/new-file',
          stagingPath: '/state/.new-file.stage',
          mode: 0o600,
          validationToken: '0'.repeat(32),
          targetPreimage: 4,
          stagingPreimage: 5,
        },
      ],
      authorityFingerprint: base.authorityFingerprint,
      receiptPath: '/checkout/.scene-glass/onboarding/receipt.v1.json',
      manifest: base.manifest,
      replacedWalStage: {
        identity: WAL_IDENTITY,
        mode: 0o600,
        authorityFingerprint: FINGERPRINT_B,
      },
    });
    if (record.operation !== 'uninstall') {
      throw new Error('uninstall fixture changed operation');
    }
    const entries = [
      ...record.preimages.map((_, index) => ({
        sourceKind: 'preimage' as const,
        sourceIndex: index,
        destinationKind: 'preimage' as const,
        destinationIndex: index,
      })),
      ...record.mutations.map((_, index) => ({
        sourceKind: 'mutation' as const,
        sourceIndex: index,
        destinationKind: 'mutation' as const,
        destinationIndex: index,
      })),
      {
        sourceKind: 'creation-intent' as const,
        sourceIndex: 0,
        destinationKind: 'creation-intent' as const,
        destinationIndex: 0,
      },
      {
        sourceKind: 'replaced-wal-stage' as const,
        sourceIndex: 0,
        destinationKind: 'replaced-wal-stage' as const,
        destinationIndex: 0,
      },
      ...record.manifest.artifacts.flatMap((_, index) => [
        {
          sourceKind: 'manifest-artifact' as const,
          sourceIndex: index,
          destinationKind: 'manifest-artifact' as const,
          destinationIndex: index,
        },
        {
          sourceKind: 'manifest-inverse' as const,
          sourceIndex: index,
          destinationKind: 'manifest-inverse' as const,
          destinationIndex: index,
        },
      ]),
    ];
    const sourceFileFacts = {
      path: '/checkout/.scene-glass/onboarding/lifecycle.wal.v1.json',
      identity: WAL_IDENTITY,
      owner: '501',
      mode: 0o600,
      byteLength: 512,
      sha256: FINGERPRINT_A,
      parserVersion: 'v2',
      authorityFingerprint: FINGERPRINT_A,
      authorityMap: {
        entries,
        cursorTransitions: [{ sourceMutationIndex: 0, destinationMutationIndex: 0 }],
      },
    };
    expect(translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, sourceFileFacts)).toBeDefined();

    const firstEntry = entries[0];
    if (firstEntry === undefined) {
      throw new Error('authority entry fixture is incomplete');
    }
    const sparseEntries = new Array(entries.length) as unknown as typeof entries;
    sparseEntries[0] = firstEntry;
    const sparseTransitions = new Array(
      1,
    ) as unknown as typeof sourceFileFacts.authorityMap.cursorTransitions;
    expect(() =>
      translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, {
        ...sourceFileFacts,
        authorityMap: {
          entries: sparseEntries,
          cursorTransitions: sourceFileFacts.authorityMap.cursorTransitions,
        },
      }),
    ).toThrow();
    expect(() =>
      translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, {
        ...sourceFileFacts,
        authorityMap: { entries, cursorTransitions: sparseTransitions },
      }),
    ).toThrow();
    expect(() =>
      translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, {
        ...sourceFileFacts,
        authorityMap: {
          entries: [
            { ...firstEntry, destinationKind: 'mutation' as const, destinationIndex: 0 },
            ...entries.slice(1),
          ],
          cursorTransitions: sourceFileFacts.authorityMap.cursorTransitions,
        },
      }),
    ).toThrow();
    expect(() =>
      translateLegacyWalV2ToHostV3(record, HOST_CONTEXT, {
        ...sourceFileFacts,
        authorityMap: {
          entries,
          cursorTransitions: [{ sourceMutationIndex: 0, destinationMutationIndex: 1 }],
        },
      }),
    ).toThrow();
  });
});
describe('owned static loader removal', () => {
  const spaLoader =
    '<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>';
  const encoder = new TextEncoder();
  const fingerprint = (source: string) =>
    `sha256:${createHash('sha256').update(encoder.encode(source)).digest('hex')}`;

  for (const [subject, loader] of [
    ['scg-html-loader', STATIC_LOADER_MARKER],
    ['scg-vue3-loader', spaLoader],
    ['scg-react-loader', spaLoader],
  ] as const) {
    it(`preserves unrelated ${subject} index.html edits while removing only its loader`, () => {
      const preimage = '<html><head>\n  </head><body>base</body></html>\n';
      const postimage = `<html><head>\n${loader}\n  </head><body>base</body></html>\n`;
      const current = `<html data-user="before"><head>\n${loader}\n  </head><body>user-after</body></html>\n`;
      const inverse = {
        preimageFingerprint: fingerprint(preimage),
        postimageFingerprint: fingerprint(postimage),
        ownedInsertion: 'line' as const,
        hunks: [
          {
            id: 'loader',
            fingerprint: fingerprint(postimage),
            operation: 'insert' as const,
            subject,
          },
        ],
      };

      expect(
        new TextDecoder().decode(
          reconstructOwnedStaticFilePreimage(inverse, encoder.encode(current)),
        ),
      ).toBe('<html data-user="before"><head>\n  </head><body>user-after</body></html>\n');
      expect(
        new TextDecoder().decode(
          reconstructOwnedStaticFilePreimage(inverse, encoder.encode(postimage)),
        ),
      ).toBe(preimage);

      for (const invalid of [
        postimage.replace(loader, `${loader} altered`),
        postimage.replace(loader, ''),
        postimage.replace(loader, `${loader}\n${loader}`),
      ]) {
        expect(
          reconstructOwnedStaticFilePreimage(inverse, encoder.encode(invalid)),
        ).toBeUndefined();
      }
    });
  }
});
