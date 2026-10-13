import { describe, expect, it, vi } from 'vitest';

import {
  LifecycleEngine,
  LifecyclePreparedStartUnavailableError,
  LifecycleStartDiagnosticError,
  createTransactionObservedCredentialAuthority,
  type ForegroundMcpExit,
  type LifecycleCleanupContext,
  type LifecycleEnginePort,
  type LifecycleForegroundMcp,
  type LifecycleInspection,
  type LifecycleSetupPreflightInput,
  type LifecycleSetupTransaction,
  type LifecycleUninstallTransaction,
  type LifecycleSetupFacts,
  type LifecycleStartFacts,
  type SetupMutationPreparation,
  type SetupMutationReceipt,
  type SetupPlanBuildReceipt,
} from '../../packages/onboarding/src/lifecycle/engine.js';
import type {
  HostIntegrationPlan,
  HostPlanInput,
} from '../../packages/onboarding/src/lifecycle/host-plan.js';
import type { SetupManifestV1, SetupPlan } from '../../packages/onboarding/src/lifecycle/types.js';
import type { CredentialAuthority } from '../../packages/onboarding/src/types.js';
import type { SetupTransactionReceipt } from '../../packages/onboarding/src/lifecycle/transaction.js';

const FINGERPRINT = `sha256:${'a'.repeat(64)}`;
const PROJECT = {
  projectId: 'alpha',
  root: '/workspace/html',
  allowedOrigins: ['http://127.0.0.1:4173'],
  tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
  framework: 'html',
} as const;
const AUTHORITY = {
  projectId: 'alpha',
  path: '/var/lib/scene-glass/alpha.credential',
  device: '10',
  inode: '20',
} as const;
const CREATED_AUTHORITY = {
  projectId: 'alpha',
  path: '/var/lib/scene-glass/alpha.created.credential',
  device: '11',
  inode: '21',
} as const;
type CreatedAuthority = NonNullable<SetupMutationReceipt['createdAuthority']>;
type ObservedCreatedAuthority = NonNullable<SetupMutationReceipt['observedCreatedAuthority']>;

function createdAuthority(overrides: Partial<CredentialAuthority> = {}): CreatedAuthority {
  return { ...CREATED_AUTHORITY, ...overrides };
}

function setupTransactionReceipt(): SetupTransactionReceipt {
  return Object.freeze({}) as unknown as SetupTransactionReceipt;
}

function hostPlan(created = true): HostPlanInput {
  return {
    schemaVersion: 1,
    candidates: [
      {
        rootPath: '/workspace/html',
        descriptor: {
          projectId: 'alpha',
          port: 4173,
          installId: 'install-alpha',
          approvedRootIdentity: { device: '1', inode: '2' },
          credentialAuthorities: created ? [] : [AUTHORITY],
        },
        package: undefined,
        viteConfig: undefined,
        sourceScan: {
          complete: true,
          sources: [
            { path: 'public/index.html', source: '<html><head></head><body></body></html>\n' },
          ],
        },
      },
    ],
    credential: created
      ? {
          kind: 'create',
          requestId: 'candidate-alpha',
          bits: 256,
          projectId: CREATED_AUTHORITY.projectId,
          path: CREATED_AUTHORITY.path,
        }
      : { kind: 'adopt', authority: AUTHORITY },
  };
}

function artifact() {
  return {
    path: '/workspace/html/public/scene-glass-loader.js',
    kind: 'file' as const,
    fingerprint: FINGERPRINT,
    hunks: [],
    inverse: {
      kind: 'delete-created-file' as const,
      path: '/workspace/html/public/scene-glass-loader.js',
      expectedFingerprint: FINGERPRINT,
    },
  };
}

function manifest(): SetupManifestV1 {
  return {
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId: 'install-alpha',
    state: 'active',
    artifacts: [artifact()],
  };
}
interface PreparedStart {
  readonly manifest: SetupManifestV1;
  readonly state: 'prepared' | 'transferred';
}
type AssertNever<T extends never> = T;
type RemovedStartApi = Extract<
  keyof LifecycleEngine,
  `preflightStart${string}` | `legacyStart${string}`
>;
export type LifecycleEngineHasNoLegacyStartApi = AssertNever<RemovedStartApi>;

class Port implements LifecycleEnginePort {
  public readonly calls: string[] = [];
  public inspection: LifecycleInspection = { state: 'never-installed' };
  public approved = true;
  public createdCredential = true;
  public failAt: string | undefined;
  public failCompensation = false;
  public failZeroization = false;
  public failStartWait = false;
  public startCleanupFailuresBeforeSuccess = 0;
  public retryStartCleanupFailures = false;
  public forcedPreparationId: string | undefined;
  public candidate = new Uint8Array(32).fill(7);
  public generatedCandidate: Uint8Array | undefined;
  public preparedCandidate: Uint8Array | undefined;
  public readonly preflightInputs: LifecycleSetupPreflightInput[] = [];
  public openedCandidate: Uint8Array | undefined;
  public appliedCandidate: Uint8Array | undefined;
  public zeroizedCandidate: Uint8Array | undefined;
  public claimedPostWriteAuthority: SetupMutationReceipt['createdAuthority'] = {
    ...CREATED_AUTHORITY,
  };
  public observedAuthorityOverrides: Partial<CredentialAuthority> = {};
  public omitObservedPostWriteAuthority = false;
  public observedAuthorityTransform:
    ((authority: ObservedCreatedAuthority) => ObservedCreatedAuthority) | undefined;
  public observed = [
    {
      path: '/workspace/html/public/scene-glass-loader.js',
      fingerprint: FINGERPRINT,
      hunks: [],
      semanticConfig: undefined,
    },
  ];
  public foregroundExit: ForegroundMcpExit = { reason: 'signal', exitCode: 0 };
  public readonly startFacts: LifecycleStartFacts = {
    snapshotId: 'snapshot-alpha',
    selectedProjectId: 'alpha',
    config: { schemaVersion: 1, projects: [PROJECT] },
    projects: [
      {
        projectId: 'alpha',
        authority: { id: 'authority-alpha' },
        descriptor: { id: 'descriptor-alpha' },
        cache: { id: 'cache-alpha' },
      },
    ],
  };
  public preparedStartFacts: LifecycleStartFacts | undefined;
  public readonly preparedStarts = new Map<string, PreparedStart>();
  public nextPreparationId = 0;
  public failPreparedStartDiscard = false;
  public finalizePreparedStart: NonNullable<LifecycleEnginePort['finalizePreparedStart']> =
    async () => undefined;
  public startAuthorityReleaseCount = 0;

  public async inspectLifecycle(input: {
    readonly operation: 'setup' | 'start' | 'uninstall';
  }): Promise<LifecycleInspection> {
    this.hit(`inspect:${input.operation}`);
    return this.inspection;
  }

  public async recoverAuthorizedWal(): Promise<'recovered' | 'recovery-required'> {
    this.hit('recover');
    return 'recovered';
  }

  public async inspectSetupFacts(): Promise<LifecycleSetupFacts> {
    this.hit('setup-facts');
    return {
      configHomes: {
        legacyPath: '/workspace/legacy.json',
        newPath: '/workspace/config.json',
        legacy: undefined,
        new: undefined,
      },
      project: PROJECT,
      hostPlan: hostPlan(this.createdCredential),
      build: { revision: 1 },
    };
  }

  public async buildSetupPlan(input: {
    readonly config: { readonly config: unknown };
    readonly host: { readonly installId: string };
  }): Promise<SetupPlanBuildReceipt> {
    this.hit('build');
    return {
      receiptId: 'builder-alpha',
      plan: {
        schemaVersion: 1,
        installId: input.host.installId,
        state: 'active',
        config: input.config.config as SetupPlan['config'],
        artifacts: [artifact()],
        inverse: [artifact().inverse],
        preview: {
          state: 'active',
          operations: [
            {
              kind: 'create-file',
              path: '/workspace/html/public/scene-glass-loader.js',
              hunkCount: 0,
              hunkSubjects: [],
            },
          ],
        },
      },
    };
  }

  public async requestSetupApproval(): Promise<boolean> {
    this.hit('approval');
    return this.approved;
  }

  public async runNativeSelfTest(): Promise<void> {
    this.hit('native');
  }

  public async runEmptyChromiumSmoke(): Promise<void> {
    this.hit('chromium');
  }

  public async generateCredentialToken(): Promise<Uint8Array> {
    this.hit('token');
    this.generatedCandidate = this.candidate;
    return this.candidate;
  }

  public async zeroizeCredentialToken(input: { readonly token: Uint8Array }): Promise<void> {
    this.zeroizedCandidate = input.token;
    this.hit('zeroize');
    if (this.failZeroization) {
      throw new Error('fault:zeroize');
    }
    input.token.fill(0);
  }

  public async preflightSetup(input: LifecycleSetupPreflightInput): Promise<void> {
    this.hit(`preflight:${input.stage}`);
    this.preflightInputs.push(input);
  }

  public async openSetupTransaction(
    input: Readonly<{
      readonly plan: SetupPlan;
      readonly plannedHost: HostIntegrationPlan;
      readonly mutationId: string;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<LifecycleSetupTransaction> {
    this.hit('transaction:open');
    this.openedCandidate = input.candidate;
    return {
      apply: async ({ observedAuthorityIssuer }): Promise<SetupMutationReceipt> => {
        this.appliedCandidate = input.candidate;
        this.hit('transaction:apply');
        const transactionReceipt = setupTransactionReceipt();
        const issuedAuthority =
          this.createdCredential && !this.omitObservedPostWriteAuthority
            ? createTransactionObservedCredentialAuthority({
                issuer: observedAuthorityIssuer,
                receipt: transactionReceipt,
                authority: createdAuthority(this.observedAuthorityOverrides),
              })
            : undefined;
        const observedCreatedAuthority =
          issuedAuthority === undefined
            ? undefined
            : (this.observedAuthorityTransform?.(issuedAuthority) ?? issuedAuthority);
        return {
          observedCreatedAuthority,
          ...(observedCreatedAuthority === undefined ? {} : { transactionReceipt }),
          ...(this.claimedPostWriteAuthority === undefined
            ? {}
            : { createdAuthority: this.claimedPostWriteAuthority }),
        };
      },
      publishActive: async () => {
        this.hit('transaction:publish');
        return 'active';
      },
      compensate: async () => {
        this.hit('transaction:compensate');
        if (this.failCompensation) {
          throw new Error('fault:transaction:compensate');
        }
        return 'recovered';
      },
    };
  }

  public async prepareSetupMutation(
    input: Readonly<{
      readonly receiptId: string;
      readonly plan: SetupPlan;
      readonly candidate: Uint8Array | undefined;
    }>,
  ): Promise<SetupMutationPreparation> {
    this.hit('prepare');
    this.preparedCandidate = input.candidate;
    return { mutationId: 'mutation-alpha' };
  }

  public async validateFinalizedSetup(): Promise<void> {
    this.hit('validate');
  }

  public async runLiveDiagnostics(): Promise<void> {
    this.hit('diagnostics');
  }

  public async inspectStartFacts(): Promise<LifecycleStartFacts> {
    this.hit('start-facts');
    return this.startFacts;
  }

  public async prepareStart(input: {
    readonly manifest: SetupManifestV1;
    readonly facts: LifecycleStartFacts;
  }): Promise<{ readonly preparationId: string }> {
    this.hit('start:prepare');
    this.preparedStartFacts = input.facts;
    const preparationId = this.forcedPreparationId ?? `prepared-start-${this.nextPreparationId}`;
    this.nextPreparationId += 1;
    if (this.forcedPreparationId === undefined) {
      this.preparedStarts.set(preparationId, { manifest: input.manifest, state: 'prepared' });
    }
    return { preparationId };
  }

  public async discardPreparedStart(input: { readonly preparationId: string }): Promise<void> {
    this.hit('start:discard');
    const prepared = this.preparedStarts.get(input.preparationId);
    if (prepared === undefined) {
      throw new LifecyclePreparedStartUnavailableError('missing');
    }
    if (prepared.state !== 'prepared') {
      throw new LifecyclePreparedStartUnavailableError('reused');
    }
    if (this.failPreparedStartDiscard) {
      throw new Error('prepared start authority cannot be discarded');
    }
    this.preparedStarts.delete(input.preparationId);
  }

  public async launchMcpForeground(input: {
    readonly manifest: SetupManifestV1;
    readonly preparationId: string;
  }): Promise<LifecycleForegroundMcp> {
    this.hit('start:launch');
    const prepared = this.preparedStarts.get(input.preparationId);
    if (prepared === undefined) {
      throw new LifecyclePreparedStartUnavailableError('missing');
    }
    if (
      prepared.state !== 'prepared' ||
      JSON.stringify(prepared.manifest) !== JSON.stringify(input.manifest)
    ) {
      throw new LifecyclePreparedStartUnavailableError('reused');
    }
    this.preparedStarts.set(input.preparationId, { ...prepared, state: 'transferred' });
    let cleanupCalls = 0;
    return {
      waitForExit: async () => {
        this.hit('start:wait');
        if (this.failStartWait) {
          throw new Error('fault:start:wait');
        }
        return this.foregroundExit;
      },
      cleanup: async () => {
        cleanupCalls += 1;
        this.hit('start:cleanup');
        if (cleanupCalls <= this.startCleanupFailuresBeforeSuccess) {
          const error = new Error('fault:start:cleanup');
          if (this.retryStartCleanupFailures) {
            Object.assign(error, { retryable: true });
          }
          throw error;
        }
        if (this.preparedStarts.get(input.preparationId)?.state !== 'transferred') {
          throw new Error('foreground cleanup authority is unavailable');
        }
        this.preparedStarts.delete(input.preparationId);
        this.startAuthorityReleaseCount += 1;
      },
    };
  }

  public async observeUninstallTargets() {
    this.hit('uninstall:observe');
    return { complete: true, observed: this.observed };
  }

  public async openUninstallTransaction(): Promise<LifecycleUninstallTransaction> {
    this.hit('uninstall:open');
    return {
      apply: async () => {
        this.hit('uninstall:apply');
        return 'uninstalled';
      },
      compensate: async () => {
        this.hit('uninstall:compensate');
        return 'recovered';
      },
    };
  }

  private hit(name: string): void {
    this.calls.push(name);
    if (this.failAt === name) {
      throw new Error(`fault:${name}`);
    }
  }
}
function dataRecord(value: unknown, allowedKeys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('expected a plain data record');
  }
  expect(Reflect.ownKeys(value)).toStrictEqual(allowedKeys);
  const record: Record<string, unknown> = {};
  for (const key of allowedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new Error(`expected data descriptor for ${key}`);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function dataArray(value: unknown, visit: (item: unknown) => void): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new Error('expected a dense data array');
  }
  expect(Reflect.ownKeys(value)).toStrictEqual([
    ...Array.from({ length: value.length }, (_, index) => String(index)),
    'length',
  ]);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new Error(`expected data descriptor for array item ${index}`);
    }
    visit(descriptor.value);
  }
  const length = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    length === undefined ||
    !Object.hasOwn(length, 'value') ||
    length.get !== undefined ||
    length.set !== undefined
  ) {
    throw new Error('expected data descriptor for array length');
  }
  return value;
}

function assertAuthority(value: unknown, created: boolean, finalized: boolean): void {
  const expected = created ? CREATED_AUTHORITY : AUTHORITY;
  const authority = dataRecord(
    value,
    finalized || !created ? ['projectId', 'path', 'device', 'inode'] : ['projectId', 'path'],
  );
  expect(authority).toStrictEqual(
    finalized || !created
      ? expected
      : { projectId: CREATED_AUTHORITY.projectId, path: CREATED_AUTHORITY.path },
  );
}

function assertInverse(value: unknown): void {
  const inverse = dataRecord(value, ['kind', 'path', 'expectedFingerprint']);
  expect(inverse).toStrictEqual(artifact().inverse);
}

function assertOwnedArtifact(value: unknown): void {
  const owned = dataRecord(value, ['path', 'kind', 'fingerprint', 'hunks', 'inverse']);
  expect(owned.path).toBe('/workspace/html/public/scene-glass-loader.js');
  expect(owned.kind).toBe('file');
  expect(owned.fingerprint).toBe(FINGERPRINT);
  dataArray(owned.hunks, () => {
    throw new Error('expected no owned artifact hunks');
  });
  assertInverse(owned.inverse);
}

function assertPlannedHostArtifact(value: unknown): void {
  const planned = dataRecord(value, ['role', 'artifact']);
  if (planned.role !== 'loader' && planned.role !== 'descriptor' && planned.role !== 'helper') {
    throw new Error('expected a static host artifact role');
  }
  const artifact = dataRecord(planned.artifact, [
    'path',
    'kind',
    'fingerprint',
    'hunks',
    'inverse',
  ]);
  expect(artifact.path).toBe(
    planned.role === 'loader'
      ? '/workspace/html/public/index.html'
      : planned.role === 'descriptor'
        ? '/workspace/html/.scg/runtime/host-descriptor.v1.json'
        : '/workspace/html/.scg/runtime/host-integration-helper.mjs',
  );
  expect(artifact.kind).toBe('file');
  expect(typeof artifact.fingerprint).toBe('string');
  dataArray(artifact.hunks, (hunk) => {
    const ownedHunk = dataRecord(hunk, ['id', 'fingerprint', 'operation', 'subject']);
    expect(typeof ownedHunk.id).toBe('string');
    expect(typeof ownedHunk.fingerprint).toBe('string');
    expect(['insert', 'update']).toContain(ownedHunk.operation);
    expect(typeof ownedHunk.subject).toBe('string');
  });
  expect(artifact.hunks).toHaveLength(1);
  if (planned.role === 'loader') {
    expect(dataRecord(artifact.inverse, ['kind'])).toStrictEqual({ kind: 'none' });
    return;
  }
  const inverse = dataRecord(artifact.inverse, ['kind', 'path', 'expectedFingerprint']);
  expect(inverse).toStrictEqual({
    kind: 'delete-created-file',
    path: artifact.path,
    expectedFingerprint: artifact.fingerprint,
  });
}

function assertDescriptor(value: unknown, created: boolean, finalized: boolean): void {
  const descriptor = dataRecord(
    value,
    finalized
      ? [
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
        ]
      : [
          'kind',
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
        ],
  );
  if (!finalized) {
    expect(descriptor.kind).toBe('host-descriptor-blueprint-v1');
  }
  expect({
    schemaVersion: descriptor.schemaVersion,
    template: descriptor.template,
    publicRoot: descriptor.publicRoot,
    host: descriptor.host,
    port: descriptor.port,
    projectId: descriptor.projectId,
    loaderUrl: descriptor.loaderUrl,
    credentialProjectId: descriptor.credentialProjectId,
    credentialKey: descriptor.credentialKey,
    navigation: descriptor.navigation,
    readinessPath: descriptor.readinessPath,
  }).toStrictEqual({
    schemaVersion: 1,
    template: 'public/index.html',
    publicRoot: 'public',
    host: '127.0.0.1',
    port: 4173,
    projectId: 'alpha',
    loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
    credentialProjectId: 'alpha',
    credentialKey: 'SCENE_GLASS_HOST_TOKEN',
    navigation: 'document',
    readinessPath: '/__scene-glass/ready',
  });
  expect(dataRecord(descriptor.approvedRootIdentity, ['device', 'inode'])).toStrictEqual({
    device: '1',
    inode: '2',
  });
  const credentialAuthorities = dataArray(descriptor.credentialAuthorities, (authority) =>
    assertAuthority(authority, created, finalized),
  );
  expect(credentialAuthorities).toHaveLength(1);
  if (!created && !finalized) {
    expect(credentialAuthorities[0]).toStrictEqual(AUTHORITY);
  }
}

function assertCredential(value: unknown, created: boolean): void {
  if (created) {
    const credential = dataRecord(value, [
      'kind',
      'requestId',
      'bits',
      'projectId',
      'path',
      'artifact',
    ]);
    expect({
      kind: credential.kind,
      requestId: credential.requestId,
      bits: credential.bits,
      projectId: credential.projectId,
      path: credential.path,
    }).toStrictEqual({
      kind: 'setup-created-candidate',
      requestId: 'candidate-alpha',
      bits: 256,
      projectId: CREATED_AUTHORITY.projectId,
      path: CREATED_AUTHORITY.path,
    });
    const artifactValue = dataRecord(credential.artifact, ['path', 'kind', 'ownership', 'inverse']);
    expect({
      path: artifactValue.path,
      kind: artifactValue.kind,
      ownership: artifactValue.ownership,
      inverse: dataRecord(artifactValue.inverse, ['kind', 'path']),
    }).toStrictEqual({
      path: CREATED_AUTHORITY.path,
      kind: 'credential',
      ownership: 'setup-created',
      inverse: { kind: 'delete-created-credential', path: CREATED_AUTHORITY.path },
    });
    return;
  }

  const credential = dataRecord(value, ['kind', 'authority', 'artifact']);
  expect(credential.kind).toBe('adopted-authority');
  expect(dataRecord(credential.authority, ['projectId', 'path', 'device', 'inode'])).toStrictEqual(
    AUTHORITY,
  );
  const artifactValue = dataRecord(credential.artifact, ['path', 'kind', 'ownership', 'inverse']);
  expect({
    path: artifactValue.path,
    kind: artifactValue.kind,
    ownership: artifactValue.ownership,
    inverse: dataRecord(artifactValue.inverse, ['kind']),
  }).toStrictEqual({
    path: AUTHORITY.path,
    kind: 'credential',
    ownership: 'adopted',
    inverse: { kind: 'none' },
  });
}

function assertSetupPlan(value: unknown): void {
  const plan = dataRecord(value, [
    'schemaVersion',
    'installId',
    'state',
    'config',
    'artifacts',
    'inverse',
    'preview',
  ]);
  expect({
    schemaVersion: plan.schemaVersion,
    installId: plan.installId,
    state: plan.state,
  }).toStrictEqual({ schemaVersion: 1, installId: 'install-alpha', state: 'active' });
  const config = dataRecord(plan.config, ['schemaVersion', 'projects']);
  expect(config.schemaVersion).toBe(1);
  dataArray(config.projects, (project) => {
    const projectRecord = dataRecord(project, [
      'projectId',
      'root',
      'allowedOrigins',
      'tokenEnv',
      'framework',
    ]);
    expect(projectRecord.projectId).toBe(PROJECT.projectId);
    expect(projectRecord.root).toBe(PROJECT.root);
    dataArray(projectRecord.allowedOrigins, (origin) => {
      expect(origin).toBe('http://127.0.0.1:4173');
    });
    expect(projectRecord.tokenEnv).toBe(PROJECT.tokenEnv);
    expect(projectRecord.framework).toBe(PROJECT.framework);
  });
  expect(config.projects).toHaveLength(1);
  dataArray(plan.artifacts, assertOwnedArtifact);
  expect(plan.artifacts).toHaveLength(1);
  dataArray(plan.inverse, assertInverse);
  expect(plan.inverse).toHaveLength(1);
  const preview = dataRecord(plan.preview, ['state', 'operations']);
  expect(preview.state).toBe('active');
  dataArray(preview.operations, (operation) => {
    const previewOperation = dataRecord(operation, ['kind', 'path', 'hunkCount', 'hunkSubjects']);
    expect({
      kind: previewOperation.kind,
      path: previewOperation.path,
      hunkCount: previewOperation.hunkCount,
    }).toStrictEqual({
      kind: 'create-file',
      path: '/workspace/html/public/scene-glass-loader.js',
      hunkCount: 0,
    });
    dataArray(previewOperation.hunkSubjects, () => {
      throw new Error('expected no public hunk subjects');
    });
  });
  expect(preview.operations).toHaveLength(1);
}

function assertHost(value: unknown, created: boolean, finalized: boolean): void {
  const host = dataRecord(value, [
    'schemaVersion',
    'host',
    'rootPath',
    'installId',
    'descriptor',
    'loader',
    'credential',
    'artifacts',
  ]);
  expect({
    schemaVersion: host.schemaVersion,
    host: host.host,
    rootPath: host.rootPath,
    installId: host.installId,
  }).toStrictEqual({
    schemaVersion: 1,
    host: 'html',
    rootPath: '/workspace/html',
    installId: 'install-alpha',
  });
  assertDescriptor(host.descriptor, created, finalized);
  expect(
    dataRecord(host.loader, [
      'async',
      'navigation',
      'dataScgNavigation',
      'sourceMarker',
      'sourceMarkerPlacement',
      'targetPath',
      'insertionStrategy',
    ]),
  ).toStrictEqual({
    async: true,
    navigation: 'document',
    dataScgNavigation: 'document',
    sourceMarker: true,
    sourceMarkerPlacement: 'immediately-before-unique-head',
    targetPath: 'public/index.html',
    insertionStrategy: 'immediately-before-unique-head',
  });
  assertCredential(host.credential, created);
  dataArray(host.artifacts, assertPlannedHostArtifact);
  expect(host.artifacts).toHaveLength(3);
}

function assertExactPreflight(input: LifecycleSetupPreflightInput, created: boolean): void {
  const preflight = dataRecord(
    input,
    input.stage === 3
      ? ['stage', 'plan', 'finalizedHost', 'mutationId', 'candidate']
      : ['stage', 'plan', 'plannedHost', 'mutationId', 'candidate'],
  );
  expect(preflight.mutationId).toBe('mutation-alpha');
  assertSetupPlan(preflight.plan);
  if (input.stage === 3) {
    assertHost(preflight.finalizedHost, created, true);
  } else {
    assertHost(preflight.plannedHost, created, false);
  }
}
function expectSetupPreflights(port: Port, created: boolean): void {
  const [first, second, third] = port.preflightInputs;
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    first.stage !== 1 ||
    second.stage !== 2 ||
    third.stage !== 3
  ) {
    throw new Error('expected exactly one preflight at each setup stage');
  }

  for (const input of [first, second]) {
    assertExactPreflight(input, created);
    const authority = input.plannedHost.descriptor.credentialAuthorities[0];
    if (authority === undefined) {
      throw new Error('expected planned credential authority');
    }
    expect(Object.isFrozen(input)).toBe(true);
    expect(Object.isFrozen(input.plan)).toBe(true);
    expect(Object.isFrozen(input.plannedHost)).toBe(true);
    expect(Object.isFrozen(input.plannedHost.descriptor)).toBe(true);
    expect(Object.isFrozen(input.plannedHost.descriptor.credentialAuthorities)).toBe(true);
    expect(Object.isFrozen(authority)).toBe(true);
    expect(Object.isFrozen(input.plannedHost.artifacts)).toBe(true);
  }

  assertExactPreflight(third, created);
  const finalizedAuthority = third.finalizedHost.descriptor.credentialAuthorities[0];
  if (finalizedAuthority === undefined) {
    throw new Error('expected finalized credential authority');
  }
  expect(Object.isFrozen(third)).toBe(true);
  expect(Object.isFrozen(third.plan)).toBe(true);
  expect(Object.isFrozen(third.finalizedHost)).toBe(true);
  expect(Object.isFrozen(third.finalizedHost.descriptor)).toBe(true);
  expect(Object.isFrozen(third.finalizedHost.descriptor.credentialAuthorities)).toBe(true);
  expect(Object.isFrozen(finalizedAuthority)).toBe(true);
  expect(Object.isFrozen(third.finalizedHost.artifacts)).toBe(true);

  expect(first.plannedHost).not.toBe(second.plannedHost);
  expect(first.plannedHost).toStrictEqual(second.plannedHost);
  if (created) {
    expect(first.candidate).toBe(port.candidate);
    expect(second.candidate).toBe(port.candidate);
    expect(third.candidate).toBe(port.candidate);
  } else {
    expect(first.candidate).toBeUndefined();
    expect(second.candidate).toBeUndefined();
    expect(third.candidate).toBeUndefined();
  }
}

describe('onboarding lifecycle engine', () => {
  it('performs approved created-credential setup with exact immutable public preflights', async () => {
    const port = new Port();
    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'success',
      state: 'active',
      code: 'SCG_LIFECYCLE_ACTIVE',
    });
    expect(port.calls).toEqual([
      'inspect:setup',
      'setup-facts',
      'build',
      'approval',
      'native',
      'chromium',
      'token',
      'prepare',
      'preflight:1',
      'transaction:open',
      'preflight:2',
      'transaction:apply',
      'validate',
      'preflight:3',
      'diagnostics',
      'transaction:publish',
      'zeroize',
    ]);
    expectSetupPreflights(port, true);
    expect(port.generatedCandidate).toBe(port.candidate);
    expect(port.preparedCandidate).toBe(port.candidate);
    expect(port.openedCandidate).toBe(port.candidate);
    expect(port.appliedCandidate).toBe(port.candidate);
    expect(port.zeroizedCandidate).toBe(port.candidate);
    expect(port.candidate).toEqual(new Uint8Array(32));
  });

  it('uses exact adopted-credential host semantics without a candidate in all public preflights', async () => {
    const port = new Port();
    port.createdCredential = false;
    port.claimedPostWriteAuthority = undefined;

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'success',
      state: 'active',
      code: 'SCG_LIFECYCLE_ACTIVE',
    });
    expect(port.calls).toEqual([
      'inspect:setup',
      'setup-facts',
      'build',
      'approval',
      'native',
      'chromium',
      'prepare',
      'preflight:1',
      'transaction:open',
      'preflight:2',
      'transaction:apply',
      'validate',
      'preflight:3',
      'diagnostics',
      'transaction:publish',
    ]);
    expectSetupPreflights(port, false);
    expect(port.generatedCandidate).toBeUndefined();
    expect(port.zeroizedCandidate).toBeUndefined();
  });

  it('declines before entropy, lock, process, or write-capable transaction work', async () => {
    const port = new Port();
    port.approved = false;

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({ status: 'success', code: 'SCG_LIFECYCLE_DECLINED' });
    expect(port.calls).toEqual(['inspect:setup', 'setup-facts', 'build', 'approval']);
  });

  it.each([
    [
      'native',
      'native-self-test',
      false,
      ['inspect:setup', 'setup-facts', 'build', 'approval', 'native'],
    ],
    [
      'chromium',
      'chromium-smoke',
      false,
      ['inspect:setup', 'setup-facts', 'build', 'approval', 'native', 'chromium'],
    ],
    [
      'token',
      'token-generation',
      false,
      ['inspect:setup', 'setup-facts', 'build', 'approval', 'native', 'chromium', 'token'],
    ],
    [
      'prepare',
      'mutation-preparation',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'zeroize',
      ],
    ],
    [
      'preflight:1',
      'public-preflight-1',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'zeroize',
      ],
    ],
    [
      'transaction:open',
      'transaction-open',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'zeroize',
      ],
    ],
    [
      'preflight:2',
      'public-preflight-2',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:compensate',
        'zeroize',
      ],
    ],
    [
      'transaction:apply',
      'transaction-apply',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'transaction:compensate',
        'zeroize',
      ],
    ],
    [
      'validate',
      'authority-validation',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'transaction:compensate',
        'zeroize',
      ],
    ],
    [
      'preflight:3',
      'public-preflight-3',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
        'transaction:compensate',
        'zeroize',
      ],
    ],
    [
      'diagnostics',
      'diagnostics',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
        'diagnostics',
        'transaction:compensate',
        'zeroize',
      ],
    ],
    [
      'transaction:publish',
      'active-publication',
      true,
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
        'diagnostics',
        'transaction:publish',
        'transaction:compensate',
        'zeroize',
      ],
    ],
  ] as const)(
    'stops setup at the failed boundary and compensates only after transaction open (%s)',
    async (failure, stage, zeroizes, trace) => {
      const port = new Port();
      port.failAt = failure;

      const result = await new LifecycleEngine(port).runSetup();

      expect(result).toMatchObject({ status: 'failed', code: 'SCG_LIFECYCLE_FAILED' });
      expect(result.failures).toStrictEqual([{ stage }]);
      expect(port.calls).toStrictEqual(trace);
      expect(port.zeroizedCandidate).toBe(zeroizes ? port.candidate : undefined);
      expect(port.candidate).toEqual(zeroizes ? new Uint8Array(32) : new Uint8Array(32).fill(7));
    },
  );
  it.each([31, 33])(
    'rejects a generated candidate with %i bytes before preparation and zeroes that same object',
    async (length) => {
      const port = new Port();
      port.candidate = new Uint8Array(length).fill(7);

      const result = await new LifecycleEngine(port).runSetup();

      expect(result.status).toBe('failed');
      expect(result.state).toBe('never-installed');
      expect(result.code).toBe('SCG_LIFECYCLE_FAILED');
      expect(result.failures).toStrictEqual([{ stage: 'token-generation' }]);
      expect(port.calls).toStrictEqual([
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'zeroize',
      ]);
      expect(port.generatedCandidate).toBe(port.candidate);
      expect(port.zeroizedCandidate).toBe(port.candidate);
      expect(port.candidate).toEqual(new Uint8Array(length));
    },
  );
  it.each([
    [
      'cloned',
      (authority: ObservedCreatedAuthority): ObservedCreatedAuthority =>
        ({ ...authority }) as unknown as ObservedCreatedAuthority,
    ],
    [
      'independently frozen',
      (authority: ObservedCreatedAuthority): ObservedCreatedAuthority =>
        Object.freeze({ ...authority }) as unknown as ObservedCreatedAuthority,
    ],
    [
      'forged',
      (): ObservedCreatedAuthority =>
        Object.freeze(Object.create(null)) as ObservedCreatedAuthority,
    ],
  ] as const)(
    'rejects a %s observed created-authority capability before validation or publication',
    async (_case, observedAuthorityTransform) => {
      const port = new Port();
      port.observedAuthorityTransform = observedAuthorityTransform;

      const result = await new LifecycleEngine(port).runSetup();

      expect(result.status).toBe('failed');
      expect(result.state).toBe('never-installed');
      expect(result.code).toBe('SCG_LIFECYCLE_FAILED');
      expect(result.failures).toStrictEqual([{ stage: 'transaction-apply' }]);
      expect(port.calls).toStrictEqual([
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'transaction:compensate',
        'zeroize',
      ]);
      expect(port.calls.filter((call) => call === 'transaction:compensate')).toHaveLength(1);
      expect(port.calls.filter((call) => call === 'zeroize')).toHaveLength(1);
      expect(port.calls).not.toContain('validate');
      expect(port.calls).not.toContain('preflight:3');
      expect(port.calls).not.toContain('diagnostics');
      expect(port.calls).not.toContain('transaction:publish');
      expect(port.zeroizedCandidate).toBe(port.candidate);
      expect(port.candidate).toEqual(new Uint8Array(32));
    },
  );
  it('zeroes the candidate even when adapter zeroization fails', async () => {
    const port = new Port();
    port.failAt = 'zeroize';

    const result = await new LifecycleEngine(port).runSetup();

    expect(result.status).toBe('success');
    expect(result.failures).toStrictEqual([{ stage: 'token-zeroization' }]);
    expect(port.calls).toStrictEqual([
      'inspect:setup',
      'setup-facts',
      'build',
      'approval',
      'native',
      'chromium',
      'token',
      'prepare',
      'preflight:1',
      'transaction:open',
      'preflight:2',
      'transaction:apply',
      'validate',
      'preflight:3',
      'diagnostics',
      'transaction:publish',
      'zeroize',
    ]);
    expect(port.zeroizedCandidate).toBe(port.candidate);
    expect(port.candidate).toEqual(new Uint8Array(32));
  });
  it.each([
    [
      'preflight:2',
      'public-preflight-2',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
      ],
    ],
    [
      'transaction:apply',
      'transaction-apply',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
      ],
    ],
    [
      'validate',
      'authority-validation',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
      ],
    ],
    [
      'diagnostics',
      'diagnostics',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
        'diagnostics',
      ],
    ],
    [
      'preflight:3',
      'public-preflight-3',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
      ],
    ],
    [
      'transaction:publish',
      'active-publication',
      [
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'validate',
        'preflight:3',
        'diagnostics',
        'transaction:publish',
      ],
    ],
  ] as const)(
    'retains the primary %s failure when compensation and zeroization also fail',
    async (failure, primaryStage, primaryTrace) => {
      const port = new Port();
      port.failAt = failure;
      port.failCompensation = true;
      port.failZeroization = true;

      const result = await new LifecycleEngine(port).runSetup();

      expect(result).toMatchObject({
        status: 'failed',
        state: 'recovery-required',
        code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      });
      expect(result.failures).toStrictEqual([
        { stage: primaryStage },
        { stage: 'compensation' },
        { stage: 'token-zeroization' },
      ]);
      expect(port.calls).toStrictEqual([...primaryTrace, 'transaction:compensate', 'zeroize']);
      expect(port.zeroizedCandidate).toBe(port.candidate);
      expect(port.candidate).toEqual(new Uint8Array(32));
    },
  );
  it.each([
    ['missing claimed authority', undefined, {}, false],
    ['missing observed authority', createdAuthority(), {}, true],
    ['missing claimed and observed authority', undefined, {}, true],
    ['observed-only projectId mismatch', createdAuthority(), { projectId: 'bravo' }, false],
    ['claimed-only projectId mismatch', createdAuthority({ projectId: 'bravo' }), {}, false],
    [
      'both-equal-but-wrong projectId',
      createdAuthority({ projectId: 'bravo' }),
      { projectId: 'bravo' },
      false,
    ],
    [
      'observed-only path mismatch',
      createdAuthority(),
      { path: '/var/lib/scene-glass/wrong.credential' },
      false,
    ],
    [
      'claimed-only path mismatch',
      createdAuthority({ path: '/var/lib/scene-glass/wrong.credential' }),
      {},
      false,
    ],
    [
      'both-equal-but-wrong path',
      createdAuthority({ path: '/var/lib/scene-glass/wrong.credential' }),
      { path: '/var/lib/scene-glass/wrong.credential' },
      false,
    ],
    ['observed-only device mismatch', createdAuthority(), { device: '12' }, false],
    ['claimed-only device mismatch', createdAuthority({ device: '12' }), {}, false],
    ['observed-only inode mismatch', createdAuthority(), { inode: '22' }, false],
    ['claimed-only inode mismatch', createdAuthority({ inode: '22' }), {}, false],
  ] as const)(
    'rejects %s created-credential authority before validation, diagnostics, or publication',
    async (_case, claimedAuthority, observedAuthorityOverrides, omitObservedPostWriteAuthority) => {
      const port = new Port();
      port.claimedPostWriteAuthority = claimedAuthority;
      port.observedAuthorityOverrides = observedAuthorityOverrides;
      port.omitObservedPostWriteAuthority = omitObservedPostWriteAuthority;

      const result = await new LifecycleEngine(port).runSetup();

      expect(result).toMatchObject({
        status: 'failed',
        state: 'never-installed',
        code: 'SCG_LIFECYCLE_FAILED',
      });
      expect(result.failures).toStrictEqual([{ stage: 'transaction-apply' }]);
      expect(port.calls).toStrictEqual([
        'inspect:setup',
        'setup-facts',
        'build',
        'approval',
        'native',
        'chromium',
        'token',
        'prepare',
        'preflight:1',
        'transaction:open',
        'preflight:2',
        'transaction:apply',
        'transaction:compensate',
        'zeroize',
      ]);
      expect(port.calls.filter((call) => call === 'transaction:compensate')).toHaveLength(1);
      expect(port.calls.filter((call) => call === 'zeroize')).toHaveLength(1);
      expect(port.calls).not.toContain('validate');
      expect(port.calls).not.toContain('preflight:3');
      expect(port.calls).not.toContain('diagnostics');
      expect(port.calls).not.toContain('transaction:publish');
      expect(port.zeroizedCandidate).toBe(port.candidate);
      expect(port.candidate).toEqual(new Uint8Array(32));
    },
  );

  it('rejects a claimed created authority for an adopted credential before publication', async () => {
    const port = new Port();
    port.createdCredential = false;
    port.claimedPostWriteAuthority = createdAuthority();

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'failed',
      state: 'never-installed',
      code: 'SCG_LIFECYCLE_FAILED',
    });
    expect(result.failures).toStrictEqual([{ stage: 'transaction-apply' }]);
    expect(port.calls).toStrictEqual([
      'inspect:setup',
      'setup-facts',
      'build',
      'approval',
      'native',
      'chromium',
      'prepare',
      'preflight:1',
      'transaction:open',
      'preflight:2',
      'transaction:apply',
      'transaction:compensate',
    ]);
    expect(port.zeroizedCandidate).toBeUndefined();
  });

  it('converges an active setup rerun without discovery or transaction work', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({ status: 'success', state: 'active' });
    expect(port.calls).toEqual(['inspect:setup']);
  });

  it('recovers an authorized WAL before inspecting setup facts', async () => {
    const port = new Port();
    let inspections = 0;
    port.inspectLifecycle = async (input) => {
      port.calls.push(`inspect:${input.operation}`);
      inspections += 1;
      return inspections === 1
        ? { state: 'recovery-required', authorizedWal: { recoveryId: 'recovery-alpha' } }
        : { state: 'active', activeManifest: manifest() };
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({ status: 'success', state: 'active' });
    expect(port.calls).toEqual(['inspect:setup', 'recover', 'inspect:setup']);
  });
  it('fails closed when authorized WAL recovery remains unresolved without starting fresh setup work', async () => {
    const port = new Port();
    port.inspection = {
      state: 'recovery-required',
      authorizedWal: { recoveryId: 'recovery-alpha' },
    };
    port.recoverAuthorizedWal = async () => {
      port.calls.push('recover');
      return 'recovery-required';
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'failed',
      state: 'recovery-required',
      code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
    });
    expect(port.calls).toStrictEqual(['inspect:setup', 'recover']);
    expect(port.calls).not.toContain('setup-facts');
    expect(port.calls).not.toContain('token');
    expect(port.calls).not.toContain('prepare');
    expect(port.calls).not.toContain('transaction:open');
  });

  it('fails closed when recovered WAL reinspection remains unresolved without starting fresh setup work', async () => {
    const port = new Port();
    let inspections = 0;
    port.inspectLifecycle = async (input) => {
      port.calls.push(`inspect:${input.operation}`);
      inspections += 1;
      return {
        state: 'recovery-required',
        authorizedWal: { recoveryId: `recovery-${inspections}` },
      };
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'failed',
      state: 'recovery-required',
      code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
    });
    expect(port.calls).toStrictEqual(['inspect:setup', 'recover', 'inspect:setup']);
    expect(port.calls).not.toContain('setup-facts');
    expect(port.calls).not.toContain('token');
    expect(port.calls).not.toContain('prepare');
    expect(port.calls).not.toContain('transaction:open');
  });

  it('deeply snapshots mutable start facts before foreground launch and releases the transferred authority in cleanup', async () => {
    const port = new Port();
    const sourceAllowedOrigins = ['http://127.0.0.1:4173'];
    const sourceConfigValues = ['config-before'];
    const sourceAuthorityValues = ['authority-before'];
    const sourceConfig = {
      nested: { values: sourceConfigValues },
      projects: [{ allowedOrigins: sourceAllowedOrigins, projectId: 'alpha' }],
      schemaVersion: 1,
    };
    const sourceAuthority = { id: 'authority-alpha', nested: { values: sourceAuthorityValues } };
    const sourceFacts: LifecycleStartFacts = {
      snapshotId: 'snapshot-alpha',
      selectedProjectId: 'alpha',
      config: sourceConfig,
      projects: [
        {
          projectId: 'alpha',
          authority: sourceAuthority,
          descriptor: { id: 'descriptor-alpha' },
          cache: { id: 'cache-alpha' },
        },
      ],
    };
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.inspectStartFacts = async () => {
      port.calls.push('start-facts');
      return sourceFacts;
    };
    const prepareStart = port.prepareStart.bind(port);
    port.prepareStart = async (input) => {
      sourceAllowedOrigins.push('http://127.0.0.1:4999');
      sourceConfigValues.push('config-after');
      sourceAuthorityValues.push('authority-after');
      return prepareStart(input);
    };

    const result = await new LifecycleEngine(port).runStart();

    const facts = port.preparedStartFacts;
    const preparedProject = facts?.projects[0];
    if (facts === undefined || preparedProject === undefined) {
      throw new Error('expected prepared start facts');
    }
    const preparedConfig = facts.config as {
      readonly nested: { readonly values: readonly string[] };
      readonly projects: readonly {
        readonly allowedOrigins: readonly string[];
        readonly projectId: string;
      }[];
      readonly schemaVersion: number;
    };
    const preparedAuthority = preparedProject.authority as {
      readonly id: string;
      readonly nested: { readonly values: readonly string[] };
    };
    const preparedConfigProject = preparedConfig.projects[0];
    if (preparedConfigProject === undefined) {
      throw new Error('expected prepared config project');
    }

    expect(result).toMatchObject({ status: 'success', code: 'SCG_LIFECYCLE_START_EXITED' });
    expect(port.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:launch',
      'start:wait',
      'start:cleanup',
    ]);
    expect(facts).not.toBe(sourceFacts);
    expect(facts.config).not.toBe(sourceConfig);
    expect(preparedConfig.projects).not.toBe(sourceConfig.projects);
    expect(preparedConfigProject).not.toBe(sourceConfig.projects[0]);
    expect(preparedConfigProject.allowedOrigins).not.toBe(sourceAllowedOrigins);
    expect(preparedProject.authority).not.toBe(sourceAuthority);
    expect(preparedAuthority.nested.values).not.toBe(sourceAuthorityValues);
    expect(Object.isFrozen(facts)).toBe(true);
    expect(Object.isFrozen(preparedConfig)).toBe(true);
    expect(Object.isFrozen(preparedConfig.nested)).toBe(true);
    expect(Object.isFrozen(preparedConfig.nested.values)).toBe(true);
    expect(Object.isFrozen(preparedConfig.projects)).toBe(true);
    expect(Object.isFrozen(preparedConfigProject)).toBe(true);
    expect(Object.isFrozen(preparedConfigProject.allowedOrigins)).toBe(true);
    expect(Object.isFrozen(preparedAuthority)).toBe(true);
    expect(Object.isFrozen(preparedAuthority.nested)).toBe(true);
    expect(Object.isFrozen(preparedAuthority.nested.values)).toBe(true);
    expect(preparedConfig).toStrictEqual({
      nested: { values: ['config-before'] },
      projects: [{ allowedOrigins: ['http://127.0.0.1:4173'], projectId: 'alpha' }],
      schemaVersion: 1,
    });
    expect(preparedAuthority).toStrictEqual({
      id: 'authority-alpha',
      nested: { values: ['authority-before'] },
    });
    expect(() => {
      (preparedConfigProject.allowedOrigins as string[]).push('http://attacker.invalid');
    }).toThrow(TypeError);
    expect(sourceAllowedOrigins).toStrictEqual(['http://127.0.0.1:4173', 'http://127.0.0.1:4999']);
    expect(sourceConfigValues).toStrictEqual(['config-before', 'config-after']);
    expect(sourceAuthorityValues).toStrictEqual(['authority-before', 'authority-after']);
    expect(port.preparedStarts.size).toBe(0);
  });

  it('rejects accessor, prototype, and cyclic start facts before preparation or launch', async () => {
    const validFacts = (): Record<string, unknown> => ({
      config: { projects: [{ projectId: 'alpha' }], schemaVersion: 1 },
      projects: [
        {
          authority: { id: 'authority-alpha' },
          cache: { id: 'cache-alpha' },
          descriptor: { id: 'descriptor-alpha' },
          projectId: 'alpha',
        },
      ],
      selectedProjectId: 'alpha',
      snapshotId: 'snapshot-alpha',
    });
    let accessorCalls = 0;
    const accessorFacts = validFacts();
    Object.defineProperty(accessorFacts, 'config', {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls += 1;
        return { schemaVersion: 1 };
      },
    });
    const prototypeFacts = validFacts();
    Object.setPrototypeOf(prototypeFacts, { inherited: 'hostile' });
    const cyclicFacts = validFacts();
    const cyclicConfig = cyclicFacts.config;
    if (cyclicConfig === null || typeof cyclicConfig !== 'object') {
      throw new Error('expected mutable cyclic config fixture');
    }
    Object.assign(cyclicConfig, { self: cyclicConfig });
    const invalidSnapshotIdFacts = validFacts();
    invalidSnapshotIdFacts.snapshotId = '';
    const missingSnapshotIdFacts = validFacts();
    delete missingSnapshotIdFacts.snapshotId;
    const duplicateProjectFacts = validFacts();
    const duplicateProjects = duplicateProjectFacts.projects;
    if (!Array.isArray(duplicateProjects)) {
      throw new Error('expected mutable duplicate project fixture');
    }
    duplicateProjects.push({
      authority: { id: 'authority-beta' },
      cache: { id: 'cache-beta' },
      descriptor: { id: 'descriptor-beta' },
      projectId: 'alpha',
    });
    const absentSelectedProjectFacts = validFacts();
    absentSelectedProjectFacts.selectedProjectId = 'beta';

    for (const [, facts] of [
      ['accessor', accessorFacts],
      ['prototype', prototypeFacts],
      ['cycle', cyclicFacts],
      ['invalid snapshot ID', invalidSnapshotIdFacts],
      ['missing snapshot ID', missingSnapshotIdFacts],
      ['duplicate projects', duplicateProjectFacts],
      ['absent selected project', absentSelectedProjectFacts],
    ] as const) {
      const port = new Port();
      port.inspection = { state: 'active', activeManifest: manifest() };
      port.inspectStartFacts = async () => {
        port.calls.push('start-facts');
        return facts as unknown as LifecycleStartFacts;
      };

      const result = await new LifecycleEngine(port).runStart();

      expect(result).toMatchObject({
        status: 'failed',
        state: 'active',
        code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      });
      expect(result.failures).toStrictEqual([{ stage: 'start-registry-preflight' }]);
      expect(port.calls).toStrictEqual(['inspect:start', 'start-facts']);
    }
    expect(accessorCalls).toBe(0);
  });

  it('blocks start before foreground launch when prepared-start preflight fails', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.failAt = 'start:prepare';

    const result = await new LifecycleEngine(port).runStart();

    expect(result).toMatchObject({ status: 'failed', code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED' });
    expect(result.failures).toEqual([{ stage: 'start-registry-preflight' }]);
    expect(port.calls).toEqual(['inspect:start', 'start-facts', 'start:prepare']);
  });
  it('finalizes prepared starts before launch, retains branded diagnostics, and revokes on rejection', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.finalizePreparedStart = async ({ preparationId }) => {
      port.calls.push(`start:finalize:${preparationId}`);
    };

    const success = await new LifecycleEngine(port).runStart();

    expect(success).toMatchObject({ status: 'success', code: 'SCG_LIFECYCLE_START_EXITED' });
    expect(port.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:finalize:prepared-start-0',
      'start:launch',
      'start:wait',
      'start:cleanup',
    ]);
    expect(port.startAuthorityReleaseCount).toBe(1);
    expect(port.preparedStarts.size).toBe(0);

    const brandedPort = new Port();
    brandedPort.inspection = { state: 'active', activeManifest: manifest() };
    brandedPort.finalizePreparedStart = async () => {
      throw new LifecycleStartDiagnosticError({
        code: 'SCG_START_VITE_ORIGIN_CONFLICT',
        projectId: 'alpha',
      });
    };
    const branded = await new LifecycleEngine(brandedPort).runStart();
    expect(branded).toMatchObject({
      code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      startDiagnostic: { code: 'SCG_START_VITE_ORIGIN_CONFLICT', projectId: 'alpha' },
    });
    expect(brandedPort.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:discard',
    ]);
    expect(brandedPort.preparedStarts.size).toBe(0);

    const genericPort = new Port();
    genericPort.inspection = { state: 'active', activeManifest: manifest() };
    genericPort.finalizePreparedStart = async () => {
      throw new Error('adapter-private-failure');
    };
    const generic = await new LifecycleEngine(genericPort).runStart();
    expect(generic).toMatchObject({
      code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      failures: [{ stage: 'start-registry-preflight' }],
    });
    expect(generic).not.toHaveProperty('startDiagnostic');
    expect(genericPort.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:discard',
    ]);
    expect(genericPort.preparedStarts.size).toBe(0);
  });

  it('discards a prepared start when foreground launch fails before transfer', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.failAt = 'start:launch';

    const result = await new LifecycleEngine(port).runStart();

    expect(result).toMatchObject({ status: 'failed', code: 'SCG_LIFECYCLE_FAILED' });
    expect(result.failures).toEqual([{ stage: 'start-foreground' }]);
    expect(port.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:launch',
      'start:discard',
    ]);
    expect(port.preparedStarts.size).toBe(0);
  });

  it('records prepared-start discard failure without masking the foreground failure', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.failAt = 'start:launch';
    port.failPreparedStartDiscard = true;

    const result = await new LifecycleEngine(port).runStart();

    expect(result).toMatchObject({ status: 'failed', code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED' });
    expect(result.failures).toEqual([
      { stage: 'start-foreground' },
      { stage: 'start-preparation-revoke' },
    ]);
    expect(port.calls).toEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:launch',
      'start:discard',
    ]);
  });

  it('retries a transient physical foreground cleanup without replaying the completed wait stage', async () => {
    const port = new Port();
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.startCleanupFailuresBeforeSuccess = 1;
    port.retryStartCleanupFailures = true;

    const result = await new LifecycleEngine(port).runStart();

    expect(result).toStrictEqual({
      operation: 'start',
      status: 'success',
      state: 'active',
      code: 'SCG_LIFECYCLE_START_EXITED',
      failures: [],
      events: [
        { sequence: 1, operation: 'start', phase: 'inspection', code: 'SCG_LIFECYCLE_ACTIVE' },
        { sequence: 2, operation: 'start', phase: 'preflight', code: 'SCG_LIFECYCLE_ACTIVE' },
        { sequence: 3, operation: 'start', phase: 'foreground', code: 'SCG_LIFECYCLE_ACTIVE' },
        { sequence: 4, operation: 'start', phase: 'cleanup', code: 'SCG_LIFECYCLE_ACTIVE' },
        {
          sequence: 5,
          operation: 'start',
          phase: 'completed',
          code: 'SCG_LIFECYCLE_START_EXITED',
        },
      ],
    });
    expect(port.calls).toStrictEqual([
      'inspect:start',
      'start-facts',
      'start:prepare',
      'start:launch',
      'start:wait',
      'start:cleanup',
      'start:cleanup',
    ]);
    expect(port.calls.filter((call) => call === 'start:wait')).toHaveLength(1);
    expect(port.calls.filter((call) => call === 'start:cleanup')).toHaveLength(2);
    expect(port.startAuthorityReleaseCount).toBe(1);
    expect(port.preparedStarts.size).toBe(0);
  });
  it('shares one cleanup deadline across terminal retryable prepared-start cleanup rejections', async () => {
    const port = new Port();
    const expectedAttempts = 2;
    const cleanupStartedAt = 1_700_000_000_000;
    const cleanupDeadline = cleanupStartedAt + 30_000;
    const cleanupContexts: LifecycleCleanupContext[] = [];
    const cleanupAttemptTimes: number[] = [];
    let now = cleanupStartedAt;
    port.inspection = { state: 'active', activeManifest: manifest() };
    port.startCleanupFailuresBeforeSuccess = Number.POSITIVE_INFINITY;
    port.retryStartCleanupFailures = true;
    const launchMcpForeground = port.launchMcpForeground.bind(port);
    port.launchMcpForeground = async (input) => {
      const foreground = await launchMcpForeground(input);
      return {
        waitForExit: () => foreground.waitForExit(),
        cleanup: async (context) => {
          if (context === undefined) {
            throw new Error('foreground cleanup context is required');
          }
          cleanupContexts.push(context);
          cleanupAttemptTimes.push(now);
          now += 1;
          await foreground.cleanup(context);
        },
      };
    };
    const dateNow = vi.spyOn(Date, 'now').mockImplementation(() => now);

    try {
      const result = await new LifecycleEngine(port).runStart();

      expect(result).toStrictEqual({
        operation: 'start',
        status: 'failed',
        state: 'recovery-required',
        code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
        failures: [{ stage: 'start-cleanup' }],
        events: [
          { sequence: 1, operation: 'start', phase: 'inspection', code: 'SCG_LIFECYCLE_ACTIVE' },
          { sequence: 2, operation: 'start', phase: 'preflight', code: 'SCG_LIFECYCLE_ACTIVE' },
          { sequence: 3, operation: 'start', phase: 'foreground', code: 'SCG_LIFECYCLE_ACTIVE' },
          { sequence: 4, operation: 'start', phase: 'cleanup', code: 'SCG_LIFECYCLE_ACTIVE' },
          {
            sequence: 5,
            operation: 'start',
            phase: 'failed',
            code: 'SCG_LIFECYCLE_RECOVERY_REQUIRED',
          },
        ],
      });
      expect(port.calls).toStrictEqual([
        'inspect:start',
        'start-facts',
        'start:prepare',
        'start:launch',
        'start:wait',
        'start:cleanup',
        'start:cleanup',
      ]);
      expect(port.calls.filter((call) => call === 'start:wait')).toHaveLength(1);
      expect(port.calls.filter((call) => call === 'start:cleanup')).toHaveLength(expectedAttempts);
      expect(cleanupContexts).toHaveLength(expectedAttempts);
      const [firstCleanupContext] = cleanupContexts;
      const [firstAttemptAt, secondAttemptAt] = cleanupAttemptTimes;
      if (
        firstCleanupContext === undefined ||
        firstAttemptAt === undefined ||
        secondAttemptAt === undefined
      ) {
        throw new Error('expected every cleanup attempt to receive a context and consume time');
      }
      expect(Object.isFrozen(firstCleanupContext)).toBe(true);
      for (const cleanupContext of cleanupContexts) {
        expect(cleanupContext).toBe(firstCleanupContext);
        expect(cleanupContext.deadline).toBe(cleanupDeadline);
      }
      expect(cleanupAttemptTimes).toStrictEqual([cleanupStartedAt, cleanupStartedAt + 1]);
      expect(firstCleanupContext.deadline - firstAttemptAt).toBe(30_000);
      expect(firstCleanupContext.deadline - secondAttemptAt).toBe(29_999);
      expect(port.startAuthorityReleaseCount).toBe(0);
      expect(port.preparedStarts.size).toBe(1);
    } finally {
      dateNow.mockRestore();
    }
  });

  it.each([
    [
      'wait rejection',
      true,
      0,
      'SCG_LIFECYCLE_FAILED',
      [{ stage: 'start-wait' }],
      ['start:wait', 'start:cleanup'],
      1,
      0,
      1,
      0,
    ],
    [
      'permanent cleanup rejection',
      false,
      1,
      'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      [{ stage: 'start-cleanup' }],
      ['start:wait', 'start:cleanup'],
      1,
      0,
      0,
      1,
    ],
    [
      'wait and permanent cleanup rejection',
      true,
      1,
      'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      [{ stage: 'start-wait' }, { stage: 'start-cleanup' }],
      ['start:wait', 'start:cleanup'],
      1,
      0,
      0,
      1,
    ],
  ] as const)(
    'records each logical failure once after %s',
    async (
      _case,
      failStartWait,
      startCleanupFailuresBeforeSuccess,
      expectedCode,
      expectedFailures,
      terminalCalls,
      expectedCleanupAttempts,
      expectedDiscardAttempts,
      expectedAuthorityReleases,
      expectedPreparedStarts,
    ) => {
      const port = new Port();
      port.inspection = { state: 'active', activeManifest: manifest() };
      port.failStartWait = failStartWait;
      port.startCleanupFailuresBeforeSuccess = startCleanupFailuresBeforeSuccess;

      const result = await new LifecycleEngine(port).runStart();

      expect(result).toStrictEqual({
        operation: 'start',
        status: 'failed',
        state: expectedCode === 'SCG_LIFECYCLE_RECOVERY_REQUIRED' ? 'recovery-required' : 'active',
        code: expectedCode,
        failures: expectedFailures,
        events: [
          {
            sequence: 1,
            operation: 'start',
            phase: 'inspection',
            code: 'SCG_LIFECYCLE_ACTIVE',
          },
          {
            sequence: 2,
            operation: 'start',
            phase: 'preflight',
            code: 'SCG_LIFECYCLE_ACTIVE',
          },
          {
            sequence: 3,
            operation: 'start',
            phase: 'foreground',
            code: 'SCG_LIFECYCLE_ACTIVE',
          },
          ...(failStartWait
            ? []
            : [
                {
                  sequence: 4,
                  operation: 'start' as const,
                  phase: 'cleanup' as const,
                  code: 'SCG_LIFECYCLE_ACTIVE' as const,
                },
              ]),
          {
            sequence: failStartWait ? 4 : 5,
            operation: 'start',
            phase: 'failed',
            code: expectedCode,
          },
        ],
      });
      expect(port.calls).toStrictEqual([
        'inspect:start',
        'start-facts',
        'start:prepare',
        'start:launch',
        ...terminalCalls,
      ]);
      expect(port.calls.filter((call) => call === 'start:wait')).toHaveLength(1);
      expect(port.calls.filter((call) => call === 'start:cleanup')).toHaveLength(
        expectedCleanupAttempts,
      );
      expect(port.calls.filter((call) => call === 'start:discard')).toHaveLength(
        expectedDiscardAttempts,
      );
      expect(port.startAuthorityReleaseCount).toBe(expectedAuthorityReleases);
      expect(port.preparedStarts.size).toBe(expectedPreparedStarts);
    },
  );

  it.each([
    [
      'missing',
      'prepared-start-missing',
      undefined,
      'SCG_LIFECYCLE_FAILED',
      'active',
      [{ stage: 'start-foreground' }],
      0,
    ],
    [
      'reused',
      'prepared-start-reused',
      { manifest: manifest(), state: 'transferred' as const },
      'SCG_LIFECYCLE_RECOVERY_REQUIRED',
      'recovery-required',
      [{ stage: 'start-foreground' }, { stage: 'start-preparation-revoke' }],
      1,
    ],
  ] as const)(
    'applies the exact %s prepared-start unavailable semantics through the LifecycleEngine contract',
    async (
      _case,
      preparationId,
      existing,
      expectedCode,
      expectedState,
      expectedFailures,
      expectedPreparedStarts,
    ) => {
      const port = new Port();
      port.inspection = { state: 'active', activeManifest: manifest() };
      port.forcedPreparationId = preparationId;
      if (existing !== undefined) {
        port.preparedStarts.set(preparationId, existing);
      }

      const result = await new LifecycleEngine(port).runStart();

      expect(result).toMatchObject({
        status: 'failed',
        state: expectedState,
        code: expectedCode,
      });
      expect(result.failures).toStrictEqual(expectedFailures);
      expect(port.calls).toStrictEqual([
        'inspect:start',
        'start-facts',
        'start:prepare',
        'start:launch',
        'start:discard',
      ]);
      expect(port.preparedStarts.size).toBe(expectedPreparedStarts);
    },
  );

  it('uses provenance preflight before directional uninstall, blocks conflicts without writes, and short-circuits repeat uninstall', async () => {
    const conflict = new Port();
    conflict.inspection = { state: 'active', activeManifest: manifest() };
    const observed = conflict.observed[0];
    if (observed === undefined) {
      throw new Error('expected owned target');
    }
    conflict.observed = [{ ...observed, fingerprint: `sha256:${'b'.repeat(64)}` }];

    const conflictResult = await new LifecycleEngine(conflict).runUninstall();
    expect(conflictResult).toMatchObject({
      status: 'failed',
      code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
    });
    expect(conflict.calls).toEqual(['inspect:uninstall', 'uninstall:observe']);

    const valid = new Port();
    valid.inspection = { state: 'active', activeManifest: manifest() };
    const result = await new LifecycleEngine(valid).runUninstall();
    expect(result).toMatchObject({ status: 'success', state: 'uninstalled' });
    expect(valid.calls).toEqual([
      'inspect:uninstall',
      'uninstall:observe',
      'uninstall:open',
      'uninstall:apply',
    ]);

    const repeated = new Port();
    repeated.inspection = {
      state: 'uninstalled',
      terminalReceipt: {
        schemaVersion: 1,
        kind: 'scene-glass-lifecycle-receipt',
        operationId: 'uninstall-alpha',
        installId: 'install-alpha',
        terminalState: 'uninstalled',
        manifestFingerprint: FINGERPRINT,
      },
    };
    const repeatResult = await new LifecycleEngine(repeated).runUninstall();
    expect(repeatResult).toMatchObject({
      status: 'success',
      code: 'SCG_LIFECYCLE_ALREADY_UNINSTALLED',
    });
    expect(repeated.calls).toEqual(['inspect:uninstall']);
  });
});
