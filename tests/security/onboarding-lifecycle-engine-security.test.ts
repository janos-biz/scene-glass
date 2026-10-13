import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  createTransactionObservedCredentialAuthority,
  LifecycleEngine,
  type LifecycleEnginePort,
  type LifecycleEventReceipt,
  type LifecycleResult,
  type LifecycleForegroundMcp,
  type LifecycleInspection,
  type LifecycleSetupPreflightInput,
  type LifecycleSetupTransaction,
  type LifecycleUninstallTransaction,
  type LifecycleSetupFacts,
  type LifecycleStartFacts,
  type SetupMutationPreparation,
  type SetupMutationReceipt,
} from '../../packages/onboarding/src/lifecycle/engine.js';
import type { ObservedOwnedTarget } from '../../packages/onboarding/src/lifecycle/provenance.js';
import type { SetupManifestV1, SetupPlan } from '../../packages/onboarding/src/lifecycle/types.js';
import type { SetupTransactionReceipt } from '../../packages/onboarding/src/lifecycle/transaction.js';

const FINGERPRINT = `sha256:${'c'.repeat(64)}`;
const SECRET = 'token-that-must-never-appear-in-a-lifecycle-result';
const FIXED_CANDIDATE_SECRET_CANARIES = [
  'token-that-must-never-appear-in-a-lifecycle-result',
  'token-that-must-never-appear-in-',
  'dG9rZW4tdGhhdC1tdXN0LW5ldmVyLWFwcGVhci1pbi0=',
  'dG9rZW4tdGhhdC1tdXN0LW5ldmVyLWFwcGVhci1pbi0',
  '746f6b656e2d746861742d6d7573742d6e657665722d6170706561722d696e2d',
  '0e4148a997a4d08259d9d513a4af997042a8038d5665fe1626ea5bda67e44c1d',
  'sha256:0e4148a997a4d08259d9d513a4af997042a8038d5665fe1626ea5bda67e44c1d',
] as const;
const OWNED_PATH = '/workspace/html/public/scene-glass-loader.js';
const ADOPTED_PATH = '/var/lib/scene-glass/alpha.credential';
const CREATED_AUTHORITY = {
  projectId: 'alpha',
  path: '/var/lib/scene-glass/alpha.created.credential',
  device: '11',
  inode: '21',
} as const;
const PROJECT = {
  projectId: 'alpha',
  root: '/workspace/html',
  allowedOrigins: ['http://127.0.0.1:4173'],
  tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
  framework: 'html',
} as const;
function setupTransactionReceipt(): SetupTransactionReceipt {
  return Object.freeze({}) as unknown as SetupTransactionReceipt;
}

function fileArtifact() {
  return {
    path: OWNED_PATH,
    kind: 'file' as const,
    fingerprint: FINGERPRINT,
    hunks: [],
    inverse: {
      kind: 'delete-created-file' as const,
      path: OWNED_PATH,
      expectedFingerprint: FINGERPRINT,
    },
  };
}

function adoptedArtifact() {
  return {
    path: ADOPTED_PATH,
    kind: 'credential' as const,
    ownership: 'adopted' as const,
    inverse: { kind: 'none' as const },
  };
}

function activeManifest(adopted = false): SetupManifestV1 {
  return {
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId: 'install-alpha',
    state: 'active',
    artifacts: adopted ? [fileArtifact(), adoptedArtifact()] : [fileArtifact()],
  };
}
function setupFacts(created = true): LifecycleSetupFacts {
  const adoptedAuthority = {
    projectId: 'alpha',
    path: ADOPTED_PATH,
    device: '10',
    inode: '20',
  };
  return {
    configHomes: {
      legacyPath: '/workspace/legacy.json',
      newPath: '/workspace/config.json',
      legacy: undefined,
      new: undefined,
    },
    project: PROJECT,
    hostPlan: {
      schemaVersion: 1,
      candidates: [
        {
          rootPath: '/workspace/html',
          descriptor: {
            projectId: 'alpha',
            port: 4173,
            installId: 'install-alpha',
            approvedRootIdentity: { device: '1', inode: '2' },
            credentialAuthorities: created ? [] : [adoptedAuthority],
          },
          package: undefined,
          viteConfig: undefined,
          sourceScan: {
            complete: true,
            sources: [
              {
                path: 'public/index.html',
                source: '<html><head></head><body></body></html>\n',
              },
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
        : { kind: 'adopt', authority: adoptedAuthority },
    },
    build: { bounded: true },
  };
}

function publicDataRecord(value: unknown, allowedKeys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('public receipt must be a plain data record');
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
      throw new Error(`public receipt key ${key} must be a data descriptor`);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function publicDataArray(value: unknown, visit: (item: unknown) => void): void {
  if (!Array.isArray(value)) {
    throw new Error('public receipt must contain a dense data array');
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
      throw new Error(`public receipt item ${index} must be a data descriptor`);
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
    throw new Error('public receipt array length must be a data descriptor');
  }
}

function secretCanaries(preZeroizationBytes: Uint8Array): readonly string[] {
  const bytes = Buffer.from(preZeroizationBytes);
  const canonicalBase64url = bytes.toString('base64url');
  const digest = createHash('sha256').update(canonicalBase64url).digest('hex');
  return [
    SECRET,
    new TextDecoder().decode(preZeroizationBytes),
    bytes.toString('base64'),
    canonicalBase64url,
    bytes.toString('hex'),
    digest,
    `sha256:${digest}`,
  ];
}

function assertRedactedString(value: unknown, canaries: readonly string[]): void {
  if (typeof value !== 'string') {
    throw new Error('public receipt retained a non-string value');
  }
  for (const canary of canaries) {
    expect(value).not.toContain(canary);
  }
  expect(value).not.toContain(OWNED_PATH);
  expect(value).not.toContain(ADOPTED_PATH);
}

function assertPublicEventIsRedacted(
  value: unknown,
  candidate: Uint8Array,
  preZeroizationBytes: Uint8Array,
): void {
  if (value === candidate) {
    throw new Error('public event retained candidate identity');
  }
  const event = publicDataRecord(value, ['sequence', 'operation', 'phase', 'code']);
  if (typeof event.sequence !== 'number') {
    throw new Error('public event sequence must be numeric');
  }
  const canaries = secretCanaries(preZeroizationBytes);
  assertRedactedString(event.operation, canaries);
  assertRedactedString(event.phase, canaries);
  assertRedactedString(event.code, canaries);
}

function assertPublicResultIsRedacted(
  value: unknown,
  candidate: Uint8Array,
  preZeroizationBytes: Uint8Array,
): void {
  if (value === candidate) {
    throw new Error('public result retained candidate identity');
  }
  const result = publicDataRecord(value, [
    'operation',
    'status',
    'state',
    'code',
    'failures',
    'events',
  ]);
  const canaries = secretCanaries(preZeroizationBytes);
  assertRedactedString(result.operation, canaries);
  assertRedactedString(result.status, canaries);
  assertRedactedString(result.state, canaries);
  assertRedactedString(result.code, canaries);
  publicDataArray(result.failures, (failure) => {
    const receipt = publicDataRecord(failure, ['stage']);
    assertRedactedString(receipt.stage, canaries);
  });
  publicDataArray(result.events, (event) =>
    assertPublicEventIsRedacted(event, candidate, preZeroizationBytes),
  );
}
interface PreparedStart {
  readonly manifest: SetupManifestV1;
  readonly state: 'prepared' | 'transferred';
}

interface SecurityPort extends LifecycleEnginePort {
  readonly calls: string[];
  inspection: LifecycleInspection;
  created: boolean;
  claimedPostWriteAuthority: SetupMutationReceipt['createdAuthority'];
  approvalPreview: unknown;
  prepared: SetupPlan | undefined;
  generated: number;
  generatedCandidate: Uint8Array | undefined;
  generatedCandidates: Uint8Array[];
  candidateSnapshot: Uint8Array | undefined;
  candidateSnapshots: Uint8Array[];
  preparedCandidate: Uint8Array | undefined;
  preflightCandidates: Array<Uint8Array | undefined>;
  openedCandidate: Uint8Array | undefined;
  appliedCandidate: Uint8Array | undefined;
  zeroizedCandidate: Uint8Array | undefined;
  zeroizedCandidates: Uint8Array[];
  zeroized: number;
  events: LifecycleEventReceipt[];
  observed: readonly ObservedOwnedTarget[];
  failPreflightStage: 1 | 2 | 3 | undefined;
  failUninstallApply: boolean;
  uninstallCompensations: number;
  preparedStartFacts: LifecycleStartFacts | undefined;
  preparedStarts: Map<string, PreparedStart>;
  nextPreparationId: number;
}

function createPort(): SecurityPort {
  const port: SecurityPort = {
    calls: [],
    inspection: { state: 'never-installed' },
    created: true,
    claimedPostWriteAuthority: { ...CREATED_AUTHORITY },
    approvalPreview: undefined,
    prepared: undefined,
    generated: 0,
    generatedCandidate: undefined,
    generatedCandidates: [],
    candidateSnapshot: undefined,
    candidateSnapshots: [],
    preparedCandidate: undefined,
    preflightCandidates: [],
    openedCandidate: undefined,
    appliedCandidate: undefined,
    zeroizedCandidate: undefined,
    zeroizedCandidates: [],
    zeroized: 0,
    events: [],
    observed: [
      { path: OWNED_PATH, fingerprint: FINGERPRINT, hunks: [], semanticConfig: undefined },
      { path: ADOPTED_PATH, fingerprint: undefined, hunks: [], semanticConfig: undefined },
    ],
    failPreflightStage: undefined,
    failUninstallApply: false,
    uninstallCompensations: 0,
    preparedStartFacts: undefined,
    preparedStarts: new Map(),
    nextPreparationId: 0,
    async inspectLifecycle(input) {
      port.calls.push(`inspect:${input.operation}`);
      return port.inspection;
    },
    async recoverAuthorizedWal() {
      port.calls.push('recover');
      return 'recovered';
    },
    async inspectSetupFacts(): Promise<LifecycleSetupFacts> {
      port.calls.push('facts');
      return setupFacts(port.created);
    },
    async buildSetupPlan(input) {
      port.calls.push('build');
      return {
        receiptId: 'builder-alpha',
        plan: {
          schemaVersion: 1,
          installId: input.host.installId,
          state: 'active',
          config: input.config.config,
          artifacts: [fileArtifact()],
          inverse: [fileArtifact().inverse],
          preview: {
            state: 'active',
            operations: [
              { kind: 'create-file', path: OWNED_PATH, hunkCount: 0, hunkSubjects: ['scg-loader'] },
            ],
          },
        },
      };
    },
    async requestSetupApproval(input) {
      port.calls.push('approval');
      port.approvalPreview = input;
      return true;
    },
    async runNativeSelfTest() {
      port.calls.push('native');
    },
    async runEmptyChromiumSmoke() {
      port.calls.push('chromium');
    },
    async generateCredentialToken() {
      port.calls.push('generate');
      port.generated += 1;
      const candidate = new TextEncoder().encode(`${SECRET}..........`).slice(0, 32);
      port.generatedCandidate = candidate;
      port.candidateSnapshot = new Uint8Array(candidate);
      port.generatedCandidates.push(candidate);
      port.candidateSnapshots.push(port.candidateSnapshot);
      return candidate;
    },
    async zeroizeCredentialToken(input) {
      port.calls.push('zeroize');
      port.zeroized += 1;
      port.zeroizedCandidate = input.token;
      port.zeroizedCandidates.push(input.token);
      input.token.fill(0);
    },
    async preflightSetup(input: LifecycleSetupPreflightInput) {
      port.calls.push(`preflight:${input.stage}`);
      port.preflightCandidates.push(input.candidate);
      if (port.failPreflightStage === input.stage) {
        throw new Error(SECRET);
      }
    },
    async openSetupTransaction(input) {
      port.calls.push('open');
      port.openedCandidate = input.candidate;
      return {
        apply: async ({ observedAuthorityIssuer }) => {
          port.appliedCandidate = input.candidate;
          port.calls.push('apply');
          const transactionReceipt = setupTransactionReceipt();
          const observedCreatedAuthority = port.created
            ? createTransactionObservedCredentialAuthority({
                issuer: observedAuthorityIssuer,
                receipt: transactionReceipt,
                authority: CREATED_AUTHORITY,
              })
            : undefined;
          return {
            observedCreatedAuthority,
            ...(observedCreatedAuthority === undefined ? {} : { transactionReceipt }),
            ...(port.claimedPostWriteAuthority === undefined
              ? {}
              : { createdAuthority: port.claimedPostWriteAuthority }),
          };
        },
        publishActive: async () => {
          port.calls.push('publish');
          return 'active';
        },
        compensate: async () => {
          port.calls.push('compensate');
          return 'recovered';
        },
      } satisfies LifecycleSetupTransaction;
    },
    async prepareSetupMutation(input): Promise<SetupMutationPreparation> {
      port.calls.push('prepare');
      port.prepared = input.plan;
      port.preparedCandidate = input.candidate;
      return { mutationId: 'mutation-alpha' };
    },
    async validateFinalizedSetup() {
      port.calls.push('validate');
    },
    async runLiveDiagnostics() {
      port.calls.push('diagnostics');
    },
    async inspectStartFacts(): Promise<LifecycleStartFacts> {
      port.calls.push('start-facts');
      return {
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
    },
    async prepareStart(input) {
      port.calls.push('start:prepare');
      port.preparedStartFacts = input.facts;
      const preparationId = `prepared-start-${port.nextPreparationId}`;
      port.nextPreparationId += 1;
      port.preparedStarts.set(preparationId, { manifest: input.manifest, state: 'prepared' });
      return Object.freeze({ preparationId });
    },
    async finalizePreparedStart(input) {
      if (port.preparedStarts.get(input.preparationId)?.state !== 'prepared') {
        throw new Error('prepared start authority is unavailable');
      }
    },
    async discardPreparedStart(input) {
      port.calls.push('start:discard');
      if (port.preparedStarts.get(input.preparationId)?.state !== 'prepared') {
        throw new Error('prepared start authority is unavailable');
      }
      port.preparedStarts.delete(input.preparationId);
    },
    async launchMcpForeground(input): Promise<LifecycleForegroundMcp> {
      port.calls.push('start:launch');
      const prepared = port.preparedStarts.get(input.preparationId);
      if (
        prepared === undefined ||
        prepared.state !== 'prepared' ||
        JSON.stringify(prepared.manifest) !== JSON.stringify(input.manifest)
      ) {
        throw new Error('prepared start authority is unavailable');
      }
      port.preparedStarts.set(input.preparationId, { ...prepared, state: 'transferred' });
      let cleanupCalls = 0;
      return {
        waitForExit: async () => ({ reason: 'exit', exitCode: 0 }),
        cleanup: async () => {
          cleanupCalls += 1;
          if (cleanupCalls !== 1) {
            throw new Error('foreground cleanup was invoked more than once');
          }
          port.preparedStarts.delete(input.preparationId);
        },
      };
    },
    async observeUninstallTargets() {
      port.calls.push('observe');
      return { complete: true, observed: port.observed };
    },
    async openUninstallTransaction(input) {
      port.calls.push('uninstall-open');
      expect(
        input.preflight.inverse.some(
          (operation) => 'path' in operation && operation.path === ADOPTED_PATH,
        ),
      ).toBe(false);
      return {
        apply: async () => {
          port.calls.push('uninstall-apply');
          if (port.failUninstallApply) {
            throw new Error('uninstall apply failed');
          }
          return 'uninstalled';
        },
        compensate: async () => {
          port.calls.push('uninstall-compensate');
          port.uninstallCompensations += 1;
          return 'recovered';
        },
      } satisfies LifecycleUninstallTransaction;
    },
    emitLifecycleEvent(event) {
      port.events.push(event);
    },
  };
  return port;
}

describe('onboarding lifecycle engine security boundary', () => {
  it.each([
    [
      1,
      'public-preflight-1',
      [
        'inspect:setup',
        'facts',
        'build',
        'approval',
        'native',
        'chromium',
        'generate',
        'prepare',
        'preflight:1',
        'zeroize',
      ],
    ],
    [
      2,
      'public-preflight-2',
      [
        'inspect:setup',
        'facts',
        'build',
        'approval',
        'native',
        'chromium',
        'generate',
        'prepare',
        'preflight:1',
        'open',
        'preflight:2',
        'compensate',
        'zeroize',
      ],
    ],
    [
      3,
      'public-preflight-3',
      [
        'inspect:setup',
        'facts',
        'build',
        'approval',
        'native',
        'chromium',
        'generate',
        'prepare',
        'preflight:1',
        'open',
        'preflight:2',
        'apply',
        'validate',
        'preflight:3',
        'compensate',
        'zeroize',
      ],
    ],
  ] as const)(
    'redacts graph-reachable secret material after a stage-%i preflight failure',
    async (stage, failureStage, trace) => {
      const port = createPort();
      port.failPreflightStage = stage;

      const result = await new LifecycleEngine(port).runSetup();

      const candidate = port.generatedCandidate;
      const candidateSnapshot = port.candidateSnapshot;
      if (candidate === undefined || candidateSnapshot === undefined) {
        throw new Error('expected generated candidate and saved pre-zeroization bytes');
      }
      expect(result).toMatchObject({ status: 'failed', code: 'SCG_LIFECYCLE_FAILED' });
      expect(result.failures).toStrictEqual([{ stage: failureStage }]);
      expect(port.calls).toStrictEqual(trace);
      expect(port.preflightCandidates).toHaveLength(stage);
      expect(port.preflightCandidates).toStrictEqual(
        Array.from({ length: stage }, () => candidate),
      );
      expect(port.zeroizedCandidate).toBe(candidate);
      expect(candidate).toEqual(new Uint8Array(32));
      expect(candidateSnapshot).toStrictEqual(
        new TextEncoder().encode(`${SECRET}..........`).slice(0, 32),
      );
      assertPublicResultIsRedacted(result, candidate, candidateSnapshot);
      for (const event of port.events) {
        assertPublicEventIsRedacted(event, candidate, candidateSnapshot);
      }
    },
  );
  it('rejects hidden payloads and every raw, encoded, or digest candidate canary in public receipt audits', () => {
    const candidateSnapshot = new TextEncoder().encode(`${SECRET}..........`).slice(0, 32);
    const candidate = new Uint8Array(candidateSnapshot);
    expect(secretCanaries(candidateSnapshot)).toStrictEqual(FIXED_CANDIDATE_SECRET_CANARIES);
    const event: LifecycleEventReceipt = {
      sequence: 1,
      operation: 'setup',
      phase: 'completed',
      code: 'SCG_LIFECYCLE_ACTIVE',
    };
    const result: LifecycleResult = {
      operation: 'setup',
      status: 'success',
      state: 'active',
      code: 'SCG_LIFECYCLE_ACTIVE',
      failures: [],
      events: [event],
    };
    assertPublicResultIsRedacted(result, candidate, candidateSnapshot);
    assertPublicEventIsRedacted(event, candidate, candidateSnapshot);

    const hiddenError = { ...event };
    Object.defineProperty(hiddenError, 'hidden', { value: new Error(SECRET) });
    const symbolBuffer = { ...event };
    Object.defineProperty(symbolBuffer, Symbol('buffer'), { value: new ArrayBuffer(32) });
    const symbolView = { ...event };
    Object.defineProperty(symbolView, Symbol('view'), { value: new DataView(new ArrayBuffer(32)) });
    const hiddenFailure = { stage: 'planning' };
    Object.defineProperty(hiddenFailure, 'hidden', { value: new Uint8Array(candidate) });

    for (const receipt of [
      hiddenError,
      symbolBuffer,
      symbolView,
      { ...event, code: candidate as unknown as LifecycleEventReceipt['code'] },
      { ...event, code: [...candidate] as unknown as LifecycleEventReceipt['code'] },
      ...FIXED_CANDIDATE_SECRET_CANARIES.map((canary) => ({
        ...event,
        code: canary as LifecycleEventReceipt['code'],
      })),
    ]) {
      expect(() => assertPublicEventIsRedacted(receipt, candidate, candidateSnapshot)).toThrow();
    }
    expect(() =>
      assertPublicResultIsRedacted(
        { ...result, failures: [hiddenFailure] },
        candidate,
        candidateSnapshot,
      ),
    ).toThrow();
  });

  it('copies valid exposed facts before builder callbacks without freezing their sources', async () => {
    const port = createPort();
    port.created = false;
    port.claimedPostWriteAuthority = undefined;
    const sourceAllowedOrigins: string[] = [...PROJECT.allowedOrigins];
    const sourceProject = {
      ...PROJECT,
      allowedOrigins: sourceAllowedOrigins,
    };
    const sourceAuthority: {
      projectId: string;
      path: string;
      device: string;
      inode: string;
    } = {
      projectId: 'alpha',
      path: ADOPTED_PATH,
      device: '10',
      inode: '20',
    };
    const baseFacts = setupFacts(false);
    const sourceFacts = {
      ...baseFacts,
      project: sourceProject,
      hostPlan: {
        ...baseFacts.hostPlan,
        candidates: baseFacts.hostPlan.candidates.map((candidate) => ({
          ...candidate,
          descriptor: {
            ...candidate.descriptor,
            credentialAuthorities: [sourceAuthority],
          },
        })),
        credential: { kind: 'adopt' as const, authority: sourceAuthority },
      },
    };
    port.inspectSetupFacts = async () => {
      port.calls.push('facts');
      return sourceFacts;
    };
    const buildSetupPlan = port.buildSetupPlan;
    port.buildSetupPlan = async (input) => {
      const callbackProject = input.config.config.projects[0];
      const callbackAuthority = input.host.descriptor.credentialAuthorities[0];
      if (callbackProject === undefined || callbackAuthority === undefined) {
        throw new Error('expected builder callback snapshots');
      }
      const callbackAllowedOrigins = callbackProject.allowedOrigins;
      expect(callbackAllowedOrigins).not.toBe(sourceAllowedOrigins);
      expect(Object.isFrozen(callbackAllowedOrigins)).toBe(true);
      expect(callbackAllowedOrigins).toStrictEqual(['http://127.0.0.1:4173']);
      expect(() => {
        (callbackAllowedOrigins as string[]).push('http://attacker.invalid');
      }).toThrow(TypeError);
      expect(callbackProject).not.toBe(sourceProject);
      expect(callbackAuthority).not.toBe(sourceAuthority);
      expect(Object.isFrozen(sourceFacts)).toBe(false);
      expect(Object.isFrozen(sourceFacts.hostPlan)).toBe(false);
      expect(Object.isFrozen(sourceProject)).toBe(false);
      expect(Object.isFrozen(sourceAuthority)).toBe(false);
      expect(Object.isFrozen(callbackProject)).toBe(true);
      expect(Object.isFrozen(callbackAuthority)).toBe(true);
      expect(() => {
        (callbackProject as { root: string }).root = '/attacker';
      }).toThrow(TypeError);
      expect(() => {
        (callbackAuthority as { path: string }).path = '/attacker.credential';
      }).toThrow(TypeError);

      sourceProject.allowedOrigins.push('http://127.0.0.1:4999');
      sourceAuthority.path = '/attacker.credential';
      expect(callbackAuthority.path).toBe(ADOPTED_PATH);
      expect(callbackAllowedOrigins).toStrictEqual(['http://127.0.0.1:4173']);
      return buildSetupPlan(input);
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result.status).toBe('success');
    expect(Object.isFrozen(sourceFacts)).toBe(false);
    expect(Object.isFrozen(sourceFacts.hostPlan)).toBe(false);
    expect(Object.isFrozen(sourceProject)).toBe(false);
    expect(Object.isFrozen(sourceAuthority)).toBe(false);
    expect(sourceProject.allowedOrigins).toContain('http://127.0.0.1:4999');
    expect(sourceAuthority.path).toBe('/attacker.credential');
  });

  it('isolates the finalized post-apply authority from mutable adapter evidence', async () => {
    const port = createPort();
    const sourceAuthority: {
      projectId: string;
      path: string;
      device: string;
      inode: string;
    } = {
      projectId: CREATED_AUTHORITY.projectId,
      path: CREATED_AUTHORITY.path,
      device: CREATED_AUTHORITY.device,
      inode: CREATED_AUTHORITY.inode,
    };
    port.claimedPostWriteAuthority = sourceAuthority;
    const finalizedAuthorityObservation = {
      present: false,
      sharesIdentityWithSource: undefined as boolean | undefined,
      sourceIsFrozen: undefined as boolean | undefined,
      finalizedIsFrozen: undefined as boolean | undefined,
      mutationError: undefined as unknown,
      pathAfterSourceMutation: undefined as string | undefined,
    };
    const preflightSetup = port.preflightSetup;
    port.preflightSetup = async (input) => {
      if (input.stage === 3) {
        const finalizedAuthority = input.finalizedHost.descriptor.credentialAuthorities[0];
        finalizedAuthorityObservation.present = finalizedAuthority !== undefined;

        if (finalizedAuthority !== undefined) {
          finalizedAuthorityObservation.sharesIdentityWithSource =
            finalizedAuthority === sourceAuthority;
          finalizedAuthorityObservation.sourceIsFrozen = Object.isFrozen(sourceAuthority);
          finalizedAuthorityObservation.finalizedIsFrozen = Object.isFrozen(finalizedAuthority);
          try {
            (finalizedAuthority as { path: string }).path = '/attacker.credential';
          } catch (error) {
            finalizedAuthorityObservation.mutationError = error;
          }

          sourceAuthority.path = '/attacker.credential';
          finalizedAuthorityObservation.pathAfterSourceMutation = finalizedAuthority.path;
        }
      }
      await preflightSetup(input);
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result.status).toBe('success');
    expect(finalizedAuthorityObservation).toStrictEqual({
      present: true,
      sharesIdentityWithSource: false,
      sourceIsFrozen: false,
      finalizedIsFrozen: true,
      mutationError: expect.any(TypeError),
      pathAfterSourceMutation: CREATED_AUTHORITY.path,
    });

    expect(Object.isFrozen(sourceAuthority)).toBe(false);
    expect(sourceAuthority.path).toBe('/attacker.credential');
  });

  it('rejects a valid facts fixture with one accessor without invoking its getter', async () => {
    const port = createPort();
    const facts: LifecycleSetupFacts = { ...setupFacts() };
    let getterCalls = 0;
    Object.defineProperty(facts, 'project', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return PROJECT;
      },
    });
    port.inspectSetupFacts = async () => {
      port.calls.push('facts');
      return facts;
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'failed',
      code: 'SCG_LIFECYCLE_FAILED',
      failures: [{ stage: 'inspection' }],
    });
    expect(getterCalls).toBe(0);
    expect(port.calls).toStrictEqual(['inspect:setup', 'facts']);
  });
  it.each([
    [
      'inherited getter',
      (getter: () => never): LifecycleSetupFacts => {
        const facts = setupFacts();
        const prototype = {};
        Object.defineProperty(prototype, 'project', {
          enumerable: true,
          get: getter,
        });
        return Object.assign(Object.create(prototype), {
          configHomes: facts.configHomes,
          hostPlan: facts.hostPlan,
          build: facts.build,
        }) as LifecycleSetupFacts;
      },
    ],
    [
      'attacker-controlled prototype',
      (getter: () => never): LifecycleSetupFacts => {
        const prototype = {};
        Object.defineProperty(prototype, 'trap', {
          enumerable: true,
          get: getter,
        });
        return Object.assign(Object.create(prototype), setupFacts()) as LifecycleSetupFacts;
      },
    ],
    [
      'nested accessor',
      (getter: () => never): LifecycleSetupFacts => {
        const facts = setupFacts();
        const hostPlan = { ...facts.hostPlan };
        Object.defineProperty(hostPlan, 'credential', {
          enumerable: true,
          get: getter,
        });
        return { ...facts, hostPlan };
      },
    ],
  ] as const)(
    'rejects hostile setup facts with a %s before approval or mutation work',
    async (_case, createFacts) => {
      const port = createPort();
      let getterCalls = 0;
      const facts = createFacts((): never => {
        getterCalls += 1;
        throw new Error('hostile getter must not be invoked');
      });
      port.inspectSetupFacts = async () => {
        port.calls.push('facts');
        return facts;
      };

      const result = await new LifecycleEngine(port).runSetup();

      expect(result.status).toBe('failed');
      expect(result.state).toBe('never-installed');
      expect(result.code).toBe('SCG_LIFECYCLE_FAILED');
      expect(result.failures).toStrictEqual([{ stage: 'inspection' }]);
      expect(getterCalls).toBe(0);
      expect(port.calls).toStrictEqual(['inspect:setup', 'facts']);
      expect(port.approvalPreview).toBeUndefined();
      expect(port.generated).toBe(0);
      expect(port.prepared).toBeUndefined();
      expect(port.openedCandidate).toBeUndefined();
      expect(port.appliedCandidate).toBeUndefined();
      expect(port.zeroized).toBe(0);
      expect(port.calls).not.toContain('approval');
      expect(port.calls).not.toContain('generate');
      expect(port.calls).not.toContain('prepare');
      expect(port.calls).not.toContain('open');
      expect(port.calls).not.toContain('apply');
      expect(port.calls).not.toContain('compensate');
      expect(port.calls).not.toContain('publish');
    },
  );
  it.each([
    [
      'non-enumerable secret data property',
      (facts: LifecycleSetupFacts): void => {
        const candidate = facts.hostPlan.candidates[0];
        if (candidate === undefined) {
          throw new Error('expected host candidate');
        }
        const packageFacts = {
          name: 'alpha',
          resolvedDependencies: [],
        };
        Object.defineProperty(packageFacts, 'secret', {
          enumerable: false,
          value: SECRET,
        });
        Object.defineProperty(candidate, 'package', {
          enumerable: true,
          value: packageFacts,
        });
      },
    ],
    [
      'accessor',
      (facts: LifecycleSetupFacts, getter: () => never): void => {
        const candidate = facts.hostPlan.candidates[0];
        if (candidate === undefined) {
          throw new Error('expected host candidate');
        }
        Object.defineProperty(candidate, 'package', {
          enumerable: true,
          get: getter,
        });
      },
    ],
    [
      'prototype',
      (facts: LifecycleSetupFacts, getter: () => never): void => {
        const candidate = facts.hostPlan.candidates[0];
        if (candidate === undefined) {
          throw new Error('expected host candidate');
        }
        const prototype = {};
        Object.defineProperty(prototype, 'trap', {
          enumerable: true,
          get: getter,
        });
        const packageFacts = Object.assign(Object.create(prototype), {
          name: 'alpha',
          resolvedDependencies: [],
        });
        Object.defineProperty(candidate, 'package', {
          enumerable: true,
          value: packageFacts,
        });
      },
    ],
    [
      'cycle',
      (facts: LifecycleSetupFacts): void => {
        const candidate = facts.hostPlan.candidates[0];
        if (candidate === undefined) {
          throw new Error('expected host candidate');
        }
        const packageFacts: { name: string; resolvedDependencies: unknown[] } = {
          name: 'alpha',
          resolvedDependencies: [],
        };
        packageFacts.resolvedDependencies.push(packageFacts);
        Object.defineProperty(candidate, 'package', {
          enumerable: true,
          value: packageFacts,
        });
      },
    ],
  ] as const)(
    'rejects hostile host candidate package facts with a %s before approval or mutation work',
    async (_case, mutate) => {
      const port = createPort();
      const facts = setupFacts();
      let getterCalls = 0;
      mutate(facts, (): never => {
        getterCalls += 1;
        throw new Error(SECRET);
      });
      port.inspectSetupFacts = async () => {
        port.calls.push('facts');
        return facts;
      };

      const result = await new LifecycleEngine(port).runSetup();
      const candidateSnapshot = new TextEncoder().encode(`${SECRET}..........`).slice(0, 32);

      expect(result).toMatchObject({
        status: 'failed',
        state: 'never-installed',
        code: 'SCG_LIFECYCLE_FAILED',
        failures: [{ stage: 'inspection' }],
      });
      expect(getterCalls).toBe(0);
      expect(port.calls).toStrictEqual(['inspect:setup', 'facts']);
      expect(port.approvalPreview).toBeUndefined();
      expect(port.generated).toBe(0);
      expect(port.prepared).toBeUndefined();
      expect(port.openedCandidate).toBeUndefined();
      expect(port.appliedCandidate).toBeUndefined();
      expect(port.zeroized).toBe(0);
      assertPublicResultIsRedacted(result, new Uint8Array(candidateSnapshot), candidateSnapshot);
    },
  );

  it('rejects a valid facts fixture with one cycle before approval, entropy, or transaction work', async () => {
    const port = createPort();
    const validFacts = setupFacts();
    type CyclicBuildFixture = {
      bounded: true;
      self?: CyclicBuildFixture;
    };
    const build: CyclicBuildFixture = { bounded: true };
    build.self = build;
    port.inspectSetupFacts = async () => {
      port.calls.push('facts');
      return { ...validFacts, build };
    };

    const result = await new LifecycleEngine(port).runSetup();

    expect(result).toMatchObject({
      status: 'failed',
      code: 'SCG_LIFECYCLE_FAILED',
      failures: [{ stage: 'inspection' }],
    });
    expect(port.calls).toStrictEqual(['inspect:setup', 'facts']);
  });

  it.each([
    {
      name: 'credential-delete',
      inverse: { kind: 'delete-created-credential', path: ADOPTED_PATH },
    },
    {
      name: 'file-delete alias',
      inverse: {
        kind: 'delete-created-file',
        path: ADOPTED_PATH,
        expectedFingerprint: FINGERPRINT,
      },
    },
  ] as const)(
    'rejects the $name destructive inverse alias targeting an adopted credential',
    async ({ inverse }) => {
      const port = createPort();
      port.inspection = {
        state: 'active',
        activeManifest: {
          ...activeManifest(true),
          artifacts: [
            fileArtifact(),
            {
              ...adoptedArtifact(),
              inverse,
            },
          ],
        },
      };

      const result = await new LifecycleEngine(port).runUninstall();

      expect(result).toMatchObject({
        status: 'failed',
        state: 'lost-provenance',
        code: 'SCG_LIFECYCLE_PREFLIGHT_FAILED',
      });
      expect(result.failures).toStrictEqual([{ stage: 'uninstall-manifest' }]);
      expect(port.calls).toStrictEqual(['inspect:uninstall']);
    },
  );
  it('never generates or deletes an adopted credential and exposes uninstall compensation', async () => {
    const setup = createPort();
    setup.created = false;
    setup.claimedPostWriteAuthority = undefined;

    const setupResult = await new LifecycleEngine(setup).runSetup();

    expect(setupResult.status).toBe('success');
    expect(setup.generated).toBe(0);
    expect(setup.zeroized).toBe(0);

    const uninstall = createPort();
    uninstall.inspection = { state: 'active', activeManifest: activeManifest(true) };
    const uninstallResult = await new LifecycleEngine(uninstall).runUninstall();

    expect(uninstallResult).toMatchObject({ status: 'success', state: 'uninstalled' });
    expect(uninstall.calls).toStrictEqual([
      'inspect:uninstall',
      'observe',
      'uninstall-open',
      'uninstall-apply',
    ]);
    expect(uninstall.uninstallCompensations).toBe(0);

    const failedUninstall = createPort();
    failedUninstall.inspection = { state: 'active', activeManifest: activeManifest(true) };
    failedUninstall.failUninstallApply = true;
    const failedUninstallResult = await new LifecycleEngine(failedUninstall).runUninstall();

    expect(failedUninstallResult).toMatchObject({
      status: 'failed',
      state: 'active',
      code: 'SCG_LIFECYCLE_FAILED',
      failures: [{ stage: 'uninstall-apply' }],
    });
    expect(failedUninstall.calls).toStrictEqual([
      'inspect:uninstall',
      'observe',
      'uninstall-open',
      'uninstall-apply',
      'uninstall-compensate',
    ]);
    expect(failedUninstall.uninstallCompensations).toBe(1);
  });

  it('signals production event-sink saturation at item 65 without retrying and audits success and failure events', async () => {
    const saturated = createPort();
    const delivered: LifecycleEventReceipt[] = [];
    const cleanupTraceAfterSaturation = [
      'chromium',
      'generate',
      'prepare',
      'preflight:1',
      'open',
      'preflight:2',
      'apply',
      'validate',
      'preflight:3',
      'diagnostics',
      'publish',
      'zeroize',
    ];
    let attempts = 0;
    let dropped = 0;
    let callsAtFirstDroppedEvent: number | undefined;
    saturated.emitLifecycleEvent = (event) => {
      attempts += 1;
      if (attempts > 64) {
        callsAtFirstDroppedEvent ??= saturated.calls.length;
        dropped += 1;
        throw new Error('event sink saturated');
      }
      delivered.push(event);
    };
    const engine = new LifecycleEngine(saturated);
    const results: LifecycleResult[] = [];
    for (let index = 0; index < 6; index += 1) {
      results.push(await engine.runSetup());
    }

    if (callsAtFirstDroppedEvent === undefined) {
      throw new Error('expected event-sink saturation');
    }
    expect(results.every((result) => result.status === 'success')).toBe(true);
    expect(attempts).toBe(72);
    expect(delivered).toHaveLength(64);
    expect(dropped).toBe(8);
    expect(saturated.calls.slice(callsAtFirstDroppedEvent)).toStrictEqual(
      cleanupTraceAfterSaturation,
    );
    expect(saturated.generated).toBe(6);
    expect(saturated.generatedCandidates).toHaveLength(6);
    expect(new Set(saturated.generatedCandidates).size).toBe(6);
    expect(saturated.candidateSnapshots).toHaveLength(6);
    expect(saturated.zeroized).toBe(6);
    expect(saturated.zeroizedCandidates).toHaveLength(6);
    for (const [index, result] of results.entries()) {
      const candidate = saturated.generatedCandidates[index];
      const candidateSnapshot = saturated.candidateSnapshots[index];
      const zeroizedCandidate = saturated.zeroizedCandidates[index];
      if (
        candidate === undefined ||
        candidateSnapshot === undefined ||
        zeroizedCandidate === undefined
      ) {
        throw new Error('expected generated candidate, snapshot, and zeroization');
      }
      expect(zeroizedCandidate).toBe(candidate);
      expect(candidate).toStrictEqual(new Uint8Array(32));
      expect(candidateSnapshot).toStrictEqual(
        new TextEncoder().encode(`${SECRET}..........`).slice(0, 32),
      );
      assertPublicResultIsRedacted(result, candidate, candidateSnapshot);
    }
    const firstCandidate = saturated.generatedCandidates[0];
    const firstCandidateSnapshot = saturated.candidateSnapshots[0];
    if (firstCandidate === undefined || firstCandidateSnapshot === undefined) {
      throw new Error('expected first candidate material for receipt audit');
    }
    for (const event of delivered) {
      assertPublicEventIsRedacted(event, firstCandidate, firstCandidateSnapshot);
    }

    const failed = createPort();
    failed.failPreflightStage = 2;
    const failedResult = await new LifecycleEngine(failed).runSetup();
    const failedCandidate = failed.generatedCandidate;
    const failedCandidateSnapshot = failed.candidateSnapshot;
    if (failedCandidate === undefined || failedCandidateSnapshot === undefined) {
      throw new Error('expected failed candidate material for receipt audit');
    }
    expect(failedResult).toMatchObject({
      status: 'failed',
      code: 'SCG_LIFECYCLE_FAILED',
      failures: [{ stage: 'public-preflight-2' }],
    });
    assertPublicResultIsRedacted(failedResult, failedCandidate, failedCandidateSnapshot);
    for (const event of failed.events) {
      assertPublicEventIsRedacted(event, failedCandidate, failedCandidateSnapshot);
    }
  });
});
