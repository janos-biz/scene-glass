import type { AddressInfo } from 'node:net';
import { formatWithOptions, inspect } from 'node:util';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { createNodeFinalizedVerificationAuthority } from '../../packages/onboarding/src/lifecycle/node-verification-port.js';
import {
  CANONICAL_LOADER_PATH,
  LIVE_DIAGNOSTIC_PROTOCOL_VERSION,
  LiveDiagnosticError,
  MAX_DIAGNOSTIC_RESPONSE_BYTES,
  runLiveDiagnostics,
  snapshotDiagnosticCloseReceipt,
  type BrowserDiagnosticCloseReceipt,
  type BrowserDiagnosticProfileHandle,
  type DiagnosticCloseReceipt,
  type DiagnosticExecutionContext,
  type DiagnosticHttpResponse,
  type LiveDiagnosticBrowserPort,
  type LiveDiagnosticHostPort,
  type LiveDiagnosticMcpPort,
  type LoopbackMcpRuntimeHandle,
  type SelectedHostKind,
} from '../../packages/onboarding/src/lifecycle/verification.js';

const SESSION_ID = 'diagnostic_session_123';
const MALFORMED_TOKEN_CANARY = 'token-canary-malformed-initialize-7Gx';
const MALFORMED_PATH_CANARY = '/private/scene-glass/malformed-initialize';
const OVERSIZED_TOKEN_CANARY = 'token-canary-oversized-initialize-7Gx';
const OVERSIZED_PATH_CANARY = '/private/scene-glass/oversized-initialize';
const MALFORMED_RESPONSE_CANARIES = Object.freeze([MALFORMED_TOKEN_CANARY, MALFORMED_PATH_CANARY]);
const OVERSIZED_RESPONSE_CANARIES = Object.freeze([OVERSIZED_TOKEN_CANARY, OVERSIZED_PATH_CANARY]);
const PERSISTENT_SECRET_CANARIES = Object.freeze({
  pathCanaries: Object.freeze(['/private/authority']),
  tokenMatcher: Object.freeze({
    matches: () => false,
  }),
});
const LIVE_CLOSE_TOKEN_CANARY = 'token-canary-live-close-receipt-7Gx';
const LIVE_CLOSE_PATH_CANARY = '/private/scene-glass/live-close-receipt';
const LIVE_CLOSE_CANARIES = Object.freeze([LIVE_CLOSE_TOKEN_CANARY, LIVE_CLOSE_PATH_CANARY]);
const LIVE_CLOSE_PERSISTENT_SECRET_CANARIES = Object.freeze({
  pathCanaries: Object.freeze([LIVE_CLOSE_PATH_CANARY]),
  tokenMatcher: Object.freeze({
    matches(value: Uint8Array): boolean {
      return containsBytes(value, new TextEncoder().encode(LIVE_CLOSE_TOKEN_CANARY));
    },
  }),
});
const authority = createNodeFinalizedVerificationAuthority({
  configuredProjects: [{ projectId: 'diagnostic' }],
  finalizedHost: {
    artifacts: [],
    credential: {
      artifact: {
        inverse: {
          kind: 'delete-created-credential',
          path: '/private/authority',
        },
        kind: 'credential',
        ownership: 'setup-created',
        path: '/private/authority',
      },
      bits: 256,
      kind: 'setup-created-candidate',
      path: '/private/authority',
      projectId: 'diagnostic',
      requestId: 'diagnostic-credential',
    },
    descriptor: {
      approvedRootIdentity: { device: '1', inode: '1' },
      credentialAuthorities: [],
      credentialKey: 'SCENE_GLASS_HOST_TOKEN',
      credentialProjectId: 'diagnostic',
      host: '127.0.0.1',
      loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js',
      navigation: 'document',
      port: 4175,
      projectId: 'diagnostic',
      publicRoot: 'public',
      readinessPath: '/__scene-glass/ready',
      schemaVersion: 1,
      template: 'public/index.html',
    },
    host: 'html',
    installId: 'diagnostic-install',
    loader: {
      async: true,
      dataScgNavigation: 'document',
      navigation: 'document',
      sourceMarker: true,
      sourceMarkerPlacement: 'immediately-before-unique-head',
      targetPath: 'public/index.html',
      insertionStrategy: 'immediately-before-unique-head',
    },
    rootPath: '/workspace/diagnostic',
    schemaVersion: 1,
  },
  projectRoot: '/workspace/diagnostic',
});
const harnesses: ProtocolHarness[] = [];

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((harness) => harness.app.close()));
});

type AcquisitionFault = 'mcp';
type CloseFault = 'browser' | 'host' | 'mcp-server' | 'mcp-session';
type HostCredentialCapabilityRevocation = false | 'omitted';
type DeferredBrowserProfileCloseOutcome = 'invalid-receipt' | 'rejected' | 'success';
type InitializeFault = 'malformed' | 'missing-session' | 'oversized';

interface HarnessOptions {
  readonly acquisitionFault?: AcquisitionFault;
  readonly blockAllCloseUntilReleased?: true;
  readonly hostCredentialCapabilityRevocation?: HostCredentialCapabilityRevocation;
  readonly blockCloseUntilDeadline?: CloseFault;
  readonly abortDuringBrowser?: AbortController;
  readonly browserFailure?: boolean;
  readonly deferredBrowserProfileCloseOutcome?: DeferredBrowserProfileCloseOutcome;
  readonly browserCloseRecords?: BrowserDiagnosticCloseReceipt['records'];
  readonly captureBrowserCloseSnapshot?: boolean;
  readonly mutateBrowserCloseReceiptDuringCleanup?: boolean;
  readonly closeFault?: CloseFault;
  readonly initializeFault?: InitializeFault;
  readonly selectedHost?: SelectedHostKind;
}

interface ProtocolHarness {
  readonly browserCloseSourceReceipt: BrowserDiagnosticCloseReceipt | undefined;
  readonly browserCloseAuditSnapshot: BrowserDiagnosticCloseReceipt | undefined;
  readonly app: FastifyInstance;
  readonly calls: string[];
  readonly closeCounts: Readonly<Record<CloseFault, number>>;
  readonly closeContexts: readonly DiagnosticExecutionContext[];
  readonly deferredBrowserProfileStarted: Promise<void> | undefined;
  readonly allCloseOperationsStarted: Promise<void> | undefined;
  readonly blockedCloseContexts: readonly DiagnosticExecutionContext[];
  readonly mcpRequests: ReadonlyArray<{
    readonly body: Record<string, unknown>;
    readonly headers: Headers;
  }>;
  readonly releaseDeferredBrowserProfile: (() => void) | undefined;
  readonly releaseAllCloseOperations: (() => void) | undefined;
  readonly ports: {
    readonly browser: LiveDiagnosticBrowserPort;
    readonly host: LiveDiagnosticHostPort;
    readonly mcp: LiveDiagnosticMcpPort;
  };
}

describe('onboarding lifecycle live verification', () => {
  it.each(['static'] as const)(
    'runs the complete real HTTP/JSON-RPC sequence against a %s host port',
    async (selectedHost) => {
      const harness = await startHarness({ selectedHost });

      await expect(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
          selectedHost,
        }),
      ).resolves.toEqual({
        host: selectedHost,
        initializeStatus: 200,
        initializedStatus: 202,
        annotationsListStatus: 200,
        loaderStatus: 200,
        persistent: false,
        pingStatus: 200,
      });

      expect(harness.calls).toEqual([
        `host-start:${selectedHost}`,
        'mcp-start',
        'mcp:initialize',
        'mcp:notifications/initialized',
        'mcp:ping',
        'host:loader',
        'browser-start',
        'browser-diagnostic',
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      expect(harness.mcpRequests).toHaveLength(4);
      expect(harness.mcpRequests[0]?.headers.get('mcp-protocol-version')).toBe(
        LIVE_DIAGNOSTIC_PROTOCOL_VERSION,
      );
      expect(harness.mcpRequests[0]?.headers.get('mcp-session-id')).toBeNull();
      expect(harness.mcpRequests[1]?.headers.get('mcp-session-id')).toBe(SESSION_ID);
      expect(harness.mcpRequests[2]?.headers.get('mcp-session-id')).toBe(SESSION_ID);
      expect(harness.mcpRequests[3]?.headers.get('mcp-session-id')).toBe(SESSION_ID);
      expectExactCleanup(harness, [
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
    },
  );

  it('unwinds only the acquired host when MCP acquisition fails', async () => {
    const diagnosticContext = context(new AbortController().signal, 100);
    const harness = await startHarness({
      acquisitionFault: 'mcp',
      blockCloseUntilDeadline: 'host',
      closeFault: 'host',
    });

    const error = await failureOf(
      runLiveDiagnostics({
        authority,
        browser: harness.ports.browser,
        context: diagnosticContext,
        host: harness.ports.host,
        mcp: harness.ports.mcp,
        persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
        selectedHost: 'static',
      }),
    );

    expect(error.failures).toStrictEqual([{ phase: 'mcp-start' }]);
    expect(error.message).toBe('live diagnostics failed: mcp-start');
    assertErrorGraphRedacted(error, faultCanaries('acquisition-mcp'));
    expect(harness.calls).toEqual(['host-start:static', 'mcp-start', 'host-close']);
    expectExactCleanup(harness, ['host-close']);
    expectCleanupContexts(harness, diagnosticContext, 1);
    expect(harness.blockedCloseContexts).toEqual(harness.closeContexts);
    const cleanupConvergence = error.cleanupConvergence;
    if (cleanupConvergence === undefined) {
      throw new Error('late host cleanup convergence was unavailable');
    }
    const lateCleanupFailure = await expectDeferredBrowserProfileCleanupConvergence(
      cleanupConvergence,
      'rejected',
    );
    if (lateCleanupFailure === undefined) {
      throw new Error('late host cleanup convergence unexpectedly fulfilled');
    }
    assertErrorGraphRedacted(lateCleanupFailure, faultCanaries('cleanup-host'));
  });

  it.each([
    ['static', 'success'],
    ['static', 'rejected'],
    ['static', 'invalid-receipt'],
  ] as const)(
    'adopts a deferred %s browser-profile startup with a %s late close receipt',
    async (selectedHost, deferredBrowserProfileCloseOutcome) => {
      const aborter = new AbortController();
      const diagnosticContext = context(aborter.signal);
      const harness = await startHarness({
        deferredBrowserProfileCloseOutcome,
        selectedHost,
      });
      const profileStarted = harness.deferredBrowserProfileStarted;
      const releaseProfile = harness.releaseDeferredBrowserProfile;
      if (profileStarted === undefined || releaseProfile === undefined) {
        throw new Error('deferred browser profile control was unavailable');
      }

      const diagnostic = runLiveDiagnostics({
        authority,
        browser: harness.ports.browser,
        context: diagnosticContext,
        host: harness.ports.host,
        mcp: harness.ports.mcp,
        persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
        selectedHost,
      });
      await awaitBounded(profileStarted, 'deferred browser profile startup');
      aborter.abort();

      const error = await failureOf(
        awaitBounded(diagnostic, 'caller-facing deferred browser profile diagnostic'),
      );
      const terminalFailures = error.failures;
      const terminalMessage = error.message;
      expect(error.failures).toStrictEqual([{ phase: 'aborted' }]);
      expect(error.message).toBe('live diagnostics failed: aborted');
      expect(Object.isFrozen(error.failures)).toBe(true);
      expect(Object.isFrozen(error.failures[0])).toBe(true);
      assertErrorGraphRedacted(error, faultCanaries('late-browser-close'));
      expectExactCleanup(harness, ['mcp-session-close', 'mcp-server-close', 'host-close']);
      expectCleanupContexts(harness, diagnosticContext, 3);

      const cleanupConvergence = error.cleanupConvergence;
      if (cleanupConvergence === undefined) {
        throw new Error('late browser profile cleanup convergence was unavailable');
      }
      let convergenceSettled = false;
      void cleanupConvergence.then(
        () => {
          convergenceSettled = true;
        },
        () => {
          convergenceSettled = true;
        },
      );
      await Promise.resolve();
      expect(convergenceSettled).toBe(false);

      releaseProfile();
      const lateCleanupFailure = await expectDeferredBrowserProfileCleanupConvergence(
        cleanupConvergence,
        deferredBrowserProfileCloseOutcome,
      );
      if (lateCleanupFailure !== undefined) {
        assertErrorGraphRedacted(lateCleanupFailure, faultCanaries('late-browser-close'));
      }

      expectExactCleanup(harness, [
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
        'browser-close',
      ]);
      expectCleanupContexts(harness, diagnosticContext, 4);
      expect(error.failures).toBe(terminalFailures);
      expect(error.failures).toStrictEqual([{ phase: 'aborted' }]);
      expect(error.message).toBe(terminalMessage);
    },
  );

  it.each(['browser', 'mcp-session', 'mcp-server', 'host'] as const)(
    'settles every created handle when %s cleanup fails',
    async (closeFault) => {
      const harness = await startHarness({ browserFailure: true, closeFault });

      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
          selectedHost: 'static',
        }),
      );

      expect(error.failures).toEqual([
        { phase: 'browser-diagnostic' },
        { phase: `${closeFault}-close` },
      ]);
      expectExactCleanup(harness, [
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      assertErrorGraphRedacted(error, [
        ...faultCanaries('browser-diagnostic'),
        ...faultCanaries(`cleanup-${closeFault}`),
      ]);
    },
  );

  it('reports only the primary abort when caller cancellation does not interrupt cleanup', async () => {
    const aborter = new AbortController();
    const diagnosticContext = context(aborter.signal);
    const harness = await startHarness({ abortDuringBrowser: aborter });

    const error = await failureOf(
      runLiveDiagnostics({
        authority,
        browser: harness.ports.browser,
        context: diagnosticContext,
        host: harness.ports.host,
        mcp: harness.ports.mcp,
        persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
        selectedHost: 'static',
      }),
    );

    expect(error.failures).toEqual([{ phase: 'aborted' }]);
    assertErrorGraphRedacted(error, []);
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
    expect(harness.closeContexts).toHaveLength(4);
    expect(new Set(harness.closeContexts.map((closeContext) => closeContext.signal))).toHaveLength(
      1,
    );
    for (const closeContext of harness.closeContexts) {
      expect(closeContext.deadline).toBe(diagnosticContext.deadline);
      expect(closeContext.signal).not.toBe(diagnosticContext.signal);
      expect(closeContext.signal.aborted).toBe(false);
    }
  });

  it('starts every acquired cleanup at the original deadline without late terminal mutation', async () => {
    const aborter = new AbortController();
    const harness = await startHarness({
      abortDuringBrowser: aborter,
      blockAllCloseUntilReleased: true,
      blockCloseUntilDeadline: 'browser',
      closeFault: 'browser',
    });
    const allCloseOperationsStarted = harness.allCloseOperationsStarted;
    const releaseAllCloseOperations = harness.releaseAllCloseOperations;
    if (allCloseOperationsStarted === undefined || releaseAllCloseOperations === undefined) {
      throw new Error('shared cleanup start barrier was unavailable');
    }
    const diagnosticContext = context(aborter.signal, 500);
    const startedAt = Date.now();
    const diagnostic = runLiveDiagnostics({
      authority,
      browser: harness.ports.browser,
      context: diagnosticContext,
      host: harness.ports.host,
      mcp: harness.ports.mcp,
      persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
      selectedHost: 'static',
    });

    await awaitBounded(allCloseOperationsStarted, 'shared cleanup start barrier');
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
    expectCleanupContexts(harness, diagnosticContext, 4);
    releaseAllCloseOperations();

    const error = await failureOf(diagnostic);
    const completedAt = Date.now();
    const terminalFailures = error.failures;
    const terminalMessage = error.message;

    expect(error.failures).toStrictEqual([{ phase: 'aborted' }]);
    expect(error.message).toBe('live diagnostics failed: aborted');
    assertErrorGraphRedacted(error, faultCanaries('cleanup-browser'));
    expect(harness.blockedCloseContexts).toStrictEqual([harness.closeContexts[0]]);
    expect(completedAt).toBeGreaterThanOrEqual(diagnosticContext.deadline - 5);
    expect(completedAt).toBeLessThan(diagnosticContext.deadline + 1_000);
    expect(startedAt).toBeLessThan(diagnosticContext.deadline);
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
    expectCleanupContexts(harness, diagnosticContext, 4);
    const cleanupConvergence = error.cleanupConvergence;
    if (cleanupConvergence === undefined) {
      throw new Error('expired deadline cleanup convergence was unavailable');
    }
    const lateCleanupFailure = await expectDeferredBrowserProfileCleanupConvergence(
      cleanupConvergence,
      'rejected',
    );
    if (lateCleanupFailure === undefined) {
      throw new Error('expired deadline cleanup convergence unexpectedly fulfilled');
    }
    assertErrorGraphRedacted(lateCleanupFailure, faultCanaries('cleanup-browser'));

    expect(error.failures).toBe(terminalFailures);
    expect(error.failures).toStrictEqual(terminalFailures);
    expect(error.message).toBe(terminalMessage);
    assertErrorGraphRedacted(error, faultCanaries('cleanup-browser'));
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
  });

  it.each(['browser', 'mcp-session', 'mcp-server', 'host'] as const)(
    'reports the real %s cleanup failure alongside the primary abort',
    async (closeFault) => {
      const aborter = new AbortController();
      const harness = await startHarness({ abortDuringBrowser: aborter, closeFault });

      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(aborter.signal),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
          selectedHost: 'static',
        }),
      );

      expect(error.failures).toEqual([{ phase: 'aborted' }, { phase: `${closeFault}-close` }]);
      assertErrorGraphRedacted(error, faultCanaries(`cleanup-${closeFault}`));
      expectExactCleanup(harness, [
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
    },
  );

  it('rejects missing and empty live canary bundles before acquiring any diagnostic authority', async () => {
    const invalidCanaryBundles = [
      Object.freeze({ pathCanaries: Object.freeze([LIVE_CLOSE_PATH_CANARY]) }),
      Object.freeze({
        pathCanaries: Object.freeze([]),
        tokenMatcher: Object.freeze({ matches: () => false }),
      }),
    ] as const;

    for (const persistentSecretCanaries of invalidCanaryBundles) {
      const harness = await startHarness({});
      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: persistentSecretCanaries as never,
          selectedHost: 'static',
        }),
      );

      expect(error.failures).toStrictEqual([{ phase: 'secret-receipt' }]);
      expect(error.message).toBe('live diagnostics failed: secret-receipt');
      assertErrorGraphRedacted(error, LIVE_CLOSE_CANARIES);
      expect(harness.calls).toStrictEqual([]);
      expectExactCleanup(harness, []);
    }
  });

  it.each([
    ['a non-boolean result', (): unknown => undefined],
    [
      'a thrown result',
      (): unknown => {
        throw new Error('invalid live canary matcher result');
      },
    ],
  ] as const)(
    'rejects %s from a live token matcher after complete cleanup',
    async (_case, matches) => {
      const harness = await startHarness({
        browserCloseRecords: [{ kind: 'log', text: 'safe-live-close-receipt' }],
      });
      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: {
            pathCanaries: [LIVE_CLOSE_PATH_CANARY],
            tokenMatcher: { matches },
          } as never,
          selectedHost: 'static',
        }),
      );

      expect(error.failures).toStrictEqual([{ phase: 'secret-receipt' }]);
      expect(error.message).toBe('live diagnostics failed: secret-receipt');
      assertErrorGraphRedacted(error, LIVE_CLOSE_CANARIES);
      expect(harness.calls).toStrictEqual([
        'host-start:static',
        'mcp-start',
        'mcp:initialize',
        'mcp:notifications/initialized',
        'mcp:ping',
        'host:loader',
        'browser-start',
        'browser-diagnostic',
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      expectExactCleanup(harness, [
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
    },
  );
  it.each([
    ['static', 'omitted', 'omitted'],
    ['static', 'false', false],
  ] as const)(
    'rejects a %s host receipt with %s credential capability revocation after cleanup',
    async (selectedHost, _receipt, hostCredentialCapabilityRevocation) => {
      const harness = await startHarness({ hostCredentialCapabilityRevocation, selectedHost });
      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
          selectedHost,
        }),
      );

      expect(error.failures).toStrictEqual([{ phase: 'secret-receipt' }]);
      expect(error.message).toBe('live diagnostics failed: secret-receipt');
      expect(harness.calls).toStrictEqual([
        `host-start:${selectedHost}`,
        'mcp-start',
        'mcp:initialize',
        'mcp:notifications/initialized',
        'mcp:ping',
        'host:loader',
        'browser-start',
        'browser-diagnostic',
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      expectExactCleanup(harness, [
        'browser-close',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      const cleanupConvergence = error.cleanupConvergence;
      if (cleanupConvergence === undefined) {
        throw new Error('invalid host receipt cleanup convergence was unavailable');
      }
      await expect(cleanupConvergence).rejects.toMatchObject({ phase: 'secret-receipt' });
    },
  );

  it('rejects a valid live browser close receipt retaining independent token and path canaries', async () => {
    const harness = await startHarness({
      browserCloseRecords: [
        { kind: 'log', text: `${LIVE_CLOSE_TOKEN_CANARY}:${LIVE_CLOSE_PATH_CANARY}` },
      ],
    });
    const error = await failureOf(
      runLiveDiagnostics({
        authority,
        browser: harness.ports.browser,
        context: context(),
        host: harness.ports.host,
        mcp: harness.ports.mcp,
        persistentSecretCanaries: LIVE_CLOSE_PERSISTENT_SECRET_CANARIES,
        selectedHost: 'static',
      }),
    );

    expect(error.failures).toStrictEqual([{ phase: 'secret-receipt' }]);
    expect(error.message).toBe('live diagnostics failed: secret-receipt');
    assertErrorGraphRedacted(error, LIVE_CLOSE_CANARIES);
    expect(harness.calls).toStrictEqual([
      'host-start:static',
      'mcp-start',
      'mcp:initialize',
      'mcp:notifications/initialized',
      'mcp:ping',
      'host:loader',
      'browser-start',
      'browser-diagnostic',
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
    const cleanupConvergence = error.cleanupConvergence;
    if (cleanupConvergence === undefined) {
      throw new Error('secret close receipt convergence was unavailable');
    }
    const lateCleanupFailure = await expectDeferredBrowserProfileCleanupConvergence(
      cleanupConvergence,
      'rejected',
    );
    if (lateCleanupFailure === undefined) {
      throw new Error('secret close receipt convergence unexpectedly fulfilled');
    }
    assertErrorGraphRedacted(lateCleanupFailure, LIVE_CLOSE_CANARIES);
  });

  it('audits a deeply frozen browser close snapshot after its fulfilled source receipt is mutated', async () => {
    const scannedReceiptText: string[] = [];
    const harness = await startHarness({
      browserCloseRecords: [{ kind: 'log', text: 'safe-browser-close-receipt' }],
      captureBrowserCloseSnapshot: true,
      mutateBrowserCloseReceiptDuringCleanup: true,
    });

    await expect(
      runLiveDiagnostics({
        authority,
        browser: harness.ports.browser,
        context: context(),
        host: harness.ports.host,
        mcp: harness.ports.mcp,
        persistentSecretCanaries: {
          pathCanaries: [LIVE_CLOSE_PATH_CANARY],
          tokenMatcher: {
            matches(value: Uint8Array): boolean {
              scannedReceiptText.push(new TextDecoder().decode(value));
              return false;
            },
          },
        },
        selectedHost: 'static',
      }),
    ).resolves.toStrictEqual({
      host: 'static',
      initializeStatus: 200,
      initializedStatus: 202,
      annotationsListStatus: 200,
      loaderStatus: 200,
      persistent: false,
      pingStatus: 200,
    });

    const sourceReceipt = harness.browserCloseSourceReceipt;
    const auditedReceipt = harness.browserCloseAuditSnapshot;
    const auditedRecord = auditedReceipt?.records[0];
    const sourceRecord = sourceReceipt?.records[0];
    if (sourceReceipt === undefined || sourceRecord === undefined || sourceRecord.kind !== 'log') {
      throw new Error('expected fulfilled mutable browser close receipt');
    }
    if (
      auditedReceipt === undefined ||
      auditedRecord === undefined ||
      auditedRecord.kind !== 'log'
    ) {
      throw new Error('expected immutable audited browser close receipt');
    }
    expect(auditedReceipt).not.toBe(sourceReceipt);
    expect(Object.isFrozen(auditedReceipt)).toBe(true);
    expect(Object.isFrozen(auditedReceipt.records)).toBe(true);
    expect(Object.isFrozen(auditedRecord)).toBe(true);
    expect(Object.isFrozen(auditedReceipt.browserState)).toBe(true);
    expect(auditedRecord.text).toBe('safe-browser-close-receipt');
    expect(() => {
      (auditedReceipt.records as unknown as unknown[]).push({});
    }).toThrow(TypeError);
    expect(Object.isFrozen(sourceReceipt)).toBe(false);
    expect(Object.isFrozen(sourceReceipt.records)).toBe(false);
    expect(sourceRecord.text).toBe(`${LIVE_CLOSE_TOKEN_CANARY}:${LIVE_CLOSE_PATH_CANARY}`);
    expect(scannedReceiptText).toStrictEqual(['safe-browser-close-receipt']);
    expectExactCleanup(harness, [
      'browser-close',
      'mcp-session-close',
      'mcp-server-close',
      'host-close',
    ]);
  });

  it.each([
    [
      'prototype property',
      () => {
        const error = new Error('safe');
        Object.setPrototypeOf(error, { retained: LIVE_CLOSE_TOKEN_CANARY });
        return error;
      },
    ],
    [
      'Map entry hidden by custom inspection',
      () => {
        const retained = new Map([['safe', LIVE_CLOSE_PATH_CANARY]]);
        Object.defineProperty(retained, inspect.custom, { value: () => 'safe' });
        return Object.assign(new Error('safe'), { retained });
      },
    ],
    [
      'Set entry hidden by custom inspection',
      () => {
        const retained = new Set([LIVE_CLOSE_TOKEN_CANARY]);
        Object.defineProperty(retained, inspect.custom, { value: () => 'safe' });
        return Object.assign(new Error('safe'), { retained });
      },
    ],
  ] as const)('fails closed when a canary is retained in a %s', (_surface, createError) => {
    const failure = errorGraphFailure(() =>
      assertErrorGraphRedacted(createError(), LIVE_CLOSE_CANARIES),
    );
    expect(failure.message).toBe('diagnostic error retained sensitive data');
  });
  it.each(['missing-session', 'malformed', 'oversized'] as const)(
    'rejects %s initialize responses without retaining response content',
    async (initializeFault) => {
      const harness = await startHarness({ initializeFault });

      const error = await failureOf(
        runLiveDiagnostics({
          authority,
          browser: harness.ports.browser,
          context: context(),
          host: harness.ports.host,
          mcp: harness.ports.mcp,
          persistentSecretCanaries: PERSISTENT_SECRET_CANARIES,
          selectedHost: 'static',
        }),
      );

      expect(error.failures).toEqual([{ phase: 'initialize', status: 200 }]);
      expect(error.message).toBe('live diagnostics failed: initialize/200');
      assertErrorGraphRedacted(error, initializeFaultCanaries(initializeFault));
      expect(harness.calls).toEqual([
        'host-start:static',
        'mcp-start',
        'mcp:initialize',
        'mcp-session-close',
        'mcp-server-close',
        'host-close',
      ]);
      expectExactCleanup(harness, ['mcp-session-close', 'mcp-server-close', 'host-close']);
    },
  );
});

async function startHarness(options: HarnessOptions): Promise<ProtocolHarness> {
  const app = Fastify();
  const calls: string[] = [];
  const mcpRequests: { body: Record<string, unknown>; headers: Headers }[] = [];
  const closeCounts: Record<CloseFault, number> = {
    browser: 0,
    host: 0,
    'mcp-server': 0,
    'mcp-session': 0,
  };
  const closeContexts: DiagnosticExecutionContext[] = [];
  const blockedCloseContexts: DiagnosticExecutionContext[] = [];

  app.post('/mcp', async (request, reply) => {
    const body = request.body as Record<string, unknown>;
    mcpRequests.push({ body, headers: new Headers(request.headers as Record<string, string>) });
    const method = body.method;

    if (method === 'initialize') {
      if (options.initializeFault === 'oversized') {
        reply.code(200).header('mcp-session-id', SESSION_ID).type('application/json');
        return `${OVERSIZED_TOKEN_CANARY}:${OVERSIZED_PATH_CANARY}:${'x'.repeat(
          MAX_DIAGNOSTIC_RESPONSE_BYTES + 1,
        )}`;
      }
      if (options.initializeFault === 'malformed') {
        reply.code(200).header('mcp-session-id', SESSION_ID).type('application/json');
        return `{not-json:${MALFORMED_TOKEN_CANARY}:${MALFORMED_PATH_CANARY}`;
      }
      if (options.initializeFault !== 'missing-session') {
        reply.header('mcp-session-id', SESSION_ID);
      }
      return {
        id: 'scene-glass-live-initialize',
        jsonrpc: '2.0',
        result: { protocolVersion: LIVE_DIAGNOSTIC_PROTOCOL_VERSION },
      };
    }
    if (method === 'notifications/initialized') {
      return reply.code(202).send();
    }
    if (method === 'ping') {
      return { id: 'scene-glass-live-ping', jsonrpc: '2.0', result: {} };
    }
    if (method === 'tools/call') {
      return { id: 'scene-glass-live-annotations-list', jsonrpc: '2.0', result: {} };
    }
    return reply.code(400).send();
  });

  app.get(CANONICAL_LOADER_PATH, async (_request, reply) => {
    return reply
      .header('cache-control', 'no-store, private, max-age=0')
      .type('text/javascript')
      .send('loader');
  });

  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (address === null || typeof address === 'string') {
    await app.close();
    throw new Error('diagnostic Fastify harness did not bind TCP');
  }
  const baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
  const selectedHost = options.selectedHost ?? 'static';
  const closeStartBarrier =
    options.blockAllCloseUntilReleased === true ? createCleanupStartBarrier(4) : undefined;

  const deferredBrowserProfileControl =
    options.deferredBrowserProfileCloseOutcome === undefined
      ? undefined
      : {
          profile: createDeferred<BrowserDiagnosticProfileHandle>(),
          started: createDeferred<void>(),
        };
  let browserCloseSourceReceipt: BrowserDiagnosticCloseReceipt | undefined;
  let browserCloseAuditSnapshot: BrowserDiagnosticCloseReceipt | undefined;
  const createBrowserProfile = (): BrowserDiagnosticProfileHandle => {
    let closed = false;
    return {
      persistent: false,
      async close(closeContext) {
        closeContexts.push(closeContext);
        closeCounts.browser += 1;
        calls.push('browser-close');
        if (closed) {
          throw new Error('browser close invoked more than once');
        }
        closed = true;
        if (closeStartBarrier !== undefined) {
          await closeStartBarrier.wait();
        }
        if (options.blockCloseUntilDeadline === 'browser') {
          blockedCloseContexts.push(closeContext);
          await waitUntilAfterDeadline(closeContext.deadline);
        }
        if (options.closeFault === 'browser') {
          throw faultError('cleanup-browser');
        }
        if (options.deferredBrowserProfileCloseOutcome === 'rejected') {
          throw faultError('late-browser-close');
        }
        if (options.deferredBrowserProfileCloseOutcome === 'invalid-receipt') {
          return browserReceipt('bootstrap-profile');
        }
        browserCloseSourceReceipt = browserReceipt(
          'browser-profile',
          options.browserCloseRecords ?? [],
        );
        if (options.captureBrowserCloseSnapshot) {
          browserCloseAuditSnapshot = snapshotDiagnosticCloseReceipt(
            browserCloseSourceReceipt,
          ) as BrowserDiagnosticCloseReceipt;
        }
        return browserCloseSourceReceipt;
      },
      async verifyHostPage() {
        calls.push('browser-diagnostic');
        options.abortDuringBrowser?.abort();
        if (options.browserFailure) {
          throw faultError('browser-diagnostic');
        }
        return { loaderReady: true, logs: [], panelReady: true };
      },
    };
  };
  let deferredBrowserProfileReleased = false;
  const releaseDeferredBrowserProfile =
    deferredBrowserProfileControl === undefined
      ? undefined
      : (): void => {
          if (deferredBrowserProfileReleased) {
            throw new Error('deferred browser profile released more than once');
          }
          deferredBrowserProfileReleased = true;
          deferredBrowserProfileControl.profile.resolve(createBrowserProfile());
        };
  const ports = {
    browser: {
      async startProfile(): Promise<BrowserDiagnosticProfileHandle> {
        calls.push('browser-start');
        if (deferredBrowserProfileControl !== undefined) {
          deferredBrowserProfileControl.started.resolve(undefined);
          return deferredBrowserProfileControl.profile.promise;
        }
        return createBrowserProfile();
      },
    } satisfies LiveDiagnosticBrowserPort,
    host: {
      async start(input): Promise<{
        readonly foreground: true;
        readonly kind: SelectedHostKind;
        readonly persistent: false;
        close(context: DiagnosticExecutionContext): Promise<DiagnosticCloseReceipt>;
        load(
          path: typeof CANONICAL_LOADER_PATH,
          context: DiagnosticExecutionContext,
        ): Promise<DiagnosticHttpResponse>;
      }> {
        expect(input.selectedHost).toBe(selectedHost);
        calls.push(`host-start:${input.selectedHost}`);
        let closed = false;
        return {
          foreground: true,
          kind: input.selectedHost,
          persistent: false,
          async close(closeContext) {
            closeContexts.push(closeContext);
            closeCounts.host += 1;
            calls.push('host-close');
            if (closed) {
              throw new Error('host close invoked more than once');
            }
            closed = true;
            if (closeStartBarrier !== undefined) {
              await closeStartBarrier.wait();
            }
            if (options.blockCloseUntilDeadline === 'host') {
              blockedCloseContexts.push(closeContext);
              await waitUntilAfterDeadline(closeContext.deadline);
            }
            if (options.closeFault === 'host') {
              throw faultError('cleanup-host');
            }
            return hostReceipt(input.selectedHost, options.hostCredentialCapabilityRevocation);
          },
          async load(path) {
            calls.push('host:loader');
            expect(path).toBe(CANONICAL_LOADER_PATH);
            return fetchResponse(await fetch(`${baseUrl}${path}`));
          },
        };
      },
    } satisfies LiveDiagnosticHostPort,
    mcp: {
      async startLoopback(): Promise<LoopbackMcpRuntimeHandle> {
        calls.push('mcp-start');
        if (options.acquisitionFault === 'mcp') {
          throw faultError('acquisition-mcp');
        }
        let serverClosed = false;
        let sessionClosed = false;
        return {
          server: {
            loopback: true,
            persistent: false,
            async close(closeContext) {
              closeContexts.push(closeContext);
              closeCounts['mcp-server'] += 1;
              calls.push('mcp-server-close');
              if (serverClosed) {
                throw new Error('MCP server close invoked more than once');
              }
              serverClosed = true;
              if (closeStartBarrier !== undefined) {
                await closeStartBarrier.wait();
              }
              if (options.blockCloseUntilDeadline === 'mcp-server') {
                blockedCloseContexts.push(closeContext);
                await waitUntilAfterDeadline(closeContext.deadline);
              }
              if (options.closeFault === 'mcp-server') {
                throw faultError('cleanup-mcp-server');
              }
              return receipt('mcp-server');
            },
          },
          session: {
            async close(closeContext) {
              closeContexts.push(closeContext);
              closeCounts['mcp-session'] += 1;
              calls.push('mcp-session-close');
              if (sessionClosed) {
                throw new Error('MCP session close invoked more than once');
              }
              sessionClosed = true;
              if (closeStartBarrier !== undefined) {
                await closeStartBarrier.wait();
              }
              if (options.blockCloseUntilDeadline === 'mcp-session') {
                blockedCloseContexts.push(closeContext);
                await waitUntilAfterDeadline(closeContext.deadline);
              }
              if (options.mutateBrowserCloseReceiptDuringCleanup) {
                await new Promise<void>((resolve) => {
                  setTimeout(resolve, 0);
                });
                const record = browserCloseSourceReceipt?.records[0];
                if (record === undefined || record.kind !== 'log') {
                  throw new Error('mutable browser close receipt fixture was unavailable');
                }
                (record as { text: string }).text =
                  `${LIVE_CLOSE_TOKEN_CANARY}:${LIVE_CLOSE_PATH_CANARY}`;
              }
              if (options.closeFault === 'mcp-session') {
                throw faultError('cleanup-mcp-session');
              }
              return receipt('mcp-session');
            },
            async request(request) {
              const method = request.body.method;
              if (method !== 'tools/call') calls.push(`mcp:${method}`);
              return fetchResponse(
                await fetch(`${baseUrl}/mcp`, {
                  body: JSON.stringify(request.body),
                  headers: { 'content-type': 'application/json', ...request.headers },
                  method: 'POST',
                }),
              );
            },
          },
        };
      },
    } satisfies LiveDiagnosticMcpPort,
  };

  const harness = {
    get browserCloseAuditSnapshot(): BrowserDiagnosticCloseReceipt | undefined {
      return browserCloseAuditSnapshot;
    },
    get browserCloseSourceReceipt(): BrowserDiagnosticCloseReceipt | undefined {
      return browserCloseSourceReceipt;
    },
    app,
    allCloseOperationsStarted: closeStartBarrier?.started,
    blockedCloseContexts,
    calls,
    closeContexts,
    closeCounts,
    mcpRequests,
    deferredBrowserProfileStarted: deferredBrowserProfileControl?.started.promise,
    ports,
    releaseDeferredBrowserProfile,
    releaseAllCloseOperations: closeStartBarrier?.release,
  };
  harnesses.push(harness);
  return harness;
}

function context(
  signal: AbortSignal = new AbortController().signal,
  timeoutMs: number = 10_000,
): DiagnosticExecutionContext {
  return { deadline: Date.now() + timeoutMs, signal };
}
interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
}

function createDeferred<T>(): Deferred<T> {
  let resolvePromise: ((value: T | PromiseLike<T>) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  if (resolvePromise === undefined) {
    throw new Error('deferred promise did not expose its resolver');
  }
  const resolve = resolvePromise;
  return Object.freeze({
    promise,
    resolve(value: T): void {
      resolve(value);
    },
  });
}
interface CleanupStartBarrier {
  readonly started: Promise<void>;
  wait(): Promise<void>;
  release(): void;
}

function createCleanupStartBarrier(participants: number): CleanupStartBarrier {
  const started = createDeferred<void>();
  const released = createDeferred<void>();
  let arrivals = 0;
  let didRelease = false;
  return Object.freeze({
    started: started.promise,
    async wait(): Promise<void> {
      arrivals += 1;
      if (arrivals > participants) {
        throw new Error('cleanup start barrier received too many participants');
      }
      if (arrivals === participants) {
        started.resolve(undefined);
      }
      await released.promise;
    },
    release(): void {
      if (didRelease) {
        throw new Error('cleanup start barrier released more than once');
      }
      didRelease = true;
      released.resolve(undefined);
    },
  });
}

async function awaitBounded<T>(operation: Promise<T>, description: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutFailure = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`${description} did not settle within the bounded test interval`));
    }, 2_000);
  });
  try {
    return await Promise.race([operation, timeoutFailure]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}
async function expectDeferredBrowserProfileCleanupConvergence(
  cleanupConvergence: Promise<void>,
  expectedOutcome: DeferredBrowserProfileCloseOutcome,
): Promise<Error | undefined> {
  const timeoutSentinel = Symbol('deferred browser profile cleanup convergence timeout');
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const settled = await (() => {
    const timeoutResult = new Promise<typeof timeoutSentinel>((resolve) => {
      timeout = setTimeout(() => {
        resolve(timeoutSentinel);
      }, 2_000);
    });
    return Promise.race([
      cleanupConvergence.then(
        () => ({ state: 'fulfilled' as const }),
        (reason: unknown) => ({ reason, state: 'rejected' as const }),
      ),
      timeoutResult,
    ]);
  })().finally(() => {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  });

  if (settled === timeoutSentinel) {
    throw new Error(
      'deferred browser profile cleanup convergence did not settle within the bounded test interval',
    );
  }
  if (expectedOutcome === 'success') {
    expect(settled).toEqual({ state: 'fulfilled' });
    return undefined;
  }
  expect(settled.state).toBe('rejected');
  if (settled.state !== 'rejected') {
    throw new Error('deferred browser profile cleanup convergence unexpectedly fulfilled');
  }

  const rejection = settled.reason;
  expect(rejection).toBeInstanceOf(Error);
  if (!(rejection instanceof Error)) {
    throw new Error(
      'deferred browser profile cleanup convergence rejected without a product error',
    );
  }
  expect(rejection.constructor.name).toBe('DiagnosticPhaseError');
  expect(rejection.name).toBe('DiagnosticPhaseError');
  expect(rejection.message).toBe('secret-receipt');
  expect((rejection as Error & { readonly phase?: unknown }).phase).toBe('secret-receipt');
  return rejection;
}

function expectExactCleanup(
  harness: ProtocolHarness,
  expectedCalls: readonly `${CloseFault}-close`[],
): void {
  expect(harness.calls.filter((call) => call.endsWith('-close'))).toEqual(expectedCalls);
  expect(harness.closeCounts).toEqual({
    browser: expectedCalls.filter((call) => call === 'browser-close').length,
    host: expectedCalls.filter((call) => call === 'host-close').length,
    'mcp-server': expectedCalls.filter((call) => call === 'mcp-server-close').length,
    'mcp-session': expectedCalls.filter((call) => call === 'mcp-session-close').length,
  });
  expect(harness.closeContexts).toHaveLength(expectedCalls.length);
}

function expectCleanupContexts(
  harness: ProtocolHarness,
  originalContext: DiagnosticExecutionContext,
  expectedCount: number,
): void {
  expect(harness.closeContexts).toHaveLength(expectedCount);
  const [cleanupContext] = harness.closeContexts;
  if (cleanupContext === undefined) {
    throw new Error('expected every acquired handle to receive a cleanup context');
  }
  expect(Object.isFrozen(cleanupContext)).toBe(true);
  for (const closeContext of harness.closeContexts) {
    expect(closeContext).toBe(cleanupContext);
    expect(closeContext.deadline).toBe(originalContext.deadline);
    expect(closeContext.signal).not.toBe(originalContext.signal);
    expect(closeContext.signal.aborted).toBe(false);
  }
}

async function waitUntilAfterDeadline(deadline: number): Promise<void> {
  const boundedWaitDeadline = performance.now() + 2_000;
  while (Date.now() <= deadline) {
    if (performance.now() >= boundedWaitDeadline) {
      throw new Error('wall clock did not advance beyond the diagnostic deadline');
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, Math.max(1, Math.min(25, deadline - Date.now() + 1)));
    });
  }
}
async function fetchResponse(response: Response): Promise<DiagnosticHttpResponse> {
  return {
    body: new Uint8Array(await response.arrayBuffer()),
    headers: Object.fromEntries(response.headers.entries()),
    status: response.status,
  };
}

function receipt(
  phase: Exclude<DiagnosticCloseReceipt['phase'], 'bootstrap-profile' | 'browser-profile' | 'host'>,
): DiagnosticCloseReceipt {
  return { phase, records: [] };
}
function hostReceipt(
  runtime: SelectedHostKind,
  credentialCapabilityRevocation: HostCredentialCapabilityRevocation | undefined = undefined,
): DiagnosticCloseReceipt {
  const credentialCapability =
    credentialCapabilityRevocation === 'omitted'
      ? {}
      : { credentialCapabilityRevoked: credentialCapabilityRevocation ?? true };
  return (runtime === 'static'
    ? {
        phase: 'host',
        records: [
          {
            ...credentialCapability,
            kind: 'runtime-cleanup',
            listenerClosed: true,
            runtime,
            tokenWiped: true,
          },
        ],
      }
    : {
        phase: 'host',
        records: [
          {
            cacheAuthorityClosed: true,
            cacheWriterClosed: true,
            ...credentialCapability,
            kind: 'runtime-cleanup',
            processLeaseReleased: true,
            runtime,
            serverClosed: true,
            signalListenersRemoved: true,
            umaskRestored: true,
          },
        ],
      }) as unknown as DiagnosticCloseReceipt;
}

function browserReceipt(
  phase: BrowserDiagnosticCloseReceipt['phase'],
  records: BrowserDiagnosticCloseReceipt['records'] = [],
): BrowserDiagnosticCloseReceipt {
  return {
    browserState: {
      cacheStorageNames: [],
      indexedDbNames: [],
      localStorageKeys: [],
      serviceWorkerRegistrations: [],
      sessionStorageKeys: [],
    },
    phase,
    records,
  };
}

async function failureOf(promise: Promise<unknown>): Promise<LiveDiagnosticError> {
  try {
    await promise;
  } catch (error: unknown) {
    if (error instanceof LiveDiagnosticError) {
      return error;
    }
    throw new Error('diagnostic invocation rejected with an unexpected error');
  }
  throw new Error('diagnostic invocation unexpectedly succeeded');
}
function initializeFaultCanaries(fault: InitializeFault): readonly string[] {
  if (fault === 'malformed') return MALFORMED_RESPONSE_CANARIES;
  if (fault === 'oversized') return OVERSIZED_RESPONSE_CANARIES;
  return [];
}

function faultCanaries(scope: string): readonly string[] {
  return Object.freeze([`token-canary-${scope}-7Gx`, `/private/scene-glass/${scope}`]);
}

function faultError(scope: string): Error {
  const [token, path] = faultCanaries(scope);
  const error = new Error(`diagnostic fault ${token}:${path}`);
  const cause = new Error(`diagnostic cause ${path}:${token}`);
  Object.defineProperty(error, 'cause', { value: cause });
  Object.defineProperty(error, 'retained', {
    value: Object.freeze({
      nested: Object.freeze({
        bytes: new TextEncoder().encode(`${path}:${token}`),
        path,
        token,
      }),
    }),
  });
  Object.defineProperty(error, Symbol(`diagnostic ${token}`), {
    value: Object.freeze({ path, token }),
  });
  error.stack = `${error.stack ?? error.name}\n${token}\n${path}`;
  return error;
}

const ERROR_GRAPH_NODE_LIMIT = 128;
const ERROR_GRAPH_DEPTH_LIMIT = 8;
const ERROR_GRAPH_PROPERTY_LIMIT = 64;
const ERROR_GRAPH_TEXT_LIMIT = 131_072;
const ERROR_GRAPH_BYTE_LIMIT = 131_072;
const ERROR_GRAPH_INSPECT_OPTIONS = Object.freeze({
  breakLength: 120,
  compact: true,
  customInspect: true,
  depth: ERROR_GRAPH_DEPTH_LIMIT,
  getters: false,
  maxArrayLength: ERROR_GRAPH_PROPERTY_LIMIT,
  maxStringLength: ERROR_GRAPH_TEXT_LIMIT,
  showHidden: true,
  sorted: true,
});
const ERROR_GRAPH_TRUSTED_PROTOTYPES = new Set<object>([
  Array.prototype,
  ArrayBuffer.prototype,
  DataView.prototype,
  Error.prototype,
  Function.prototype,
  Map.prototype,
  Object.prototype,
  Set.prototype,
  Uint8Array.prototype,
]);

interface ErrorGraphEntry {
  readonly depth: number;
  readonly value: unknown;
}

function assertErrorGraphRedacted(error: unknown, canaries: readonly string[]): void {
  if (canaries.length > ERROR_GRAPH_PROPERTY_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  const tokenBytes = canaries.map((canary) => {
    if (canary.length > ERROR_GRAPH_TEXT_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }
    return new TextEncoder().encode(canary);
  });
  const queue: ErrorGraphEntry[] = [{ depth: 0, value: error }];
  const seen = new WeakSet<object>();

  for (let offset = 0; offset < queue.length; offset += 1) {
    const entry = queue[offset];
    if (entry === undefined) {
      throwSensitiveErrorGraphFailure();
    }
    assertErrorGraphValue(entry.value, canaries, tokenBytes);

    if (!isErrorGraphObject(entry.value)) {
      continue;
    }
    if (seen.has(entry.value)) {
      continue;
    }
    if (entry.depth >= ERROR_GRAPH_DEPTH_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }
    seen.add(entry.value);
    let prototype: object | null;
    try {
      prototype = Object.getPrototypeOf(entry.value);
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    if (prototype !== null && !ERROR_GRAPH_TRUSTED_PROTOTYPES.has(prototype)) {
      enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: prototype });
    }
    enqueueErrorGraphCollectionEntries(entry.value, entry.depth, queue);

    assertErrorGraphSurface(() => String(entry.value), canaries, tokenBytes);
    assertErrorGraphSurface(
      () => inspect(entry.value, ERROR_GRAPH_INSPECT_OPTIONS),
      canaries,
      tokenBytes,
    );
    assertErrorGraphSurface(
      () => formatWithOptions(ERROR_GRAPH_INSPECT_OPTIONS, '%o', entry.value),
      canaries,
      tokenBytes,
    );
    assertErrorGraphSurface(
      () => formatWithOptions(ERROR_GRAPH_INSPECT_OPTIONS, '%O', entry.value),
      canaries,
      tokenBytes,
    );

    let keys: readonly PropertyKey[];
    try {
      keys = Reflect.ownKeys(entry.value);
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    if (keys.length > ERROR_GRAPH_PROPERTY_LIMIT) {
      throwSensitiveErrorGraphFailure();
    }

    for (const key of keys) {
      if (typeof key === 'string') {
        assertErrorGraphText(key, canaries, tokenBytes);
      } else {
        assertErrorGraphSurface(() => String(key), canaries, tokenBytes);
      }

      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(entry.value, key);
      } catch {
        throwSensitiveErrorGraphFailure();
      }
      if (descriptor === undefined) {
        throwSensitiveErrorGraphFailure();
      }
      if ('value' in descriptor) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.value });
      }
      if (descriptor.get !== undefined) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.get });
        let getterValue: unknown;
        try {
          getterValue = Reflect.get(entry.value, key);
        } catch {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: getterValue });
      }
      if (descriptor.set !== undefined) {
        enqueueErrorGraphValue(queue, { depth: entry.depth + 1, value: descriptor.set });
      }
    }
  }
}

function enqueueErrorGraphValue(queue: ErrorGraphEntry[], entry: ErrorGraphEntry): void {
  if (queue.length >= ERROR_GRAPH_NODE_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  queue.push(entry);
}
function enqueueErrorGraphCollectionEntries(
  value: object,
  depth: number,
  queue: ErrorGraphEntry[],
): void {
  if (value instanceof Map) {
    let entries = 0;
    try {
      for (const [key, item] of Map.prototype.entries.call(value)) {
        entries += 1;
        if (entries > ERROR_GRAPH_PROPERTY_LIMIT) {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: key });
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: item });
      }
    } catch {
      throwSensitiveErrorGraphFailure();
    }
    return;
  }
  if (value instanceof Set) {
    let entries = 0;
    try {
      for (const item of Set.prototype.values.call(value)) {
        entries += 1;
        if (entries > ERROR_GRAPH_PROPERTY_LIMIT) {
          throwSensitiveErrorGraphFailure();
        }
        enqueueErrorGraphValue(queue, { depth: depth + 1, value: item });
      }
    } catch {
      throwSensitiveErrorGraphFailure();
    }
  }
}

function isErrorGraphObject(value: unknown): value is object {
  return (typeof value === 'object' && value !== null) || typeof value === 'function';
}

function assertErrorGraphValue(
  value: unknown,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  if (typeof value === 'string') {
    assertErrorGraphText(value, canaries, tokenBytes);
    return;
  }
  if (typeof value === 'symbol') {
    assertErrorGraphSurface(() => String(value), canaries, tokenBytes);
    return;
  }
  if (value instanceof Uint8Array) {
    assertErrorGraphBytes(value, tokenBytes);
    return;
  }
  if (ArrayBuffer.isView(value)) {
    assertErrorGraphBytes(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
      tokenBytes,
    );
    return;
  }
  if (value instanceof ArrayBuffer) {
    assertErrorGraphBytes(new Uint8Array(value), tokenBytes);
  }
}

function assertErrorGraphSurface(
  render: () => string,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  try {
    assertErrorGraphText(render(), canaries, tokenBytes);
  } catch {
    throwSensitiveErrorGraphFailure();
  }
}

function assertErrorGraphText(
  value: string,
  canaries: readonly string[],
  tokenBytes: readonly Uint8Array[],
): void {
  if (value.length > ERROR_GRAPH_TEXT_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  for (const canary of canaries) {
    if (value.includes(canary)) {
      throwSensitiveErrorGraphFailure();
    }
  }
  assertErrorGraphBytes(new TextEncoder().encode(value), tokenBytes);
}

function assertErrorGraphBytes(value: Uint8Array, canaries: readonly Uint8Array[]): void {
  if (value.byteLength > ERROR_GRAPH_BYTE_LIMIT) {
    throwSensitiveErrorGraphFailure();
  }
  for (const canary of canaries) {
    if (containsBytes(value, canary)) {
      throwSensitiveErrorGraphFailure();
    }
  }
}

function containsBytes(value: Uint8Array, candidate: Uint8Array): boolean {
  for (let offset = 0; offset <= value.length - candidate.length; offset += 1) {
    let matches = true;
    for (let index = 0; index < candidate.length; index += 1) {
      if (value[offset + index] !== candidate[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

function errorGraphFailure(action: () => void): Error {
  try {
    action();
  } catch (error: unknown) {
    if (error instanceof Error) {
      return error;
    }
    throw error;
  }
  throw new Error('error graph oracle unexpectedly passed');
}
function throwSensitiveErrorGraphFailure(): never {
  throw new Error('diagnostic error retained sensitive data');
}
