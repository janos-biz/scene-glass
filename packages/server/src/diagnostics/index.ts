import type { SceneGlassLogger } from '../observability/logger.js';
import { DiagnosticsIssuer, type DiagnosticsIssuerOptions } from './issuer.js';
import { DiagnosticRunStore, type DiagnosticRunStoreOptions } from './run-store.js';
import { DiagnosticsTeardown, type DiagnosticsTeardownOptions } from './teardown.js';

export {
  DIAGNOSTIC_RUN_TTL_MS,
  DiagnosticsTeardown,
  type DiagnosticTeardownEvidence,
  type DiagnosticTeardownReason,
  type DiagnosticsTeardownOptions,
} from './teardown.js';
export {
  DiagnosticsIssuer,
  type DiagnosticAuthorizationResult,
  type DiagnosticFailure,
  type DiagnosticFailureCode,
  type DiagnosticIssueInput,
  type DiagnosticIssueResult,
  type DiagnosticRunCredentialInput,
  type DiagnosticRunRecord,
  type DiagnosticRunStatus,
  type DiagnosticsIssuerOptions,
} from './issuer.js';
export {
  DiagnosticRunStore,
  type AuthorizeDiagnosticMethodInput,
  type CloseDiagnosticRunInput,
  type ConsumeDiagnosticInitializeInput,
  type DiagnosticAllowedMethod,
  type DiagnosticMethodFailure,
  type DiagnosticRunStoreOptions,
  type DiagnosticSession,
  type DiagnosticSessionResult,
} from './run-store.js';

export interface CreateDiagnosticsLifecycleOptions {
  readonly now?: () => number;
  readonly logger: SceneGlassLogger;
  readonly random?: (byteLength: number) => Uint8Array;
  readonly digest?: DiagnosticsIssuerOptions['digest'];
}

export interface DiagnosticsLifecycle {
  readonly issuer: DiagnosticsIssuer;
  readonly runStore: DiagnosticRunStore;
  readonly teardown: DiagnosticsTeardown;
  /** Final server lifecycle hook; it is idempotent and leaves zero active runs. */
  readonly shutdown: () => number;
}

/**
 * Creates one cohesive lifecycle so issuer, session store, and teardown share
 * the same clock, random source, and central active-run ownership.
 */
export function createDiagnosticsLifecycle(
  options: CreateDiagnosticsLifecycleOptions,
): DiagnosticsLifecycle {
  const teardownOptions: DiagnosticsTeardownOptions = {
    logger: options.logger,
    ...(options.now === undefined ? {} : { now: options.now }),
  };
  const teardown = new DiagnosticsTeardown(teardownOptions);
  const issuerOptions: DiagnosticsIssuerOptions = {
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.random === undefined ? {} : { random: options.random }),
    ...(options.digest === undefined ? {} : { digest: options.digest }),
  };
  const issuer = new DiagnosticsIssuer(teardown, issuerOptions);
  const runStoreOptions: DiagnosticRunStoreOptions = {
    ...(options.random === undefined ? {} : { random: options.random }),
  };
  const runStore = new DiagnosticRunStore(issuer, teardown, runStoreOptions);

  return Object.freeze({
    issuer,
    runStore,
    teardown,
    shutdown: (): number => {
      const closed = teardown.shutdown();
      issuer.clearShutdownState();
      runStore.assertEmpty();
      teardown.assertEmpty();
      return closed;
    },
  });
}
