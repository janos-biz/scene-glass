import { randomBytes as nodeRandomBytes } from 'node:crypto';

import { isExactHttpOrigin, isProjectId, isRecord, type LimitValues } from '@scene-glass/contracts';

import { AuthContext } from '../auth/auth-context.js';
import { DIAGNOSTICS_AUDIENCE, SCENE_GLASS_AUDIENCE } from '../auth/credential-subject.js';
import { isHighEntropyOpaqueToken, TokenDigest } from '../auth/local-token-verifier.js';
import {
  DIAGNOSTIC_RUN_TTL_MS,
  type DiagnosticTeardownReason,
  type DiagnosticsTeardown,
} from './teardown.js';

const DIAGNOSTIC_TOKEN_BYTES = 32;
const DIAGNOSTIC_RUN_ID_BYTES = 16;
const ISSUANCE_WINDOW_MS = 60_000;
const DIAGNOSTIC_TOMBSTONE_LIMIT = 128;

export type DiagnosticRunStatus = 'issued' | 'initialized';

/**
 * The only retained representation of a diagnostic capability. It deliberately
 * has no raw bearer value and TokenDigest refuses ordinary JSON serialization.
 */
export interface DiagnosticRunRecord {
  readonly digest: TokenDigest;
  readonly runId: string;
  readonly projectId: string;
  readonly origin: string;
  readonly aud: typeof DIAGNOSTICS_AUDIENCE;
  readonly expiresAt: number;
  readonly status: DiagnosticRunStatus;
}

export interface DiagnosticIssueInput {
  /** A verified normal project credential; diagnostics cannot issue themselves. */
  readonly auth: AuthContext;
  readonly limits: Pick<
    LimitValues,
    | 'diagnosticActiveRunsPerProject'
    | 'diagnosticActiveRunsGlobal'
    | 'diagnosticRunsPerProjectPerMinute'
  >;
}

export interface DiagnosticRunCredentialInput {
  /** Ephemeral request material. It is hashed immediately and never retained. */
  readonly token: string;
  readonly projectId: string;
  readonly origin: string;
  readonly audience: typeof DIAGNOSTICS_AUDIENCE;
}

export type DiagnosticFailureCode =
  | 'SCG_DIAGNOSTIC_INVALID'
  | 'SCG_DIAGNOSTIC_EXPIRED'
  | 'SCG_DIAGNOSTIC_REUSED'
  | 'SCG_DIAGNOSTIC_LIMIT_PROJECT'
  | 'SCG_DIAGNOSTIC_LIMIT_GLOBAL'
  | 'SCG_DIAGNOSTIC_RATE_LIMIT'
  | 'SCG_DIAGNOSTIC_SHUTDOWN';

export interface DiagnosticFailure {
  readonly ok: false;
  readonly status: 401 | 429 | 503;
  readonly code: DiagnosticFailureCode;
}
interface DiagnosticRunTombstone {
  readonly record: DiagnosticRunRecord;
  readonly code: Extract<
    DiagnosticFailureCode,
    'SCG_DIAGNOSTIC_EXPIRED' | 'SCG_DIAGNOSTIC_INVALID'
  >;
}

export interface DiagnosticIssueSuccess {
  readonly ok: true;
  readonly runId: string;
  /** Returned exactly once by issue(); no retained state contains this value. */
  readonly token: string;
  readonly expiresAt: number;
}

export interface DiagnosticAuthorizationSuccess {
  readonly ok: true;
  readonly record: DiagnosticRunRecord;
}

export type DiagnosticIssueResult = DiagnosticIssueSuccess | DiagnosticFailure;
export type DiagnosticAuthorizationResult = DiagnosticAuthorizationSuccess | DiagnosticFailure;

export interface DiagnosticsIssuerOptions {
  /** Injectable only to make TTL and issuance-window tests deterministic. */
  readonly now?: () => number;
  /** Injectable only to make opaque-token creation deterministic in tests. */
  readonly random?: (byteLength: number) => Uint8Array;
  /** Injectable only to test digest behavior without retaining bearer material. */
  readonly digest?: (token: string) => TokenDigest;
}

/**
 * Issues short-lived, one-run diagnostics credentials. The issuer owns only
 * digest metadata; lifecycle timers and active-run slots belong to teardown.
 */
export class DiagnosticsIssuer {
  readonly #records = new Map<string, DiagnosticRunRecord>();
  readonly #issuanceTimesByProject = new Map<string, number[]>();
  readonly #tombstones = new Map<string, DiagnosticRunTombstone>();
  readonly #teardown: DiagnosticsTeardown;
  readonly #now: () => number;
  readonly #random: (byteLength: number) => Uint8Array;
  readonly #digest: (token: string) => TokenDigest;

  public constructor(teardown: DiagnosticsTeardown, options: DiagnosticsIssuerOptions = {}) {
    this.#teardown = teardown;
    this.#now = options.now ?? Date.now;
    this.#random = options.random ?? nodeRandomBytes;
    this.#digest = options.digest ?? TokenDigest.fromOpaqueToken;
  }

  public get activeRunCount(): number {
    return this.#records.size;
  }

  public issue(input: DiagnosticIssueInput): DiagnosticIssueResult {
    const now = this.readNow();
    this.pruneTombstones(now);
    if (this.#teardown.shutDown) {
      return diagnosticFailure('SCG_DIAGNOSTIC_SHUTDOWN');
    }
    if (!isIssueAuthorized(input.auth, now)) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }

    const limits = readDiagnosticLimits(input.limits);
    const projectId = input.auth.projectId;
    if (this.#teardown.activeRunCount >= limits.diagnosticActiveRunsGlobal) {
      return diagnosticFailure('SCG_DIAGNOSTIC_LIMIT_GLOBAL');
    }
    if (
      this.#teardown.activeRunCountForProject(projectId) >= limits.diagnosticActiveRunsPerProject
    ) {
      return diagnosticFailure('SCG_DIAGNOSTIC_LIMIT_PROJECT');
    }

    const issuanceTimes = this.pruneIssuanceTimes(projectId, now);
    if (issuanceTimes.length >= limits.diagnosticRunsPerProjectPerMinute) {
      return diagnosticFailure('SCG_DIAGNOSTIC_RATE_LIMIT');
    }

    const expiresAt = safeAdd(now, DIAGNOSTIC_RUN_TTL_MS);
    const capability = this.createCapability();
    const record = freezeRecord({
      digest: capability.digest,
      runId: capability.runId,
      projectId,
      origin: input.auth.origin,
      aud: DIAGNOSTICS_AUDIENCE,
      expiresAt,
      status: 'issued',
    });

    this.#records.set(record.runId, record);
    const registered = this.#teardown.register({
      runId: record.runId,
      projectId: record.projectId,
      expiresAt: record.expiresAt,
      cleanup: (reason) => {
        this.#records.delete(record.runId);
        this.rememberTombstone(record, reason);
      },
    });
    if (!registered) {
      this.#records.delete(record.runId);
      return diagnosticFailure('SCG_DIAGNOSTIC_SHUTDOWN');
    }

    issuanceTimes.push(now);
    return Object.freeze({
      ok: true,
      runId: record.runId,
      token: capability.token,
      expiresAt: record.expiresAt,
    });
  }

  /**
   * Re-hashes the transient bearer and checks every bound metadata field.
   * Callers receive no raw credential and cannot enumerate active records.
   */
  public authenticate(input: DiagnosticRunCredentialInput): DiagnosticAuthorizationResult {
    const now = this.readNow();
    this.pruneTombstones(now);
    if (this.#teardown.shutDown) {
      return diagnosticFailure('SCG_DIAGNOSTIC_SHUTDOWN');
    }
    if (!isCredentialInputValid(input)) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }

    let digest: TokenDigest;
    try {
      digest = this.#digest(input.token);
    } catch {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }
    if (!(digest instanceof TokenDigest)) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }

    let record: DiagnosticRunRecord | undefined;
    for (const candidate of this.#records.values()) {
      if (candidate.digest.equals(digest)) {
        record = candidate;
      }
    }
    if (record === undefined) {
      let tombstone: DiagnosticRunTombstone | undefined;
      for (const candidate of this.#tombstones.values()) {
        if (candidate.record.digest.equals(digest)) {
          tombstone = candidate;
        }
      }
      if (tombstone === undefined) {
        return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
      }
      if (
        tombstone.record.projectId !== input.projectId ||
        tombstone.record.origin !== input.origin ||
        tombstone.record.aud !== input.audience
      ) {
        return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
      }
      return diagnosticFailure(tombstone.code);
    }
    if (
      record.projectId !== input.projectId ||
      record.origin !== input.origin ||
      record.aud !== input.audience
    ) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }
    if (now >= record.expiresAt) {
      this.#teardown.expire(record.runId);
      return diagnosticFailure('SCG_DIAGNOSTIC_EXPIRED');
    }

    return Object.freeze({ ok: true, record });
  }

  /** Atomically converts the one issued credential into its only active run. */
  public consume(runId: string): DiagnosticAuthorizationResult {
    const now = this.readNow();
    this.pruneTombstones(now);
    if (this.#teardown.shutDown) {
      return diagnosticFailure('SCG_DIAGNOSTIC_SHUTDOWN');
    }
    const record = this.#records.get(runId);
    if (record === undefined || record.status !== 'issued') {
      return diagnosticFailure('SCG_DIAGNOSTIC_REUSED');
    }
    if (now >= record.expiresAt) {
      this.#teardown.expire(record.runId);
      return diagnosticFailure('SCG_DIAGNOSTIC_EXPIRED');
    }

    const initialized = freezeRecord({ ...record, status: 'initialized' });
    this.#records.set(initialized.runId, initialized);
    return Object.freeze({ ok: true, record: initialized });
  }

  public revoke(runId: string): boolean {
    return this.#teardown.revoke(runId);
  }
  /** Identifies only retained digests; no caller receives bearer material. */
  public recognizesCredential(token: string): boolean {
    let digest: TokenDigest;
    try {
      digest = this.#digest(token);
    } catch {
      return false;
    }
    if (!(digest instanceof TokenDigest)) {
      return false;
    }

    let recognized = false;
    for (const record of this.#records.values()) {
      if (record.digest.equals(digest)) {
        recognized = true;
      }
    }
    for (const tombstone of this.#tombstones.values()) {
      if (tombstone.record.digest.equals(digest)) {
        recognized = true;
      }
    }
    return recognized;
  }

  public isEmpty(): boolean {
    return this.#records.size === 0;
  }

  /** Clears retained issuance timestamps after final server shutdown. */
  public clearShutdownState(): void {
    if (this.#teardown.shutDown) {
      this.#issuanceTimesByProject.clear();
      this.#tombstones.clear();
    }
  }

  private rememberTombstone(record: DiagnosticRunRecord, reason: DiagnosticTeardownReason): void {
    if (reason === 'shutdown') {
      return;
    }
    this.#tombstones.delete(record.runId);
    this.#tombstones.set(
      record.runId,
      Object.freeze({
        record,
        code: reason === 'expired' ? 'SCG_DIAGNOSTIC_EXPIRED' : 'SCG_DIAGNOSTIC_INVALID',
      }),
    );
    while (this.#tombstones.size > DIAGNOSTIC_TOMBSTONE_LIMIT) {
      const oldestRunId = this.#tombstones.keys().next().value;
      if (oldestRunId === undefined) {
        return;
      }
      this.#tombstones.delete(oldestRunId);
    }
  }

  private createCapability(): {
    readonly runId: string;
    readonly token: string;
    readonly digest: TokenDigest;
  } {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const token = encodeRandom(this.#random, DIAGNOSTIC_TOKEN_BYTES);
      if (!isHighEntropyOpaqueToken(token)) {
        throw new TypeError('diagnostic random source did not produce 256 bits');
      }
      const digest = this.#digest(token);
      if (!(digest instanceof TokenDigest)) {
        throw new TypeError('diagnostic digest source returned an invalid digest');
      }
      const runId = `diagnostic-${encodeRandom(this.#random, DIAGNOSTIC_RUN_ID_BYTES)}`;
      if (
        !this.#records.has(runId) &&
        ![...this.#records.values()].some((record) => record.digest.equals(digest))
      ) {
        return Object.freeze({ runId, token, digest });
      }
    }
    throw new Error('diagnostic random source produced a duplicate capability');
  }

  private pruneIssuanceTimes(projectId: string, now: number): number[] {
    const cutoff = now - ISSUANCE_WINDOW_MS;
    const existing = this.#issuanceTimesByProject.get(projectId) ?? [];
    const retained = existing.filter((issuedAt) => issuedAt > cutoff);
    this.#issuanceTimesByProject.set(projectId, retained);
    return retained;
  }
  private pruneTombstones(now: number): void {
    for (const [runId, tombstone] of this.#tombstones) {
      if (now - tombstone.record.expiresAt >= DIAGNOSTIC_RUN_TTL_MS) {
        this.#tombstones.delete(runId);
      }
    }
  }

  private readNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('diagnostic clock must return a non-negative safe integer');
    }
    return now;
  }
}

function isIssueAuthorized(auth: unknown, now: number): auth is AuthContext {
  return (
    auth instanceof AuthContext &&
    auth.audience === SCENE_GLASS_AUDIENCE &&
    auth.subject.audience === SCENE_GLASS_AUDIENCE &&
    auth.subject.projectId === auth.projectId &&
    isProjectId(auth.projectId) &&
    isExactHttpOrigin(auth.origin) &&
    auth.isActiveAt(now)
  );
}

function isCredentialInputValid(input: unknown): input is DiagnosticRunCredentialInput {
  return (
    isRecord(input) &&
    isHighEntropyOpaqueToken(input.token) &&
    isProjectId(input.projectId) &&
    isExactHttpOrigin(input.origin) &&
    input.audience === DIAGNOSTICS_AUDIENCE
  );
}

function readDiagnosticLimits(
  limits: DiagnosticIssueInput['limits'],
): DiagnosticIssueInput['limits'] {
  if (
    typeof limits !== 'object' ||
    limits === null ||
    !isPositiveSafeInteger(limits.diagnosticActiveRunsPerProject) ||
    !isPositiveSafeInteger(limits.diagnosticActiveRunsGlobal) ||
    !isPositiveSafeInteger(limits.diagnosticRunsPerProjectPerMinute)
  ) {
    throw new TypeError('diagnostic limits must be positive safe integers');
  }
  return limits;
}

function diagnosticFailure(code: DiagnosticFailureCode): DiagnosticFailure {
  switch (code) {
    case 'SCG_DIAGNOSTIC_INVALID':
    case 'SCG_DIAGNOSTIC_EXPIRED':
    case 'SCG_DIAGNOSTIC_REUSED':
      return { ok: false, status: 401, code };
    case 'SCG_DIAGNOSTIC_LIMIT_PROJECT':
    case 'SCG_DIAGNOSTIC_LIMIT_GLOBAL':
    case 'SCG_DIAGNOSTIC_RATE_LIMIT':
      return { ok: false, status: 429, code };
    case 'SCG_DIAGNOSTIC_SHUTDOWN':
      return { ok: false, status: 503, code };
  }
}

function freezeRecord(input: DiagnosticRunRecord): DiagnosticRunRecord {
  return Object.freeze({ ...input });
}

function encodeRandom(random: (byteLength: number) => Uint8Array, byteLength: number): string {
  const bytes = random(byteLength);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== byteLength) {
    throw new TypeError('diagnostic random source returned an invalid byte sequence');
  }
  return Buffer.from(bytes).toString('base64url');
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) {
    throw new TypeError('diagnostic expiry exceeds safe time range');
  }
  return result;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}
