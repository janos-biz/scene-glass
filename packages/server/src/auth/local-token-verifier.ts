import { createHash, timingSafeEqual } from 'node:crypto';

import { isExactHttpOrigin, parseCanonicalOpaqueToken } from '@scene-glass/contracts';

import {
  type CredentialAudience,
  type CredentialSubject,
  createCredentialSubject,
  isCredentialAudience,
  isCredentialSubject,
} from './credential-subject.js';
import { AuthContext } from './auth-context.js';

const CANONICAL_DIGEST_PATTERN = /^[A-Za-z0-9_-]+$/;
const TOKEN_DIGEST_BYTES = 32;

/**
 * A SHA-256 verifier value. The encoded digest is intentionally private so it
 * cannot be accidentally rendered by logs or JSON serialization.
 */
export class TokenDigest {
  readonly #bytes: Buffer;

  private constructor(bytes: Uint8Array) {
    if (bytes.byteLength !== TOKEN_DIGEST_BYTES) {
      throw new TypeError('token digest must be a SHA-256 value');
    }
    this.#bytes = Buffer.from(bytes);
    Object.freeze(this);
  }

  public static fromOpaqueToken(token: string): TokenDigest {
    assertHighEntropyOpaqueToken(token);
    return new TokenDigest(createHash('sha256').update(token, 'utf8').digest());
  }

  /**
   * Accepts a canonical base64url SHA-256 digest for startup-only registry
   * construction. It is never needed on an HTTP request path.
   */
  public static fromEncoded(encoded: string): TokenDigest {
    if (!CANONICAL_DIGEST_PATTERN.test(encoded)) {
      throw new TypeError('token digest encoding is invalid');
    }

    const bytes = Buffer.from(encoded, 'base64url');
    if (bytes.byteLength !== TOKEN_DIGEST_BYTES || bytes.toString('base64url') !== encoded) {
      throw new TypeError('token digest encoding is invalid');
    }
    return new TokenDigest(bytes);
  }

  public equals(other: TokenDigest): boolean {
    return timingSafeEqual(this.#bytes, other.#bytes);
  }

  /** Do not serialize verifier material into ordinary diagnostic output. */
  public toJSON(): undefined {
    return undefined;
  }
}

export type LocalTokenCredentialMode = 'restart-bound' | 'managed';

export interface LocalTokenCredentialBaseInput {
  /**
   * Startup or issuer input only. This value is hashed immediately and is not
   * retained by the returned credential or verifier.
   */
  readonly token: string;
  readonly subject: CredentialSubject;
  /** Required by issuers that bind a credential to one document origin. */
  readonly origin?: string;
  readonly scopes?: readonly string[];
}

/** A credential valid only until the process authority is restarted. */
export interface RestartBoundLocalTokenCredentialInput extends LocalTokenCredentialBaseInput {
  readonly mode: 'restart-bound';
  readonly expiresAt?: never;
  readonly isRevoked?: never;
}

/** A credential with issuer-managed expiry and a live revocation authority. */
export interface ManagedLocalTokenCredentialInput extends LocalTokenCredentialBaseInput {
  readonly mode: 'managed';
  /** Epoch milliseconds. This must be finite and issuer-managed. */
  readonly expiresAt: number;
  /** Mutable issuer state is queried on every verification and session use. */
  readonly isRevoked: () => boolean;
}

/**
 * Credential lifecycle is always explicit. Callers choose a restart-bound
 * credential or a managed finite-expiry credential with live revocation.
 */
export type LocalTokenCredentialInput =
  RestartBoundLocalTokenCredentialInput | ManagedLocalTokenCredentialInput;

/** Explicit-factory input for a restart-bound credential. */
export interface RestartBoundCredentialOptions extends LocalTokenCredentialBaseInput {
  readonly mode?: never;
  readonly expiresAt?: never;
  readonly isRevoked?: never;
}

/** Explicit-factory input for a managed credential. */
export interface ManagedCredentialOptions extends LocalTokenCredentialBaseInput {
  readonly mode?: never;
  readonly expiresAt: number;
  readonly isRevoked: () => boolean;
}

/** A raw-token-free credential snapshot retained by the verifier. */
export interface LocalTokenCredential {
  readonly mode: LocalTokenCredentialMode;
  readonly subject: CredentialSubject;
  readonly tokenDigest: TokenDigest;
  readonly expiresAt: number;
  readonly origin?: string;
  readonly scopes: readonly string[];
  /** Internal callback retained only for live managed lifecycle enforcement. */
  readonly isRevoked: () => boolean;
}

/** Secret-free evidence produced when a live issuer callback fails. */
export interface RevocationCheckFailedEvidence {
  readonly event: 'revocation-check-failed';
  readonly credentialMode: 'managed';
}

export interface LocalTokenVerifierOptions {
  /**
   * Mandatory audit sink for failed managed revocation checks. Evidence
   * intentionally carries no token, digest, subject, origin, callback error,
   * or stack.
   */
  readonly onRevocationCheckFailed: (evidence: RevocationCheckFailedEvidence) => void;
}

export interface VerifyBearerInput {
  readonly authorization: string | undefined;
  readonly origin: string;
  /** A route may require one audience without selecting a project. */
  readonly audience?: CredentialAudience;
  readonly now?: number;
}

export type AuthFailureCode = 'SCG_AUTH_INVALID' | 'SCG_AUTH_EXPIRED';

export interface AuthVerificationSuccess {
  readonly ok: true;
  readonly context: AuthContext;
}

export interface AuthVerificationFailure {
  readonly ok: false;
  readonly status: 401;
  readonly code: AuthFailureCode;
}

export type AuthVerificationResult = AuthVerificationSuccess | AuthVerificationFailure;

/**
 * Validates opaque local bearer credentials. The verifier keeps only immutable
 * SHA-256 values and compares every candidate digest in constant time.
 */
export class LocalTokenVerifier {
  readonly #credentials: readonly LocalTokenCredential[];

  public constructor(
    credentials: Iterable<LocalTokenCredential>,
    options: LocalTokenVerifierOptions,
  ) {
    const reportRevocationCheckFailed = createRevocationFailureReporter(options);
    const snapshot = Array.from(credentials, (credential) =>
      snapshotCredential(credential, reportRevocationCheckFailed),
    );
    assertUniqueDigests(snapshot);
    this.#credentials = Object.freeze(snapshot);
    Object.freeze(this);
  }

  public verify(input: VerifyBearerInput): AuthVerificationResult {
    const now = input.now ?? Date.now();
    if (!isSafeTime(now) || !isExactHttpOrigin(input.origin)) {
      return authFailure('SCG_AUTH_INVALID');
    }
    if (input.audience !== undefined && !isCredentialAudience(input.audience)) {
      return authFailure('SCG_AUTH_INVALID');
    }

    const token = parseBearer(input.authorization);
    if (token === undefined || !isHighEntropyOpaqueToken(token)) {
      return authFailure('SCG_AUTH_INVALID');
    }

    const candidateDigest = TokenDigest.fromOpaqueToken(token);
    let matched: LocalTokenCredential | undefined;
    for (const credential of this.#credentials) {
      const matches = credential.tokenDigest.equals(candidateDigest);
      if (matches) {
        matched = credential;
      }
    }

    if (matched === undefined) {
      return authFailure('SCG_AUTH_INVALID');
    }
    if (
      (input.audience !== undefined && matched.subject.audience !== input.audience) ||
      (matched.origin !== undefined && matched.origin !== input.origin)
    ) {
      return authFailure('SCG_AUTH_INVALID');
    }
    if (matched.expiresAt <= now || matched.isRevoked()) {
      return authFailure('SCG_AUTH_EXPIRED');
    }

    return {
      ok: true,
      context: new AuthContext({
        origin: input.origin,
        subject: matched.subject,
        credentialDigest: matched.tokenDigest,
        expiresAt: matched.expiresAt,
        scopes: matched.scopes,
        isRevoked: matched.isRevoked,
      }),
    };
  }
}

/** Creates a credential from an explicitly selected lifecycle mode. */
export function createLocalTokenCredential(input: LocalTokenCredentialInput): LocalTokenCredential {
  assertCredentialInput(input);
  const mode = input.mode;
  const tokenDigest = createTokenDigest(input.token);
  const subject = snapshotSubject(input.subject);
  const origin = snapshotOrigin(input.origin);
  const scopes = snapshotScopes(input.scopes === undefined ? [] : input.scopes);

  if (mode === 'restart-bound') {
    assertRestartBoundInput(input);
    return freezeCredential({
      mode,
      subject,
      tokenDigest,
      expiresAt: Number.POSITIVE_INFINITY,
      scopes,
      isRevoked: neverRevoked,
      ...(origin === undefined ? {} : { origin }),
    });
  }

  const expiresAt = snapshotManagedExpiry(input.expiresAt);
  const isRevoked = assertRevocationCheck(input.isRevoked);
  return freezeCredential({
    mode,
    subject,
    tokenDigest,
    expiresAt,
    scopes,
    isRevoked,
    ...(origin === undefined ? {} : { origin }),
  });
}

/** Explicit factory for normal credentials that terminate on process restart. */
export function createRestartBoundLocalTokenCredential(
  input: RestartBoundCredentialOptions,
): LocalTokenCredential {
  assertNoLifecycleOverrides(input);
  return createLocalTokenCredential({
    mode: 'restart-bound',
    token: input.token,
    subject: input.subject,
    ...(input.origin === undefined ? {} : { origin: input.origin }),
    ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
  });
}

/** Explicit factory for credentials controlled by issuer expiry and revocation. */
export function createManagedLocalTokenCredential(
  input: ManagedCredentialOptions,
): LocalTokenCredential {
  assertNoModeOverride(input);
  return createLocalTokenCredential({
    mode: 'managed',
    token: input.token,
    subject: input.subject,
    expiresAt: input.expiresAt,
    isRevoked: input.isRevoked,
    ...(input.origin === undefined ? {} : { origin: input.origin }),
    ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
  });
}

export function isHighEntropyOpaqueToken(token: unknown): token is string {
  try {
    parseCanonicalOpaqueToken(token);
    return true;
  } catch {
    return false;
  }
}

export function parseBearer(authorization: string | undefined): string | undefined {
  if (authorization === undefined) {
    return undefined;
  }

  const match = /^Bearer ([A-Za-z0-9_-]+)$/i.exec(authorization);
  return match?.[1];
}

function assertHighEntropyOpaqueToken(token: string): void {
  parseCanonicalOpaqueToken(token);
}

function snapshotCredential(
  credential: LocalTokenCredential,
  reportRevocationCheckFailed: () => void,
): LocalTokenCredential {
  if (typeof credential !== 'object' || credential === null || Array.isArray(credential)) {
    throw new TypeError('credential is invalid');
  }

  const mode = snapshotCredentialMode(credential.mode);
  const subject = snapshotSubject(credential.subject);
  const tokenDigest = snapshotTokenDigest(credential.tokenDigest);
  const origin = snapshotOrigin(credential.origin);
  const scopes = snapshotScopes(credential.scopes);

  if (mode === 'restart-bound') {
    if (
      credential.expiresAt !== Number.POSITIVE_INFINITY ||
      credential.isRevoked !== neverRevoked
    ) {
      throw new TypeError('restart-bound credential lifecycle is invalid');
    }
    return freezeCredential({
      mode,
      subject,
      tokenDigest,
      expiresAt: Number.POSITIVE_INFINITY,
      scopes,
      isRevoked: neverRevoked,
      ...(origin === undefined ? {} : { origin }),
    });
  }

  const expiresAt = snapshotManagedExpiry(credential.expiresAt);
  const isRevoked = snapshotRevocationCheck(credential.isRevoked, reportRevocationCheckFailed);
  return freezeCredential({
    mode,
    subject,
    tokenDigest,
    expiresAt,
    scopes,
    isRevoked,
    ...(origin === undefined ? {} : { origin }),
  });
}

function freezeCredential(credential: LocalTokenCredential): LocalTokenCredential {
  return Object.freeze(credential);
}

function assertCredentialInput(input: unknown): asserts input is LocalTokenCredentialInput {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TypeError('credential is invalid');
  }
  const mode = (input as { readonly mode?: unknown }).mode;
  if (!isCredentialMode(mode)) {
    throw new TypeError('credential lifecycle mode is invalid');
  }
}

function assertRestartBoundInput(input: RestartBoundLocalTokenCredentialInput): void {
  if (hasProperty(input, 'expiresAt') || hasProperty(input, 'isRevoked')) {
    throw new TypeError('restart-bound credential cannot define expiry or revocation');
  }
}

function assertNoLifecycleOverrides(input: RestartBoundCredentialOptions): void {
  if (
    hasProperty(input, 'mode') ||
    hasProperty(input, 'expiresAt') ||
    hasProperty(input, 'isRevoked')
  ) {
    throw new TypeError('restart-bound credential factory does not accept lifecycle overrides');
  }
}

function assertNoModeOverride(input: ManagedCredentialOptions): void {
  if (hasProperty(input, 'mode')) {
    throw new TypeError('managed credential factory does not accept a mode override');
  }
}

function hasProperty(value: object, key: string): boolean {
  return key in value;
}

function assertUniqueDigests(credentials: readonly LocalTokenCredential[]): void {
  for (let index = 0; index < credentials.length; index += 1) {
    const credential = credentials[index];
    if (credential === undefined) {
      continue;
    }
    for (let otherIndex = 0; otherIndex < index; otherIndex += 1) {
      const other = credentials[otherIndex];
      if (other !== undefined && credential.tokenDigest.equals(other.tokenDigest)) {
        throw new TypeError('token digests must be unique');
      }
    }
  }
}

function authFailure(code: AuthFailureCode): AuthVerificationFailure {
  return { ok: false, status: 401, code };
}

function snapshotSubject(value: unknown): CredentialSubject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('credential subject is invalid');
  }

  const candidate = value as CredentialSubject;
  const audience = candidate.audience;
  const projectId = candidate.projectId;
  const id = candidate.id;
  const subject = { audience, projectId, id };
  if (!isCredentialSubject(subject)) {
    throw new TypeError('credential subject is invalid');
  }
  return createCredentialSubject(subject);
}

function createTokenDigest(value: unknown): TokenDigest {
  if (typeof value !== 'string') {
    throw new TypeError('credential token is invalid');
  }
  return TokenDigest.fromOpaqueToken(value);
}

function snapshotTokenDigest(value: unknown): TokenDigest {
  if (!(value instanceof TokenDigest)) {
    throw new TypeError('credential digest is invalid');
  }
  return value;
}

function snapshotCredentialMode(value: unknown): LocalTokenCredentialMode {
  if (!isCredentialMode(value)) {
    throw new TypeError('credential lifecycle mode is invalid');
  }
  return value;
}

function isCredentialMode(value: unknown): value is LocalTokenCredentialMode {
  return value === 'restart-bound' || value === 'managed';
}

function snapshotManagedExpiry(value: unknown): number {
  if (!isManagedCredentialExpiry(value)) {
    throw new TypeError('managed credential expiry is invalid');
  }
  return value;
}

function isManagedCredentialExpiry(value: unknown): value is number {
  return typeof value === 'number' && isSafeTime(value) && value > 0;
}

function snapshotOrigin(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string' || !isExactHttpOrigin(value)) {
    throw new TypeError('credential origin is invalid');
  }
  return value;
}

function snapshotScopes(value: unknown): readonly string[] {
  if (!Array.isArray(value)) {
    throw new TypeError('credential scopes are invalid');
  }

  const scopes: string[] = [];
  for (const scope of value) {
    if (!isCredentialScope(scope)) {
      throw new TypeError('credential scopes are invalid');
    }
    scopes.push(scope);
  }
  if (new Set(scopes).size !== scopes.length) {
    throw new TypeError('credential scopes must be unique');
  }
  return Object.freeze(scopes);
}

function assertRevocationCheck(value: unknown): () => boolean {
  if (typeof value !== 'function') {
    throw new TypeError('credential revocation check is invalid');
  }
  return value as () => boolean;
}

function snapshotRevocationCheck(value: unknown, reportFailure: () => void): () => boolean {
  const check = assertRevocationCheck(value);
  return () => safelyRevoked(check, reportFailure);
}

function isSafeTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isCredentialScope(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9:._/-]{0,127}$/.test(value);
}

function createRevocationFailureReporter(options: LocalTokenVerifierOptions): () => void {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new TypeError('local token verifier options are invalid');
  }
  const reporter = options.onRevocationCheckFailed;
  if (typeof reporter !== 'function') {
    throw new TypeError('revocation failure reporter is invalid');
  }
  const evidence = Object.freeze({
    event: 'revocation-check-failed' as const,
    credentialMode: 'managed' as const,
  });
  return () => {
    try {
      reporter(evidence);
    } catch {
      // Evidence delivery must not keep a credential usable.
    }
  };
}

function safelyRevoked(check: () => unknown, reportFailure: () => void): boolean {
  try {
    return check() !== false;
  } catch {
    reportFailure();
    return true;
  }
}

function neverRevoked(): boolean {
  return false;
}
