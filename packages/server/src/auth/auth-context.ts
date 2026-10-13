import { isExactHttpOrigin } from '@scene-glass/contracts';

import {
  type CredentialAudience,
  type CredentialSubject,
  createCredentialSubject,
  isCredentialSubject,
  sameCredentialSubject,
} from './credential-subject.js';
import { TokenDigest } from './local-token-verifier.js';

export interface AuthContextInput {
  readonly origin: string;
  readonly subject: CredentialSubject;
  readonly credentialDigest: TokenDigest;
  /** Epoch milliseconds; Infinity is valid for a restart-bound credential. */
  readonly expiresAt: number;
  readonly scopes?: readonly string[];
  /** This callback is intentionally re-evaluated at every session lookup. */
  readonly isRevoked?: () => boolean;
}

/**
 * A request authorization value with no bearer material. Origin and digest are
 * retained for server-side binding but deliberately omitted from JSON output.
 */
export class AuthContext {
  public readonly origin: string;
  public readonly audience: CredentialAudience;
  public readonly projectId: string;
  public readonly subject: CredentialSubject;
  public readonly credentialDigest: TokenDigest;
  public readonly expiresAt: number;
  public readonly scopes: readonly string[];

  readonly #isRevoked: () => boolean;

  public constructor(input: AuthContextInput) {
    if (!isExactHttpOrigin(input.origin)) {
      throw new TypeError('authentication origin is invalid');
    }
    if (!isCredentialSubject(input.subject)) {
      throw new TypeError('authentication subject is invalid');
    }
    if (!(input.credentialDigest instanceof TokenDigest)) {
      throw new TypeError('authentication credential digest is invalid');
    }
    if (!isCredentialExpiry(input.expiresAt)) {
      throw new TypeError('authentication credential expiry is invalid');
    }

    const subject = createCredentialSubject(input.subject);
    const scopes = Object.freeze([...(input.scopes ?? [])]);
    if (
      scopes.some((scope) => !isCredentialScope(scope)) ||
      new Set(scopes).size !== scopes.length
    ) {
      throw new TypeError('authentication scopes are invalid');
    }

    this.origin = input.origin;
    this.audience = subject.audience;
    this.projectId = subject.projectId;
    this.subject = subject;
    this.credentialDigest = input.credentialDigest;
    this.expiresAt = input.expiresAt;
    this.scopes = scopes;
    this.#isRevoked = input.isRevoked ?? neverRevoked;
    Object.freeze(this);
  }

  public isExpiredAt(now: number): boolean {
    assertSafeTime(now);
    return this.expiresAt <= now;
  }

  public isRevoked(): boolean {
    try {
      return this.#isRevoked() === true;
    } catch {
      // A failing issuer must never leave a credential usable.
      return true;
    }
  }

  public isActiveAt(now: number): boolean {
    return !this.isExpiredAt(now) && !this.isRevoked();
  }

  public allowsScope(scope: string): boolean {
    return this.scopes.includes(scope);
  }

  /**
   * Compares every identity component a session is required to pin. Digest
   * equality remains constant-time even though no raw bearer value is present.
   */
  public hasSameBinding(other: AuthContext): boolean {
    return (
      this.origin === other.origin &&
      this.audience === other.audience &&
      this.projectId === other.projectId &&
      sameCredentialSubject(this.subject, other.subject) &&
      this.credentialDigest.equals(other.credentialDigest) &&
      this.expiresAt === other.expiresAt &&
      sameScopes(this.scopes, other.scopes)
    );
  }

  /**
   * Safe for generic structured logs. It omits the opaque bearer-derived
   * digest, exact Origin, and subject identifier.
   */
  public toJSON(): Readonly<{
    audience: CredentialAudience;
    projectId: string;
    expiresAt: number | null;
    scopes: readonly string[];
  }> {
    return Object.freeze({
      audience: this.audience,
      projectId: this.projectId,
      expiresAt: this.expiresAt === Number.POSITIVE_INFINITY ? null : this.expiresAt,
      scopes: this.scopes,
    });
  }
}

function isCredentialExpiry(value: number): boolean {
  return value === Number.POSITIVE_INFINITY || (Number.isSafeInteger(value) && value > 0);
}

function assertSafeTime(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError('time must be a non-negative safe integer');
  }
}

function isCredentialScope(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9:._/-]{0,127}$/.test(value);
}

function sameScopes(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((scope, index) => scope === right[index]);
}

function neverRevoked(): boolean {
  return false;
}
