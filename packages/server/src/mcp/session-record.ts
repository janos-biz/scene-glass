import { randomBytes } from 'node:crypto';

import type { AuthContext } from '../auth/auth-context.js';
import type { CredentialSubject } from '../auth/credential-subject.js';
import type { TokenDigest } from '../auth/local-token-verifier.js';

export type SessionId = string & {
  readonly __sceneGlassSessionId: 'SessionId';
};

export type SessionCloseReason =
  | 'client-close'
  | 'abort'
  | 'shutdown'
  | 'revoked'
  | 'auth-expired'
  | 'session-expired'
  | 'context-mismatch';

export type SessionValidationFailureCode =
  | 'SCG_AUTH_EXPIRED'
  | 'SCG_SESSION_EXPIRED'
  | 'SCG_SESSION_CONTEXT_MISMATCH'
  | 'SCG_SESSION_NOT_FOUND';

export type SessionValidation =
  { readonly ok: true } | { readonly ok: false; readonly code: SessionValidationFailureCode };

export interface SessionResource {
  /** Must not retain the bearer token or write it to a log. */
  readonly dispose: (reason: SessionCloseReason) => void;
}

export interface SessionRecordInput {
  readonly id: SessionId;
  readonly auth: AuthContext;
  readonly createdAt: number;
  readonly sessionMaxAgeMs: number;
  readonly sessionIdleMs: number;
  readonly resources?: readonly SessionResource[];
}

/**
 * A server-side session binding. Its identity fields never change; only the
 * last-seen/lifecycle state and the resources that lifecycle owns are mutable.
 */
export class SessionRecord {
  public readonly id: SessionId;
  public readonly origin: string;
  public readonly audience: AuthContext['audience'];
  public readonly projectId: string;
  public readonly credentialSubject: CredentialSubject;
  public readonly credentialExpiresAt: number;
  public readonly createdAt: number;
  public readonly sessionExpiresAt: number;
  public readonly sessionIdleMs: number;
  public readonly signal: AbortSignal;

  readonly #auth: AuthContext;
  readonly #abortController = new AbortController();
  readonly #resources: Set<SessionResource>;
  #lastSeenAt: number;
  #closed = false;
  #expiryTimer: ReturnType<typeof setTimeout> | undefined;

  public constructor(input: SessionRecordInput) {
    if (!isSessionId(input.id)) {
      throw new TypeError('session id is invalid');
    }
    assertSafeTime(input.createdAt, 'session creation time');
    assertPositiveSafeDuration(input.sessionMaxAgeMs, 'session maximum age');
    assertPositiveSafeDuration(input.sessionIdleMs, 'session idle duration');

    const resources = new Set(input.resources ?? []);
    for (const resource of resources) {
      if (typeof resource.dispose !== 'function') {
        throw new TypeError('session resource is invalid');
      }
    }

    this.id = input.id;
    this.origin = input.auth.origin;
    this.audience = input.auth.audience;
    this.projectId = input.auth.projectId;
    this.credentialSubject = input.auth.subject;
    this.credentialExpiresAt = input.auth.expiresAt;
    this.createdAt = input.createdAt;
    this.sessionExpiresAt = Math.min(
      safeAdd(input.createdAt, input.sessionMaxAgeMs),
      input.auth.expiresAt,
    );
    this.sessionIdleMs = input.sessionIdleMs;
    this.signal = this.#abortController.signal;
    this.#auth = input.auth;
    this.#resources = resources;
    this.#lastSeenAt = input.createdAt;
    Object.freeze(this);
  }

  public get lastSeenAt(): number {
    return this.#lastSeenAt;
  }

  public get closed(): boolean {
    return this.#closed;
  }

  public get idleExpiresAt(): number {
    return Math.min(safeAdd(this.#lastSeenAt, this.sessionIdleMs), this.sessionExpiresAt);
  }

  public expiresAt(): number {
    return this.idleExpiresAt;
  }

  public validate(auth: AuthContext, now: number): SessionValidation {
    assertSafeTime(now, 'session validation time');
    if (this.#closed) {
      return { ok: false, code: 'SCG_SESSION_NOT_FOUND' };
    }
    if (!this.#auth.isActiveAt(now) || !auth.isActiveAt(now)) {
      return { ok: false, code: 'SCG_AUTH_EXPIRED' };
    }
    if (!this.#auth.hasSameBinding(auth)) {
      return { ok: false, code: 'SCG_SESSION_CONTEXT_MISMATCH' };
    }
    if (now >= this.expiresAt()) {
      return { ok: false, code: 'SCG_SESSION_EXPIRED' };
    }
    return { ok: true };
  }

  public touch(now: number): boolean {
    assertSafeTime(now, 'session activity time');
    if (this.#closed || now >= this.expiresAt()) {
      return false;
    }
    if (now > this.#lastSeenAt) {
      this.#lastSeenAt = now;
    }
    return true;
  }

  public addResource(resource: SessionResource): boolean {
    if (typeof resource.dispose !== 'function') {
      throw new TypeError('session resource is invalid');
    }
    if (this.#closed) {
      disposeResource(resource, 'abort');
      return false;
    }
    this.#resources.add(resource);
    return true;
  }

  /** Arms one server-owned timer for the moving idle/session deadline. */
  public armExpiry(onExpiry: () => void, now: number, nowProvider: () => number): void {
    assertSafeTime(now, 'session timer time');
    if (this.#closed) {
      return;
    }
    this.clearExpiryTimer();

    const schedule = (): void => {
      if (this.#closed) {
        return;
      }
      let current: number;
      try {
        current = nowProvider();
      } catch {
        // A broken clock must not extend credential lifetime.
        onExpiry();
        return;
      }
      if (!Number.isSafeInteger(current) || current < 0) {
        // A broken clock must not extend credential lifetime.
        onExpiry();
        return;
      }
      const remaining = this.expiresAt() - current;
      if (remaining <= 0) {
        onExpiry();
        return;
      }
      this.#expiryTimer = setTimeout(schedule, Math.min(remaining, MAX_TIMEOUT_MS));
    };

    const remaining = this.expiresAt() - now;
    if (remaining <= 0) {
      onExpiry();
      return;
    }
    this.#expiryTimer = setTimeout(schedule, Math.min(remaining, MAX_TIMEOUT_MS));
  }

  /**
   * This is intentionally idempotent. It clears the timer and all owned
   * resources after the manager removes the session from active accounting.
   */
  public close(reason: SessionCloseReason): boolean {
    if (this.#closed) {
      return false;
    }
    this.#closed = true;
    this.clearExpiryTimer();
    try {
      this.#abortController.abort(reason);
    } catch {
      // An abort listener cannot prevent the remaining cleanup.
    }
    for (const resource of this.#resources) {
      disposeResource(resource, reason);
    }
    this.#resources.clear();
    return true;
  }

  public matchesCredential(subject: CredentialSubject, digest: TokenDigest): boolean {
    return (
      this.credentialSubject.audience === subject.audience &&
      this.credentialSubject.projectId === subject.projectId &&
      this.credentialSubject.id === subject.id &&
      this.#auth.credentialDigest.equals(digest)
    );
  }

  /** Safe for generic logging; omits both session and credential identifiers. */
  public toJSON(): Readonly<{
    audience: AuthContext['audience'];
    projectId: string;
    credentialExpiresAt: number | null;
    sessionExpiresAt: number;
    lastSeenAt: number;
    closed: boolean;
  }> {
    return Object.freeze({
      audience: this.audience,
      projectId: this.projectId,
      credentialExpiresAt:
        this.credentialExpiresAt === Number.POSITIVE_INFINITY ? null : this.credentialExpiresAt,
      sessionExpiresAt: this.sessionExpiresAt,
      lastSeenAt: this.#lastSeenAt,
      closed: this.#closed,
    });
  }

  private clearExpiryTimer(): void {
    if (this.#expiryTimer !== undefined) {
      clearTimeout(this.#expiryTimer);
      this.#expiryTimer = undefined;
    }
  }
}

export function createServerSessionId(): SessionId {
  return randomBytes(32).toString('base64url') as SessionId;
}

export function isSessionId(value: unknown): value is SessionId {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

const MAX_TIMEOUT_MS = 2_147_483_647;

function assertSafeTime(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}

function assertPositiveSafeDuration(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
}

function safeAdd(left: number, right: number): number {
  return left > Number.MAX_SAFE_INTEGER - right ? Number.MAX_SAFE_INTEGER : left + right;
}

function disposeResource(resource: SessionResource, reason: SessionCloseReason): void {
  try {
    resource.dispose(reason);
  } catch {
    // Cleanup is best-effort, but no failure may retain the slot or timer.
  }
}
