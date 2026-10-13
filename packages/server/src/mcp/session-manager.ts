import type { AuthContext } from '../auth/auth-context.js';
import type { CredentialSubject } from '../auth/credential-subject.js';
import type { TokenDigest } from '../auth/local-token-verifier.js';
import {
  createServerSessionId,
  isSessionId,
  type SessionCloseReason,
  type SessionId,
  type SessionRecord,
  type SessionResource,
  type SessionValidationFailureCode,
  SessionRecord as SessionRecordValue,
} from './session-record.js';

export type SessionLookupMethod = 'POST' | 'GET' | 'DELETE';

export type SessionFailureCode =
  | SessionValidationFailureCode
  | 'SCG_SESSION_LIMIT_PROJECT'
  | 'SCG_SESSION_LIMIT_GLOBAL'
  | 'SCG_SESSION_SHUTDOWN';

export interface SessionFailure {
  readonly ok: false;
  readonly status: 401 | 403 | 404 | 429 | 503;
  readonly code: SessionFailureCode;
}

export interface SessionSuccess {
  readonly ok: true;
  readonly session: SessionRecord;
}

export type SessionInitializeResult = SessionSuccess | SessionFailure;
export type SessionLookupResult = SessionSuccess | SessionFailure;

export interface SessionManagerOptions {
  /** Test-only clock injection; production uses the system epoch clock. */
  readonly now?: () => number;
}

export interface SessionInitializeInput {
  readonly auth: AuthContext;
  readonly normalSessionsPerProject: number;
  readonly normalSessionsGlobal: number;
  readonly sessionMaxAgeMs: number;
  readonly sessionIdleMs: number;
  readonly resources?: readonly SessionResource[];
  /** Cancels admission before it can reserve a quota slot. */
  readonly signal?: AbortSignal;
}

export interface SessionCommitInput {
  readonly auth: AuthContext;
  readonly sessionId: string | undefined;
  /** Cancels promotion of a provisional session. */
  readonly signal?: AbortSignal;
}

export interface SessionLookupInput {
  readonly sessionId: string | undefined;
  readonly auth: AuthContext;
  readonly method: SessionLookupMethod;
  /** Cancels validation before it can refresh session activity. */
  readonly signal?: AbortSignal;
}

export interface SessionTeardownResult {
  readonly tornDown: boolean;
  readonly reason: SessionCloseReason;
}

/**
 * Owns all normal MCP sessions and their accounting slots. The initialize API
 * intentionally has no session-id input, preventing client-driven fixation.
 */
export class SessionManager {
  readonly #sessions = new Map<SessionId, SessionRecord>();
  readonly #provisionalSessions = new Map<SessionId, SessionRecord>();
  readonly #projectCounts = new Map<string, number>();
  readonly #now: () => number;
  #shutDown = false;

  public constructor(options: SessionManagerOptions = {}) {
    this.#now = options.now ?? Date.now;
  }

  public get activeSessionCount(): number {
    return this.#sessions.size + this.#provisionalSessions.size;
  }

  public get shutDown(): boolean {
    return this.#shutDown;
  }

  public sessionCountForProject(projectId: string): number {
    return this.#projectCounts.get(projectId) ?? 0;
  }

  public isEmpty(): boolean {
    return (
      this.#sessions.size === 0 &&
      this.#provisionalSessions.size === 0 &&
      this.#projectCounts.size === 0
    );
  }

  /** Useful for shutdown and integration-test zero-count assertions. */
  public assertEmpty(): void {
    if (!this.isEmpty()) {
      throw new Error('session manager still has active sessions');
    }
  }

  /**
   * Reserves a quota slot and creates an unaddressable session. Call commit()
   * only after the initialize response has been written successfully.
   */
  public initialize(input: SessionInitializeInput): SessionInitializeResult {
    input.signal?.throwIfAborted();
    const now = this.readNow();
    assertPositiveSafeInteger(input.normalSessionsPerProject, 'project session limit');
    assertPositiveSafeInteger(input.normalSessionsGlobal, 'global session limit');
    assertPositiveSafeInteger(input.sessionMaxAgeMs, 'session maximum age');
    assertPositiveSafeInteger(input.sessionIdleMs, 'session idle duration');

    if (this.#shutDown) {
      return sessionFailure('SCG_SESSION_SHUTDOWN');
    }
    if (!input.auth.isActiveAt(now)) {
      return sessionFailure('SCG_AUTH_EXPIRED');
    }

    // Check all caps before creating an ID, record, timer, or resource slot.
    if (this.activeSessionCount >= input.normalSessionsGlobal) {
      return sessionFailure('SCG_SESSION_LIMIT_GLOBAL');
    }
    if (this.sessionCountForProject(input.auth.projectId) >= input.normalSessionsPerProject) {
      return sessionFailure('SCG_SESSION_LIMIT_PROJECT');
    }

    input.signal?.throwIfAborted();
    const id = this.nextSessionId();
    const session = new SessionRecordValue({
      id,
      auth: input.auth,
      createdAt: now,
      sessionMaxAgeMs: input.sessionMaxAgeMs,
      sessionIdleMs: input.sessionIdleMs,
      ...(input.resources === undefined ? {} : { resources: input.resources }),
    });

    this.#provisionalSessions.set(id, session);
    this.incrementProjectCount(session.projectId);
    session.armExpiry(
      () => {
        this.teardownRecord(session, 'session-expired');
      },
      now,
      this.#now,
    );

    if (this.#provisionalSessions.get(id) !== session) {
      return sessionFailure('SCG_SESSION_EXPIRED');
    }
    return { ok: true, session };
  }

  /** Promotes a successful initialize reservation to a client-addressable session. */
  public commit(input: SessionCommitInput): SessionInitializeResult {
    input.signal?.throwIfAborted();
    const now = this.readNow();
    if (input.sessionId === undefined || !isSessionId(input.sessionId)) {
      return sessionFailure('SCG_SESSION_NOT_FOUND');
    }

    const session = this.#provisionalSessions.get(input.sessionId);
    if (session === undefined) {
      return sessionFailure('SCG_SESSION_NOT_FOUND');
    }

    const validation = session.validate(input.auth, now);
    if (!validation.ok) {
      this.teardownRecord(session, closeReasonFor(validation.code));
      return sessionFailure(validation.code);
    }

    input.signal?.throwIfAborted();
    if (this.#provisionalSessions.get(session.id) !== session) {
      return sessionFailure('SCG_SESSION_NOT_FOUND');
    }
    this.#provisionalSessions.delete(session.id);
    this.#sessions.set(session.id, session);
    return { ok: true, session };
  }

  /**
   * Revalidates the full session binding for every POST, GET, and DELETE.
   * This method is validation-only; an admitted DELETE calls close() separately.
   */
  public lookup(input: SessionLookupInput): SessionLookupResult {
    input.signal?.throwIfAborted();
    const now = this.readNow();
    if (!isSessionLookupMethod(input.method)) {
      throw new TypeError('session lookup method is invalid');
    }
    if (input.sessionId === undefined || !isSessionId(input.sessionId)) {
      return sessionFailure('SCG_SESSION_NOT_FOUND');
    }

    const session = this.#sessions.get(input.sessionId);
    if (session === undefined) {
      return sessionFailure('SCG_SESSION_NOT_FOUND');
    }

    const validation = session.validate(input.auth, now);
    if (!validation.ok) {
      this.teardownRecord(session, closeReasonFor(validation.code));
      return sessionFailure(validation.code);
    }

    if (input.method === 'DELETE') {
      return { ok: true, session };
    }

    input.signal?.throwIfAborted();
    if (!session.touch(now)) {
      this.teardownRecord(session, 'session-expired');
      return sessionFailure('SCG_SESSION_EXPIRED');
    }
    session.armExpiry(
      () => {
        this.teardownRecord(session, 'session-expired');
      },
      now,
      this.#now,
    );
    return { ok: true, session };
  }

  /** Idempotently closes an authenticated session at the client’s request. */
  public close(sessionId: string | undefined, signal?: AbortSignal): SessionTeardownResult {
    signal?.throwIfAborted();
    return this.teardown(sessionId, 'client-close');
  }

  /** Use for a client disconnect or an in-flight request cancellation. */
  public abort(sessionId: string | undefined): SessionTeardownResult {
    return this.teardown(sessionId, 'abort');
  }

  /** Use when an issuer revokes a credential without waiting for its expiry. */
  public revokeCredential(subject: CredentialSubject, digest: TokenDigest): number {
    let count = 0;
    for (const session of [...this.#sessions.values(), ...this.#provisionalSessions.values()]) {
      if (session.matchesCredential(subject, digest)) {
        if (this.teardownRecord(session, 'revoked')) {
          count += 1;
        }
      }
    }
    return count;
  }

  /** Shutdown is final: it rejects future initialization and drains all state. */
  public shutdown(): number {
    if (this.#shutDown) {
      return 0;
    }
    this.#shutDown = true;
    let count = 0;
    for (const session of [...this.#sessions.values(), ...this.#provisionalSessions.values()]) {
      if (this.teardownRecord(session, 'shutdown')) {
        count += 1;
      }
    }
    return count;
  }

  /**
   * Idempotent internal or trusted-lifecycle teardown. HTTP DELETE must use
   * lookup() so its caller is authenticated before reaching this method.
   */
  public teardown(
    sessionId: string | undefined,
    reason: SessionCloseReason,
  ): SessionTeardownResult {
    if (sessionId === undefined || !isSessionId(sessionId)) {
      return { tornDown: false, reason };
    }
    const session = this.#sessions.get(sessionId) ?? this.#provisionalSessions.get(sessionId);
    if (session === undefined) {
      return { tornDown: false, reason };
    }
    return { tornDown: this.teardownRecord(session, reason), reason };
  }

  private nextSessionId(): SessionId {
    let id = createServerSessionId();
    while (this.#sessions.has(id) || this.#provisionalSessions.has(id)) {
      id = createServerSessionId();
    }
    return id;
  }

  private teardownRecord(session: SessionRecord, reason: SessionCloseReason): boolean {
    const isCommitted = this.#sessions.get(session.id) === session;
    const isProvisional = this.#provisionalSessions.get(session.id) === session;
    if (!isCommitted && !isProvisional) {
      return false;
    }
    if (isCommitted) {
      this.#sessions.delete(session.id);
    } else {
      this.#provisionalSessions.delete(session.id);
    }
    this.decrementProjectCount(session.projectId);
    session.close(reason);
    return true;
  }

  private incrementProjectCount(projectId: string): void {
    this.#projectCounts.set(projectId, this.sessionCountForProject(projectId) + 1);
  }

  private decrementProjectCount(projectId: string): void {
    const next = this.sessionCountForProject(projectId) - 1;
    if (next <= 0) {
      this.#projectCounts.delete(projectId);
    } else {
      this.#projectCounts.set(projectId, next);
    }
  }

  private readNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('session clock must return a non-negative safe integer');
    }
    return now;
  }
}

function isSessionLookupMethod(value: string): value is SessionLookupMethod {
  return value === 'POST' || value === 'GET' || value === 'DELETE';
}

function sessionFailure(code: SessionFailureCode): SessionFailure {
  switch (code) {
    case 'SCG_AUTH_EXPIRED':
    case 'SCG_SESSION_EXPIRED':
      return { ok: false, status: 401, code };
    case 'SCG_SESSION_CONTEXT_MISMATCH':
      return { ok: false, status: 403, code };
    case 'SCG_SESSION_NOT_FOUND':
      return { ok: false, status: 404, code };
    case 'SCG_SESSION_LIMIT_PROJECT':
    case 'SCG_SESSION_LIMIT_GLOBAL':
      return { ok: false, status: 429, code };
    case 'SCG_SESSION_SHUTDOWN':
      return { ok: false, status: 503, code };
  }
}

function closeReasonFor(code: SessionValidationFailureCode): SessionCloseReason {
  switch (code) {
    case 'SCG_AUTH_EXPIRED':
      return 'auth-expired';
    case 'SCG_SESSION_EXPIRED':
      return 'session-expired';
    case 'SCG_SESSION_CONTEXT_MISMATCH':
      return 'context-mismatch';
    case 'SCG_SESSION_NOT_FOUND':
      return 'abort';
  }
}

function assertPositiveSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
}
