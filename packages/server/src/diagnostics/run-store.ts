import { DIAGNOSTICS_AUDIENCE, type CredentialAudience } from '../auth/credential-subject.js';
import {
  type DiagnosticAuthorizationResult,
  type DiagnosticFailure,
  type DiagnosticRunCredentialInput,
  type DiagnosticsIssuer,
} from './issuer.js';
import { type DiagnosticsTeardown } from './teardown.js';

const DIAGNOSTIC_SESSION_ID_BYTES = 16;

export type DiagnosticAllowedMethod = 'notifications/initialized' | 'ping';

export type DiagnosticForbiddenMethodCode = 'SCG_DIAGNOSTIC_METHOD_FORBIDDEN';

export interface DiagnosticMethodFailure {
  readonly ok: false;
  readonly status: 403;
  readonly code: DiagnosticForbiddenMethodCode;
}

export interface DiagnosticSession {
  readonly id: string;
  readonly runId: string;
  readonly projectId: string;
  readonly origin: string;
  readonly audience: typeof DIAGNOSTICS_AUDIENCE;
  readonly expiresAt: number;
}

export interface ConsumeDiagnosticInitializeInput extends DiagnosticRunCredentialInput {
  /** Supplying any other RPC method fails before a run is consumed. */
  readonly method?: string;
}

export interface AuthorizeDiagnosticMethodInput extends DiagnosticRunCredentialInput {
  readonly sessionId: string | undefined;
  readonly method: string;
}

export interface CloseDiagnosticRunInput extends DiagnosticRunCredentialInput {
  readonly sessionId: string | undefined;
}

export interface DiagnosticSessionSuccess {
  readonly ok: true;
  readonly session: DiagnosticSession;
}

export type DiagnosticSessionFailure = DiagnosticFailure | DiagnosticMethodFailure;
export type DiagnosticSessionResult = DiagnosticSessionSuccess | DiagnosticSessionFailure;

export interface DiagnosticRunStoreOptions {
  /** Injectable only to make generated diagnostic session IDs deterministic. */
  readonly random?: (byteLength: number) => Uint8Array;
}

/**
 * Holds the single session created by each consumed diagnostic credential. It
 * deliberately has no annotation, export, or general MCP dispatch entrypoint.
 */
export class DiagnosticRunStore {
  readonly #sessionsById = new Map<string, DiagnosticSession>();
  readonly #issuer: DiagnosticsIssuer;
  readonly #teardown: DiagnosticsTeardown;
  readonly #random: (byteLength: number) => Uint8Array;

  public constructor(
    issuer: DiagnosticsIssuer,
    teardown: DiagnosticsTeardown,
    options: DiagnosticRunStoreOptions = {},
  ) {
    this.#issuer = issuer;
    this.#teardown = teardown;
    this.#random = options.random ?? defaultRandom;
  }

  public get activeSessionCount(): number {
    return this.#sessionsById.size;
  }

  public isEmpty(): boolean {
    return this.#sessionsById.size === 0;
  }

  /** Useful for server-shutdown and integration-test zero-count assertions. */
  public assertEmpty(): void {
    if (!this.isEmpty()) {
      throw new Error('diagnostic run store still has active sessions');
    }
  }
  /**
   * Identifies a bound diagnostic capability before its lifecycle method is
   * selected, without retaining the bearer beyond the current request.
   */
  public authenticate(input: DiagnosticRunCredentialInput): DiagnosticAuthorizationResult {
    return this.#issuer.authenticate(input);
  }

  public recognizesCredential(token: string): boolean {
    return this.#issuer.recognizesCredential(token);
  }

  /**
   * The only operation that can consume an issued capability. No await point
   * occurs between checking the issued status, generating an ID, and changing
   * it to initialized, making first-initialize consumption atomic in-process.
   */
  public consumeInitialize(input: ConsumeDiagnosticInitializeInput): DiagnosticSessionResult {
    if (input.method !== undefined && input.method !== 'initialize') {
      return methodFailure();
    }

    const authorized = this.#issuer.authenticate(input);
    if (!authorized.ok) {
      return authorized;
    }
    if (authorized.record.status !== 'issued') {
      return diagnosticFailure('SCG_DIAGNOSTIC_REUSED');
    }

    const session = this.createSession(authorized.record);

    const consumed = this.#issuer.consume(authorized.record.runId);
    if (!consumed.ok) {
      return consumed;
    }

    const initializedSession = Object.freeze({
      ...session,
      expiresAt: consumed.record.expiresAt,
    });
    this.#sessionsById.set(initializedSession.id, initializedSession);
    const registered = this.#teardown.addCleanup(initializedSession.runId, () => {
      if (this.#sessionsById.get(initializedSession.id) === initializedSession) {
        this.#sessionsById.delete(initializedSession.id);
      }
    });
    if (!registered) {
      this.#sessionsById.delete(initializedSession.id);
      return diagnosticFailure('SCG_DIAGNOSTIC_EXPIRED');
    }

    return Object.freeze({ ok: true, session: initializedSession });
  }

  /**
   * Authorizes only the two diagnostics notifications. Every tools, annotation,
   * export, or other MCP method is rejected before a caller can dispatch it.
   */
  public authorizeMethod(input: AuthorizeDiagnosticMethodInput): DiagnosticSessionResult {
    if (!isAllowedDiagnosticMethod(input.method)) {
      return methodFailure();
    }
    return this.authorizeSession(input);
  }

  /** Authenticates the DELETE close path and centrally releases the run. */
  public close(input: CloseDiagnosticRunInput): DiagnosticSessionResult {
    const authorized = this.authorizeSession(input);
    if (!authorized.ok) {
      return authorized;
    }
    if (!this.#teardown.close(authorized.session.runId)) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }
    return authorized;
  }

  /** Server-owned disconnect cleanup needs no bearer re-verification. */
  public abort(sessionId: string | undefined): boolean {
    if (sessionId === undefined) {
      return false;
    }
    const session = this.#sessionsById.get(sessionId);
    return session === undefined ? false : this.#teardown.abort(session.runId);
  }

  public revoke(runId: string): boolean {
    return this.#teardown.revoke(runId);
  }

  public shutdown(): number {
    return this.#teardown.shutdown();
  }

  private authorizeSession(
    input: DiagnosticRunCredentialInput & { readonly sessionId: string | undefined },
  ): DiagnosticSessionResult {
    if (input.sessionId === undefined || !isDiagnosticSessionId(input.sessionId)) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }
    const session = this.#sessionsById.get(input.sessionId);
    if (session === undefined) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }

    const authorized = this.#issuer.authenticate(input);
    if (!authorized.ok) {
      return authorized;
    }
    if (
      authorized.record.status !== 'initialized' ||
      authorized.record.runId !== session.runId ||
      session.projectId !== input.projectId ||
      session.origin !== input.origin ||
      session.audience !== input.audience
    ) {
      return diagnosticFailure('SCG_DIAGNOSTIC_INVALID');
    }
    return Object.freeze({ ok: true, session });
  }

  private createSession(record: {
    readonly runId: string;
    readonly projectId: string;
    readonly origin: string;
    readonly aud: CredentialAudience;
    readonly expiresAt: number;
  }): DiagnosticSession {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const bytes = this.#random(DIAGNOSTIC_SESSION_ID_BYTES);
      if (!(bytes instanceof Uint8Array) || bytes.byteLength !== DIAGNOSTIC_SESSION_ID_BYTES) {
        throw new TypeError('diagnostic random source returned an invalid byte sequence');
      }
      const id = `diagnostic-session-${Buffer.from(bytes).toString('base64url')}`;
      if (!this.#sessionsById.has(id)) {
        return Object.freeze({
          id,
          runId: record.runId,
          projectId: record.projectId,
          origin: record.origin,
          audience: DIAGNOSTICS_AUDIENCE,
          expiresAt: record.expiresAt,
        });
      }
    }
    throw new Error('diagnostic random source produced a duplicate session id');
  }
}

function isAllowedDiagnosticMethod(value: string): value is DiagnosticAllowedMethod {
  return value === 'notifications/initialized' || value === 'ping';
}

function methodFailure(): DiagnosticMethodFailure {
  return {
    ok: false,
    status: 403,
    code: 'SCG_DIAGNOSTIC_METHOD_FORBIDDEN',
  };
}

function diagnosticFailure(
  code: Extract<
    DiagnosticFailure['code'],
    'SCG_DIAGNOSTIC_INVALID' | 'SCG_DIAGNOSTIC_REUSED' | 'SCG_DIAGNOSTIC_EXPIRED'
  >,
): DiagnosticFailure {
  return { ok: false, status: 401, code };
}

function isDiagnosticSessionId(value: string): boolean {
  return /^diagnostic-session-[A-Za-z0-9_-]{22}$/.test(value);
}

function defaultRandom(byteLength: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
}
