import { isProjectId } from '@scene-glass/contracts';
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';

import type { AuthContext } from '../auth/auth-context.js';
import { DIAGNOSTICS_AUDIENCE, SCENE_GLASS_AUDIENCE } from '../auth/credential-subject.js';
import {
  parseBearer,
  type AuthVerificationResult,
  type VerifyBearerInput,
} from '../auth/local-token-verifier.js';
import type {
  SessionInitializeInput,
  SessionInitializeResult,
  SessionLookupInput,
  SessionLookupResult,
} from '../mcp/session-manager.js';
import type { SessionRecord } from '../mcp/session-record.js';
import type { DiagnosticRunStore } from '../diagnostics/run-store.js';
import {
  createMcpDispatcher as createStrictMcpDispatcher,
  MCP_PROTOCOL_VERSION,
  type McpDispatcher as StrictMcpDispatcher,
} from '../mcp/dispatcher.js';
import type {
  AuthorizedProject,
  ProjectRegistry,
  RequestAdmissionProject,
} from '../registry/config-project-registry.js';
import type { SceneGlassLogger, SceneGlassTerminalOutcome } from '../observability/logger.js';
import {
  assertDeclaredBodyWithinLimit,
  assertJsonMediaType,
  bodyFailureKind,
  parsedJsonBody,
} from './body-parser.js';
import {
  isAllowedCorsPreflight,
  isAllowedOrigin,
  readCorsPreflightRequest,
  sendCorsPreflight,
  sendOriginDenied,
  singleHeader,
} from './cors.js';
import {
  sendAcceptedNotification,
  sendBodyFailure,
  sendInvalidRpc,
  sendJsonRpc,
  sendNoContent,
  sendProblem,
  type JsonRpcId,
} from './wire-errors.js';

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const MCP_ROUTE_URL = '/mcp/v1/projects/:projectId';

export interface McpJsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly method: string;
  readonly id?: JsonRpcId;
  readonly params?: unknown;
}

export interface McpDispatcherInput {
  readonly auth: AuthContext;
  readonly message: McpJsonRpcRequest;
  readonly project: AuthorizedProject;
  readonly session: SessionRecord;
  readonly signal: AbortSignal;
}

/** The HTTP layer owns no tools or storage and only invokes this boundary. */
export interface McpDispatcher {
  dispatch(input: McpDispatcherInput): Promise<unknown | undefined> | unknown | undefined;
}

export interface McpBearerVerifier {
  verify(
    input: VerifyBearerInput & Readonly<{ signal?: AbortSignal }>,
  ): Promise<AuthVerificationResult> | AuthVerificationResult;
}

export interface McpSessionGateway {
  initialize(
    input: SessionInitializeInput,
  ): Promise<SessionInitializeResult> | SessionInitializeResult;
  commit(input: {
    readonly auth: AuthContext;
    readonly sessionId: string | undefined;
    readonly signal?: AbortSignal;
  }): Promise<SessionInitializeResult> | SessionInitializeResult;
  lookup(input: SessionLookupInput): Promise<SessionLookupResult> | SessionLookupResult;
  /** Server-owned cleanup for an authenticated in-flight session. */
  abort(sessionId: string | undefined): unknown;
  /** Client close after route authentication, authorization, and admission. */
  close(sessionId: string, signal?: AbortSignal): Promise<unknown> | unknown;
}

export interface McpScopeAuthorizer {
  allows(input: {
    readonly auth: AuthContext;
    readonly operation: 'delete' | 'get' | 'post';
    readonly project: AuthorizedProject;
    readonly signal?: AbortSignal;
  }): Promise<boolean> | boolean;
}

export interface McpRouteOptions {
  readonly dispatcher: McpDispatcher;
  readonly diagnosticRunStore?: Pick<
    DiagnosticRunStore,
    | 'abort'
    | 'authenticate'
    | 'authorizeMethod'
    | 'close'
    | 'consumeInitialize'
    | 'recognizesCredential'
  >;
  readonly maxBodyBytes: number;
  readonly now?: () => number;
  readonly requestTimeoutMs?: number;
  readonly logger: SceneGlassLogger;
  readonly registry: ProjectRegistry;
  readonly scopeAuthorizer?: McpScopeAuthorizer;
  readonly sessions: McpSessionGateway;
  readonly verifier: McpBearerVerifier;
}

interface McpRequestContextBase {
  readonly origin: string;
  readonly projectId: string;
  readonly protocolVersion: typeof MCP_PROTOCOL_VERSION | undefined;
}

interface NormalMcpRequestContext extends McpRequestContextBase {
  readonly kind: 'normal';
  readonly auth: AuthContext;
  readonly session: SessionRecord | undefined;
}

interface DiagnosticMcpRequestContext extends McpRequestContextBase {
  readonly kind: 'diagnostic';
  readonly runStore: NonNullable<McpRouteOptions['diagnosticRunStore']>;
  readonly token: string;
}
type McpRequestContext = DiagnosticMcpRequestContext | NormalMcpRequestContext;

type McpTerminalStage =
  | 'admission-rejected'
  | 'authentication-rejected'
  | 'disconnect'
  | 'handler-error'
  | 'json-rpc-error'
  | 'origin-rejected'
  | 'protocol-rejected'
  | 'request-timeout'
  | 'scope-rejected'
  | 'success';
interface McpRequestAdmissionState {
  global: number;
  readonly projects: Map<string, number>;
}

type McpRequestAdmission =
  | {
      readonly ok: false;
      readonly code: 'SCG_REQUEST_LIMIT_GLOBAL' | 'SCG_REQUEST_LIMIT_PROJECT';
    }
  | {
      readonly ok: true;
      release(): void;
    };

/**
 * Streamable-MCP HTTP transport. Its onRequest hook deliberately authenticates
 * before Fastify invokes the JSON content-type parser.
 */
export const mcpRoute: FastifyPluginAsync<McpRouteOptions> = async (fastify, options) => {
  assertRouteOptions(options);
  const contexts = new WeakMap<FastifyRequest, McpRequestContext>();
  const allowedOrigins = new WeakMap<FastifyRequest, string>();
  const lifecycles = new WeakMap<FastifyRequest, McpRequestLifecycle>();
  const requestAdmissions: McpRequestAdmissionState = {
    global: 0,
    projects: new Map<string, number>(),
  };
  const diagnosticProtocols = new DiagnosticProtocolSessions(options.now ?? Date.now);

  const beginRequest = (request: FastifyRequest, reply: FastifyReply): McpRequestLifecycle => {
    const lifecycle = createMcpRequestLifecycle(request, reply, options, diagnosticProtocols);
    lifecycles.set(request, lifecycle);
    diagnosticProtocols.prune();
    lifecycle.armDeadline(options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);
    return lifecycle;
  };

  fastify.setErrorHandler((error, request, reply) => {
    const lifecycle = lifecycles.get(request);
    const origin =
      contexts.get(request)?.origin ??
      allowedOrigins.get(request) ??
      allowedOriginFromRequest(request, options.registry);
    if (lifecycle === undefined) {
      return sendProblem(reply, origin, 500, 'SCG_HTTP_INTERNAL');
    }
    if (finishIfAborted(lifecycle, reply, origin)) {
      return;
    }
    const failure = bodyFailureKind(error);
    if (failure !== undefined) {
      return sendMcpBodyFailure(lifecycle, reply, origin, failure);
    }
    return sendMcpProblem(lifecycle, reply, origin, 500, 'SCG_HTTP_INTERNAL', 'handler-error');
  });

  fastify.options(
    MCP_ROUTE_URL,
    {
      onRequest: async (request, reply) => {
        beginRequest(request, reply);
      },
    },
    async (request, reply) => {
      const lifecycle = lifecycles.get(request);
      if (lifecycle === undefined) {
        return sendProblem(reply, undefined, 500, 'SCG_HTTP_CONTEXT_MISSING');
      }
      if (finishIfAborted(lifecycle, reply, undefined)) {
        return;
      }
      const projectId = projectIdFromRequest(request);
      const policy =
        projectId === undefined ? undefined : options.registry.getOriginPolicy(projectId);
      const preflight = readCorsPreflightRequest(request.headers);
      if (!isAllowedOrigin(policy, preflight.origin)) {
        lifecycle.recordOriginRejected();
        return sendMcpResponse(lifecycle, reply, 'failure', 'origin-rejected', () =>
          sendOriginDenied(reply),
        );
      }
      if (!isAllowedCorsPreflight('mcp', preflight)) {
        return sendMcpProblem(
          lifecycle,
          reply,
          preflight.origin,
          400,
          'SCG_CORS_PREFLIGHT_INVALID',
          'protocol-rejected',
        );
      }
      return sendMcpResponse(lifecycle, reply, 'success', 'success', () =>
        sendCorsPreflight(reply, 'mcp', preflight),
      );
    },
  );

  fastify.post(
    MCP_ROUTE_URL,
    {
      bodyLimit: options.maxBodyBytes,
      onRequest: async (request, reply) => {
        const lifecycle = beginRequest(request, reply);
        await establishMcpContext(
          request,
          reply,
          options,
          contexts,
          allowedOrigins,
          lifecycle,
          requestAdmissions,
          'POST',
        );
      },
    },
    async (request, reply) => {
      const lifecycle = lifecycles.get(request);
      const context = contexts.get(request);
      if (lifecycle === undefined) {
        return sendProblem(reply, undefined, 500, 'SCG_HTTP_CONTEXT_MISSING');
      }
      if (finishIfAborted(lifecycle, reply, context?.origin)) {
        return;
      }
      if (context === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          undefined,
          500,
          'SCG_HTTP_CONTEXT_MISSING',
          'handler-error',
        );
      }

      if (context.kind === 'diagnostic') {
        return sendDiagnosticPost(request, reply, context, lifecycle, diagnosticProtocols);
      }

      lifecycle.bindNormalSession(context.session?.id);
      const project = options.registry.resolveAuthorizedProject(context.auth);
      if (project === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_PROJECT_FORBIDDEN',
          'authentication-rejected',
        );
      }
      lifecycle.tightenDeadline(project.effectiveLimits.requestTimeoutMs);
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      const message = parseMcpJsonRpc(parsedJsonBody(request));
      if (message === undefined) {
        return sendMcpResponse(lifecycle, reply, 'failure', 'protocol-rejected', () =>
          sendInvalidRpc(reply, context.origin),
        );
      }
      const scope = await allowsScope(
        options.scopeAuthorizer,
        context.auth,
        project,
        'post',
        lifecycle.signal,
      );
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      if (scope === 'failed') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          500,
          'SCG_SCOPE_AUTHORIZER_FAILED',
          'handler-error',
        );
      }
      if (scope === 'denied') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_SCOPE_FORBIDDEN',
          'scope-rejected',
        );
      }
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }

      const admission = admitMcpRequest(requestAdmissions, project);
      if (!admission.ok) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          429,
          admission.code,
          'admission-rejected',
        );
      }
      let session = context.session;
      let ownedSession = false;
      try {
        if (session === undefined) {
          if (message.method !== 'initialize' || message.id === undefined) {
            return sendMcpProblem(
              lifecycle,
              reply,
              context.origin,
              404,
              'SCG_SESSION_NOT_FOUND',
              'protocol-rejected',
            );
          }
          if (!hasConsistentInitializeProtocol(message, context.protocolVersion)) {
            return sendMcpProblem(
              lifecycle,
              reply,
              context.origin,
              400,
              'SCG_MCP_PROTOCOL_VERSION',
              'protocol-rejected',
            );
          }

          const initialized = await options.sessions.initialize({
            auth: context.auth,
            normalSessionsPerProject: project.effectiveLimits.normalSessionsPerProject,
            normalSessionsGlobal: project.effectiveLimits.normalSessionsGlobal,
            sessionMaxAgeMs: project.effectiveLimits.sessionMaxAgeMs,
            sessionIdleMs: project.effectiveLimits.sessionIdleMs,
            signal: lifecycle.signal,
          });
          if (!initialized.ok) {
            if (finishIfAborted(lifecycle, reply, context.origin)) {
              return;
            }
            return sendMcpProblem(
              lifecycle,
              reply,
              context.origin,
              initialized.status,
              initialized.code,
              'protocol-rejected',
            );
          }
          session = initialized.session;
          ownedSession = true;
          lifecycle.bindProvisionalNormalSession(session.id);
          if (finishIfAborted(lifecycle, reply, context.origin)) {
            return;
          }
        }

        const response = await options.dispatcher.dispatch({
          auth: context.auth,
          message,
          project,
          session,
          signal: lifecycle.signal,
        });
        if (finishIfAborted(lifecycle, reply, context.origin)) {
          return;
        }
        if (message.id === undefined) {
          if (response !== undefined) {
            return sendMcpProblem(
              lifecycle,
              reply,
              context.origin,
              500,
              'SCG_MCP_RESPONSE_INVALID',
              'handler-error',
            );
          }
          return sendMcpResponse(lifecycle, reply, 'success', 'success', () =>
            sendAcceptedNotification(reply, context.origin),
          );
        }

        const envelope = validateJsonRpcResponse(message, response);
        if (envelope === 'invalid') {
          return sendMcpProblem(
            lifecycle,
            reply,
            context.origin,
            500,
            'SCG_MCP_RESPONSE_INVALID',
            'handler-error',
          );
        }
        if (
          !ownedSession ||
          envelope !== 'result' ||
          !isSuccessfulInitializeResponse(response, context.protocolVersion)
        ) {
          return sendMcpJsonRpcResponse(lifecycle, reply, context.origin, response);
        }

        reply.header('mcp-session-id', session.id);
        reply.header('access-control-expose-headers', 'mcp-session-id');
        let written: FastifyReply | undefined;
        try {
          written = writeMcpJsonRpcResponse(lifecycle, reply, context.origin, response);
        } catch (error) {
          reply.removeHeader('mcp-session-id');
          reply.removeHeader('access-control-expose-headers');
          throw error;
        }
        if (written === undefined) {
          return;
        }

        let committed: SessionInitializeResult;
        try {
          committed = await options.sessions.commit({
            auth: context.auth,
            sessionId: session.id,
            signal: lifecycle.signal,
          });
        } catch {
          if (finishIfAborted(lifecycle, reply, context.origin)) {
            return written;
          }
          lifecycle.terminal('failure', 'handler-error');
          lifecycle.complete();
          return written;
        }
        if (finishIfAborted(lifecycle, reply, context.origin)) {
          return written;
        }
        if (!committed.ok) {
          lifecycle.terminal('failure', 'handler-error');
          lifecycle.complete();
          return written;
        }

        ownedSession = false;
        lifecycle.commitNormalSession();
        lifecycle.terminal('success', 'success');
        lifecycle.complete();
        return written;
      } finally {
        try {
          if (ownedSession) {
            lifecycle.abortProvisionalNormalSession();
          }
        } finally {
          admission.release();
        }
      }
    },
  );

  fastify.get(
    MCP_ROUTE_URL,
    {
      onRequest: async (request, reply) => {
        const lifecycle = beginRequest(request, reply);
        await establishMcpContext(
          request,
          reply,
          options,
          contexts,
          allowedOrigins,
          lifecycle,
          requestAdmissions,
          'GET',
        );
      },
    },
    async (request, reply) => {
      const lifecycle = lifecycles.get(request);
      const context = contexts.get(request);
      if (lifecycle === undefined) {
        return sendProblem(reply, undefined, 500, 'SCG_HTTP_CONTEXT_MISSING');
      }
      if (finishIfAborted(lifecycle, reply, context?.origin)) {
        return;
      }
      if (context === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          undefined,
          500,
          'SCG_HTTP_CONTEXT_MISSING',
          'handler-error',
        );
      }
      if (context.kind === 'diagnostic') {
        return sendDiagnosticGet(reply, context, lifecycle);
      }

      lifecycle.bindNormalSession(context.session?.id);
      const project = options.registry.resolveAuthorizedProject(context.auth);
      if (project === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_PROJECT_FORBIDDEN',
          'authentication-rejected',
        );
      }
      lifecycle.tightenDeadline(project.effectiveLimits.requestTimeoutMs);
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      const scope = await allowsScope(
        options.scopeAuthorizer,
        context.auth,
        project,
        'get',
        lifecycle.signal,
      );
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      if (scope === 'failed') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          500,
          'SCG_SCOPE_AUTHORIZER_FAILED',
          'handler-error',
        );
      }
      if (scope === 'denied') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_SCOPE_FORBIDDEN',
          'scope-rejected',
        );
      }
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }

      const admission = admitMcpRequest(requestAdmissions, project);
      if (!admission.ok) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          429,
          admission.code,
          'admission-rejected',
        );
      }
      try {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          405,
          'SCG_MCP_GET_UNSUPPORTED',
          'protocol-rejected',
        );
      } finally {
        admission.release();
      }
    },
  );

  fastify.delete(
    MCP_ROUTE_URL,
    {
      onRequest: async (request, reply) => {
        const lifecycle = beginRequest(request, reply);
        await establishMcpContext(
          request,
          reply,
          options,
          contexts,
          allowedOrigins,
          lifecycle,
          requestAdmissions,
          'DELETE',
        );
      },
    },
    async (request, reply) => {
      const lifecycle = lifecycles.get(request);
      const context = contexts.get(request);
      if (lifecycle === undefined) {
        return sendProblem(reply, undefined, 500, 'SCG_HTTP_CONTEXT_MISSING');
      }
      if (finishIfAborted(lifecycle, reply, context?.origin)) {
        return;
      }
      if (context === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          undefined,
          500,
          'SCG_HTTP_CONTEXT_MISSING',
          'handler-error',
        );
      }
      if (context.kind === 'diagnostic') {
        return sendDiagnosticClose(request, reply, context, lifecycle, diagnosticProtocols);
      }

      lifecycle.bindNormalSession(context.session?.id);
      if (context.session === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          404,
          'SCG_SESSION_NOT_FOUND',
          'protocol-rejected',
        );
      }
      const project = options.registry.resolveAuthorizedProject(context.auth);
      if (project === undefined) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_PROJECT_FORBIDDEN',
          'authentication-rejected',
        );
      }
      lifecycle.tightenDeadline(project.effectiveLimits.requestTimeoutMs);
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      const scope = await allowsScope(
        options.scopeAuthorizer,
        context.auth,
        project,
        'delete',
        lifecycle.signal,
      );
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }
      if (scope === 'failed') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          500,
          'SCG_SCOPE_AUTHORIZER_FAILED',
          'handler-error',
        );
      }
      if (scope === 'denied') {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          403,
          'SCG_SCOPE_FORBIDDEN',
          'scope-rejected',
        );
      }
      if (finishIfAborted(lifecycle, reply, context.origin)) {
        return;
      }

      const admission = admitMcpRequest(requestAdmissions, project);
      if (!admission.ok) {
        return sendMcpProblem(
          lifecycle,
          reply,
          context.origin,
          429,
          admission.code,
          'admission-rejected',
        );
      }
      try {
        await options.sessions.close(context.session.id, lifecycle.signal);
        if (finishIfAborted(lifecycle, reply, context.origin)) {
          return;
        }
        return sendMcpResponse(lifecycle, reply, 'success', 'success', () =>
          sendNoContent(reply, context.origin),
        );
      } finally {
        admission.release();
      }
    },
  );
};

/**
 * Diagnostic admission is acquired during onRequest, before transport or body
 * processing. The request lifecycle owns the lease through every terminal path.
 */
async function sendDiagnosticPost(
  request: FastifyRequest,
  reply: FastifyReply,
  context: DiagnosticMcpRequestContext,
  lifecycle: McpRequestLifecycle,
  protocols: DiagnosticProtocolSessions,
): Promise<FastifyReply | undefined> {
  const message = parseMcpJsonRpc(parsedJsonBody(request));
  if (message === undefined) {
    return sendMcpResponse(lifecycle, reply, 'failure', 'protocol-rejected', () =>
      sendInvalidRpc(reply, context.origin),
    );
  }
  return sendDiagnosticPostMessage(request, reply, context, message, lifecycle, protocols);
}
async function sendDiagnosticGet(
  reply: FastifyReply,
  context: DiagnosticMcpRequestContext,
  lifecycle: McpRequestLifecycle,
): Promise<FastifyReply | undefined> {
  return sendMcpProblem(
    lifecycle,
    reply,
    context.origin,
    405,
    'SCG_MCP_GET_UNSUPPORTED',
    'protocol-rejected',
  );
}
function diagnosticCredential(context: DiagnosticMcpRequestContext) {
  return {
    token: context.token,
    projectId: context.projectId,
    origin: context.origin,
    audience: DIAGNOSTICS_AUDIENCE,
  } as const;
}

async function sendDiagnosticPostMessage(
  request: FastifyRequest,
  reply: FastifyReply,
  context: DiagnosticMcpRequestContext,
  message: McpJsonRpcRequest,
  lifecycle: McpRequestLifecycle,
  protocols: DiagnosticProtocolSessions,
): Promise<FastifyReply | undefined> {
  const credential = diagnosticCredential(context);
  const runStore = context.runStore;
  if (message.method === 'initialize' && request.headers['mcp-session-id'] === undefined) {
    if (message.id === undefined) {
      return sendMcpResponse(lifecycle, reply, 'failure', 'protocol-rejected', () =>
        sendInvalidRpc(reply, context.origin),
      );
    }
    if (!hasConsistentInitializeProtocol(message, context.protocolVersion)) {
      return sendMcpProblem(
        lifecycle,
        reply,
        context.origin,
        400,
        'SCG_MCP_PROTOCOL_VERSION',
        'protocol-rejected',
      );
    }

    const dispatcher = createStrictMcpDispatcher({ scope: 'diagnostic' });
    const response = await dispatcher.dispatch(message, { signal: lifecycle.signal });
    if (finishIfAborted(lifecycle, reply, context.origin)) {
      return undefined;
    }
    const envelope = validateJsonRpcResponse(message, response);
    if (envelope === 'invalid') {
      return sendMcpProblem(
        lifecycle,
        reply,
        context.origin,
        500,
        'SCG_MCP_RESPONSE_INVALID',
        'handler-error',
      );
    }
    if (
      envelope !== 'result' ||
      !isSuccessfulInitializeResponse(response, context.protocolVersion)
    ) {
      return sendMcpJsonRpcResponse(lifecycle, reply, context.origin, response);
    }

    let initialized: ReturnType<typeof runStore.consumeInitialize>;
    try {
      initialized = runStore.consumeInitialize({
        ...credential,
        method: message.method,
      });
    } catch {
      return sendMcpProblem(
        lifecycle,
        reply,
        context.origin,
        500,
        'SCG_DIAGNOSTIC_STORE_FAILED',
        'handler-error',
      );
    }
    if (!initialized.ok) {
      return sendMcpProblem(
        lifecycle,
        reply,
        context.origin,
        initialized.status,
        initialized.code,
        'protocol-rejected',
      );
    }
    protocols.set(initialized.session, dispatcher);
    lifecycle.bindDiagnosticSession(initialized.session.id);
    if (finishIfAborted(lifecycle, reply, context.origin)) {
      return undefined;
    }
    reply.header('mcp-session-id', initialized.session.id);
    reply.header('access-control-expose-headers', 'mcp-session-id');
    return sendMcpJsonRpcResponse(lifecycle, reply, context.origin, response);
  }

  let authorized: ReturnType<typeof runStore.authorizeMethod>;
  try {
    authorized = runStore.authorizeMethod({
      ...credential,
      sessionId: singleHeader(request.headers['mcp-session-id']),
      method: message.method,
    });
  } catch {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      500,
      'SCG_DIAGNOSTIC_STORE_FAILED',
      'handler-error',
    );
  }
  if (!authorized.ok) {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      authorized.status,
      authorized.code,
      'protocol-rejected',
    );
  }
  lifecycle.bindDiagnosticSession(authorized.session.id);
  if (finishIfAborted(lifecycle, reply, context.origin)) {
    return undefined;
  }
  const dispatcher = protocols.get(authorized.session.id);
  if (dispatcher === undefined) {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      401,
      'SCG_DIAGNOSTIC_INVALID',
      'protocol-rejected',
    );
  }

  const response = await dispatcher.dispatch(message, { signal: lifecycle.signal });
  if (finishIfAborted(lifecycle, reply, context.origin)) {
    return undefined;
  }
  if (message.id === undefined) {
    if (response !== undefined) {
      return sendMcpProblem(
        lifecycle,
        reply,
        context.origin,
        500,
        'SCG_MCP_RESPONSE_INVALID',
        'handler-error',
      );
    }
    return sendMcpResponse(lifecycle, reply, 'success', 'success', () =>
      sendAcceptedNotification(reply, context.origin),
    );
  }
  if (validateJsonRpcResponse(message, response) === 'invalid') {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      500,
      'SCG_MCP_RESPONSE_INVALID',
      'handler-error',
    );
  }
  return sendMcpJsonRpcResponse(lifecycle, reply, context.origin, response);
}

async function sendDiagnosticClose(
  request: FastifyRequest,
  reply: FastifyReply,
  context: DiagnosticMcpRequestContext,
  lifecycle: McpRequestLifecycle,
  protocols: DiagnosticProtocolSessions,
): Promise<FastifyReply | undefined> {
  const sessionId = singleHeader(request.headers['mcp-session-id']);
  let closed: ReturnType<typeof context.runStore.close>;
  try {
    closed = context.runStore.close({
      ...diagnosticCredential(context),
      sessionId,
    });
  } catch {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      500,
      'SCG_DIAGNOSTIC_STORE_FAILED',
      'handler-error',
    );
  }
  if (!closed.ok) {
    return sendMcpProblem(
      lifecycle,
      reply,
      context.origin,
      closed.status,
      closed.code,
      'protocol-rejected',
    );
  }
  protocols.delete(closed.session.id);
  lifecycle.bindDiagnosticSession(closed.session.id);
  if (finishIfAborted(lifecycle, reply, context.origin)) {
    return undefined;
  }
  return sendMcpResponse(lifecycle, reply, 'success', 'success', () =>
    sendNoContent(reply, context.origin),
  );
}
class DiagnosticProtocolSessions {
  readonly #dispatchers = new Map<string, DiagnosticProtocolState>();
  readonly #now: () => number;

  public constructor(now: () => number) {
    this.#now = now;
  }

  public set(
    session: Readonly<{ readonly expiresAt: number; readonly id: string }>,
    dispatcher: StrictMcpDispatcher,
  ): void {
    this.prune();
    this.#dispatchers.set(session.id, { dispatcher, expiresAt: session.expiresAt });
  }

  public get(sessionId: string): StrictMcpDispatcher | undefined {
    this.prune();
    return this.#dispatchers.get(sessionId)?.dispatcher;
  }

  public delete(sessionId: string | undefined): void {
    if (sessionId !== undefined) {
      this.#dispatchers.delete(sessionId);
    }
  }

  public prune(): void {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('diagnostic protocol clock must return a non-negative safe integer');
    }
    for (const [sessionId, state] of this.#dispatchers) {
      if (state.expiresAt <= now) {
        this.#dispatchers.delete(sessionId);
      }
    }
  }
}

interface DiagnosticProtocolState {
  readonly dispatcher: StrictMcpDispatcher;
  readonly expiresAt: number;
}

async function establishMcpContext(
  request: FastifyRequest,
  reply: FastifyReply,
  options: McpRouteOptions,
  contexts: WeakMap<FastifyRequest, McpRequestContext>,
  allowedOrigins: WeakMap<FastifyRequest, string>,
  lifecycle: McpRequestLifecycle,
  requestAdmissions: McpRequestAdmissionState,
  method: 'DELETE' | 'GET' | 'POST',
): Promise<void> {
  const projectId = projectIdFromRequest(request);
  const policy = projectId === undefined ? undefined : options.registry.getOriginPolicy(projectId);
  const origin = singleHeader(request.headers.origin);
  if (!isAllowedOrigin(policy, origin)) {
    lifecycle.recordOriginRejected();
    sendMcpResponse(lifecycle, reply, 'failure', 'origin-rejected', () => sendOriginDenied(reply));
    return;
  }
  lifecycle.setOrigin(origin);
  allowedOrigins.set(request, origin);

  let verification: AuthVerificationResult;
  try {
    verification = await options.verifier.verify({
      authorization: singleHeader(request.headers.authorization),
      audience: SCENE_GLASS_AUDIENCE,
      origin,
      signal: lifecycle.signal,
    });
  } catch {
    if (finishIfAborted(lifecycle, reply, origin)) {
      return;
    }
    sendMcpProblem(lifecycle, reply, origin, 500, 'SCG_AUTH_VERIFIER_FAILED', 'handler-error');
    return;
  }
  if (finishIfAborted(lifecycle, reply, origin)) {
    return;
  }
  if (!verification.ok) {
    const runStore = options.diagnosticRunStore;
    const token = diagnosticBearer(request);
    if (runStore !== undefined && token !== undefined && projectId !== undefined) {
      let diagnostic: ReturnType<typeof runStore.authenticate>;
      try {
        diagnostic = runStore.authenticate({
          token,
          projectId,
          origin,
          audience: DIAGNOSTICS_AUDIENCE,
        });
      } catch {
        if (finishIfAborted(lifecycle, reply, origin)) {
          return;
        }
        sendMcpProblem(
          lifecycle,
          reply,
          origin,
          500,
          'SCG_DIAGNOSTIC_STORE_FAILED',
          'handler-error',
        );
        return;
      }
      if (diagnostic.ok) {
        const admissionProject = options.registry.getRequestAdmissionProject?.(projectId);
        if (admissionProject === undefined) {
          sendMcpProblem(lifecycle, reply, origin, 500, 'SCG_HTTP_INTERNAL', 'handler-error');
          return;
        }
        const admission = admitMcpRequest(requestAdmissions, admissionProject);
        if (!admission.ok) {
          sendMcpProblem(lifecycle, reply, origin, 429, admission.code, 'admission-rejected');
          return;
        }
        lifecycle.bindRequestAdmission(admission.release);
        const negotiation = validateMcpTransportNegotiation(request);
        if (!negotiation.ok) {
          sendMcpProblem(
            lifecycle,
            reply,
            origin,
            negotiation.status,
            negotiation.code,
            'protocol-rejected',
          );
          return;
        }
        if (method === 'POST') {
          try {
            assertJsonMediaType(request.headers['content-type']);
            assertDeclaredBodyWithinLimit(request.headers['content-length'], options.maxBodyBytes);
          } catch (error: unknown) {
            const failure = bodyFailureKind(error);
            if (failure === undefined) {
              throw error;
            }
            sendMcpBodyFailure(lifecycle, reply, origin, failure);
            return;
          }
        }
        contexts.set(
          request,
          Object.freeze({
            kind: 'diagnostic' as const,
            origin,
            projectId,
            protocolVersion: negotiation.protocolVersion,
            runStore,
            token,
          }),
        );
        return;
      }

      let recognizesCredential: boolean;
      try {
        recognizesCredential = runStore.recognizesCredential(token);
      } catch {
        if (finishIfAborted(lifecycle, reply, origin)) {
          return;
        }
        sendMcpProblem(
          lifecycle,
          reply,
          origin,
          500,
          'SCG_DIAGNOSTIC_STORE_FAILED',
          'handler-error',
        );
        return;
      }
      if (diagnostic.code !== 'SCG_DIAGNOSTIC_INVALID' || recognizesCredential) {
        lifecycle.recordAuthenticationRejected();
        sendMcpProblem(
          lifecycle,
          reply,
          origin,
          diagnostic.status,
          diagnostic.code,
          'authentication-rejected',
        );
        return;
      }
    }
    lifecycle.recordAuthenticationRejected();
    sendMcpProblem(
      lifecycle,
      reply,
      origin,
      verification.status,
      verification.code,
      'authentication-rejected',
    );
    return;
  }
  if (verification.context.projectId !== projectId) {
    lifecycle.recordAuthenticationRejected();
    sendMcpProblem(
      lifecycle,
      reply,
      origin,
      403,
      'SCG_PROJECT_FORBIDDEN',
      'authentication-rejected',
    );
    return;
  }
  const negotiation = validateMcpTransportNegotiation(request);
  if (!negotiation.ok) {
    sendMcpProblem(
      lifecycle,
      reply,
      origin,
      negotiation.status,
      negotiation.code,
      'protocol-rejected',
    );
    return;
  }

  let session: SessionRecord | undefined;
  const sessionHeader = request.headers['mcp-session-id'];
  const sessionId = singleHeader(sessionHeader);
  const hasSessionHeader = sessionHeader !== undefined;
  if (method !== 'POST' || hasSessionHeader) {
    const lookup = await options.sessions.lookup({
      auth: verification.context,
      method,
      sessionId,
      signal: lifecycle.signal,
    });
    if (!lookup.ok) {
      if (finishIfAborted(lifecycle, reply, origin)) {
        return;
      }
      sendMcpProblem(lifecycle, reply, origin, lookup.status, lookup.code, 'protocol-rejected');
      return;
    }
    session = lookup.session;
    lifecycle.bindNormalSession(session.id);
    if (finishIfAborted(lifecycle, reply, origin)) {
      return;
    }
  }

  if (method === 'POST') {
    try {
      assertJsonMediaType(request.headers['content-type']);
      assertDeclaredBodyWithinLimit(request.headers['content-length'], options.maxBodyBytes);
    } catch (error: unknown) {
      const failure = bodyFailureKind(error);
      if (failure === undefined) {
        throw error;
      }
      sendMcpBodyFailure(lifecycle, reply, origin, failure);
      return;
    }
  }

  contexts.set(
    request,
    Object.freeze({
      kind: 'normal' as const,
      auth: verification.context,
      origin,
      projectId,
      protocolVersion: negotiation.protocolVersion,
      session,
    }),
  );
}
function createMcpRequestLifecycle(
  request: FastifyRequest,
  reply: FastifyReply,
  options: McpRouteOptions,
  protocols: DiagnosticProtocolSessions,
): McpRequestLifecycle {
  return new McpRequestLifecycle(
    request,
    reply,
    options.logger,
    (sessionId) => {
      options.sessions.abort(sessionId);
    },
    (sessionId) => {
      protocols.delete(sessionId);
      options.diagnosticRunStore?.abort(sessionId);
    },
  );
}

class McpRequestLifecycle {
  readonly #abortDiagnosticSession: (sessionId: string | undefined) => void;
  readonly #abortNormalSession: (sessionId: string | undefined) => void;
  readonly #controller = new AbortController();
  readonly #logger: SceneGlassLogger;
  readonly #reply: FastifyReply;
  readonly #request: FastifyRequest;
  readonly #startedAt = performance.now();
  #completed = false;
  #deadline: ReturnType<typeof setTimeout> | undefined;
  #deadlineAt: number | undefined;
  #diagnosticSessionId: string | undefined;
  #requestAdmissionRelease: (() => void) | undefined;
  #normalSessionId: string | undefined;
  #normalSessionProvisional = false;
  #origin: string | undefined;
  #terminal = false;
  #transportAborted = false;

  public constructor(
    request: FastifyRequest,
    reply: FastifyReply,
    logger: SceneGlassLogger,
    abortNormalSession: (sessionId: string | undefined) => void,
    abortDiagnosticSession: (sessionId: string | undefined) => void,
  ) {
    this.#request = request;
    this.#reply = reply;
    this.#logger = logger;
    this.#abortNormalSession = abortNormalSession;
    this.#abortDiagnosticSession = abortDiagnosticSession;
    request.raw.once('aborted', this.onTransportAbort);
    request.raw.socket.once('close', this.onSocketClose);
    if (request.raw.aborted || reply.raw.destroyed) {
      this.abortTransport();
    }
  }

  public get signal(): AbortSignal {
    return this.#controller.signal;
  }

  public observeTransportAbort(): boolean {
    if (
      this.#request.raw.aborted ||
      (this.#reply.raw.destroyed && !this.#reply.raw.writableEnded)
    ) {
      this.abortTransport();
    }
    return this.#transportAborted;
  }

  public get transportAborted(): boolean {
    return this.#transportAborted;
  }

  public setOrigin(origin: string): void {
    this.#origin = origin;
  }

  public recordOriginRejected(): void {
    this.#logger.emit('origin.rejected', undefined, { requestId: this.#request.id });
  }

  public recordAuthenticationRejected(): void {
    this.#logger.emit('auth.rejected', undefined, { requestId: this.#request.id });
  }

  public armDeadline(timeoutMs: number): void {
    this.tightenDeadline(timeoutMs);
  }

  public tightenDeadline(timeoutMs: number): void {
    if (this.#completed || this.#controller.signal.aborted) {
      return;
    }
    const candidate = this.#startedAt + timeoutMs;
    if (this.#deadlineAt !== undefined && candidate >= this.#deadlineAt) {
      return;
    }
    this.#deadlineAt = candidate;
    this.clearDeadline();
    this.scheduleDeadline();
  }
  public bindRequestAdmission(release: () => void): void {
    if (this.#requestAdmissionRelease !== undefined) {
      release();
      return;
    }
    this.#requestAdmissionRelease = release;
    if (this.#completed || this.#transportAborted) {
      this.releaseRequestAdmission();
    }
  }

  public bindDiagnosticSession(sessionId: string | undefined): void {
    this.#diagnosticSessionId = sessionId;
    if (this.#transportAborted) {
      this.abortDiagnostic();
    }
  }

  public bindNormalSession(sessionId: string | undefined): void {
    this.#normalSessionId = sessionId;
    this.#normalSessionProvisional = false;
    if (this.#transportAborted) {
      this.abortNormal();
    }
  }

  public bindProvisionalNormalSession(sessionId: string): void {
    this.#normalSessionId = sessionId;
    this.#normalSessionProvisional = true;
    if (this.#transportAborted || this.#controller.signal.aborted) {
      this.abortNormal();
    }
  }

  public abortProvisionalNormalSession(): void {
    if (this.#normalSessionProvisional) {
      this.abortNormal();
    }
  }

  public commitNormalSession(): void {
    this.#normalSessionProvisional = false;
  }

  public complete(): void {
    if (this.#completed) {
      return;
    }
    this.#completed = true;
    this.#deadlineAt = undefined;
    this.clearDeadline();
    this.releaseRequestAdmission();
    this.#request.raw.removeListener('aborted', this.onTransportAbort);
    this.#request.raw.socket.removeListener('close', this.onSocketClose);
  }

  public terminal(outcome: SceneGlassTerminalOutcome, stage: McpTerminalStage): void {
    if (this.#terminal) {
      return;
    }
    this.#terminal = true;
    this.#logger.terminal({ requestId: this.#request.id }, outcome, Object.freeze({ stage }));
  }

  private readonly onSocketClose = (): void => {
    if (!this.#reply.raw.writableEnded) {
      this.abortTransport();
    }
  };

  private readonly onTransportAbort = (): void => {
    this.abortTransport();
  };

  private readonly onDeadline = (): void => {
    this.#deadline = undefined;
    if (this.#completed || this.#transportAborted || this.#deadlineAt === undefined) {
      return;
    }
    if (performance.now() < this.#deadlineAt) {
      this.scheduleDeadline();
      return;
    }

    this.observeTransportAbort();
    if (this.#completed || this.#transportAborted) {
      return;
    }
    this.#controller.abort();
    if (this.#normalSessionProvisional) {
      this.abortNormal();
    }
    if (!this.#reply.sent) {
      try {
        sendProblem(this.#reply, this.#origin, 503, 'SCG_REQUEST_TIMEOUT');
      } catch {
        this.#logger.emit(
          'cleanup.failed',
          { resource: 'timeout-response' },
          { requestId: this.#request.id },
        );
      }
    }
    this.terminal('failure', 'request-timeout');
    this.complete();
  };

  private scheduleDeadline(): void {
    if (this.#deadlineAt === undefined || this.#completed || this.#transportAborted) {
      return;
    }
    const remaining = this.#deadlineAt - performance.now();
    if (remaining <= 0) {
      this.onDeadline();
      return;
    }
    this.#deadline = setTimeout(this.onDeadline, Math.min(remaining, 2_147_483_647));
  }

  private clearDeadline(): void {
    if (this.#deadline !== undefined) {
      clearTimeout(this.#deadline);
      this.#deadline = undefined;
    }
  }

  private abortDiagnostic(): void {
    try {
      this.#abortDiagnosticSession(this.#diagnosticSessionId);
    } catch {
      this.#logger.emit(
        'cleanup.failed',
        { resource: 'diagnostic' },
        { requestId: this.#request.id },
      );
    }
  }

  private abortNormal(): void {
    this.#normalSessionProvisional = false;
    try {
      this.#abortNormalSession(this.#normalSessionId);
    } catch {
      this.#logger.emit('cleanup.failed', { resource: 'normal' }, { requestId: this.#request.id });
    }
  }

  private abortTransport(): void {
    if (this.#transportAborted || this.#completed) {
      return;
    }
    this.#transportAborted = true;
    this.#controller.abort();
    this.abortNormal();
    this.abortDiagnostic();
    this.terminal('cancelled', 'disconnect');
    this.complete();
  }

  private releaseRequestAdmission(): void {
    const release = this.#requestAdmissionRelease;
    this.#requestAdmissionRelease = undefined;
    release?.();
  }
}

function finishIfAborted(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  origin: string | undefined,
): boolean {
  lifecycle.observeTransportAbort();
  if (!lifecycle.signal.aborted) {
    return false;
  }
  if (lifecycle.transportAborted) {
    lifecycle.complete();
    return true;
  }
  sendMcpProblem(lifecycle, reply, origin, 503, 'SCG_REQUEST_TIMEOUT', 'request-timeout');
  return true;
}

function sendMcpBodyFailure(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  origin: string | undefined,
  failure: Parameters<typeof sendBodyFailure>[2],
): FastifyReply | undefined {
  return sendMcpResponse(lifecycle, reply, 'failure', 'protocol-rejected', () =>
    sendBodyFailure(reply, origin, failure),
  );
}

function sendMcpProblem(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  origin: string | undefined,
  status: number,
  code: string,
  stage: McpTerminalStage,
): FastifyReply | undefined {
  return sendMcpResponse(lifecycle, reply, 'failure', stage, () =>
    sendProblem(reply, origin, status, code),
  );
}

function sendMcpResponse(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  outcome: SceneGlassTerminalOutcome,
  stage: McpTerminalStage,
  write: () => FastifyReply,
): FastifyReply | undefined {
  lifecycle.observeTransportAbort();
  if (lifecycle.transportAborted || reply.sent) {
    lifecycle.complete();
    return undefined;
  }
  try {
    const response = write();
    lifecycle.terminal(outcome, stage);
    return response;
  } finally {
    lifecycle.complete();
  }
}
function writeMcpJsonRpcResponse(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  origin: string | undefined,
  response: unknown,
): FastifyReply | undefined {
  lifecycle.observeTransportAbort();
  if (lifecycle.transportAborted || reply.sent) {
    lifecycle.complete();
    return undefined;
  }
  return sendJsonRpc(reply, origin, response);
}
function sendMcpJsonRpcResponse(
  lifecycle: McpRequestLifecycle,
  reply: FastifyReply,
  origin: string | undefined,
  response: unknown,
): FastifyReply | undefined {
  const failed = isJsonRpcFailure(response);
  return sendMcpResponse(
    lifecycle,
    reply,
    failed ? 'failure' : 'success',
    failed ? 'json-rpc-error' : 'success',
    () => sendJsonRpc(reply, origin, response),
  );
}

type JsonRpcResponseEnvelope = 'error' | 'invalid' | 'result';

function validateJsonRpcResponse(
  request: McpJsonRpcRequest,
  response: unknown,
): JsonRpcResponseEnvelope {
  if (
    request.id === undefined ||
    !isRecord(response) ||
    response.jsonrpc !== '2.0' ||
    !Object.is(response.id, request.id)
  ) {
    return 'invalid';
  }

  const keys = Object.keys(response);
  const hasResult = Object.hasOwn(response, 'result');
  const hasError = Object.hasOwn(response, 'error');
  if (
    keys.some((key) => key !== 'jsonrpc' && key !== 'id' && key !== 'result' && key !== 'error') ||
    hasResult === hasError
  ) {
    return 'invalid';
  }

  return hasError && isJsonRpcFailure(response) ? 'error' : hasResult ? 'result' : 'invalid';
}

function isSuccessfulInitializeResponse(
  response: unknown,
  protocolVersion: typeof MCP_PROTOCOL_VERSION | undefined,
): boolean {
  return (
    isRecord(response) &&
    isRecord(response.result) &&
    response.result.protocolVersion === MCP_PROTOCOL_VERSION &&
    (protocolVersion === undefined || response.result.protocolVersion === protocolVersion)
  );
}

function isJsonRpcFailure(response: unknown): boolean {
  if (!isRecord(response) || !isRecord(response.error)) {
    return false;
  }
  const keys = Object.keys(response.error);
  return (
    keys.every((key) => key === 'code' || key === 'data' || key === 'message') &&
    typeof response.error.code === 'number' &&
    Number.isFinite(response.error.code) &&
    typeof response.error.message === 'string'
  );
}

type McpTransportNegotiation =
  | { readonly ok: true; readonly protocolVersion: typeof MCP_PROTOCOL_VERSION | undefined }
  | {
      readonly ok: false;
      readonly code: 'SCG_MCP_ACCEPT_INVALID' | 'SCG_MCP_PROTOCOL_VERSION';
      readonly status: 400 | 406;
    };

function validateMcpTransportNegotiation(request: FastifyRequest): McpTransportNegotiation {
  const protocolVersion = strictRequestHeader(request, 'mcp-protocol-version');
  if (
    protocolVersion === null ||
    (protocolVersion !== undefined && protocolVersion !== MCP_PROTOCOL_VERSION)
  ) {
    return { ok: false, status: 400, code: 'SCG_MCP_PROTOCOL_VERSION' };
  }

  const accept = strictRequestHeader(request, 'accept');
  if (accept === null || (accept !== undefined && !acceptsJsonResponse(accept))) {
    return { ok: false, status: 406, code: 'SCG_MCP_ACCEPT_INVALID' };
  }
  return { ok: true, protocolVersion };
}

function strictRequestHeader(request: FastifyRequest, name: string): string | null | undefined {
  const value = request.headers[name];
  if (value !== undefined && typeof value !== 'string') {
    return null;
  }

  let rawCount = 0;
  for (let index = 0; index < request.raw.rawHeaders.length; index += 2) {
    if (request.raw.rawHeaders[index]?.toLowerCase() === name) {
      rawCount += 1;
    }
  }
  return rawCount > 1 ? null : value;
}

function acceptsJsonResponse(value: string): boolean {
  const ranges = value.split(',').map((range) => range.trim());
  if (ranges.length === 0 || ranges.some((range) => range.length === 0)) {
    return false;
  }

  let acceptsJson = false;
  for (const range of ranges) {
    const [mediaRange, ...parameters] = range.split(';').map((part) => part.trim());
    if (
      mediaRange === undefined ||
      !/^(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|\*)\/(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|\*)$/.test(mediaRange)
    ) {
      return false;
    }

    let quality = 1;
    for (const parameter of parameters) {
      const separator = parameter.indexOf('=');
      if (separator <= 0 || separator === parameter.length - 1) {
        return false;
      }
      if (parameter.slice(0, separator).trim().toLowerCase() === 'q') {
        quality = Number(parameter.slice(separator + 1).trim());
        if (!Number.isFinite(quality) || quality < 0 || quality > 1) {
          return false;
        }
      }
    }

    if (
      quality > 0 &&
      (mediaRange.toLowerCase() === 'application/json' ||
        mediaRange.toLowerCase() === 'application/*' ||
        mediaRange === '*/*')
    ) {
      acceptsJson = true;
    }
  }
  return acceptsJson;
}

function hasConsistentInitializeProtocol(
  message: McpJsonRpcRequest,
  protocolVersion: typeof MCP_PROTOCOL_VERSION | undefined,
): boolean {
  return (
    protocolVersion === undefined ||
    (isRecord(message.params) && message.params.protocolVersion === protocolVersion)
  );
}

function parseMcpJsonRpc(value: unknown): McpJsonRpcRequest | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const keys = Object.keys(value);
  if (
    keys.some((key) => key !== 'id' && key !== 'jsonrpc' && key !== 'method' && key !== 'params') ||
    value.jsonrpc !== '2.0' ||
    typeof value.method !== 'string' ||
    value.method.length === 0 ||
    value.method.length > 256 ||
    (Object.hasOwn(value, 'id') && !isJsonRpcId(value.id))
  ) {
    return undefined;
  }

  return Object.freeze({
    jsonrpc: '2.0',
    method: value.method,
    ...(Object.hasOwn(value, 'id') ? { id: value.id as JsonRpcId } : {}),
    ...(Object.hasOwn(value, 'params') ? { params: value.params } : {}),
  });
}

function isJsonRpcId(value: unknown): value is Exclude<JsonRpcId, null> {
  return typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
}

function projectIdFromRequest(request: FastifyRequest): string | undefined {
  const params = request.params;
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    return undefined;
  }
  const projectId = (params as Record<string, unknown>).projectId;
  return isProjectId(projectId) ? projectId : undefined;
}
function allowedOriginFromRequest(
  request: FastifyRequest,
  registry: ProjectRegistry,
): string | undefined {
  const projectId = projectIdFromRequest(request);
  const origin = singleHeader(request.headers.origin);
  return isAllowedOrigin(
    projectId === undefined ? undefined : registry.getOriginPolicy(projectId),
    origin,
  )
    ? origin
    : undefined;
}
function diagnosticBearer(request: FastifyRequest): string | undefined {
  return parseBearer(singleHeader(request.headers.authorization));
}

type ScopeAuthorization = 'allowed' | 'denied' | 'failed';

async function allowsScope(
  authorizer: McpScopeAuthorizer | undefined,
  auth: AuthContext,
  project: AuthorizedProject,
  operation: 'delete' | 'get' | 'post',
  signal: AbortSignal,
): Promise<ScopeAuthorization> {
  if (authorizer === undefined) {
    return signal.aborted ? 'failed' : 'allowed';
  }
  try {
    signal.throwIfAborted();
    const allowed = await authorizer.allows({ auth, operation, project, signal });
    signal.throwIfAborted();
    return allowed === true ? 'allowed' : 'denied';
  } catch {
    return 'failed';
  }
}
function admitMcpRequest(
  state: McpRequestAdmissionState,
  project: Pick<RequestAdmissionProject, 'effectiveLimits' | 'projectId'>,
): McpRequestAdmission {
  if (state.global >= project.effectiveLimits.concurrentRequestsGlobal) {
    return { ok: false, code: 'SCG_REQUEST_LIMIT_GLOBAL' };
  }

  const projectCount = state.projects.get(project.projectId) ?? 0;
  if (projectCount >= project.effectiveLimits.concurrentRequestsPerProject) {
    return { ok: false, code: 'SCG_REQUEST_LIMIT_PROJECT' };
  }

  state.global += 1;
  state.projects.set(project.projectId, projectCount + 1);
  let released = false;
  return {
    ok: true,
    release(): void {
      if (released) {
        return;
      }
      released = true;
      state.global -= 1;
      const nextProjectCount = (state.projects.get(project.projectId) ?? 0) - 1;
      if (nextProjectCount <= 0) {
        state.projects.delete(project.projectId);
      } else {
        state.projects.set(project.projectId, nextProjectCount);
      }
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertRouteOptions(options: McpRouteOptions): void {
  if (
    options === null ||
    typeof options !== 'object' ||
    options.registry === undefined ||
    options.registry === null ||
    typeof options.registry.getOriginPolicy !== 'function' ||
    typeof options.registry.resolveAuthorizedProject !== 'function' ||
    (options.diagnosticRunStore !== undefined &&
      typeof options.registry.getRequestAdmissionProject !== 'function') ||
    options.verifier === undefined ||
    options.sessions === undefined ||
    options.sessions === null ||
    typeof options.sessions.abort !== 'function' ||
    typeof options.sessions.close !== 'function' ||
    typeof options.sessions.commit !== 'function' ||
    typeof options.sessions.initialize !== 'function' ||
    typeof options.sessions.lookup !== 'function' ||
    options.dispatcher === undefined ||
    options.logger === undefined ||
    options.logger === null ||
    typeof options.logger.terminal !== 'function' ||
    !Number.isSafeInteger(options.maxBodyBytes) ||
    options.maxBodyBytes <= 0 ||
    (options.requestTimeoutMs !== undefined &&
      (!Number.isSafeInteger(options.requestTimeoutMs) || options.requestTimeoutMs <= 0)) ||
    (options.now !== undefined && typeof options.now !== 'function')
  ) {
    throw new TypeError('MCP route options are invalid');
  }
}
