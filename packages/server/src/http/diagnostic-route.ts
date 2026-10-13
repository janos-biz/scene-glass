import { isProjectId } from '@scene-glass/contracts';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

import type { AuthContext } from '../auth/auth-context.js';
import { SCENE_GLASS_AUDIENCE } from '../auth/credential-subject.js';
import type { AuthVerificationResult, VerifyBearerInput } from '../auth/local-token-verifier.js';
import type { DiagnosticIssueInput, DiagnosticIssueResult } from '../diagnostics/issuer.js';
import type { AuthorizedProject, ProjectRegistry } from '../registry/config-project-registry.js';
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
import { sendBodyFailure, sendJson, sendProblem } from './wire-errors.js';

const DIAGNOSTIC_ROUTE_URL = '/mcp/v1/projects/:projectId/diagnostic-runs';

export interface DiagnosticIssuer {
  issue(input: DiagnosticIssueInput): Promise<DiagnosticIssueResult> | DiagnosticIssueResult;
}

export interface DiagnosticBearerVerifier {
  verify(input: VerifyBearerInput): Promise<AuthVerificationResult> | AuthVerificationResult;
}

export interface DiagnosticScopeAuthorizer {
  allows(input: {
    readonly auth: AuthContext;
    readonly project: AuthorizedProject;
  }): Promise<boolean> | boolean;
}

export interface DiagnosticRouteOptions {
  /** Produces the MCP endpoint included in a one-run diagnostic capability. */
  readonly endpointForProject: (project: AuthorizedProject) => string;
  readonly issuer: DiagnosticIssuer;
  readonly maxBodyBytes: number;
  readonly registry: ProjectRegistry;
  readonly scopeAuthorizer?: DiagnosticScopeAuthorizer;
  readonly verifier: DiagnosticBearerVerifier;
}

interface DiagnosticRequestContext {
  readonly auth: AuthContext;
  readonly origin: string;
}

/** Issues a scoped, short-lived diagnostic capability; it never exposes runs. */
export const diagnosticRoute: FastifyPluginAsync<DiagnosticRouteOptions> = async (
  fastify,
  options,
) => {
  assertRouteOptions(options);
  const contexts = new WeakMap<FastifyRequest, DiagnosticRequestContext>();
  const allowedOrigins = new WeakMap<FastifyRequest, string>();

  fastify.setErrorHandler((error, request, reply) => {
    const origin = contexts.get(request)?.origin ?? allowedOrigins.get(request);
    const failure = bodyFailureKind(error);
    if (failure !== undefined) {
      return sendBodyFailure(reply, origin, failure);
    }
    return sendProblem(reply, origin, 500, 'SCG_HTTP_INTERNAL');
  });

  fastify.options(DIAGNOSTIC_ROUTE_URL, async (request, reply) => {
    const projectId = projectIdFromRequest(request);
    const policy =
      projectId === undefined ? undefined : options.registry.getOriginPolicy(projectId);
    const preflight = readCorsPreflightRequest(request.headers);
    if (!isAllowedOrigin(policy, preflight.origin)) {
      return sendOriginDenied(reply);
    }
    if (!isAllowedCorsPreflight('diagnostic', preflight)) {
      return sendProblem(reply, preflight.origin, 400, 'SCG_CORS_PREFLIGHT_INVALID');
    }
    return sendCorsPreflight(reply, 'diagnostic', preflight);
  });

  fastify.post(
    DIAGNOSTIC_ROUTE_URL,
    {
      bodyLimit: options.maxBodyBytes,
      onRequest: async (request, reply) => {
        await establishDiagnosticContext(request, reply, options, contexts, allowedOrigins);
      },
    },
    async (request, reply) => {
      const context = contexts.get(request);
      if (context === undefined) {
        return sendProblem(reply, undefined, 500, 'SCG_HTTP_CONTEXT_MISSING');
      }
      if (!isDiagnosticRequest(parsedJsonBody(request))) {
        return sendProblem(reply, context.origin, 422, 'SCG_DIAGNOSTIC_DTO_INVALID');
      }

      const project = options.registry.resolveAuthorizedProject(context.auth);
      if (project === undefined) {
        return sendProblem(reply, context.origin, 403, 'SCG_PROJECT_FORBIDDEN');
      }
      if (!(await allowsScope(options.scopeAuthorizer, context.auth, project))) {
        return sendProblem(reply, context.origin, 403, 'SCG_SCOPE_FORBIDDEN');
      }

      const issued = await options.issuer.issue({
        auth: context.auth,
        limits: project.effectiveLimits,
      });
      if (!issued.ok) {
        return sendProblem(reply, context.origin, issued.status, issued.code);
      }

      let endpoint: string;
      try {
        endpoint = options.endpointForProject(project);
      } catch {
        return sendProblem(reply, context.origin, 500, 'SCG_DIAGNOSTIC_ENDPOINT_INVALID');
      }
      if (typeof endpoint !== 'string' || endpoint.trim().length === 0) {
        return sendProblem(reply, context.origin, 500, 'SCG_DIAGNOSTIC_ENDPOINT_INVALID');
      }

      return sendJson(reply, context.origin, 201, {
        runId: issued.runId,
        token: issued.token,
        expiresAt: new Date(issued.expiresAt).toISOString(),
        endpoint,
      });
    },
  );
};

async function establishDiagnosticContext(
  request: FastifyRequest,
  reply: Parameters<typeof sendProblem>[0],
  options: DiagnosticRouteOptions,
  contexts: WeakMap<FastifyRequest, DiagnosticRequestContext>,
  allowedOrigins: WeakMap<FastifyRequest, string>,
): Promise<void> {
  const projectId = projectIdFromRequest(request);
  const policy = projectId === undefined ? undefined : options.registry.getOriginPolicy(projectId);
  const origin = singleHeader(request.headers.origin);
  if (!isAllowedOrigin(policy, origin)) {
    sendOriginDenied(reply);
    return;
  }
  allowedOrigins.set(request, origin);

  let verification: AuthVerificationResult;
  try {
    verification = await options.verifier.verify({
      authorization: singleHeader(request.headers.authorization),
      audience: SCENE_GLASS_AUDIENCE,
      origin,
    });
  } catch {
    sendProblem(reply, origin, 500, 'SCG_AUTH_VERIFIER_FAILED');
    return;
  }
  if (!verification.ok) {
    sendProblem(reply, origin, verification.status, verification.code);
    return;
  }
  if (verification.context.projectId !== projectId) {
    sendProblem(reply, origin, 403, 'SCG_PROJECT_FORBIDDEN');
    return;
  }

  try {
    assertJsonMediaType(request.headers['content-type']);
    assertDeclaredBodyWithinLimit(request.headers['content-length'], options.maxBodyBytes);
  } catch (error: unknown) {
    const failure = bodyFailureKind(error);
    if (failure === undefined) {
      throw error;
    }
    sendBodyFailure(reply, origin, failure);
    return;
  }
  contexts.set(request, Object.freeze({ auth: verification.context, origin }));
}

function isDiagnosticRequest(value: unknown): value is { readonly schemaVersion: 1 } {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    Object.hasOwn(value, 'schemaVersion') &&
    (value as Record<string, unknown>).schemaVersion === 1
  );
}

function projectIdFromRequest(request: FastifyRequest): string | undefined {
  const params = request.params;
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    return undefined;
  }
  const projectId = (params as Record<string, unknown>).projectId;
  return isProjectId(projectId) ? projectId : undefined;
}

async function allowsScope(
  authorizer: DiagnosticScopeAuthorizer | undefined,
  auth: AuthContext,
  project: AuthorizedProject,
): Promise<boolean> {
  if (authorizer === undefined) {
    return true;
  }
  try {
    return (await authorizer.allows({ auth, project })) === true;
  } catch {
    return false;
  }
}

function assertRouteOptions(options: DiagnosticRouteOptions): void {
  if (
    options === null ||
    typeof options !== 'object' ||
    options.registry === undefined ||
    options.verifier === undefined ||
    options.issuer === undefined ||
    typeof options.endpointForProject !== 'function' ||
    !Number.isSafeInteger(options.maxBodyBytes) ||
    options.maxBodyBytes <= 0
  ) {
    throw new TypeError('diagnostic route options are invalid');
  }
}
