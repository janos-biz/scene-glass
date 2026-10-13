import { isExactHttpOrigin } from '@scene-glass/contracts';
import type { FastifyReply } from 'fastify';

import type { OriginPolicy } from '../registry/config-project-registry.js';

export type CorsRouteKind = 'diagnostic' | 'mcp';

const ALLOWED_METHODS: Readonly<Record<CorsRouteKind, readonly string[]>> = Object.freeze({
  diagnostic: Object.freeze(['POST']),
  mcp: Object.freeze(['DELETE', 'GET', 'POST']),
});

const ALLOWED_HEADERS: Readonly<Record<CorsRouteKind, readonly string[]>> = Object.freeze({
  diagnostic: Object.freeze(['authorization', 'content-type']),
  mcp: Object.freeze(['authorization', 'content-type', 'mcp-protocol-version', 'mcp-session-id']),
});

export interface CorsPreflightRequest {
  readonly origin: string | undefined;
  readonly requestedHeaders: readonly string[];
  readonly requestedMethod: string | undefined;
  readonly requestsPrivateNetwork: boolean;
}

/**
 * Extracts one ordinary request header. Repeated values are invalid rather
 * than silently selecting a value controlled by an intermediary.
 */
export function singleHeader(value: string | string[] | undefined): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export function readCorsPreflightRequest(
  headers: Readonly<Record<string, unknown>>,
): CorsPreflightRequest {
  const origin = singleHeader(headers.origin as string | string[] | undefined);
  const requestedMethod = singleHeader(
    headers['access-control-request-method'] as string | string[] | undefined,
  );
  const privateNetwork = singleHeader(
    headers['access-control-request-private-network'] as string | string[] | undefined,
  );
  const requestedHeadersValue = singleHeader(
    headers['access-control-request-headers'] as string | string[] | undefined,
  );

  return Object.freeze({
    origin,
    requestedMethod,
    requestedHeaders: parseRequestedHeaders(requestedHeadersValue),
    requestsPrivateNetwork: privateNetwork === 'true',
  });
}

export function isAllowedOrigin(
  policy: OriginPolicy | undefined,
  origin: string | undefined,
): origin is string {
  return (
    origin !== undefined &&
    isExactHttpOrigin(origin) &&
    policy !== undefined &&
    policy.allowsOrigin(origin)
  );
}

/** Applies the only CORS headers allowed on an actual request response. */
export function applyAllowedOriginCors(reply: FastifyReply, origin: string): void {
  reply.header('access-control-allow-origin', origin);
  reply.header('vary', 'Origin');
}

/** Origin denial intentionally has no CORS or problem response. */
export function sendOriginDenied(reply: FastifyReply): FastifyReply {
  return reply.code(403).send();
}

/**
 * Writes a successful, route-specific preflight response. The caller must
 * first resolve only the project's OriginPolicy; this function has no access
 * to credentials, sessions, or authorized project roots.
 */
export function sendCorsPreflight(
  reply: FastifyReply,
  kind: CorsRouteKind,
  preflight: CorsPreflightRequest,
): FastifyReply {
  const method = preflight.requestedMethod;
  if (
    method === undefined ||
    !ALLOWED_METHODS[kind].includes(method) ||
    !areAllowedHeaders(kind, preflight.requestedHeaders)
  ) {
    return reply.code(400).send();
  }

  applyAllowedOriginCors(reply, preflight.origin as string);
  reply.header('access-control-allow-methods', method);

  const allowedHeaders = ALLOWED_HEADERS[kind].filter((header) =>
    preflight.requestedHeaders.includes(header),
  );
  if (allowedHeaders.length > 0) {
    reply.header('access-control-allow-headers', allowedHeaders.join(', '));
  }
  if (preflight.requestsPrivateNetwork) {
    reply.header('access-control-allow-private-network', 'true');
  }
  return reply.code(204).send();
}

export function isAllowedCorsPreflight(
  kind: CorsRouteKind,
  preflight: CorsPreflightRequest,
): boolean {
  return (
    preflight.requestedMethod !== undefined &&
    ALLOWED_METHODS[kind].includes(preflight.requestedMethod) &&
    areAllowedHeaders(kind, preflight.requestedHeaders)
  );
}

function parseRequestedHeaders(value: string | undefined): readonly string[] {
  if (value === undefined || value.trim().length === 0) {
    return Object.freeze([]);
  }

  const headers = value.split(',').map((header) => header.trim().toLowerCase());
  if (
    headers.some((header) => !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(header)) ||
    new Set(headers).size !== headers.length
  ) {
    return Object.freeze(['\u0000']);
  }
  return Object.freeze(headers);
}

function areAllowedHeaders(kind: CorsRouteKind, headers: readonly string[]): boolean {
  return headers.every((header) => ALLOWED_HEADERS[kind].includes(header));
}
