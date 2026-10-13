import type { FastifyReply } from 'fastify';

import { applyAllowedOriginCors } from './cors.js';
import type { BodyFailureKind } from './body-parser.js';

export type JsonRpcId = null | number | string;

export interface JsonRpcErrorResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly error: {
    readonly code: number;
    readonly message: string;
  };
}

export interface ProblemResponse {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly code: string;
}

const PROBLEM_TITLES: Readonly<Record<number, string>> = Object.freeze({
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  413: 'Content Too Large',
  415: 'Unsupported Media Type',
  422: 'Unprocessable Content',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
});

export function sendProblem(
  reply: FastifyReply,
  origin: string | undefined,
  status: number,
  code: string,
): FastifyReply {
  applyCorsIfAllowed(reply, origin);
  reply.header('cache-control', 'no-store');
  if (status === 401) {
    reply.header('www-authenticate', 'Bearer');
  }
  return reply.code(status).type('application/problem+json').send(problem(status, code));
}

export function sendBodyFailure(
  reply: FastifyReply,
  origin: string | undefined,
  failure: BodyFailureKind,
): FastifyReply {
  switch (failure) {
    case 'invalid-json':
      return sendProblem(reply, origin, 400, 'SCG_JSON_INVALID');
    case 'media-type':
      return sendProblem(reply, origin, 415, 'SCG_MEDIA_TYPE_INVALID');
    case 'too-large':
      return sendProblem(reply, origin, 413, 'SCG_BODY_TOO_LARGE');
  }
}

export function sendInvalidRpc(reply: FastifyReply, origin: string | undefined): FastifyReply {
  return sendJsonRpcError(reply, origin, null, -32600, 'Invalid Request');
}

export function sendInvalidParams(
  reply: FastifyReply,
  origin: string | undefined,
  id: JsonRpcId,
): FastifyReply {
  return sendJsonRpcError(reply, origin, id, -32602, 'Invalid params');
}

export function sendJsonRpcError(
  reply: FastifyReply,
  origin: string | undefined,
  id: JsonRpcId,
  code: number,
  message: string,
): FastifyReply {
  return sendJson(reply, origin, 200, {
    jsonrpc: '2.0',
    id,
    error: { code, message },
  });
}

/** For dispatcher results, including stable domain errors, without wrapping. */
export function sendJsonRpc(
  reply: FastifyReply,
  origin: string | undefined,
  value: unknown,
): FastifyReply {
  return sendJson(reply, origin, 200, value);
}

export function sendAcceptedNotification(
  reply: FastifyReply,
  origin: string | undefined,
): FastifyReply {
  applyCorsIfAllowed(reply, origin);
  reply.header('cache-control', 'no-store');
  return reply.code(202).send();
}

export function sendNoContent(
  reply: FastifyReply,
  origin: string | undefined,
  status = 204,
): FastifyReply {
  applyCorsIfAllowed(reply, origin);
  reply.header('cache-control', 'no-store');
  return reply.code(status).send();
}

export function sendJson(
  reply: FastifyReply,
  origin: string | undefined,
  status: number,
  value: unknown,
): FastifyReply {
  applyCorsIfAllowed(reply, origin);
  reply.header('cache-control', 'no-store');
  return reply.code(status).type('application/json').send(value);
}

function applyCorsIfAllowed(reply: FastifyReply, origin: string | undefined): void {
  if (origin !== undefined) {
    applyAllowedOriginCors(reply, origin);
  }
}

function problem(status: number, code: string): ProblemResponse {
  return Object.freeze({
    type: `urn:scene-glass:problem:${code.toLowerCase()}`,
    title: PROBLEM_TITLES[status] ?? 'Request Failed',
    status,
    code,
  });
}
