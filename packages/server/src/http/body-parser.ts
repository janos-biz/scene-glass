import type { FastifyRequest } from 'fastify';

import { singleHeader } from './cors.js';

export type BodyFailureKind = 'invalid-json' | 'media-type' | 'too-large';

/** A route-owned body failure that the wire-error handler can serialize. */
export class HttpBodyError extends Error {
  public readonly kind: BodyFailureKind;

  public constructor(kind: BodyFailureKind) {
    super(kind);
    this.name = 'HttpBodyError';
    this.kind = kind;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Only JSON with an optional UTF-8 charset is accepted by the local API. */
export function assertJsonMediaType(value: string | string[] | undefined): void {
  const contentType = singleHeader(value);
  if (
    contentType === undefined ||
    !/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?\s*$/i.test(contentType)
  ) {
    throw new HttpBodyError('media-type');
  }
}

/** Rejects an oversized declared body before Fastify materializes it. */
export function assertDeclaredBodyWithinLimit(
  value: string | string[] | undefined,
  maximumBytes: number,
): void {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    throw new TypeError('HTTP body limit must be a positive safe integer');
  }

  if (Array.isArray(value)) {
    throw new HttpBodyError('invalid-json');
  }
  const contentLength = singleHeader(value);
  if (contentLength === undefined) {
    return;
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
    throw new HttpBodyError('invalid-json');
  }

  const bytes = Number(contentLength);
  if (!Number.isSafeInteger(bytes)) {
    throw new HttpBodyError('too-large');
  }
  if (bytes > maximumBytes) {
    throw new HttpBodyError('too-large');
  }
}

/**
 * Fastify's JSON parser runs after `onRequest`, so route authentication has
 * already completed when this body becomes observable.
 */
export function parsedJsonBody(request: FastifyRequest): unknown {
  if (request.body === undefined) {
    throw new HttpBodyError('invalid-json');
  }
  return request.body;
}

export function bodyFailureKind(error: unknown): BodyFailureKind | undefined {
  if (error instanceof HttpBodyError) {
    return error.kind;
  }
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }

  const code = 'code' in error ? error.code : undefined;
  switch (code) {
    case 'FST_ERR_CTP_BODY_TOO_LARGE':
      return 'too-large';
    case 'FST_ERR_CTP_INVALID_MEDIA_TYPE':
      return 'media-type';
    case 'FST_ERR_CTP_INVALID_JSON_BODY':
      return 'invalid-json';
    default:
      return undefined;
  }
}
