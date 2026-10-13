import { Buffer } from 'node:buffer';
import type { ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { extname } from 'node:path';

export const STATIC_CACHE_CONTROL = 'no-store, private, max-age=0';
export const STATIC_PRAGMA = 'no-cache';
export const STATIC_METHOD_ALLOW = 'GET, HEAD';

const MIME_TYPES: Readonly<Record<string, string>> = {
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

export interface StaticHttpResponse {
  readonly statusCode: 200 | 404 | 405 | 500;
  readonly body: Uint8Array;
  readonly contentType?: string;
  readonly allow?: string;
}

export function staticMimeType(pathname: string): string {
  return MIME_TYPES[extname(pathname).toLowerCase()] ?? 'application/octet-stream';
}

export function staticNotFound(): StaticHttpResponse {
  return {
    statusCode: 404,
    body: Buffer.alloc(0),
  };
}
export function staticInternalServerError(): StaticHttpResponse {
  return {
    statusCode: 500,
    body: Buffer.alloc(0),
  };
}

export function staticMethodNotAllowed(): StaticHttpResponse {
  return {
    statusCode: 405,
    body: Buffer.alloc(0),
    allow: STATIC_METHOD_ALLOW,
  };
}

export function writeStaticResponse(
  response: ServerResponse,
  method: string | undefined,
  result: StaticHttpResponse,
): void {
  response.writeHead(result.statusCode, staticResponseHeaders(result));
  response.end(method === 'HEAD' ? undefined : result.body);
}

export function writeStaticSocketResponse(
  socket: Duplex,
  result: StaticHttpResponse,
): Promise<void> {
  const body = result.body;
  const head = Buffer.from(
    [
      `HTTP/1.1 ${result.statusCode} ${staticStatusText(result.statusCode)}`,
      ...Object.entries(staticResponseHeaders(result)).map(([name, value]) => `${name}: ${value}`),
      'Connection: close',
      '',
      '',
    ].join('\r\n'),
    'ascii',
  );
  return new Promise((resolve, reject) => {
    let completed = false;
    const cleanup = (): void => {
      socket.off('finish', complete);
      socket.off('close', complete);
      socket.off('error', fail);
    };
    const complete = (): void => {
      if (!completed) {
        completed = true;
        cleanup();
        body.fill(0);
        resolve();
      }
    };
    const fail = (error: Error): void => {
      if (!completed) {
        completed = true;
        cleanup();
        body.fill(0);
        reject(error);
      }
    };
    socket.once('finish', complete);
    socket.once('close', complete);
    socket.once('error', fail);
    if (socket.destroyed) {
      complete();
      return;
    }
    try {
      socket.write(head);
      socket.end(body);
    } catch (error: unknown) {
      fail(error instanceof Error ? error : new Error('static socket response failed'));
    }
  });
}

function staticResponseHeaders(result: StaticHttpResponse): Record<string, string> {
  const headers: Record<string, string> = {
    'Cache-Control': STATIC_CACHE_CONTROL,
    'Content-Length': String(result.body.byteLength),
    Pragma: STATIC_PRAGMA,
  };
  if (result.contentType !== undefined) {
    headers['Content-Type'] = result.contentType;
  }
  if (result.allow !== undefined) {
    headers.Allow = result.allow;
  }
  return headers;
}

function staticStatusText(statusCode: StaticHttpResponse['statusCode']): string {
  switch (statusCode) {
    case 200:
      return 'OK';
    case 404:
      return 'Not Found';
    case 405:
      return 'Method Not Allowed';
    case 500:
      return 'Internal Server Error';
  }
}
