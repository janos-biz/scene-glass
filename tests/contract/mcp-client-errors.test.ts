import { describe, expect, it, vi } from 'vitest';
import type {
  CreateAnnotationInput,
  DeleteAnnotationInput,
  ElementAnnotation,
  PageId,
  PageIdentityInput,
  UpdateAnnotationInput,
  UuidV4,
} from '@scene-glass/contracts';

import {
  MCP_PROTOCOL_VERSION,
  McpClient,
  McpClientError,
  McpHttpError,
  McpProtocolError,
  McpRpcDomainError,
  SceneGlassClient,
  createSceneGlassApi,
  type FetchLike,
} from '../../packages/browser-client/src/index.js';
import type {
  AnnotationListToolResult,
  AnnotationMutationToolResult,
  PromptExportToolResult,
} from '../../packages/browser-client/src/mcp-client.js';

type Equal<Left, Right> =
  (<Type>() => Type extends Left ? 1 : 2) extends <Type>() => Type extends Right ? 1 : 2
    ? true
    : false;
type Assert<Condition extends true> = Condition;

function assertDecodedResultTypeContracts(mcp: McpClient, client: SceneGlassClient): void {
  const assertions: readonly [
    Assert<Equal<ReturnType<McpClient['listAnnotations']>, Promise<AnnotationListToolResult>>>,
    Assert<Equal<ReturnType<McpClient['createAnnotation']>, Promise<AnnotationMutationToolResult>>>,
    Assert<Equal<ReturnType<McpClient['updateAnnotation']>, Promise<AnnotationMutationToolResult>>>,
    Assert<Equal<ReturnType<McpClient['deleteAnnotation']>, Promise<AnnotationMutationToolResult>>>,
    Assert<Equal<ReturnType<McpClient['exportPrompt']>, Promise<PromptExportToolResult>>>,
    Assert<
      Equal<ReturnType<SceneGlassClient['listAnnotations']>, Promise<AnnotationListToolResult>>
    >,
    Assert<
      Equal<ReturnType<SceneGlassClient['createAnnotation']>, Promise<AnnotationMutationToolResult>>
    >,
    Assert<
      Equal<ReturnType<SceneGlassClient['updateAnnotation']>, Promise<AnnotationMutationToolResult>>
    >,
    Assert<
      Equal<ReturnType<SceneGlassClient['deleteAnnotation']>, Promise<AnnotationMutationToolResult>>
    >,
    Assert<Equal<ReturnType<SceneGlassClient['exportPrompt']>, Promise<PromptExportToolResult>>>,
  ] = [true, true, true, true, true, true, true, true, true, true];
  void assertions;

  // @ts-expect-error decoded list results cannot be caller-selected.
  void mcp.listAnnotations<{ readonly fabricated: true }>(page);
  // @ts-expect-error decoded mutation results cannot be caller-selected.
  void mcp.createAnnotation<{ readonly fabricated: true }>(createInput);
  // @ts-expect-error decoded mutation results cannot be caller-selected.
  void mcp.updateAnnotation<{ readonly fabricated: true }>(updateInput);
  // @ts-expect-error decoded mutation results cannot be caller-selected.
  void mcp.deleteAnnotation<{ readonly fabricated: true }>(deleteInput);
  // @ts-expect-error decoded prompt results cannot be caller-selected.
  void mcp.exportPrompt<{ readonly fabricated: true }>({ mode: 'project' });
  // @ts-expect-error client wrappers cannot be caller-selected.
  void client.listAnnotations<{ readonly fabricated: true }>(page);
  // @ts-expect-error client wrappers cannot be caller-selected.
  void client.createAnnotation<{ readonly fabricated: true }>(createInput);
  // @ts-expect-error client wrappers cannot be caller-selected.
  void client.updateAnnotation<{ readonly fabricated: true }>(updateInput);
  // @ts-expect-error client wrappers cannot be caller-selected.
  void client.deleteAnnotation<{ readonly fabricated: true }>(deleteInput);
  // @ts-expect-error client wrappers cannot be caller-selected.
  void client.exportPrompt<{ readonly fabricated: true }>({ mode: 'project' });
}
void assertDecodedResultTypeContracts;

const endpoint = 'http://127.0.0.1:4175/mcp/v1/projects/browser-errors';
const diagnosticEndpoint = 'http://127.0.0.1:4175/mcp/v1/diagnostics/browser-errors';
const token = 't'.repeat(64);
const pageId = `p_${'a'.repeat(64)}` as PageId;
const annotationId = '123e4567-e89b-42d3-a456-426614174000' as UuidV4;
const operationId = '223e4567-e89b-42d3-a456-426614174000' as UuidV4;
const page: PageIdentityInput = {
  policyVersion: 1,
  canonicalIdentity: '/browser-errors',
  route: '/browser-errors',
  pageId,
};
const annotation: ElementAnnotation = {
  id: annotationId,
  locator: { dataScgId: 'annotation-target' },
  memo: 'Browser error test annotation',
  surroundingText: '',
  domOrder: 0,
  resolution: { status: 'resolved', reason: null },
  createdAt: '2026-07-16T00:00:00.000Z',
  updatedAt: '2026-07-16T00:00:00.000Z',
};
const createInput: CreateAnnotationInput = {
  page,
  expectedRevision: 0,
  operationId,
  locator: annotation.locator,
  memo: annotation.memo,
  surroundingText: annotation.surroundingText,
  domOrder: annotation.domOrder,
  resolution: annotation.resolution,
};
const updateInput: UpdateAnnotationInput = {
  page,
  annotationId,
  expectedRevision: 0,
  operationId,
  patch: { memo: 'Updated browser error test annotation' },
};
const deleteInput: DeleteAnnotationInput = {
  page,
  annotationId,
  expectedRevision: 0,
  operationId,
};
const diagnosticRunId = `diagnostic-${'A'.repeat(22)}`;
const diagnosticToken = 'A'.repeat(43);

function isSessionClose(init: RequestInit | undefined): boolean {
  return init?.method === 'DELETE';
}

function closedSessionAcknowledgement(): Response {
  return new Response(null, { status: 204 });
}

function diagnosticCapability(
  now: number,
  overrides: Partial<{
    endpoint: string;
    expiresAt: string;
    runId: string;
    token: string;
  }> = {},
): {
  endpoint: string;
  expiresAt: string;
  runId: string;
  token: string;
} {
  return {
    runId: diagnosticRunId,
    token: diagnosticToken,
    expiresAt: new Date(now + 60_000).toISOString(),
    endpoint,
    ...overrides,
  };
}

function rpcRequest(init: RequestInit | undefined): Record<string, unknown> {
  if (typeof init?.body !== 'string') {
    throw new Error('expected a JSON request body');
  }
  return JSON.parse(init.body) as Record<string, unknown>;
}

function jsonResponse(value: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function domainFailure(id: unknown, data: Record<string, unknown>): Response {
  return jsonResponse({
    jsonrpc: '2.0',
    id,
    error: {
      code: -32_000,
      message: 'Scene Glass operation failed',
      data,
    },
  });
}
function initializeResponse(
  request: Record<string, unknown>,
  sessionId = 'browser-session',
): Response {
  return jsonResponse(
    {
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'scene-glass', version: '0.1.0' },
      },
    },
    { 'mcp-session-id': sessionId },
  );
}

function initializedAcknowledgement(): Response {
  return new Response(null, { status: 202 });
}

function withHandshake(
  handler: (request: Record<string, unknown>, init: RequestInit | undefined) => Response,
): FetchLike {
  return async (_input, init) => {
    if (isSessionClose(init)) {
      return closedSessionAcknowledgement();
    }
    const request = rpcRequest(init);
    if (request.method === 'initialize') {
      return initializeResponse(request);
    }
    if (request.method === 'notifications/initialized') {
      return initializedAcknowledgement();
    }
    return handler(request, init);
  };
}
async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}
function countErrorIdentity(
  root: unknown,
  expected: unknown,
  visited: Set<object> = new Set<object>(),
): number {
  const occurrences = root === expected ? 1 : 0;
  if (typeof root !== 'object' || root === null || visited.has(root)) {
    return occurrences;
  }
  visited.add(root);
  const nestedErrors: readonly unknown[] =
    root instanceof AggregateError
      ? root.errors
      : root instanceof McpClientError
        ? root.cleanupErrors
        : [];
  return (
    occurrences +
    nestedErrors.reduce<number>(
      (count, error) => count + countErrorIdentity(error, expected, visited),
      0,
    )
  );
}

describe('browser JSON-RPC domain errors', () => {
  it('preserves stable scalar domain data', async () => {
    const fetch = withHandshake((request) =>
      domainFailure(request.id, {
        code: 'SCG_LIMIT_FILE',
        limit: 32,
        retryable: false,
        detail: null,
      }),
    );
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });
    await client.initialize();

    const error = await client.ping().catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(McpRpcDomainError);
    expect(error).toMatchObject({ code: 'SCG_LIMIT_FILE', rpcCode: -32_000 });
    expect((error as McpRpcDomainError).data).toEqual({
      code: 'SCG_LIMIT_FILE',
      limit: 32,
      retryable: false,
      detail: null,
    });
    expect(Object.isFrozen((error as McpRpcDomainError).data)).toBe(true);
  });

  it.each([
    ['missing data', { code: -32_000, message: 'failed' }],
    ['non-SCG code', { code: -32_000, message: 'failed', data: { code: 'LIMIT_FILE' } }],
    [
      'nested data',
      { code: -32_000, message: 'failed', data: { code: 'SCG_LIMIT_FILE', nested: {} } },
    ],
    [
      'unsafe RPC code',
      { code: Number.MAX_SAFE_INTEGER + 1, message: 'failed', data: { code: 'SCG_LIMIT_FILE' } },
    ],
    [
      'extra envelope key',
      {
        code: -32_000,
        message: 'failed',
        data: { code: 'SCG_LIMIT_FILE' },
        extra: true,
      },
    ],
  ])('rejects malformed %s as a protocol error', async (_name, rpcError) => {
    const fetch = withHandshake((request) =>
      jsonResponse({ jsonrpc: '2.0', id: request.id, error: rpcError }),
    );
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });
    await client.initialize();

    await expect(client.ping()).rejects.toBeInstanceOf(McpProtocolError);
  });

  it('keeps Scene Glass ready after an operation-local domain failure', async () => {
    const states: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return jsonResponse(
          {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              protocolVersion: MCP_PROTOCOL_VERSION,
              capabilities: { tools: { listChanged: false } },
              serverInfo: { name: 'scene-glass', version: '0.1.0' },
            },
          },
          { 'mcp-session-id': 's_browser_domain_error' },
        );
      }
      if (request.method === 'notifications/initialized') {
        return new Response(null, { status: 202 });
      }
      return domainFailure(request.id, { code: 'SCG_REVISION_CONFLICT', currentRevision: 4 });
    };
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch,
      onStateChange: (state) => states.push(state),
    });

    await client.start();
    expect(client.state).toBe('ready');
    await expect(client.exportPrompt({ mode: 'project' })).rejects.toMatchObject({
      code: 'SCG_REVISION_CONFLICT',
    });
    expect(client.state).toBe('ready');
    expect(states).toEqual(['connecting', 'ready']);
  });
});
describe('browser MCP transport validation', () => {
  it('rejects a malformed initialize negotiation before accepting its session', async () => {
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      return jsonResponse(
        {
          jsonrpc: '2.0',
          id: request.id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: 'scene-glass', version: '0.1.0' },
          },
        },
        { 'mcp-session-id': 'invalid-negotiation-session' },
      );
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
    expect(closedSessionIds).toEqual(['invalid-negotiation-session']);
  });

  it('requires an empty accepted initialized-notification acknowledgement', async () => {
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return initializeResponse(request);
      }
      return new Response('unexpected acknowledgement body', { status: 202 });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
    expect(closedSessionIds).toEqual(['browser-session']);
  });

  it('rejects fragmented, never-closing SSE and cancels the response body', async () => {
    let cancelled = false;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method !== 'initialize') {
        throw new Error('unexpected MCP request');
      }
      expect(new Headers(init?.headers).get('accept')).toBe('application/json');
      const message = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'scene-glass', version: '0.1.0' },
        },
      });
      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('data: '));
          controller.enqueue(encoder.encode(message.slice(0, 8)));
          controller.enqueue(encoder.encode(message.slice(8)));
        },
        cancel() {
          cancelled = true;
        },
      });
      return new Response(stream, {
        status: 200,
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
          'mcp-session-id': 'sse-session',
        },
      });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
    expect(cancelled).toBe(true);
    expect(closedSessionIds).toEqual(['sse-session']);
  });

  it('preserves an HTTP authentication failure when response cancellation rejects', async () => {
    const cancellationFailure = new Error('response cancellation failed');
    const fetch: FetchLike = async () => {
      const stream = new ReadableStream<Uint8Array>({
        cancel() {
          return Promise.reject(cancellationFailure);
        },
      });
      return new Response(stream, {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const error = await client.initialize().catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(McpHttpError);
    expect(error).toMatchObject({ status: 401, cleanupErrors: [cancellationFailure] });
    const classifiedClient = new SceneGlassClient({ endpoint, diagnosticEndpoint, token, fetch });
    await classifiedClient.start();
    expect(classifiedClient.state).toBe('access-error');
  });

  it('preserves a failed initialize HTTP error when session DELETE cleanup rejects', async () => {
    const cleanupFailure = new Error('session cleanup failed');
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        throw cleanupFailure;
      }
      return new Response(null, {
        status: 403,
        headers: {
          'content-type': 'application/json',
          'mcp-session-id': 'failed-initialize-session',
        },
      });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const error = await client.initialize().catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(McpHttpError);
    expect(error).toMatchObject({ status: 403, cleanupErrors: [cleanupFailure] });
    const classifiedClient = new SceneGlassClient({ endpoint, diagnosticEndpoint, token, fetch });
    await classifiedClient.start();
    expect(classifiedClient.state).toBe('access-error');
  });

  it('preserves a response parse failure when reader cancellation rejects', async () => {
    const cancellationFailure = new Error('reader cancellation failed');
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([0xff]));
        },
        cancel() {
          return Promise.reject(cancellationFailure);
        },
      });
      return new Response(stream, {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'mcp-session-id': 'invalid-json-session',
        },
      });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const error = await client.initialize().catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(McpProtocolError);
    expect(error).toMatchObject({ cleanupErrors: [cancellationFailure] });
  });

  it('rejects malformed structured content for every supported tool result', async () => {
    const fetch = withHandshake((request) => {
      const toolName =
        request.params !== null && typeof request.params === 'object'
          ? (request.params as Record<string, unknown>).name
          : undefined;
      const structuredContent =
        toolName === 'annotations.list'
          ? { page, revision: Number.MAX_SAFE_INTEGER + 1, annotations: [] }
          : toolName === 'annotations.create'
            ? { replay: { kind: 'create', revision: 1 }, revision: 1 }
            : toolName === 'annotations.update'
              ? { replay: { kind: 'update', revision: 1, annotation }, revision: 2 }
              : toolName === 'annotations.delete'
                ? { replay: { kind: 'delete', revision: 1 }, revision: 1 }
                : { mode: 'project', markdown: 42 };
      return jsonResponse({
        jsonrpc: '2.0',
        id: request.id,
        result: { structuredContent },
      });
    });
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await client.initialize();
    const calls: readonly (() => Promise<unknown>)[] = [
      () => client.listAnnotations(page),
      () => client.createAnnotation(createInput),
      () => client.updateAnnotation(updateInput),
      () => client.deleteAnnotation(deleteInput),
      () => client.exportPrompt({ mode: 'project' }),
    ];
    for (const call of calls) {
      await expect(call()).rejects.toBeInstanceOf(McpProtocolError);
    }
  });
  it('lets session-only callers complete at session capture when full initialization started first', async () => {
    let initializeCalls = 0;
    let initializedCalls = 0;
    let resolveInitialized: (() => void) | undefined;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return initializeResponse(request, 'full-first-session');
      }
      if (request.method === 'notifications/initialized') {
        initializedCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveInitialized = () => resolve(initializedAcknowledgement());
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const full = client.initialize();
    const session = client.initializeSession();
    expect(client.initialize()).toBe(full);
    expect(client.initializeSession()).toBe(session);

    let fullSettled = false;
    void full.then(
      () => {
        fullSettled = true;
      },
      () => {
        fullSettled = true;
      },
    );
    await expect(session).resolves.toEqual(expect.any(Object));
    await flushMicrotasks();

    expect(fullSettled).toBe(false);
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);

    const resolve = resolveInitialized;
    if (resolve === undefined) {
      throw new Error('initialized notification did not reach the transport');
    }
    resolve();

    await expect(full).resolves.toEqual(expect.any(Object));
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);
  });
  it('upgrades an active session-only initialization to one full handshake', async () => {
    let initializeCalls = 0;
    let initializedCalls = 0;
    let resolveInitialize: (() => void) | undefined;
    let resolveInitialized: (() => void) | undefined;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveInitialize = () => resolve(initializeResponse(request, 'session-first-session'));
        });
      }
      if (request.method === 'notifications/initialized') {
        initializedCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveInitialized = () => resolve(initializedAcknowledgement());
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const session = client.initializeSession();
    const full = client.initialize();
    expect(client.initializeSession()).toBe(session);
    expect(client.initialize()).toBe(full);
    await flushMicrotasks();

    const resolveSession = resolveInitialize;
    if (resolveSession === undefined) {
      throw new Error('initialize did not reach the transport');
    }
    resolveSession();
    await expect(session).resolves.toEqual(expect.any(Object));
    await flushMicrotasks();

    let fullSettled = false;
    void full.then(
      () => {
        fullSettled = true;
      },
      () => {
        fullSettled = true;
      },
    );
    expect(fullSettled).toBe(false);
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);

    const resolveNotification = resolveInitialized;
    if (resolveNotification === undefined) {
      throw new Error('initialized notification did not reach the transport');
    }
    resolveNotification();

    await expect(full).resolves.toEqual(expect.any(Object));
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);
  });
  it('publishes cross-mode and notification ownership before synchronous transport re-entry', async () => {
    let reentrantFull: Promise<unknown> | undefined;
    let reentrantSession: Promise<unknown> | undefined;
    let reentrantNotification: Promise<void> | undefined;
    let initializeCalls = 0;
    let initializedCalls = 0;
    const fetch: FetchLike = async (_input, init) => {
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        const activeClient = client;
        if (activeClient === undefined) {
          throw new Error('client was not assigned before transport entry');
        }
        reentrantSession = activeClient.initializeSession();
        reentrantFull = activeClient.initialize();
        return initializeResponse(request, 'reentrant-session');
      }
      if (request.method === 'notifications/initialized') {
        initializedCalls += 1;
        const activeClient = client;
        if (activeClient === undefined) {
          throw new Error('client was not assigned before transport entry');
        }
        reentrantNotification = activeClient.sendInitializedNotification();
        return initializedAcknowledgement();
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const full = client.initialize();
    const session = client.initializeSession();
    await expect(full).resolves.toEqual(expect.any(Object));

    expect(reentrantFull).toBe(full);
    expect(reentrantSession).toBe(session);
    const notification = reentrantNotification;
    if (notification === undefined) {
      throw new Error('initialized notification did not re-enter the client');
    }
    await expect(notification).resolves.toBeUndefined();
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);
  });
  it('waits for an upgraded full handshake to clean up before close resolves', async () => {
    let initializeCalls = 0;
    let initializedCalls = 0;
    let resolveInitialize: (() => void) | undefined;
    let resolveInitialized: (() => void) | undefined;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveInitialize = () => resolve(initializeResponse(request, 'upgrade-close-session'));
        });
      }
      if (request.method === 'notifications/initialized') {
        initializedCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveInitialized = () => resolve(initializedAcknowledgement());
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const session = client.initializeSession();
    const full = client.initialize();
    const fullFailure = full.catch((error: unknown) => error);
    await flushMicrotasks();

    const resolveSession = resolveInitialize;
    if (resolveSession === undefined) {
      throw new Error('initialize did not reach the transport');
    }
    resolveSession();
    await expect(session).resolves.toEqual(expect.any(Object));
    await flushMicrotasks();

    const close = client.close();
    let closeSettled = false;
    void close.then(
      () => {
        closeSettled = true;
      },
      () => {
        closeSettled = true;
      },
    );
    await flushMicrotasks();

    expect(closeSettled).toBe(false);
    expect(closedSessionIds).toEqual([]);
    const resolveNotification = resolveInitialized;
    if (resolveNotification === undefined) {
      throw new Error('initialized notification did not reach the transport');
    }
    resolveNotification();

    await expect(fullFailure).resolves.toMatchObject({
      message: 'MCP session was superseded',
    });
    await expect(close).resolves.toBeUndefined();
    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);
    expect(closedSessionIds).toEqual(['upgrade-close-session']);
  });
  it('reports a failing DELETE once when close interrupts a pending initialized notification', async () => {
    const deleteFailure = new Error('pending notification cleanup failed');
    let deleteCalls = 0;
    let notificationStarted = false;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        deleteCalls += 1;
        throw deleteFailure;
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return initializeResponse(request, 'pending-notification-session');
      }
      if (request.method === 'notifications/initialized') {
        notificationStarted = true;
        const signal = init?.signal;
        if (signal === null || signal === undefined) {
          throw new Error('initialized notification omitted its abort signal');
        }
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => {
              reject(signal.reason);
            },
            { once: true },
          );
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const sessionInitialization = client.initializeSession();
    const initialization = client.initialize();
    const initializationFailure = initialization.catch((error: unknown) => error);
    await expect(sessionInitialization).resolves.toEqual(expect.any(Object));
    await flushMicrotasks();
    expect(notificationStarted).toBe(true);

    const closeFailure = await client.close().catch((error: unknown) => error);
    const fullInitializationFailure = await initializationFailure;
    expect(deleteCalls).toBe(1);
    expect(closeFailure).toBe(fullInitializationFailure);
    expect(fullInitializationFailure).toMatchObject({
      cleanupErrors: [deleteFailure],
      message: 'MCP session was superseded',
    });
    expect(countErrorIdentity(closeFailure, deleteFailure)).toBe(1);
  });
  it('cleans up a failed upgrade without weakening session-only completion', async () => {
    let initializeCalls = 0;
    let initializedCalls = 0;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return initializeResponse(request, 'upgrade-failure-session');
      }
      if (request.method === 'notifications/initialized') {
        initializedCalls += 1;
        return new Response('unexpected acknowledgement body', { status: 202 });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const session = client.initializeSession();
    const full = client.initialize();
    expect(client.initialize()).toBe(full);
    await expect(session).resolves.toEqual(expect.any(Object));
    await expect(full).rejects.toBeInstanceOf(McpProtocolError);

    expect(initializeCalls).toBe(1);
    expect(initializedCalls).toBe(1);
    expect(closedSessionIds).toEqual(['upgrade-failure-session']);
  });

  it('shares initialization ownership and waits for late initialization cleanup before close resolves', async () => {
    let initializeCalls = 0;
    const initializationSignal: { value: AbortSignal | null } = { value: null };
    let resolveFirstInitialize: (() => void) | undefined;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        initializationSignal.value = init?.signal ?? null;
        return new Promise<Response>((resolve) => {
          resolveFirstInitialize = () => resolve(initializeResponse(request, 'old-session'));
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const first = client.initialize();
    expect(client.initialize()).toBe(first);
    await flushMicrotasks();
    expect(initializationSignal.value?.aborted).toBe(false);

    const close = client.close();
    expect(initializationSignal.value?.aborted).toBe(true);
    let closeSettled = false;
    void close.then(
      () => {
        closeSettled = true;
      },
      () => {
        closeSettled = true;
      },
    );
    await flushMicrotasks();
    expect(closeSettled).toBe(false);

    const resolve = resolveFirstInitialize;
    if (resolve === undefined) {
      throw new Error('first initialization did not reach the transport');
    }
    resolve();

    await expect(close).resolves.toBeUndefined();
    expect(await first.catch((error: unknown) => error)).toBeInstanceOf(McpClientError);
    expect(initializeCalls).toBe(1);
    expect(closedSessionIds).toEqual(['old-session']);
  });
  it('preserves late initialization cleanup failures through close', async () => {
    const cleanupFailure = new Error('late initialization cleanup failed');
    const closedSessionIds: string[] = [];
    let resolveInitialize: (() => void) | undefined;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        throw cleanupFailure;
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return new Promise<Response>((resolve) => {
          resolveInitialize = () => resolve(initializeResponse(request, 'late-session'));
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const first = client.initialize();
    const firstFailure = first.catch((error: unknown) => error);
    await flushMicrotasks();
    const close = client.close();
    const resolve = resolveInitialize;
    if (resolve === undefined) {
      throw new Error('initialization did not reach the transport');
    }
    resolve();

    const closeFailure = await close.catch((error: unknown) => error);
    const initializationFailure = await firstFailure;
    expect(closeFailure).toBe(initializationFailure);
    expect(closeFailure).toMatchObject({
      cleanupErrors: [cleanupFailure],
      message: 'MCP session was superseded',
    });
    expect(closedSessionIds).toEqual(['late-session']);
  });
  it('times out an abort-ignoring initialization drain and observes its late cleanup', async () => {
    vi.useFakeTimers();
    try {
      let resolveInitialize: (() => void) | undefined;
      const fetch: FetchLike = async (_input, init) => {
        if (isSessionClose(init)) {
          return closedSessionAcknowledgement();
        }

        const request = rpcRequest(init);
        if (request.method === 'initialize') {
          return new Promise<Response>((resolve) => {
            resolveInitialize = () => resolve(initializeResponse(request, 'late-session'));
          });
        }
        throw new Error('unexpected MCP request');
      };
      const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

      const initialization = client.initialize();
      const initializationFailure = initialization.catch((error: unknown) => error);
      await flushMicrotasks();
      const close = client.close();
      expect(client.close()).toBe(close);
      const closeFailure = close.catch((error: unknown) => error);

      await vi.advanceTimersByTimeAsync(10_000);
      await expect(closeFailure).resolves.toMatchObject({
        message: 'MCP session cleanup timed out',
      });

      const resolve = resolveInitialize;
      if (resolve === undefined) {
        throw new Error('initialization did not reach the transport');
      }
      resolve();
      await expect(initializationFailure).resolves.toMatchObject({
        message: 'MCP session was superseded',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('times out an abort-ignoring DELETE transport and observes its late response', async () => {
    vi.useFakeTimers();
    try {
      const deleteTransport: { signal: AbortSignal | null } = { signal: null };
      let resolveDelete: ((response: Response) => void) | undefined;
      const fetch: FetchLike = async (_input, init) => {
        if (isSessionClose(init)) {
          deleteTransport.signal = init?.signal ?? null;
          return new Promise<Response>((resolve) => {
            resolveDelete = resolve;
          });
        }

        const request = rpcRequest(init);
        if (request.method === 'initialize') {
          return initializeResponse(request);
        }
        if (request.method === 'notifications/initialized') {
          return initializedAcknowledgement();
        }
        throw new Error('unexpected MCP request');
      };
      const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

      await client.initialize();
      const close = client.close();
      expect(client.close()).toBe(close);
      const closeFailure = close.catch((error: unknown) => error);

      await flushMicrotasks();
      expect(deleteTransport.signal?.aborted).toBe(false);

      await vi.advanceTimersByTimeAsync(10_000);
      await expect(closeFailure).resolves.toMatchObject({
        message: 'MCP session cleanup timed out',
      });
      expect(deleteTransport.signal?.aborted).toBe(true);

      const resolve = resolveDelete;
      if (resolve === undefined) {
        throw new Error('DELETE did not reach the transport');
      }
      resolve(closedSessionAcknowledgement());
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });

  it('times out hung reader and response cancellation while retaining their primary failures', async () => {
    vi.useFakeTimers();
    try {
      let resolveReaderCancel: (() => void) | undefined;
      const readerFailure = new Error('reader failed');
      const reader = {
        cancel: () =>
          new Promise<void>((resolve) => {
            resolveReaderCancel = resolve;
          }),
        read: () => Promise.reject(readerFailure),
        releaseLock: () => undefined,
      } as unknown as ReadableStreamDefaultReader<Uint8Array>;
      const readerResponse = {
        body: { getReader: () => reader },
        headers: new Headers({ 'content-type': 'application/json' }),
        status: 200,
      } as unknown as Response;
      const readerClient = new McpClient({
        endpoint,
        diagnosticEndpoint,
        token,
        fetch: async () => readerResponse,
      });

      const readerInitialization = readerClient.initialize();
      const readerInitializationFailure = readerInitialization.catch((error: unknown) => error);
      await flushMicrotasks();
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(readerInitializationFailure).resolves.toSatisfy((error: unknown) => {
        expect(error).toBeInstanceOf(AggregateError);
        expect((error as AggregateError).errors).toEqual([
          readerFailure,
          expect.objectContaining({ message: 'MCP session cleanup timed out' }),
        ]);
        return true;
      });
      resolveReaderCancel?.();
      await Promise.resolve();

      let resolveBodyCancel: (() => void) | undefined;
      const body = {
        cancel: () =>
          new Promise<void>((resolve) => {
            resolveBodyCancel = resolve;
          }),
      } as unknown as ReadableStream<Uint8Array>;
      const fetch: FetchLike = async (_input, init) => {
        if (isSessionClose(init)) {
          return {
            body,
            headers: new Headers(),
            status: 204,
          } as unknown as Response;
        }

        const request = rpcRequest(init);
        if (request.method === 'initialize') {
          return initializeResponse(request);
        }
        if (request.method === 'notifications/initialized') {
          return initializedAcknowledgement();
        }
        throw new Error('unexpected MCP request');
      };
      const responseClient = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

      await responseClient.initialize();
      const close = responseClient.close();
      const closeFailure = close.catch((error: unknown) => error);
      await flushMicrotasks();
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(closeFailure).resolves.toMatchObject({
        message: 'MCP session cleanup timed out',
      });
      resolveBodyCancel?.();
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });

  it('publishes initialization ownership before a synchronous transport re-entry', async () => {
    let reentrantInitialization: Promise<unknown> | undefined;
    const fetch: FetchLike = async (_input, init) => {
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        const activeClient = client;
        if (activeClient === undefined) {
          throw new Error('client was not assigned before transport entry');
        }
        reentrantInitialization = activeClient.initialize();
        return initializeResponse(request);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    const initialization = client.initialize();
    await expect(initialization).resolves.toEqual(expect.any(Object));
    expect(reentrantInitialization).toBe(initialization);
  });
  it('publishes close ownership before a synchronous DELETE transport re-entry', async () => {
    let reentrantClose: Promise<void> | undefined;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const activeClient = client;
        if (activeClient === undefined) {
          throw new Error('client was not assigned before transport entry');
        }
        reentrantClose = activeClient.close();
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return initializeResponse(request);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await client.initialize();
    const close = client.close();
    await expect(close).resolves.toBeUndefined();
    expect(reentrantClose).toBe(close);
  });
  it('publishes replacement ownership before an old-signal abort listener re-enters initialize', async () => {
    let reentrantInitialization: Promise<unknown> | undefined;
    let initializeCalls = 0;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return initializeResponse(
          request,
          initializeCalls === 1 ? 'old-signal-session' : 'replacement-session',
        );
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      if (request.method === 'ping') {
        const activeClient = client;
        const signal = init?.signal;
        if (activeClient === undefined || signal === null || signal === undefined) {
          throw new Error('ping did not receive an active client signal');
        }
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => {
              reentrantInitialization = activeClient.initialize();
              reject(signal.reason);
            },
            { once: true },
          );
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await client.initialize();
    await flushMicrotasks();
    const pingFailure = client.ping().catch((error: unknown) => error);
    await flushMicrotasks();

    const replacement = client.initialize();
    await expect(replacement).resolves.toEqual(expect.any(Object));
    await expect(pingFailure).resolves.toMatchObject({ message: 'MCP session was superseded' });
    expect(reentrantInitialization).toBe(replacement);
    expect(initializeCalls).toBe(2);
    expect(closedSessionIds).toEqual(['old-signal-session']);
  });
  it('drains prior-session cleanup exactly once when an old-signal abort listener re-enters close', async () => {
    let reentrantClose: Promise<void> | undefined;
    let initializeCalls = 0;
    const closedSessionIds: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        const sessionId = new Headers(init?.headers).get('mcp-session-id');
        if (sessionId === null) {
          throw new Error('session cleanup omitted its session ID');
        }
        closedSessionIds.push(sessionId);
        return closedSessionAcknowledgement();
      }

      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        return initializeResponse(request, 'reentrant-close-session');
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      if (request.method === 'ping') {
        const activeClient = client;
        const signal = init?.signal;
        if (activeClient === undefined || signal === null || signal === undefined) {
          throw new Error('ping did not receive an active client signal');
        }
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => {
              reentrantClose = activeClient.close();
              reject(signal.reason);
            },
            { once: true },
          );
        });
      }
      throw new Error('unexpected MCP request');
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch });

    await client.initialize();
    await flushMicrotasks();
    const pingFailure = client.ping().catch((error: unknown) => error);
    await flushMicrotasks();

    const replacementFailure = client.initialize().catch((error: unknown) => error);
    const close = reentrantClose;
    if (close === undefined) {
      throw new Error('old-signal abort listener did not re-enter close');
    }

    await expect(replacementFailure).resolves.toMatchObject({
      message: 'MCP session was superseded',
    });
    await expect(close).resolves.toBeUndefined();
    await expect(pingFailure).resolves.toMatchObject({ message: 'MCP session was superseded' });
    expect(client.close()).toBe(close);
    expect(initializeCalls).toBe(1);
    expect(closedSessionIds).toEqual(['reentrant-close-session']);
  });
});

describe('browser diagnostic capability validation', () => {
  it.each([
    ['non-canonical run ID', { runId: `diagnostic-${'A'.repeat(21)}B` }],
    ['non-canonical token', { token: `${'A'.repeat(42)}B` }],
    ['expired timestamp', { expiresAt: '2027-01-15T08:00:00.000Z' }],
    ['different origin', { endpoint: 'http://127.0.0.1:4176/mcp/v1/projects/browser-errors' }],
    ['different path', { endpoint: `${endpoint}/other` }],
    ['credentials', { endpoint: 'http://user@127.0.0.1:4175/mcp/v1/projects/browser-errors' }],
    ['query', { endpoint: `${endpoint}?run=1` }],
    ['fragment', { endpoint: `${endpoint}#run` }],
  ])('rejects a diagnostic capability with %s', async (_name, overrides) => {
    const now = Date.parse('2027-01-15T08:00:00.000Z');
    const fetch: FetchLike = async (input) => {
      if (String(input) !== diagnosticEndpoint) {
        throw new Error('unexpected MCP request');
      }
      return new Response(JSON.stringify(diagnosticCapability(now, overrides)), {
        status: 201,
        headers: {
          'cache-control': 'no-store',
          'content-type': 'application/json',
        },
      });
    };
    const client = new McpClient({ endpoint, diagnosticEndpoint, token, fetch, now: () => now });

    await expect(client.issueDiagnosticRun()).rejects.toBeInstanceOf(McpProtocolError);
  });
});
describe('browser diagnostics failure isolation', () => {
  it('rejects an unready or panel-less diagnostics request without changing readiness', async () => {
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch: withHandshake((request) =>
        jsonResponse({ jsonrpc: '2.0', id: request.id, result: {} }),
      ),
    });

    const api = createSceneGlassApi(client);
    await expect(api.openDiagnostics()).rejects.toThrow('not ready');
    await client.start();
    await expect(api.openDiagnostics()).rejects.toThrow('panel is unavailable');
    expect(client.state).toBe('ready');
  });

  it('returns a failed session close through the public API destroy promise', async () => {
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return new Response(null, { status: 503 });
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return initializeResponse(request);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      throw new Error('unexpected MCP request');
    };
    const client = new SceneGlassClient({ endpoint, diagnosticEndpoint, token, fetch });
    const api = createSceneGlassApi(client);

    await client.start();
    await expect(api.destroy()).rejects.toMatchObject({ status: 503 });
    expect(client.state).toBe('destroyed');
  });
  it('keeps a ready client available when the diagnostics panel callback fails', async () => {
    const fetch: FetchLike = async (input, init) => {
      if (String(input) === diagnosticEndpoint) {
        return new Response(JSON.stringify(diagnosticCapability(Date.now())), {
          status: 201,
          headers: {
            'cache-control': 'no-store',
            'content-type': 'application/json',
          },
        });
      }
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        return initializeResponse(request);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      return jsonResponse({ jsonrpc: '2.0', id: request.id, result: {} });
    };
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch,
      openDiagnosticsPanel: async () => {
        throw new Error('panel failure');
      },
    });

    await client.start();
    await expect(client.openDiagnostics()).rejects.toThrow('panel failure');
    expect(client.state).toBe('ready');
  });
  it('ignores an old session failure after a newer retry reaches ready', async () => {
    let sessionCount = 0;
    let resolveStalePing: (() => void) | undefined;
    const fetch: FetchLike = async (input, init) => {
      if (String(input) === diagnosticEndpoint) {
        return new Response(null, { status: 503 });
      }
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        sessionCount += 1;
        return initializeResponse(request, `session-${sessionCount}`);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      const sessionId = new Headers(init?.headers).get('mcp-session-id');
      if (request.method === 'ping' && sessionId === 'session-1') {
        return new Promise<Response>((resolve) => {
          resolveStalePing = () => resolve(new Response(null, { status: 500 }));
        });
      }
      return jsonResponse({ jsonrpc: '2.0', id: request.id, result: {} });
    };
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch,
      openDiagnosticsPanel: async () => undefined,
    });

    await client.start();
    client.notifyReady();
    const resolve = resolveStalePing;
    if (resolve === undefined) {
      throw new Error('first-session ping did not reach the transport');
    }
    await expect(client.openDiagnostics()).rejects.toThrow('status 503');
    expect(client.state).toBe('unavailable');

    await client.retry();
    expect(client.state).toBe('ready');
    resolve();
    await new Promise<void>((complete) => globalThis.setTimeout(complete, 0));
    expect(client.state).toBe('ready');
  });
  it('runs a retry requested from an unavailable state callback', async () => {
    let initializeCalls = 0;
    let callbackRetry: Promise<void> | undefined;
    const states: string[] = [];
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        initializeCalls += 1;
        if (initializeCalls === 1) {
          return new Response(null, { status: 503 });
        }
        return initializeResponse(request, 'retry-session');
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }
      return jsonResponse({ jsonrpc: '2.0', id: request.id, result: {} });
    };
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch,
      onStateChange: (state) => {
        states.push(state);
        if (state === 'unavailable') {
          callbackRetry = client.retry();
        }
      },
    });

    await client.start();
    const retry = callbackRetry;
    if (retry === undefined) {
      throw new Error('unavailable callback did not request a retry');
    }
    await retry;

    expect(client.state).toBe('ready');
    expect(initializeCalls).toBe(2);
    expect(states).toEqual(['connecting', 'unavailable', 'connecting', 'ready']);
  });

  it('rejects a stale domain error after a newer session becomes ready', async () => {
    let sessionCount = 0;
    let resolveStaleDomainError: (() => void) | undefined;
    const fetch: FetchLike = async (_input, init) => {
      if (isSessionClose(init)) {
        return closedSessionAcknowledgement();
      }
      const request = rpcRequest(init);
      if (request.method === 'initialize') {
        sessionCount += 1;
        return initializeResponse(request, `session-${sessionCount}`);
      }
      if (request.method === 'notifications/initialized') {
        return initializedAcknowledgement();
      }

      const sessionId = new Headers(init?.headers).get('mcp-session-id');
      if (request.method === 'tools/call' && sessionId === 'session-1') {
        return new Promise<Response>((resolve) => {
          resolveStaleDomainError = () =>
            resolve(
              domainFailure(request.id, { code: 'SCG_REVISION_CONFLICT', currentRevision: 4 }),
            );
        });
      }
      if (request.method === 'ping' && sessionId === 'session-1') {
        return new Response(null, { status: 500 });
      }
      return jsonResponse({ jsonrpc: '2.0', id: request.id, result: {} });
    };
    const client = new SceneGlassClient({
      endpoint,
      diagnosticEndpoint,
      token,
      fetch,
    });

    await client.start();
    const staleOperation = client.exportPrompt({ mode: 'project' });
    client.notifyReady();
    await new Promise<void>((complete) => globalThis.setTimeout(complete, 0));
    expect(client.state).toBe('unavailable');

    await client.retry();
    expect(client.state).toBe('ready');
    const resolve = resolveStaleDomainError;
    if (resolve === undefined) {
      throw new Error('stale operation did not reach the transport');
    }
    resolve();

    await expect(staleOperation).rejects.toThrow('superseded');
    expect(client.state).toBe('ready');
  });
});
