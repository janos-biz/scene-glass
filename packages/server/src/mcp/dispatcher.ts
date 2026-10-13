import { SceneGlassContractError } from '@scene-glass/contracts';
import { ScreenReviewError } from '@scene-glass/core/screen-review';

import { ScgStorageError } from '../storage/path-guard.js';

export const MCP_PROTOCOL_VERSION = '2025-11-25';

export type McpScope = 'diagnostic' | 'normal';
export type McpToolName =
  | 'annotations.list'
  | 'annotations.create'
  | 'annotations.update'
  | 'annotations.delete'
  | 'prompt.export';
export type JsonRpcId = number | string;
export type McpErrorData = Readonly<Record<string, boolean | null | number | string>>;
export interface McpInvocationContext {
  readonly signal: AbortSignal;
}

export interface McpTool {
  readonly name: McpToolName;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  execute(argumentsValue: unknown, context: McpInvocationContext): Promise<unknown>;
}

export interface McpServerInfo {
  readonly name: string;
  readonly version: string;
}

export interface McpDispatcherOptions {
  readonly scope: McpScope;
  readonly tools?: readonly McpTool[];
  readonly serverInfo?: McpServerInfo;
}

export interface JsonRpcSuccess {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly result: unknown;
}

export interface JsonRpcFailure {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId | null;
  readonly error: Readonly<{
    code: number;
    message: string;
    data?: McpErrorData;
  }>;
}

export type JsonRpcResponse = JsonRpcFailure | JsonRpcSuccess;

export interface McpDispatcher {
  dispatch(message: unknown, context: McpInvocationContext): Promise<JsonRpcResponse | undefined>;
}

interface JsonRpcMessage {
  readonly id: JsonRpcId | undefined;
  readonly isNotification: boolean;
  readonly method: string;
  readonly params: unknown;
}

interface InitializeParams {
  readonly protocolVersion: typeof MCP_PROTOCOL_VERSION;
}

const APPROVED_TOOL_NAMES = new Set<McpToolName>([
  'annotations.list',
  'annotations.create',
  'annotations.update',
  'annotations.delete',
  'prompt.export',
]);
const DEFAULT_SERVER_INFO: McpServerInfo = Object.freeze({
  name: 'scene-glass',
  version: '0.1.0',
});

/** A stable operational error. Its message is never sent over the wire. */
export class McpRpcError extends Error {
  public readonly code: string;
  public readonly data: McpErrorData | undefined;

  public constructor(code: string, data?: McpErrorData) {
    super(code);
    this.name = 'McpRpcError';
    this.code = code;
    this.data = data;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function createMcpDispatcher(options: McpDispatcherOptions): McpDispatcher {
  return new StrictMcpDispatcher(options);
}

class StrictMcpDispatcher implements McpDispatcher {
  readonly #scope: McpScope;
  readonly #serverInfo: McpServerInfo;
  readonly #tools: ReadonlyMap<McpToolName, McpTool>;
  #initialized = false;
  #receivedInitializedNotification = false;

  public constructor(options: McpDispatcherOptions) {
    assertDispatcherOptions(options);
    this.#scope = options.scope;
    this.#serverInfo = Object.freeze({
      ...(options.serverInfo ?? DEFAULT_SERVER_INFO),
    });
    this.#tools = buildToolMap(options.scope, options.tools ?? []);
  }

  public async dispatch(
    message: unknown,
    context: McpInvocationContext,
  ): Promise<JsonRpcResponse | undefined> {
    let parsed: JsonRpcMessage;
    try {
      parsed = parseJsonRpcMessage(message);
    } catch {
      return invalidRequest();
    }

    if (parsed.isNotification) {
      await this.dispatchNotification(parsed, context);
      return undefined;
    }

    try {
      return success(await this.dispatchRequest(parsed, context), parsed.id);
    } catch (error: unknown) {
      return requestFailure(parsed.id, error);
    }
  }

  private async dispatchNotification(
    message: JsonRpcMessage,
    context: McpInvocationContext,
  ): Promise<void> {
    context.signal.throwIfAborted();
    if (message.method !== 'notifications/initialized') {
      return;
    }
    try {
      validateEmptyParams(message.params, 'initialized notification');
    } catch {
      // JSON-RPC notifications deliberately have no error response.
      return;
    }
    context.signal.throwIfAborted();
    if (!this.#initialized || this.#receivedInitializedNotification) {
      return;
    }
    this.#receivedInitializedNotification = true;
  }

  private async dispatchRequest(
    message: JsonRpcMessage,
    context: McpInvocationContext,
  ): Promise<unknown> {
    context.signal.throwIfAborted();
    switch (message.method) {
      case 'initialize':
        return this.initialize(message.params, context);
      case 'ping':
        return this.ping(message.params, context);
      case 'tools/list':
        return this.listTools(message.params, context);
      case 'tools/call':
        return this.callTool(message.params, context);
      default:
        throw new MethodNotFoundError();
    }
  }

  private initialize(params: unknown, context: McpInvocationContext): unknown {
    context.signal.throwIfAborted();
    if (this.#initialized) {
      throw new McpRpcError('SCG_MCP_ALREADY_INITIALIZED');
    }
    const input = parseInitializeParams(params);
    context.signal.throwIfAborted();
    if (input.protocolVersion !== MCP_PROTOCOL_VERSION) {
      throw new McpRpcError('SCG_MCP_PROTOCOL_VERSION');
    }
    this.#initialized = true;
    return Object.freeze({
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities:
        this.#scope === 'normal'
          ? Object.freeze({ tools: Object.freeze({ listChanged: false }) })
          : Object.freeze({}),
      serverInfo: this.#serverInfo,
    });
  }

  private ping(params: unknown, context: McpInvocationContext): unknown {
    context.signal.throwIfAborted();
    this.assertReady();
    validateEmptyParams(params, 'ping parameters');
    context.signal.throwIfAborted();
    return Object.freeze({});
  }

  private listTools(params: unknown, context: McpInvocationContext): unknown {
    context.signal.throwIfAborted();
    this.assertNormalReady();
    validateEmptyParams(params, 'tools/list parameters');
    context.signal.throwIfAborted();
    return Object.freeze({
      tools: Object.freeze(
        [...this.#tools.values()].map((tool) =>
          Object.freeze({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema,
          }),
        ),
      ),
    });
  }

  private async callTool(params: unknown, context: McpInvocationContext): Promise<unknown> {
    context.signal.throwIfAborted();
    this.assertNormalReady();
    const call = parseToolCallParams(params);
    context.signal.throwIfAborted();
    const tool = this.#tools.get(call.name);
    if (tool === undefined) {
      throw new McpRpcError('SCG_TOOL_UNAVAILABLE');
    }
    const structuredContent = await tool.execute(call.argumentsValue, context);
    context.signal.throwIfAborted();
    const text = JSON.stringify(structuredContent);
    context.signal.throwIfAborted();
    if (text === undefined) {
      throw new McpRpcError('SCG_INTERNAL');
    }
    return Object.freeze({
      content: Object.freeze([Object.freeze({ type: 'text', text })]),
      structuredContent,
    });
  }

  private assertReady(): void {
    if (!this.#initialized || !this.#receivedInitializedNotification) {
      throw new McpRpcError('SCG_MCP_NOT_INITIALIZED');
    }
  }

  private assertNormalReady(): void {
    this.assertReady();
    if (this.#scope !== 'normal') {
      throw new MethodNotFoundError();
    }
  }
}

function assertDispatcherOptions(options: McpDispatcherOptions): void {
  if (
    options === null ||
    typeof options !== 'object' ||
    (options.scope !== 'normal' && options.scope !== 'diagnostic')
  ) {
    throw new TypeError('MCP dispatcher scope is invalid');
  }
  if (options.tools !== undefined && !Array.isArray(options.tools)) {
    throw new TypeError('MCP tool registrations are invalid');
  }
  if (options.serverInfo !== undefined) {
    if (
      typeof options.serverInfo.name !== 'string' ||
      options.serverInfo.name.length === 0 ||
      typeof options.serverInfo.version !== 'string' ||
      options.serverInfo.version.length === 0
    ) {
      throw new TypeError('MCP server information is invalid');
    }
  }
}

function buildToolMap(
  scope: McpScope,
  tools: readonly McpTool[],
): ReadonlyMap<McpToolName, McpTool> {
  if (scope === 'diagnostic' && tools.length > 0) {
    throw new TypeError('diagnostic MCP dispatchers cannot register tools');
  }
  const entries = new Map<McpToolName, McpTool>();
  for (const tool of tools) {
    if (
      tool === null ||
      typeof tool !== 'object' ||
      !APPROVED_TOOL_NAMES.has(tool.name) ||
      typeof tool.description !== 'string' ||
      typeof tool.execute !== 'function' ||
      !isPlainRecord(tool.inputSchema) ||
      entries.has(tool.name)
    ) {
      throw new TypeError('MCP tool registration is invalid');
    }
    entries.set(tool.name, tool);
  }
  return entries;
}

function parseJsonRpcMessage(value: unknown): JsonRpcMessage {
  const record = strictRecord(value, 'JSON-RPC message');
  assertOnlyKeys(record, ['jsonrpc', 'id', 'method', 'params'], 'JSON-RPC message');
  if (record.jsonrpc !== '2.0' || typeof record.method !== 'string' || record.method.length === 0) {
    throw new InvalidRequestError();
  }
  const hasId = Object.prototype.hasOwnProperty.call(record, 'id');
  if (!hasId) {
    return Object.freeze({
      id: undefined,
      isNotification: true,
      method: record.method,
      params: record.params,
    });
  }
  if (!isJsonRpcId(record.id)) {
    throw new InvalidRequestError();
  }
  return Object.freeze({
    id: record.id,
    isNotification: false,
    method: record.method,
    params: record.params,
  });
}

function parseInitializeParams(value: unknown): InitializeParams {
  const record = strictRecord(value, 'initialize parameters');
  assertOnlyKeys(
    record,
    ['protocolVersion', 'capabilities', 'clientInfo'],
    'initialize parameters',
  );
  if (
    typeof record.protocolVersion !== 'string' ||
    !isPlainRecord(record.capabilities) ||
    !isClientInfo(record.clientInfo)
  ) {
    throw new InvalidParamsError();
  }
  return Object.freeze({ protocolVersion: record.protocolVersion as typeof MCP_PROTOCOL_VERSION });
}

function isClientInfo(value: unknown): boolean {
  if (!isPlainRecord(value)) {
    return false;
  }
  assertOnlyKeys(value, ['name', 'version', 'title'], 'client information');
  return (
    typeof value.name === 'string' &&
    value.name.length > 0 &&
    typeof value.version === 'string' &&
    value.version.length > 0 &&
    (value.title === undefined || typeof value.title === 'string')
  );
}

function parseToolCallParams(value: unknown): Readonly<{
  name: McpToolName;
  argumentsValue: unknown;
}> {
  const record = strictRecord(value, 'tools/call parameters');
  assertOnlyKeys(record, ['name', 'arguments'], 'tools/call parameters');
  if (
    typeof record.name !== 'string' ||
    !APPROVED_TOOL_NAMES.has(record.name as McpToolName) ||
    !Object.prototype.hasOwnProperty.call(record, 'arguments')
  ) {
    throw new InvalidParamsError();
  }
  return Object.freeze({
    name: record.name as McpToolName,
    argumentsValue: record.arguments,
  });
}

function validateEmptyParams(value: unknown, name: string): void {
  if (value === undefined) {
    return;
  }
  const record = strictRecord(value, name);
  if (Object.keys(record).length !== 0) {
    throw new InvalidParamsError();
  }
}

function strictRecord(value: unknown, name: string): Record<string, unknown> {
  if (!isPlainRecord(value)) {
    throw new InvalidParamsError(`${name} must be an object`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function assertOnlyKeys(
  record: Record<string, unknown>,
  keys: readonly string[],
  name: string,
): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new InvalidParamsError(`${name} contains an unknown field`);
    }
  }
}

function isJsonRpcId(value: unknown): value is JsonRpcId {
  return typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
}

function success(result: unknown, id: JsonRpcId | undefined): JsonRpcSuccess {
  if (id === undefined) {
    throw new Error('JSON-RPC request id is missing');
  }
  return Object.freeze({ jsonrpc: '2.0', id, result });
}

function invalidRequest(): JsonRpcFailure {
  return failure(null, -32600, 'Invalid Request', { code: 'SCG_RPC_INVALID_REQUEST' });
}

function requestFailure(id: JsonRpcId | undefined, error: unknown): JsonRpcFailure {
  if (id === undefined) {
    throw new Error('JSON-RPC request id is missing');
  }
  if (error instanceof MethodNotFoundError) {
    return failure(id, -32601, 'Method not found', { code: 'SCG_RPC_METHOD_NOT_FOUND' });
  }
  if (error instanceof McpInvalidParamsError) {
    return failure(id, -32602, 'Invalid params', { code: error.code });
  }
  if (error instanceof InvalidParamsError) {
    return failure(id, -32602, 'Invalid params', { code: 'SCG_RPC_INVALID_PARAMS' });
  }
  if (error instanceof McpRpcError) {
    return failure(id, -32000, 'Scene Glass error', {
      code: error.code,
      ...(error.data ?? {}),
    });
  }
  if (
    error instanceof SceneGlassContractError ||
    error instanceof ScreenReviewError ||
    error instanceof ScgStorageError
  ) {
    return failure(id, -32000, 'Scene Glass error', { code: error.code });
  }
  return failure(id, -32603, 'Internal error', { code: 'SCG_INTERNAL' });
}

function failure(
  id: JsonRpcId | null,
  code: number,
  message: string,
  data: McpErrorData,
): JsonRpcFailure {
  return Object.freeze({
    jsonrpc: '2.0',
    id,
    error: Object.freeze({ code, message, data: Object.freeze({ ...data }) }),
  });
}

export class McpInvalidParamsError extends Error {
  public readonly code: string;

  public constructor(code: string) {
    super(code);
    this.name = 'McpInvalidParamsError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

class InvalidParamsError extends Error {
  public constructor(message = 'invalid parameters') {
    super(message);
    this.name = 'InvalidParamsError';
  }
}

class InvalidRequestError extends Error {
  public constructor() {
    super('invalid request');
    this.name = 'InvalidRequestError';
  }
}

class MethodNotFoundError extends Error {
  public constructor() {
    super('method not found');
    this.name = 'MethodNotFoundError';
  }
}
