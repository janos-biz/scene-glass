import {
  assertLowercaseUuidV4,
  assertSafeRevision,
  parseElementAnnotation,
  parsePageId,
  parsePageIdentityInput,
  type CreateAnnotationInput,
  type DeleteAnnotationInput,
  type ElementAnnotation,
  type PageId,
  type PageIdentityInput,
  type ReplayResult,
  type UpdateAnnotationInput,
} from '@scene-glass/contracts';

const MAX_MCP_RESPONSE_BYTES = 1_048_576;
const MCP_CLEANUP_TIMEOUT_MS = 10_000;

export const MCP_PROTOCOL_VERSION = '2025-11-25';

export const SCENE_GLASS_TOOL = Object.freeze({
  listAnnotations: 'annotations.list',
  createAnnotation: 'annotations.create',
  updateAnnotation: 'annotations.update',
  deleteAnnotation: 'annotations.delete',
  exportPrompt: 'prompt.export',
});

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface McpClientDependencies {
  readonly fetch?: FetchLike;
  readonly now?: () => number;
  readonly crypto?: Pick<Crypto, 'getRandomValues'>;
}

export interface McpClientOptions extends McpClientDependencies {
  readonly endpoint: string;
  readonly diagnosticEndpoint: string;
  readonly token: string;
  readonly clientInfo?: {
    readonly name: string;
    readonly version: string;
  };
}

export interface DiagnosticRunCapability {
  readonly runId: string;
  readonly token: string;
  readonly expiresAt: string;
  readonly endpoint: string;
}

export interface PromptExportInput {
  readonly mode: 'project' | 'page';
  readonly pageId?: PageIdentityInput['pageId'];
}

export interface AnnotationListToolResult {
  readonly page: PageIdentityInput;
  readonly revision: number;
  readonly annotations: readonly ElementAnnotation[];
}

export interface AnnotationMutationToolResult {
  readonly replay: ReplayResult;
  readonly revision: number;
}

export interface PromptExportToolResult {
  readonly markdown: string;
  readonly mode: PromptExportInput['mode'];
  readonly pageId?: PageId;
}

export class McpClientError extends Error {
  public readonly cleanupErrors: readonly unknown[] = Object.freeze([]);

  public constructor(message: string) {
    super(message);
    this.name = 'McpClientError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class McpHttpError extends McpClientError {
  public readonly status: number;

  public constructor(status: number) {
    super(`MCP request failed with status ${status}`);
    this.name = 'McpHttpError';
    this.status = status;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class McpProtocolError extends McpClientError {
  public constructor(message: string) {
    super(message);
    this.name = 'McpProtocolError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

type McpRpcScalar = boolean | null | number | string;

type McpRpcDomainData = Readonly<Record<string, McpRpcScalar>>;

export class McpRpcDomainError extends McpClientError {
  public readonly code: string;
  public readonly rpcCode: number;
  public readonly data: McpRpcDomainData;

  public constructor(code: string, rpcCode: number, data: McpRpcDomainData) {
    super(code);
    this.name = 'McpRpcDomainError';
    this.code = code;
    this.rpcCode = rpcCode;
    this.data = data;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface McpSessionCleanup {
  readonly credential: string;
  readonly sessionId: string;
  task: Promise<void> | null;
  completed: boolean;
}

interface McpSessionEpoch {
  readonly controller: AbortController;
  readonly credential: string;
  readonly pendingCleanups: readonly McpSessionCleanup[];
  provisionalSessionId: string | null;
  sessionCleanup: McpSessionCleanup | null;
}

interface McpRequestContext {
  readonly epoch: McpSessionEpoch;
  readonly sessionId: string | null;
}

interface McpRequestResponse {
  readonly result: unknown;
  readonly receivedSessionId: string | null;
}

export class McpClient {
  private readonly endpoint: string;
  private readonly diagnosticEndpoint: string;
  private readonly fetch: FetchLike;
  private readonly now: () => number;
  private readonly crypto: Pick<Crypto, 'getRandomValues'>;
  private readonly clientInfo: { readonly name: string; readonly version: string };
  private token: string | null;
  private sessionId: string | null = null;
  private sessionEpoch: McpSessionEpoch;
  private sessionInitializationTask: Promise<unknown> | null = null;
  private fullInitializationTask: Promise<unknown> | null = null;
  private initializedNotificationTask: {
    readonly epoch: McpSessionEpoch;
    readonly task: Promise<void>;
  } | null = null;
  private closeTask: Promise<void> | null = null;

  public constructor(options: McpClientOptions) {
    this.endpoint = options.endpoint;
    this.diagnosticEndpoint = options.diagnosticEndpoint;
    this.token = options.token;
    this.fetch = options.fetch ?? browserFetch;
    this.now = options.now ?? Date.now;
    this.crypto = options.crypto ?? browserCrypto();
    this.clientInfo = options.clientInfo ?? {
      name: 'scene-glass-browser',
      version: '0.1.0',
    };
    this.sessionEpoch = this.createSessionEpoch(options.token);
  }

  public initialize(): Promise<unknown> {
    try {
      return this.startInitialization(true);
    } catch (error: unknown) {
      return Promise.reject(error);
    }
  }

  public initializeSession(): Promise<unknown> {
    try {
      return this.startInitialization(false);
    } catch (error: unknown) {
      return Promise.reject(error);
    }
  }

  public sendInitializedNotification(): Promise<void> {
    const epoch = this.sessionEpoch;
    return this.startInitializedNotification(epoch, this.requireSessionId(epoch));
  }

  public async ping(): Promise<unknown> {
    const context = this.currentSessionContext();
    const response = await this.request('ping', {}, context);
    this.assertCurrentSession(context);
    return response.result;
  }

  public async callTool(name: string, argumentsValue: unknown): Promise<Record<string, unknown>> {
    const context = this.currentSessionContext();
    const response = await this.request(
      'tools/call',
      {
        name,
        arguments: argumentsValue,
      },
      context,
    );
    this.assertCurrentSession(context);
    return parseToolStructuredContent(response.result);
  }

  public async listAnnotations(page: PageIdentityInput): Promise<AnnotationListToolResult> {
    const structuredContent = await this.callTool(SCENE_GLASS_TOOL.listAnnotations, { page });
    return decodeListAnnotations(structuredContent, page);
  }

  public async createAnnotation(
    input: CreateAnnotationInput,
  ): Promise<AnnotationMutationToolResult> {
    const structuredContent = await this.callTool(SCENE_GLASS_TOOL.createAnnotation, input);
    return decodeMutation(structuredContent, 'create', undefined);
  }

  public async updateAnnotation(
    input: UpdateAnnotationInput,
  ): Promise<AnnotationMutationToolResult> {
    const structuredContent = await this.callTool(SCENE_GLASS_TOOL.updateAnnotation, input);
    return decodeMutation(structuredContent, 'update', input.annotationId);
  }

  public async deleteAnnotation(
    input: DeleteAnnotationInput,
  ): Promise<AnnotationMutationToolResult> {
    const structuredContent = await this.callTool(SCENE_GLASS_TOOL.deleteAnnotation, input);
    return decodeMutation(structuredContent, 'delete', input.annotationId);
  }

  public async exportPrompt(input: PromptExportInput): Promise<PromptExportToolResult> {
    const structuredContent = await this.callTool(SCENE_GLASS_TOOL.exportPrompt, input);
    return decodePromptExport(structuredContent, input);
  }

  public issueDiagnosticRun(): Promise<DiagnosticRunCapability> {
    return this.issueDiagnosticRunFor(this.sessionEpoch);
  }

  public async withDiagnosticRun<T>(
    consume: (capability: DiagnosticRunCapability) => Promise<T> | T,
  ): Promise<T> {
    const epoch = this.sessionEpoch;
    const capability = await this.issueDiagnosticRunFor(epoch);
    this.assertCurrentEpoch(epoch);
    try {
      const result = await consume(capability);
      this.assertCurrentEpoch(epoch);
      return result;
    } catch (error: unknown) {
      this.assertCurrentEpoch(epoch);
      throw error;
    }
  }

  public close(): Promise<void> {
    if (this.closeTask !== null) {
      return this.closeTask;
    }

    const deferred = createDeferredTask<void>();
    this.closeTask = deferred.promise;
    const epoch = this.sessionEpoch;
    const initializationTask = this.fullInitializationTask ?? this.sessionInitializationTask;
    const notificationTask =
      initializationTask === null && this.initializedNotificationTask?.epoch === epoch
        ? this.initializedNotificationTask.task
        : null;
    const cleanups = this.sessionCleanups(epoch);
    this.invalidateSession();
    this.token = null;

    void Promise.resolve()
      .then(() =>
        this.closeSessionAndInitialization(cleanups, initializationTask, notificationTask),
      )
      .then(deferred.resolve, deferred.reject);
    return deferred.promise;
  }

  public dispose(): void {
    this.invalidateSession();
    this.token = null;
  }

  private startInitialization(sendNotification: boolean): Promise<unknown> {
    const activeSessionTask = this.sessionInitializationTask;
    if (activeSessionTask !== null) {
      return sendNotification ? this.startFullInitialization(activeSessionTask) : activeSessionTask;
    }

    const credential = this.requireCredential();
    const deferred = createDeferredTask<unknown>();
    const sessionTask = deferred.promise;
    this.sessionInitializationTask = sessionTask;
    let epoch: McpSessionEpoch | null = null;

    try {
      const nextEpoch = this.beginSessionEpoch(credential);
      epoch = nextEpoch;
      void Promise.resolve()
        .then(() => this.initializeSessionForEpoch(nextEpoch))
        .then(deferred.resolve, deferred.reject);
    } catch (error: unknown) {
      deferred.reject(error);
    }

    void sessionTask.then(
      () => {
        if (
          this.sessionInitializationTask === sessionTask &&
          this.fullInitializationTask === null
        ) {
          this.sessionInitializationTask = null;
        }
      },
      () => {
        if (
          this.sessionInitializationTask === sessionTask &&
          this.fullInitializationTask === null
        ) {
          this.sessionInitializationTask = null;
        }
      },
    );
    if (!sendNotification || epoch === null) {
      return sessionTask;
    }
    return this.startFullInitialization(sessionTask);
  }

  private startFullInitialization(sessionTask: Promise<unknown>): Promise<unknown> {
    if (this.fullInitializationTask !== null) {
      return this.fullInitializationTask;
    }

    const epoch = this.sessionEpoch;
    const deferred = createDeferredTask<unknown>();
    const task = deferred.promise;
    this.fullInitializationTask = task;
    void Promise.resolve()
      .then(() => this.initializeFullyForEpoch(epoch, sessionTask))
      .then(deferred.resolve, deferred.reject);
    void task.then(
      () => {
        if (this.fullInitializationTask === task) {
          this.fullInitializationTask = null;
          if (this.sessionInitializationTask === sessionTask) {
            this.sessionInitializationTask = null;
          }
        }
      },
      () => {
        if (this.fullInitializationTask === task) {
          this.fullInitializationTask = null;
          if (this.sessionInitializationTask === sessionTask) {
            this.sessionInitializationTask = null;
          }
        }
      },
    );
    return task;
  }

  private async initializeSessionForEpoch(epoch: McpSessionEpoch): Promise<unknown> {
    try {
      for (const cleanup of epoch.pendingCleanups) {
        await this.closeSessionCleanup(cleanup);
        this.assertCurrentEpoch(epoch);
      }
      const result = await this.initializeSessionFor(epoch);
      this.assertCurrentEpoch(epoch);
      return result;
    } catch (error: unknown) {
      try {
        await this.cleanupFailedInitialization(epoch);
      } catch (cleanupError: unknown) {
        throwAfterCleanupFailure(error, cleanupError);
      }
      throw error;
    }
  }

  private async initializeFullyForEpoch(
    epoch: McpSessionEpoch,
    sessionTask: Promise<unknown>,
  ): Promise<unknown> {
    const result = await sessionTask;
    try {
      this.assertCurrentEpoch(epoch);
      await this.startInitializedNotification(epoch, this.requireSessionId(epoch));
      this.assertCurrentEpoch(epoch);
      return result;
    } catch (error: unknown) {
      try {
        await this.cleanupFailedInitialization(epoch);
      } catch (cleanupError: unknown) {
        throwAfterCleanupFailure(error, cleanupError);
      }
      throw error;
    }
  }

  private async issueDiagnosticRunFor(epoch: McpSessionEpoch): Promise<DiagnosticRunCapability> {
    this.assertCurrentEpoch(epoch);
    const token = this.requireCredential();
    const response = await this.fetch(this.diagnosticEndpoint, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      signal: epoch.controller.signal,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ schemaVersion: 1 }),
    });
    if (!this.isCurrentEpoch(epoch)) {
      await cancelResponseBodyAfterFailure(response, supersededSessionError());
    }
    this.assertCurrentEpoch(epoch);
    if (response.status !== 201) {
      await cancelResponseBodyAfterFailure(response, new McpHttpError(response.status));
    }
    if (!hasNoStore(response.headers.get('cache-control'))) {
      await cancelResponseBodyAfterFailure(
        response,
        new McpProtocolError('diagnostic response must disable caching'),
      );
    }
    const value = await parseJsonResponse(response, epoch.controller.signal);
    this.assertCurrentEpoch(epoch);
    if (!isStrictDiagnosticRun(value, this.now())) {
      throw new McpProtocolError('diagnostic response is invalid');
    }
    if (!isExactDiagnosticEndpoint(value.endpoint, this.endpoint)) {
      throw new McpProtocolError('diagnostic endpoint is invalid');
    }

    return Object.freeze({
      runId: value.runId,
      token: value.token,
      expiresAt: value.expiresAt,
      endpoint: value.endpoint,
    });
  }

  private async initializeSessionFor(epoch: McpSessionEpoch): Promise<unknown> {
    const response = await this.request(
      'initialize',
      {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: this.clientInfo,
      },
      { epoch, sessionId: null },
    );
    this.assertCurrentEpoch(epoch);
    const result = parseInitializeResult(response.result);
    const sessionId = parseSessionId(response.receivedSessionId);
    this.assertCurrentEpoch(epoch);
    epoch.provisionalSessionId = sessionId;
    this.sessionId = sessionId;
    return result;
  }

  private startInitializedNotification(epoch: McpSessionEpoch, sessionId: string): Promise<void> {
    const activeNotification = this.initializedNotificationTask;
    if (activeNotification !== null && activeNotification.epoch === epoch) {
      return activeNotification.task;
    }

    const deferred = createDeferredTask<void>();
    const task = deferred.promise;
    this.initializedNotificationTask = Object.freeze({ epoch, task });
    void Promise.resolve()
      .then(() => this.sendInitializedNotificationFor(epoch, sessionId))
      .then(deferred.resolve, deferred.reject);
    void task.then(
      () => {
        if (this.initializedNotificationTask?.task === task) {
          this.initializedNotificationTask = null;
        }
      },
      () => {
        if (this.initializedNotificationTask?.task === task) {
          this.initializedNotificationTask = null;
        }
      },
    );
    return task;
  }

  private async sendInitializedNotificationFor(
    epoch: McpSessionEpoch,
    sessionId: string,
  ): Promise<void> {
    const response = await this.notify('notifications/initialized', {}, { epoch, sessionId });
    this.assertCurrentSession({ epoch, sessionId });
    if (response.status !== 202 && response.status !== 204) {
      await cancelResponseBodyAfterFailure(
        response,
        new McpProtocolError('MCP initialized notification was not acknowledged'),
      );
    }
    const acknowledgement = await readResponseText(response, epoch.controller.signal, true);
    this.assertCurrentSession({ epoch, sessionId });
    if (acknowledgement.trim().length !== 0) {
      throw new McpProtocolError('MCP initialized notification acknowledgement must be empty');
    }
  }

  private async request(
    method: string,
    params: unknown,
    context: McpRequestContext,
  ): Promise<McpRequestResponse> {
    const id = this.createRequestId();
    const response = await this.post(
      {
        jsonrpc: '2.0',
        id,
        method,
        params,
      },
      context,
    );
    this.assertCurrentSession(context);
    const message = await parseJsonResponse(response, context.epoch.controller.signal);
    this.assertCurrentSession(context);
    return Object.freeze({
      result: parseJsonRpcResult(message, id),
      receivedSessionId: response.headers.get('mcp-session-id'),
    });
  }

  private notify(method: string, params: unknown, context: McpRequestContext): Promise<Response> {
    return this.post(
      {
        jsonrpc: '2.0',
        method,
        params,
      },
      context,
    );
  }

  private async post(
    message: Record<string, unknown>,
    context: McpRequestContext,
  ): Promise<Response> {
    this.assertCurrentSession(context);
    const token = this.requireCredential();
    const headers: Record<string, string> = {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
    };
    if (context.sessionId !== null) {
      headers['mcp-session-id'] = context.sessionId;
    }

    const response = await this.fetch(this.endpoint, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      signal: context.epoch.controller.signal,
      headers,
      body: JSON.stringify(message),
    });
    this.recordProvisionalSession(context, response);
    if (!this.isCurrentSession(context)) {
      await cancelResponseBodyAfterFailure(response, supersededSessionError());
    }
    this.assertCurrentSession(context);
    if (response.status < 200 || response.status >= 300) {
      await cancelResponseBodyAfterFailure(response, new McpHttpError(response.status));
    }
    return response;
  }

  private async cleanupFailedInitialization(epoch: McpSessionEpoch): Promise<void> {
    const cleanup = this.sessionCleanupFor(epoch);
    if (this.sessionEpoch === epoch) {
      this.invalidateSession();
    }
    if (cleanup !== null) {
      await this.closeSessionCleanup(cleanup);
    }
  }

  private async closeSessionAndInitialization(
    cleanups: readonly McpSessionCleanup[],
    initializationTask: Promise<unknown> | null,
    notificationTask: Promise<void> | null,
  ): Promise<void> {
    const cleanupErrors: unknown[] = [];
    const observedErrors = new Set<unknown>();
    const recordError = (error: unknown): void => {
      if (
        !observedErrors.has(error) &&
        !cleanupErrors.some((observedError) => errorGraphContains(observedError, error))
      ) {
        observedErrors.add(error);
        cleanupErrors.push(error);
      }
    };
    if (initializationTask !== null) {
      try {
        await awaitCleanupWithDeadline(() => initializationTask);
      } catch (error: unknown) {
        if (!isCleanSupersededSessionError(error)) {
          recordError(error);
        }
      }
    }
    if (notificationTask !== null) {
      try {
        await awaitCleanupWithDeadline(() => notificationTask);
      } catch (error: unknown) {
        if (!isCleanSupersededSessionError(error)) {
          recordError(error);
        }
      }
    }
    for (const cleanup of cleanups) {
      if (cleanup.completed) {
        continue;
      }
      try {
        await this.closeSessionCleanup(cleanup);
      } catch (error: unknown) {
        recordError(error);
      }
    }
    if (cleanupErrors.length === 1) {
      throw cleanupErrors[0];
    }
    if (cleanupErrors.length > 1) {
      throw new AggregateError(cleanupErrors, 'MCP client cleanup failed');
    }
  }

  private async closeSession(sessionId: string, credential: string): Promise<void> {
    const controller = new AbortController();
    const response = await awaitCleanupWithDeadline(
      () =>
        this.fetch(this.endpoint, {
          method: 'DELETE',
          mode: 'cors',
          credentials: 'omit',
          cache: 'no-store',
          signal: controller.signal,
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${credential}`,
            'mcp-protocol-version': MCP_PROTOCOL_VERSION,
            'mcp-session-id': sessionId,
          },
        }),
      {
        onLateFulfilled: (lateResponse) =>
          observeCleanupWithDeadline(() => cancelResponseBody(lateResponse)),
        onTimeout: (timeoutError) => controller.abort(timeoutError),
      },
    );
    throwIfAborted(controller.signal);
    if (response.status < 200 || response.status >= 300) {
      await cancelResponseBodyAfterFailure(response, new McpHttpError(response.status));
    }
    await cancelResponseBody(response);
    throwIfAborted(controller.signal);
  }

  private beginSessionEpoch(credential: string): McpSessionEpoch {
    const previous = this.sessionEpoch;
    const epoch = this.createSessionEpoch(credential, this.sessionCleanups(previous));
    this.sessionId = null;
    this.sessionEpoch = epoch;
    this.abortEpoch(previous);
    return epoch;
  }

  private invalidateSession(): McpSessionEpoch {
    const previous = this.sessionEpoch;
    const cleanups = this.sessionCleanups(previous);
    this.sessionId = null;
    this.sessionEpoch = this.createSessionEpoch(previous.credential, cleanups);
    this.abortEpoch(previous);
    return previous;
  }

  private createSessionEpoch(
    credential: string,
    pendingCleanups: readonly McpSessionCleanup[] = [],
  ): McpSessionEpoch {
    return {
      controller: new AbortController(),
      credential,
      pendingCleanups,
      provisionalSessionId: null,
      sessionCleanup: null,
    };
  }

  private createSessionCleanup(sessionId: string, credential: string): McpSessionCleanup {
    return {
      credential,
      sessionId,
      task: null,
      completed: false,
    };
  }

  private sessionCleanupFor(epoch: McpSessionEpoch): McpSessionCleanup | null {
    if (epoch.sessionCleanup !== null) {
      return epoch.sessionCleanup;
    }
    const sessionId =
      epoch.provisionalSessionId ?? (this.sessionEpoch === epoch ? this.sessionId : null);
    if (sessionId === null) {
      return null;
    }
    const cleanup = this.createSessionCleanup(sessionId, epoch.credential);
    epoch.sessionCleanup = cleanup;
    return cleanup;
  }

  private sessionCleanups(epoch: McpSessionEpoch): readonly McpSessionCleanup[] {
    const pendingCleanups = epoch.pendingCleanups.filter((cleanup) => !cleanup.completed);
    const cleanup = this.sessionCleanupFor(epoch);
    return Object.freeze(
      cleanup === null || pendingCleanups.includes(cleanup)
        ? pendingCleanups
        : [...pendingCleanups, cleanup],
    );
  }

  private closeSessionCleanup(cleanup: McpSessionCleanup): Promise<void> {
    if (cleanup.task !== null) {
      return cleanup.task;
    }

    const deferred = createDeferredTask<void>();
    cleanup.task = deferred.promise;
    void Promise.resolve()
      .then(() => this.closeSession(cleanup.sessionId, cleanup.credential))
      .then(() => {
        cleanup.completed = true;
        deferred.resolve();
      }, deferred.reject);
    return deferred.promise;
  }

  private abortEpoch(epoch: McpSessionEpoch): void {
    if (!epoch.controller.signal.aborted) {
      epoch.controller.abort(supersededSessionError());
    }
  }

  private currentSessionContext(): McpRequestContext {
    const epoch = this.sessionEpoch;
    return Object.freeze({ epoch, sessionId: this.requireSessionId(epoch) });
  }

  private requireSessionId(epoch: McpSessionEpoch): string {
    this.assertCurrentEpoch(epoch);
    if (this.sessionId === null) {
      throw new McpClientError('MCP session has not been initialized');
    }
    return this.sessionId;
  }

  private isCurrentEpoch(epoch: McpSessionEpoch): boolean {
    return this.sessionEpoch === epoch && !epoch.controller.signal.aborted;
  }

  private isCurrentSession(context: McpRequestContext): boolean {
    return (
      this.isCurrentEpoch(context.epoch) &&
      (context.sessionId === null || this.sessionId === context.sessionId)
    );
  }

  private assertCurrentEpoch(epoch: McpSessionEpoch): void {
    if (!this.isCurrentEpoch(epoch)) {
      throw supersededSessionError();
    }
  }

  private assertCurrentSession(context: McpRequestContext): void {
    this.assertCurrentEpoch(context.epoch);
    if (context.sessionId !== null && this.sessionId !== context.sessionId) {
      throw supersededSessionError();
    }
  }

  private recordProvisionalSession(context: McpRequestContext, response: Response): void {
    if (context.sessionId !== null) {
      return;
    }
    const sessionId = response.headers.get('mcp-session-id');
    if (sessionId !== null && isNonBlankString(sessionId) && sessionId === sessionId.trim()) {
      context.epoch.provisionalSessionId = sessionId;
      if (context.epoch.sessionCleanup === null) {
        context.epoch.sessionCleanup = this.createSessionCleanup(
          sessionId,
          context.epoch.credential,
        );
      }
    }
  }

  private createRequestId(): string {
    const bytes = new Uint8Array(12);
    this.crypto.getRandomValues(bytes);
    let random = '';
    for (const byte of bytes) {
      random += byte.toString(16).padStart(2, '0');
    }
    return `${this.now().toString(36)}-${random}`;
  }

  private requireCredential(): string {
    if (this.token === null) {
      throw new McpClientError('MCP client has been destroyed');
    }
    return this.token;
  }
}

function browserFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  if (typeof globalThis.fetch !== 'function') {
    throw new McpClientError('browser fetch is unavailable');
  }
  return globalThis.fetch(input, init);
}

function browserCrypto(): Pick<Crypto, 'getRandomValues'> {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new McpClientError('browser cryptography is unavailable');
  }
  return globalThis.crypto;
}
function createDeferredTask<T>(): {
  readonly promise: Promise<T>;
  readonly reject: (reason?: unknown) => void;
  readonly resolve: (value: T | PromiseLike<T>) => void;
} {
  let reject: ((reason?: unknown) => void) | undefined;
  let resolve: ((value: T | PromiseLike<T>) => void) | undefined;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  if (resolve === undefined || reject === undefined) {
    throw new McpClientError('MCP could not create a deferred task');
  }
  return Object.freeze({ promise, resolve, reject });
}

async function parseJsonResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  if (normalizeContentType(response.headers.get('content-type')) !== 'application/json') {
    await cancelResponseBodyAfterFailure(
      response,
      new McpProtocolError('MCP response uses an unsupported Content-Type'),
    );
  }
  const text = await readResponseText(response, signal);
  throwIfAborted(signal);
  return parseJsonText(text);
}

async function readResponseText(
  response: Response,
  signal: AbortSignal,
  allowEmpty = false,
): Promise<string> {
  if (response.body === null) {
    if (allowEmpty) {
      return '';
    }
    throw new McpProtocolError('MCP response is empty');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let complete = false;
  let totalBytes = 0;
  let text = '';
  try {
    for (;;) {
      const chunk = await readNextChunk(reader, signal);
      throwIfAborted(signal);
      if (chunk.done) {
        complete = true;
        break;
      }
      totalBytes += chunk.value.byteLength;
      if (totalBytes > MAX_MCP_RESPONSE_BYTES) {
        throw new McpProtocolError('MCP response exceeds the byte limit');
      }
      try {
        text += decoder.decode(chunk.value, { stream: true });
      } catch {
        throw new McpProtocolError('MCP response is not valid UTF-8');
      }
    }
    try {
      text += decoder.decode();
    } catch {
      throw new McpProtocolError('MCP response is not valid UTF-8');
    }
    if (!allowEmpty && text.trim().length === 0) {
      throw new McpProtocolError('MCP response is empty');
    }
    return text;
  } catch (error: unknown) {
    if (!complete) {
      try {
        await awaitCleanupWithDeadline(() => reader.cancel());
      } catch (cleanupError: unknown) {
        throwAfterCleanupFailure(error, cleanupError);
      }
    }
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function readNextChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  return new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortReason(signal));
      return;
    }
    const onAbort = (): void => {
      signal.removeEventListener('abort', onAbort);
      reject(abortReason(signal));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    reader.read().then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        if (signal.aborted) {
          reject(abortReason(signal));
          return;
        }
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

async function cancelResponseBody(response: Response): Promise<void> {
  const body = response.body;
  if (body !== null) {
    await awaitCleanupWithDeadline(() => body.cancel());
  }
}
interface CleanupDeadlineOptions<T> {
  readonly onLateFulfilled?: (value: T) => void;
  readonly onTimeout?: (timeoutError: McpClientError) => void;
}

async function awaitCleanupWithDeadline<T>(
  operation: () => PromiseLike<T>,
  options: CleanupDeadlineOptions<T> = {},
): Promise<T> {
  let timedOut = false;
  const timeoutError = new McpClientError('MCP session cleanup timed out');
  const work = Promise.resolve().then(operation);
  const deadline = new Promise<never>((_resolve, reject) => {
    const timer = globalThis.setTimeout(() => {
      timedOut = true;
      try {
        options.onTimeout?.(timeoutError);
      } catch (error: unknown) {
        reject(new AggregateError([timeoutError, error], 'MCP cleanup deadline failed'));
        return;
      }
      reject(timeoutError);
    }, MCP_CLEANUP_TIMEOUT_MS);
    void work.then(
      () => globalThis.clearTimeout(timer),
      () => globalThis.clearTimeout(timer),
    );
  });

  void work.then(
    (value) => {
      if (timedOut && options.onLateFulfilled !== undefined) {
        options.onLateFulfilled(value);
      }
    },
    () => undefined,
  );

  return Promise.race([work, deadline]);
}

function observeCleanupWithDeadline(operation: () => PromiseLike<unknown>): void {
  void awaitCleanupWithDeadline(operation).then(
    () => undefined,
    () => undefined,
  );
}

async function cancelResponseBodyAfterFailure(
  response: Response,
  failure: unknown,
): Promise<never> {
  try {
    await cancelResponseBody(response);
  } catch (cleanupError: unknown) {
    throwAfterCleanupFailure(failure, cleanupError);
  }
  throw failure;
}

function throwAfterCleanupFailure(primary: unknown, cleanupError: unknown): never {
  if (primary instanceof McpClientError) {
    Object.defineProperty(primary, 'cleanupErrors', {
      configurable: true,
      enumerable: true,
      value: Object.freeze([...primary.cleanupErrors, cleanupError]),
      writable: false,
    });
    throw primary;
  }
  throw new AggregateError([primary, cleanupError], 'MCP request failed and cleanup failed');
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new McpClientError('MCP request was aborted');
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw abortReason(signal);
  }
}

function parseJsonText(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new McpProtocolError('MCP response is not valid JSON');
  }
}

function normalizeContentType(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const mediaType = value.split(';')[0];
  if (mediaType === undefined) {
    return null;
  }
  const normalized = mediaType.trim().toLowerCase();
  return normalized.length === 0 ? null : normalized;
}

function parseJsonRpcResult(value: unknown, id: string): unknown {
  if (!isRecord(value) || value.jsonrpc !== '2.0' || value.id !== id) {
    throw new McpProtocolError('MCP response does not match its request');
  }
  if (Object.hasOwn(value, 'error')) {
    const error = parseMcpRpcDomainError(value, id);
    if (error !== undefined) {
      throw error;
    }
    throw new McpProtocolError('MCP returned an error response');
  }
  if (!Object.hasOwn(value, 'result')) {
    throw new McpProtocolError('MCP response has no result');
  }
  return value.result;
}

function parseMcpRpcDomainError(
  value: Record<string, unknown>,
  id: string,
): McpRpcDomainError | undefined {
  if (
    !hasExactlyKeys(value, ['jsonrpc', 'id', 'error']) ||
    value.jsonrpc !== '2.0' ||
    value.id !== id ||
    !isRecord(value.error)
  ) {
    return undefined;
  }

  const error = value.error;
  if (
    !hasExactlyKeys(error, ['code', 'message', 'data']) ||
    typeof error.code !== 'number' ||
    !Number.isSafeInteger(error.code) ||
    typeof error.message !== 'string' ||
    !isRecord(error.data)
  ) {
    return undefined;
  }

  const data = copyMcpRpcDomainData(error.data);
  if (
    data === undefined ||
    typeof data.code !== 'string' ||
    !/^SCG_[A-Z0-9_]{1,80}$/.test(data.code)
  ) {
    return undefined;
  }

  return new McpRpcDomainError(data.code, error.code, data);
}

function copyMcpRpcDomainData(value: Record<string, unknown>): McpRpcDomainData | undefined {
  const data: Record<string, McpRpcScalar> = Object.create(null) as Record<string, McpRpcScalar>;
  for (const [key, item] of Object.entries(value)) {
    if (
      item !== null &&
      typeof item !== 'string' &&
      typeof item !== 'boolean' &&
      (typeof item !== 'number' || !Number.isSafeInteger(item))
    ) {
      return undefined;
    }
    Object.defineProperty(data, key, {
      configurable: false,
      enumerable: true,
      value: item,
      writable: false,
    });
  }
  return Object.freeze(data);
}

function parseInitializeResult(value: unknown): Readonly<Record<string, unknown>> {
  const result = requireExactRecord(
    value,
    ['protocolVersion', 'capabilities', 'serverInfo'],
    'MCP initialize response is invalid',
  );
  if (result.protocolVersion !== MCP_PROTOCOL_VERSION) {
    throw new McpProtocolError('MCP server negotiated an unsupported protocol version');
  }

  const capabilities = result.capabilities;
  if (!isRecord(capabilities)) {
    throw new McpProtocolError('MCP initialize capabilities are invalid');
  }
  const capabilityKeys = Object.keys(capabilities);
  if (capabilityKeys.length === 0) {
    // Diagnostic MCP sessions intentionally expose no tools.
  } else if (
    capabilityKeys.length !== 1 ||
    capabilities.tools === undefined ||
    !isRecord(capabilities.tools) ||
    !hasExactlyKeys(capabilities.tools, ['listChanged']) ||
    capabilities.tools.listChanged !== false
  ) {
    throw new McpProtocolError('MCP initialize capabilities are invalid');
  }

  const serverInfo = requireExactRecord(
    result.serverInfo,
    ['name', 'version'],
    'MCP initialize server information is invalid',
  );
  if (!isNonBlankString(serverInfo.name) || !isNonBlankString(serverInfo.version)) {
    throw new McpProtocolError('MCP initialize server information is invalid');
  }
  return Object.freeze({
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: Object.freeze({ ...capabilities }),
    serverInfo: Object.freeze({ name: serverInfo.name, version: serverInfo.version }),
  });
}

function parseToolStructuredContent(result: unknown): Record<string, unknown> {
  if (!isRecord(result) || !Object.hasOwn(result, 'structuredContent')) {
    throw new McpProtocolError('MCP tool response has no structured content');
  }
  if (!isRecord(result.structuredContent)) {
    throw new McpProtocolError('MCP tool structured content is invalid');
  }
  return result.structuredContent;
}

function decodeListAnnotations(
  value: Record<string, unknown>,
  expectedPage: PageIdentityInput,
): AnnotationListToolResult {
  try {
    const result = requireExactRecord(
      value,
      ['page', 'revision', 'annotations'],
      'MCP annotation list structured content is invalid',
    );
    if (!Array.isArray(result.annotations)) {
      throw new McpProtocolError('MCP annotation list structured content is invalid');
    }
    const page = parsePageIdentityInput(result.page);
    if (!samePageIdentity(page, expectedPage)) {
      throw new McpProtocolError('MCP annotation list returned a different page');
    }
    const annotations = result.annotations.map((annotation) => parseElementAnnotation(annotation));
    const annotationIds = new Set<string>();
    for (const annotation of annotations) {
      if (annotationIds.has(annotation.id)) {
        throw new McpProtocolError('MCP annotation list contains duplicate annotation IDs');
      }
      annotationIds.add(annotation.id);
    }
    return Object.freeze({
      page,
      revision: assertSafeRevision(result.revision, 'annotation list revision'),
      annotations: Object.freeze(annotations),
    });
  } catch (error: unknown) {
    throw asProtocolError(error, 'MCP annotation list structured content is invalid');
  }
}

function decodeMutation(
  value: Record<string, unknown>,
  expectedKind: ReplayResult['kind'],
  expectedAnnotationId: string | undefined,
): AnnotationMutationToolResult {
  try {
    const result = requireExactRecord(
      value,
      ['replay', 'revision'],
      'MCP annotation mutation structured content is invalid',
    );
    const replay = decodeReplayResult(result.replay, expectedKind);
    const revision = assertSafeRevision(result.revision, 'annotation mutation revision');
    if (replay.revision !== revision) {
      throw new McpProtocolError('MCP annotation mutation replay revision does not match');
    }
    if (
      expectedAnnotationId !== undefined &&
      (replay.kind === 'delete' ? replay.annotationId : replay.annotation.id) !==
        expectedAnnotationId
    ) {
      throw new McpProtocolError('MCP annotation mutation replay annotation ID does not match');
    }
    return Object.freeze({ replay, revision });
  } catch (error: unknown) {
    throw asProtocolError(error, 'MCP annotation mutation structured content is invalid');
  }
}

function decodeReplayResult(value: unknown, expectedKind: ReplayResult['kind']): ReplayResult {
  switch (expectedKind) {
    case 'create': {
      const result = requireExactRecord(
        value,
        ['kind', 'revision', 'annotation'],
        'MCP annotation replay is invalid',
      );
      if (result.kind !== 'create') {
        throw new McpProtocolError('MCP annotation replay kind does not match');
      }
      return Object.freeze({
        kind: 'create' as const,
        revision: assertSafeRevision(result.revision, 'annotation replay revision'),
        annotation: parseElementAnnotation(result.annotation),
      });
    }
    case 'update': {
      const result = requireExactRecord(
        value,
        ['kind', 'revision', 'annotation'],
        'MCP annotation replay is invalid',
      );
      if (result.kind !== 'update') {
        throw new McpProtocolError('MCP annotation replay kind does not match');
      }
      return Object.freeze({
        kind: 'update' as const,
        revision: assertSafeRevision(result.revision, 'annotation replay revision'),
        annotation: parseElementAnnotation(result.annotation),
      });
    }
    case 'delete': {
      const result = requireExactRecord(
        value,
        ['kind', 'revision', 'annotationId'],
        'MCP annotation replay is invalid',
      );
      if (result.kind !== 'delete') {
        throw new McpProtocolError('MCP annotation replay kind does not match');
      }
      return Object.freeze({
        kind: 'delete' as const,
        revision: assertSafeRevision(result.revision, 'annotation replay revision'),
        annotationId: assertLowercaseUuidV4(result.annotationId, 'annotation replay annotationId'),
      });
    }
  }
}

function decodePromptExport(
  value: Record<string, unknown>,
  expected: PromptExportInput,
): PromptExportToolResult {
  try {
    if (expected.mode === 'project') {
      const result = requireExactRecord(
        value,
        ['mode', 'markdown'],
        'MCP prompt export structured content is invalid',
      );
      if (result.mode !== 'project' || typeof result.markdown !== 'string') {
        throw new McpProtocolError('MCP prompt export structured content is invalid');
      }
      return Object.freeze({ mode: 'project' as const, markdown: result.markdown });
    }

    const result = requireExactRecord(
      value,
      ['mode', 'pageId', 'markdown'],
      'MCP prompt export structured content is invalid',
    );
    if (result.mode !== 'page' || typeof result.markdown !== 'string') {
      throw new McpProtocolError('MCP prompt export structured content is invalid');
    }
    const pageId = parsePageId(result.pageId);
    if (expected.pageId === undefined || pageId !== expected.pageId) {
      throw new McpProtocolError('MCP prompt export returned a different page');
    }
    return Object.freeze({ mode: 'page' as const, pageId, markdown: result.markdown });
  } catch (error: unknown) {
    throw asProtocolError(error, 'MCP prompt export structured content is invalid');
  }
}

function requireExactRecord(
  value: unknown,
  keys: readonly string[],
  message: string,
): Record<string, unknown> {
  if (!isRecord(value) || !hasExactlyKeys(value, keys)) {
    throw new McpProtocolError(message);
  }
  return value;
}

function samePageIdentity(left: PageIdentityInput, right: PageIdentityInput): boolean {
  return (
    left.policyVersion === right.policyVersion &&
    left.canonicalIdentity === right.canonicalIdentity &&
    left.route === right.route &&
    left.pageId === right.pageId
  );
}

function parseSessionId(value: string | null): string {
  if (value === null || !isNonBlankString(value) || value !== value.trim()) {
    throw new McpProtocolError('MCP initialize response omitted a valid session ID');
  }
  return value;
}

function supersededSessionError(): McpClientError {
  return new McpClientError('MCP session was superseded');
}
function isCleanSupersededSessionError(error: unknown): boolean {
  return (
    error instanceof McpClientError &&
    error.message === 'MCP session was superseded' &&
    error.cleanupErrors.length === 0
  );
}
function errorGraphContains(
  root: unknown,
  expected: unknown,
  visited: Set<object> = new Set<object>(),
): boolean {
  if (root === expected) {
    return true;
  }
  if (typeof root !== 'object' || root === null || visited.has(root)) {
    return false;
  }
  visited.add(root);
  if (root instanceof AggregateError) {
    return root.errors.some((error) => errorGraphContains(error, expected, visited));
  }
  return (
    root instanceof McpClientError &&
    root.cleanupErrors.some((error) => errorGraphContains(error, expected, visited))
  );
}

function asProtocolError(error: unknown, fallback: string): McpProtocolError {
  return error instanceof McpProtocolError ? error : new McpProtocolError(fallback);
}

function hasExactlyKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function hasNoStore(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  return value.split(',').some((directive) => directive.trim().toLowerCase() === 'no-store');
}

function isStrictDiagnosticRun(
  value: unknown,
  now: number,
): value is {
  readonly runId: string;
  readonly token: string;
  readonly expiresAt: string;
  readonly endpoint: string;
} {
  if (!isRecord(value) || !Number.isSafeInteger(now)) {
    return false;
  }
  if (!hasExactlyKeys(value, ['runId', 'token', 'expiresAt', 'endpoint'])) {
    return false;
  }
  return (
    typeof value.runId === 'string' &&
    isCanonicalDiagnosticRunId(value.runId) &&
    typeof value.token === 'string' &&
    isCanonicalBase64Url(value.token, 32) &&
    typeof value.expiresAt === 'string' &&
    isFutureIsoTimestamp(value.expiresAt, now) &&
    typeof value.endpoint === 'string'
  );
}

function isCanonicalDiagnosticRunId(value: string): boolean {
  const prefix = 'diagnostic-';
  return value.startsWith(prefix) && isCanonicalBase64Url(value.slice(prefix.length), 16);
}

function isCanonicalBase64Url(value: string, byteLength: number): boolean {
  if (value.length !== Math.ceil((byteLength * 4) / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  const remainder = byteLength % 3;
  if (remainder === 0) {
    return true;
  }
  const last = value.at(-1);
  if (last === undefined) {
    return false;
  }
  const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(last);
  return remainder === 1 ? index >= 0 && index % 16 === 0 : index >= 0 && index % 4 === 0;
}

function isFutureIsoTimestamp(value: string, now: number): boolean {
  const timestamp = Date.parse(value);
  return (
    Number.isSafeInteger(timestamp) &&
    timestamp > now &&
    new Date(timestamp).toISOString() === value
  );
}

function isExactDiagnosticEndpoint(candidate: string, mcpEndpoint: string): boolean {
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})(?:\/|$)/.exec(candidate);
  if (match === null || match[1] === undefined || Number(match[1]) > 65535) {
    return false;
  }

  try {
    const endpoint = new URL(candidate);
    const mcp = new URL(mcpEndpoint);
    return (
      endpoint.protocol === 'http:' &&
      endpoint.hostname === '127.0.0.1' &&
      endpoint.origin === mcp.origin &&
      endpoint.pathname === mcp.pathname &&
      endpoint.username.length === 0 &&
      endpoint.password.length === 0 &&
      endpoint.search.length === 0 &&
      endpoint.hash.length === 0
    );
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonBlankString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
