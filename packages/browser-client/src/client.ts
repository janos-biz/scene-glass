import type {
  CreateAnnotationInput,
  DeleteAnnotationInput,
  PageIdentityInput,
  UpdateAnnotationInput,
} from '@scene-glass/contracts';
import {
  McpClient,
  McpHttpError,
  McpRpcDomainError,
  type AnnotationListToolResult,
  type AnnotationMutationToolResult,
  type DiagnosticRunCapability,
  type McpClientDependencies,
  type PromptExportInput,
  type PromptExportToolResult,
} from './mcp-client.js';

export type SceneGlassState =
  'booting' | 'connecting' | 'ready' | 'unavailable' | 'access-error' | 'destroyed';

export interface SceneGlassApi {
  readonly state: SceneGlassState;
  notifyReady(): void;
  retry(): Promise<void>;
  openDiagnostics(): Promise<void>;
  destroy(): Promise<void>;
}

export type DiagnosticsPanelOpener = (capability: DiagnosticRunCapability) => Promise<void> | void;

export interface SceneGlassClientOptions extends McpClientDependencies {
  readonly endpoint: string;
  readonly diagnosticEndpoint: string;
  readonly token: string;
  readonly openDiagnosticsPanel?: DiagnosticsPanelOpener;
  readonly onStateChange?: (state: SceneGlassState) => void;
  readonly onHostReady?: () => void;
}

export class SceneGlassClient {
  private readonly mcp: McpClient;
  private stateValue: SceneGlassState = 'booting';
  private connectTask: Promise<void> | null = null;
  private destroyTask: Promise<void> | null = null;
  private connectTaskEpoch: object | null = null;
  private connectionEpoch: object = Object.freeze({});
  private diagnosticsPanel: DiagnosticsPanelOpener | null;
  private stateChangeHandler: ((state: SceneGlassState) => void) | null;
  private hostReadyHandler: (() => void) | null;

  public constructor(options: SceneGlassClientOptions) {
    this.mcp = new McpClient({
      endpoint: options.endpoint,
      diagnosticEndpoint: options.diagnosticEndpoint,
      token: options.token,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.crypto === undefined ? {} : { crypto: options.crypto }),
    });
    this.diagnosticsPanel = options.openDiagnosticsPanel ?? null;
    this.stateChangeHandler = options.onStateChange ?? null;
    this.hostReadyHandler = options.onHostReady ?? null;
  }

  public get state(): SceneGlassState {
    return this.stateValue;
  }

  public start(): Promise<void> {
    if (this.stateValue !== 'booting') {
      return Promise.resolve();
    }
    return this.connect();
  }

  public retry(): Promise<void> {
    if (this.stateValue !== 'unavailable') {
      return Promise.resolve();
    }
    return this.connect();
  }

  public notifyReady(): void {
    if (this.stateValue === 'destroyed') {
      return;
    }

    try {
      this.hostReadyHandler?.();
    } catch {
      // Host callbacks are isolated from the host and do not change client availability.
    }

    if (this.stateValue === 'ready') {
      void this.pingAfterHostReady();
    }
  }

  public async openDiagnostics(): Promise<void> {
    if (this.stateValue !== 'ready') {
      throw new Error('Scene Glass is not ready');
    }
    const panel = this.diagnosticsPanel;
    if (panel === null) {
      throw new Error('Scene Glass diagnostics panel is unavailable');
    }
    await this.openDiagnosticPanel(panel, this.connectionEpoch);
  }

  public destroy(): Promise<void> {
    if (this.destroyTask !== null) {
      return this.destroyTask;
    }
    if (this.stateValue === 'destroyed') {
      return Promise.resolve();
    }

    this.invalidateConnection();
    this.diagnosticsPanel = null;
    this.hostReadyHandler = null;
    const closeTask = this.mcp.close();
    this.destroyTask = closeTask;
    this.transitionTo('destroyed');
    this.stateChangeHandler = null;
    return closeTask;
  }

  public listAnnotations(page: PageIdentityInput): Promise<AnnotationListToolResult> {
    return this.perform((mcp) => mcp.listAnnotations(page));
  }

  public createAnnotation(input: CreateAnnotationInput): Promise<AnnotationMutationToolResult> {
    return this.perform((mcp) => mcp.createAnnotation(input));
  }

  public updateAnnotation(input: UpdateAnnotationInput): Promise<AnnotationMutationToolResult> {
    return this.perform((mcp) => mcp.updateAnnotation(input));
  }

  public deleteAnnotation(input: DeleteAnnotationInput): Promise<AnnotationMutationToolResult> {
    return this.perform((mcp) => mcp.deleteAnnotation(input));
  }

  public exportPrompt(input: PromptExportInput): Promise<PromptExportToolResult> {
    return this.perform((mcp) => mcp.exportPrompt(input));
  }

  private async connect(): Promise<void> {
    if (this.connectTask !== null) {
      return this.connectTask;
    }

    const epoch = this.beginConnection();
    const task = this.initialize(epoch);
    this.connectTask = task;
    this.connectTaskEpoch = epoch;
    this.transitionTo('connecting');
    try {
      await task;
    } finally {
      this.clearConnectTask(epoch, task);
    }
  }

  private async initialize(epoch: object): Promise<void> {
    if (!this.isActiveConnection(epoch)) {
      return;
    }
    try {
      await this.mcp.initialize();
      if (this.isActiveConnection(epoch)) {
        this.transitionTo('ready');
      }
    } catch (error: unknown) {
      if (this.isActiveConnection(epoch)) {
        this.clearConnectTask(epoch);
        this.transitionToFailure(error);
      }
    }
  }

  private async pingAfterHostReady(): Promise<void> {
    const epoch = this.connectionEpoch;
    try {
      await this.mcp.ping();
    } catch (error: unknown) {
      if (this.isActiveConnection(epoch)) {
        this.transitionToFailure(error);
      }
    }
  }

  private async openDiagnosticPanel(panel: DiagnosticsPanelOpener, epoch: object): Promise<void> {
    let capability: DiagnosticRunCapability;
    try {
      capability = await this.mcp.issueDiagnosticRun();
    } catch (error: unknown) {
      if (this.isActiveConnection(epoch)) {
        this.transitionToFailure(error);
      }
      throw error;
    }

    if (!this.isReadyConnection(epoch)) {
      throw new Error('Scene Glass diagnostics request was superseded');
    }
    try {
      await panel(capability);
      if (!this.isReadyConnection(epoch)) {
        throw new Error('Scene Glass diagnostics request was superseded');
      }
    } catch (error: unknown) {
      if (!this.isReadyConnection(epoch)) {
        throw new Error('Scene Glass diagnostics request was superseded');
      }
      throw error;
    }
  }

  private async perform<T>(operation: (mcp: McpClient) => Promise<T>): Promise<T> {
    if (this.stateValue !== 'ready') {
      throw new Error('Scene Glass is not ready');
    }
    const epoch = this.connectionEpoch;
    try {
      const result = await operation(this.mcp);
      if (!this.isReadyConnection(epoch)) {
        throw new Error('Scene Glass operation was superseded');
      }
      return result;
    } catch (error: unknown) {
      if (!this.isReadyConnection(epoch)) {
        throw new Error('Scene Glass operation was superseded');
      }
      if (error instanceof McpRpcDomainError) {
        throw error;
      }
      this.transitionToFailure(error);
      throw error;
    }
  }

  private transitionToFailure(error: unknown): void {
    if (this.stateValue === 'destroyed') {
      return;
    }
    if (error instanceof McpHttpError && (error.status === 401 || error.status === 403)) {
      this.transitionTo('access-error');
      return;
    }
    this.transitionTo('unavailable');
  }
  private beginConnection(): object {
    const epoch = Object.freeze({});
    this.connectionEpoch = epoch;
    return epoch;
  }

  private invalidateConnection(): void {
    this.connectionEpoch = Object.freeze({});
  }

  private isActiveConnection(epoch: object): boolean {
    return this.connectionEpoch === epoch && this.stateValue !== 'destroyed';
  }
  private isReadyConnection(epoch: object): boolean {
    return this.isActiveConnection(epoch) && this.stateValue === 'ready';
  }

  private clearConnectTask(epoch: object, task?: Promise<void>): void {
    if (this.connectTaskEpoch === epoch && (task === undefined || this.connectTask === task)) {
      this.connectTask = null;
      this.connectTaskEpoch = null;
    }
  }
  private transitionTo(state: SceneGlassState): void {
    if (this.stateValue === state) {
      return;
    }
    this.stateValue = state;
    try {
      this.stateChangeHandler?.(state);
    } catch {
      // Application callback failures must not reach the host or alter the state machine.
    }
  }
}

export function createSceneGlassApi(client: SceneGlassClient): SceneGlassApi {
  return Object.freeze({
    get state(): SceneGlassState {
      return client.state;
    },
    notifyReady(): void {
      client.notifyReady();
    },
    retry(): Promise<void> {
      return client.retry();
    },
    openDiagnostics(): Promise<void> {
      return client.openDiagnostics();
    },
    destroy(): Promise<void> {
      return client.destroy();
    },
  });
}
