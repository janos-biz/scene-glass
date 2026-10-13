import type {
  CreateAnnotationInput,
  DeleteAnnotationInput,
  ElementAnnotation,
  LocatorInput,
  PageIdentityInput,
  UpdateAnnotationInput,
} from '@scene-glass/contracts';

import {
  resolveElementLocator,
  type LocatorResolution,
  type LocatorSearchRoot,
} from './resolver.js';

export interface AnnotationSnapshot {
  readonly revision: number;
  readonly annotations: readonly ElementAnnotation[];
}

export interface CreatedAnnotation {
  readonly revision: number;
  readonly annotation: ElementAnnotation;
}

export interface UpdatedAnnotation {
  readonly revision: number;
  readonly annotation: ElementAnnotation;
}

export interface DeletedAnnotation {
  readonly revision: number;
  readonly annotationId: DeleteAnnotationInput['annotationId'];
}

/** Browser-facing MCP boundary. It has no browser storage responsibilities. */
export interface AnnotationMcpPort {
  listAnnotations(page: PageIdentityInput): Promise<AnnotationSnapshot>;
  createAnnotation(input: CreateAnnotationInput): Promise<CreatedAnnotation>;
  updateAnnotation(input: UpdateAnnotationInput): Promise<UpdatedAnnotation>;
  deleteAnnotation(input: DeleteAnnotationInput): Promise<DeletedAnnotation>;
}

export type CreateAnnotationRequest = Omit<CreateAnnotationInput, 'expectedRevision' | 'page'>;
export type UpdateAnnotationRequest = Omit<UpdateAnnotationInput, 'expectedRevision' | 'page'>;
export type DeleteAnnotationRequest = Omit<DeleteAnnotationInput, 'expectedRevision' | 'page'>;

export interface AnnotationBinding {
  readonly annotation: ElementAnnotation;
  readonly resolution: LocatorResolution;
}

export interface AnnotationControllerError {
  readonly code: string;
  readonly message: string;
  readonly source: 'manual' | 'mcp';
}

export interface AnnotationControllerState {
  readonly generation: number;
  readonly page?: PageIdentityInput;
  readonly revision?: number;
  readonly annotations: readonly ElementAnnotation[];
  readonly bindings: readonly AnnotationBinding[];
  readonly loading: boolean;
  readonly error?: AnnotationControllerError;
}

export interface AnnotationControllerOptions {
  readonly port: AnnotationMcpPort;
  readonly resolve?: AnnotationResolver;
  readonly root?: LocatorSearchRoot;
  readonly onStateChange?: (state: AnnotationControllerState) => void;
}

export type AnnotationResolver = (
  locator: LocatorInput,
  root?: LocatorSearchRoot,
) => Promise<LocatorResolution>;

export type AnnotationOperationResult =
  | { readonly status: 'applied' }
  | { readonly status: 'ignored' }
  | { readonly status: 'failed'; readonly error: AnnotationControllerError };

/**
 * Keeps server state page-scoped and generation-scoped. Responses from an old
 * document generation are deliberately ignored rather than reconciled into a
 * new page. The controller applies no optimistic writes.
 */
export class AnnotationController {
  private readonly port: AnnotationMcpPort;
  private readonly resolve: AnnotationResolver;
  private readonly root: LocatorSearchRoot | undefined;
  private readonly listeners = new Set<(state: AnnotationControllerState) => void>();
  private state: AnnotationControllerState = emptyState();
  private sequence = 0;
  private destroyed = false;

  public constructor(options: AnnotationControllerOptions) {
    this.port = options.port;
    this.resolve = options.resolve ?? resolveElementLocator;
    this.root = options.root;
    if (options.onStateChange !== undefined) {
      this.listeners.add(options.onStateChange);
    }
  }

  public getState(): AnnotationControllerState {
    return this.state;
  }

  public subscribe(listener: (state: AnnotationControllerState) => void): () => void {
    if (this.destroyed) {
      return () => undefined;
    }
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public setPage(page: PageIdentityInput): void {
    if (this.destroyed) {
      return;
    }
    this.sequence += 1;
    this.commit({
      generation: this.state.generation + 1,
      page,
      annotations: [],
      bindings: [],
      loading: false,
    });
  }

  public async load(): Promise<AnnotationOperationResult> {
    if (this.destroyed || this.state.page === undefined) {
      return this.missingContext();
    }

    const context = Object.freeze({
      generation: this.state.generation,
      page: this.state.page,
    });
    const token = this.begin(context.generation, true);
    try {
      const snapshot = await this.port.listAnnotations(context.page);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      this.commit({
        generation: context.generation,
        page: context.page,
        revision: snapshot.revision,
        annotations: snapshot.annotations,
        bindings: [],
        loading: true,
      });
      await this.reconcileSnapshot(token, snapshot.annotations);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      this.commit({ ...this.state, loading: false });
      return { status: 'applied' };
    } catch (error: unknown) {
      return this.fail(token, error);
    }
  }

  public async create(request: CreateAnnotationRequest): Promise<AnnotationOperationResult> {
    const context = this.requireContext();
    if (context === undefined) {
      return this.missingContext();
    }

    const token = this.begin(context.generation, true);
    const input: CreateAnnotationInput = {
      ...request,
      page: context.page,
      expectedRevision: context.revision,
    };
    try {
      const response = await this.port.createAnnotation(input);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      const annotations = replaceAnnotation(this.state.annotations, response.annotation);
      this.commit({
        generation: context.generation,
        page: context.page,
        revision: response.revision,
        annotations,
        bindings: [],
        loading: true,
      });
      await this.reconcileSnapshot(token, annotations);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      this.commit({ ...this.state, loading: false });
      return { status: 'applied' };
    } catch (error: unknown) {
      return this.fail(token, error);
    }
  }

  public async update(request: UpdateAnnotationRequest): Promise<AnnotationOperationResult> {
    const context = this.requireContext();
    if (context === undefined) {
      return this.missingContext();
    }

    const token = this.begin(context.generation, true);
    const input: UpdateAnnotationInput = {
      ...request,
      page: context.page,
      expectedRevision: context.revision,
    };
    try {
      const response = await this.port.updateAnnotation(input);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      const annotations = replaceAnnotation(this.state.annotations, response.annotation);
      this.commit({
        generation: context.generation,
        page: context.page,
        revision: response.revision,
        annotations,
        bindings: [],
        loading: true,
      });
      await this.reconcileSnapshot(token, annotations);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      this.commit({ ...this.state, loading: false });
      return { status: 'applied' };
    } catch (error: unknown) {
      return this.fail(token, error);
    }
  }

  public async delete(request: DeleteAnnotationRequest): Promise<AnnotationOperationResult> {
    const context = this.requireContext();
    if (context === undefined) {
      return this.missingContext();
    }

    const token = this.begin(context.generation, true);
    const input: DeleteAnnotationInput = {
      ...request,
      page: context.page,
      expectedRevision: context.revision,
    };
    try {
      const response = await this.port.deleteAnnotation(input);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      const annotations = this.state.annotations.filter(
        (annotation) => annotation.id !== response.annotationId,
      );
      this.commit({
        generation: context.generation,
        page: context.page,
        revision: response.revision,
        annotations,
        bindings: [],
        loading: true,
      });
      await this.reconcileSnapshot(token, annotations);
      if (!this.isCurrent(token)) {
        return { status: 'ignored' };
      }
      this.commit({ ...this.state, loading: false });
      return { status: 'applied' };
    } catch (error: unknown) {
      return this.fail(token, error);
    }
  }

  /** Rebinds the currently loaded snapshot without writing it back to the MCP. */
  public async reconcile(): Promise<AnnotationOperationResult> {
    const context = this.requireContext();
    if (context === undefined) {
      return this.missingContext();
    }
    const token = this.begin(context.generation, false);
    this.commit({ ...this.state, bindings: [] });
    try {
      await this.reconcileSnapshot(token, this.state.annotations);
      return this.isCurrent(token) ? { status: 'applied' } : { status: 'ignored' };
    } catch (error: unknown) {
      return this.fail(token, error);
    }
  }

  public setManualError(message: string, code = 'SCG_MANUAL_ERROR'): void {
    if (this.destroyed) {
      return;
    }
    this.commit({
      ...this.state,
      error: freezeError({ code, message, source: 'manual' }),
    });
  }

  public clearError(): void {
    if (this.destroyed || this.state.error === undefined) {
      return;
    }
    this.commit(withoutError(this.state));
  }

  public destroy(): void {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.sequence += 1;
    this.listeners.clear();
  }

  private begin(generation: number, loading: boolean): RequestToken {
    const token = Object.freeze({ generation, sequence: (this.sequence += 1) });
    this.commit({ ...this.state, loading });
    return token;
  }

  private requireContext(): PageContext | undefined {
    if (this.destroyed || this.state.page === undefined || this.state.revision === undefined) {
      return undefined;
    }
    return Object.freeze({
      generation: this.state.generation,
      page: this.state.page,
      revision: this.state.revision,
    });
  }

  private missingContext(): AnnotationOperationResult {
    const error = freezeError({
      code: 'SCG_ANNOTATION_STATE',
      message: 'Load annotations for the current page before changing them.',
      source: 'manual',
    });
    if (!this.destroyed) {
      this.commit({ ...this.state, error });
    }
    return { status: 'failed', error };
  }

  private isCurrent(token: RequestToken): boolean {
    return (
      !this.destroyed &&
      this.state.generation === token.generation &&
      this.sequence === token.sequence
    );
  }

  private async reconcileSnapshot(
    token: RequestToken,
    annotations: readonly ElementAnnotation[],
  ): Promise<void> {
    const bindings = await Promise.all(
      annotations.map(async (annotation) =>
        Object.freeze({
          annotation,
          resolution: await this.resolve(annotation.locator, this.root),
        }),
      ),
    );
    if (!this.isCurrent(token)) {
      return;
    }
    this.commit({ ...this.state, bindings: Object.freeze(bindings) });
  }

  private fail(token: RequestToken, error: unknown): AnnotationOperationResult {
    if (!this.isCurrent(token)) {
      return { status: 'ignored' };
    }
    const normalized = errorFor(error);
    this.commit({ ...this.state, loading: false, error: normalized });
    return { status: 'failed', error: normalized };
  }

  private commit(next: AnnotationControllerState): void {
    this.state = freezeState(next);
    for (const listener of this.listeners) {
      try {
        listener(this.state);
      } catch {
        // UI listeners are isolated from browser review state.
      }
    }
  }
}

function emptyState(): AnnotationControllerState {
  return freezeState({
    generation: 0,
    annotations: [],
    bindings: [],
    loading: false,
  });
}

function replaceAnnotation(
  annotations: readonly ElementAnnotation[],
  replacement: ElementAnnotation,
): readonly ElementAnnotation[] {
  const index = annotations.findIndex((annotation) => annotation.id === replacement.id);
  if (index < 0) {
    return Object.freeze([...annotations, replacement]);
  }
  return Object.freeze([
    ...annotations.slice(0, index),
    replacement,
    ...annotations.slice(index + 1),
  ]);
}

function errorFor(error: unknown): AnnotationControllerError {
  const code = errorCode(error);
  if (code === 'SCG_LIMIT_FILE') {
    return freezeError({
      code,
      message: 'The annotation file has reached its configured limit. No change was saved.',
      source: 'mcp',
    });
  }
  return freezeError({
    code,
    message: errorMessage(error),
    source: 'mcp',
  });
}

function errorCode(error: unknown): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return error.code;
  }
  return 'SCG_MCP_ERROR';
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.length > 0
    ? error.message
    : 'Scene Glass could not complete the annotation request.';
}

function freezeError(error: AnnotationControllerError): AnnotationControllerError {
  return Object.freeze({ ...error });
}

function withoutError(state: AnnotationControllerState): AnnotationControllerState {
  const without = { ...state };
  delete without.error;
  return without;
}

function freezeState(state: AnnotationControllerState): AnnotationControllerState {
  const next: {
    generation: number;
    page?: PageIdentityInput;
    revision?: number;
    annotations: readonly ElementAnnotation[];
    bindings: readonly AnnotationBinding[];
    loading: boolean;
    error?: AnnotationControllerError;
  } = {
    generation: state.generation,
    annotations: Object.freeze([...state.annotations]),
    bindings: Object.freeze([...state.bindings]),
    loading: state.loading,
  };
  if (state.page !== undefined) {
    next.page = state.page;
  }
  if (state.revision !== undefined) {
    next.revision = state.revision;
  }
  if (state.error !== undefined) {
    next.error = state.error;
  }
  return Object.freeze(next);
}

interface PageContext {
  readonly generation: number;
  readonly page: PageIdentityInput;
  readonly revision: number;
}

interface RequestToken {
  readonly generation: number;
  readonly sequence: number;
}
