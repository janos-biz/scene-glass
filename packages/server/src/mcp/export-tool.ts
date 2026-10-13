import { performance } from 'node:perf_hooks';

import {
  SceneGlassContractError,
  PAGE_ID_PATTERN,
  parsePageId,
  type PageFileV1,
  type PageId,
} from '@scene-glass/contracts';
import { exportReviewMarkdown } from '@scene-glass/core/prompt-export';

import type { AuthorizedProject } from '../registry/config-project-registry.js';
import type { AnnotationStore } from '../storage/scg-annotation-store.js';
import type { ProjectLock } from './annotation-tools.js';
import {
  McpInvalidParamsError,
  McpRpcError,
  type McpInvocationContext,
  type McpTool,
} from './dispatcher.js';

export interface PromptExportToolDependencies {
  readonly project: AuthorizedProject;
  readonly store: AnnotationStore;
  readonly projectLock: ProjectLock;
  readonly exportTimeoutMs: number;
}

export type PromptExportResult =
  | Readonly<{ readonly markdown: string; readonly mode: 'project' }>
  | Readonly<{ readonly markdown: string; readonly mode: 'page'; readonly pageId: PageId }>;

const EXPORT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['mode'],
  properties: {
    mode: { type: 'string', enum: ['project', 'page'] },
    pageId: { type: 'string', pattern: PAGE_ID_PATTERN.source },
  },
  oneOf: [
    Object.freeze({
      properties: { mode: { const: 'project' } },
      not: { required: ['pageId'] },
    }),
    Object.freeze({
      required: ['pageId'],
      properties: { mode: { const: 'page' } },
    }),
  ],
});

/**
 * The application opts into export by registering this returned tool with a
 * normal dispatcher. Diagnostic dispatchers cannot register any tools.
 */
export function createPromptExportTool(dependencies: PromptExportToolDependencies): McpTool {
  assertDependencies(dependencies);
  return Object.freeze({
    name: 'prompt.export',
    description: 'Render a deterministic Scene Glass review prompt.',
    inputSchema: EXPORT_SCHEMA,
    execute: (argumentsValue: unknown, context: McpInvocationContext) =>
      executePromptExport(dependencies, argumentsValue, context),
  } satisfies McpTool);
}

async function executePromptExport(
  dependencies: PromptExportToolDependencies,
  argumentsValue: unknown,
  context: McpInvocationContext,
): Promise<PromptExportResult> {
  const exportRequest = createExportRequestSignal(context.signal, dependencies.exportTimeoutMs);
  try {
    const signal = exportRequest.signal;
    exportRequest.checkpoint();
    const input = parseExportInput(argumentsValue);
    exportRequest.checkpoint();
    const result = await dependencies.projectLock.runExclusive(signal, async () => {
      exportRequest.checkpoint();
      const pageFiles: PageFileV1[] = [];
      for await (const pageFile of dependencies.store.listPages(dependencies.project, signal)) {
        exportRequest.checkpoint();
        pageFiles.push(pageFile);
      }
      exportRequest.checkpoint();
      const markdown =
        input.mode === 'page'
          ? exportReviewMarkdown(pageFiles, {
              mode: 'page',
              pageId: input.pageId,
              limits: dependencies.project.effectiveLimits,
              checkpoint: exportRequest.checkpoint,
            })
          : exportReviewMarkdown(pageFiles, {
              mode: 'project',
              limits: dependencies.project.effectiveLimits,
              checkpoint: exportRequest.checkpoint,
            });
      if (input.mode === 'project') {
        return Object.freeze({ mode: 'project', markdown });
      }
      return Object.freeze({ mode: 'page', pageId: input.pageId, markdown });
    });
    exportRequest.checkpoint();
    return result;
  } finally {
    exportRequest.dispose();
  }
}

type ParsedExportInput = Readonly<{ mode: 'project' }> | Readonly<{ mode: 'page'; pageId: PageId }>;
class PromptExportInputError extends Error {}

function parseExportInput(value: unknown): ParsedExportInput {
  try {
    const record = strictRecord(value);
    if (record.mode === 'project') {
      assertExactKeys(record, ['mode']);
      return Object.freeze({ mode: 'project' });
    }
    if (record.mode === 'page') {
      assertExactKeys(record, ['mode', 'pageId']);
      return Object.freeze({ mode: 'page', pageId: parsePageId(record.pageId) });
    }
    throw new PromptExportInputError('prompt export mode is invalid');
  } catch (error: unknown) {
    if (error instanceof McpInvalidParamsError || error instanceof McpRpcError) {
      throw error;
    }
    if (error instanceof SceneGlassContractError) {
      throw new McpInvalidParamsError(error.code);
    }
    if (error instanceof PromptExportInputError) {
      throw new McpInvalidParamsError('SCG_ANNOTATION_INVALID');
    }
    throw error;
  }
}

function assertDependencies(dependencies: PromptExportToolDependencies): void {
  if (
    dependencies === null ||
    typeof dependencies !== 'object' ||
    dependencies.project === undefined ||
    dependencies.store === undefined ||
    dependencies.projectLock === undefined ||
    typeof dependencies.projectLock.runExclusive !== 'function' ||
    !Number.isSafeInteger(dependencies.exportTimeoutMs) ||
    dependencies.exportTimeoutMs <= 0
  ) {
    throw new TypeError('prompt export tool dependencies are invalid');
  }
}
interface ExportRequestSignal {
  readonly signal: AbortSignal;
  readonly checkpoint: () => void;
  dispose(): void;
}

function createExportRequestSignal(
  parent: AbortSignal,
  exportTimeoutMs: number,
): ExportRequestSignal {
  const controller = new AbortController();
  const deadlineAt = performance.now() + exportTimeoutMs;
  let disposed = false;
  let deadline: ReturnType<typeof setTimeout> | undefined;

  const dispose = (): void => {
    if (disposed) {
      return;
    }
    disposed = true;
    if (deadline !== undefined) {
      clearTimeout(deadline);
    }
    parent.removeEventListener('abort', abortFromParent);
  };
  const abort = (reason: unknown): void => {
    if (controller.signal.aborted) {
      return;
    }
    dispose();
    controller.abort(reason);
  };
  const abortFromParent = (): void => {
    abort(parent.reason);
  };
  const checkpoint = (): void => {
    if (!controller.signal.aborted && performance.now() >= deadlineAt) {
      abort(new McpRpcError('SCG_EXPORT_TIMEOUT'));
    }
    controller.signal.throwIfAborted();
  };

  if (parent.aborted) {
    abortFromParent();
  } else {
    parent.addEventListener('abort', abortFromParent, { once: true });
    deadline = setTimeout(() => {
      abort(new McpRpcError('SCG_EXPORT_TIMEOUT'));
    }, exportTimeoutMs);
  }

  return Object.freeze({
    signal: controller.signal,
    checkpoint,
    dispose,
  });
}

function strictRecord(value: unknown): Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new PromptExportInputError('prompt export parameters must be an object');
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  const expected = new Set(keys);
  if (Object.keys(record).length !== expected.size) {
    throw new PromptExportInputError('prompt export parameters are invalid');
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new PromptExportInputError('prompt export parameters are invalid');
    }
  }
}
