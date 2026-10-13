import {
  BUILT_IN_LIMITS,
  LOCATOR_STABLE_ATTRIBUTE_NAME_PATTERN,
  LOCATOR_TAG_NAME_PATTERN,
  MAX_DOM_ORDER,
  MAX_LOCATOR_ANCESTOR_SIGNATURES,
  MAX_SAFE_REVISION,
  PAGE_ID_PATTERN as PAGE_ID_PATTERN_REGEXP,
  SHA256_DIGEST_PATTERN as SHA256_DIGEST_PATTERN_REGEXP,
  SceneGlassContractError,
  parseCreateAnnotationInput,
  parseDeleteAnnotationInput,
  parsePageFileV1,
  parsePageIdentityInput,
  parseReplayRecord,
  parseUpdateAnnotationInput,
  serializeCanonicalPageFileV1,
  type CreateAnnotationInput,
  type DeleteAnnotationInput,
  type LimitValues,
  type PageFileV1,
  type PageIdentityInput,
  type ReplayResult,
  type UpdateAnnotationInput,
} from '@scene-glass/contracts';
import {
  createAnnotation,
  createScreenReview,
  deleteAnnotation,
  updateAnnotation,
  type CreateAnnotationServerValues,
  type ScreenReviewMutation,
  type UpdateAnnotationServerValues,
} from '@scene-glass/core';
import {
  canonicalizeJson,
  createOperationPayload,
  digestOperationInput,
  prepareOperationReplay,
  updateOperationPayload,
  deleteOperationPayload,
  type ReplayOperation,
} from '@scene-glass/core/operation-replay';
import { validateCanonicalPageIdentity } from '@scene-glass/core/page-identity';

import type { AuthorizedProject } from '../registry/config-project-registry.js';
import type { AnnotationStore } from '../storage/scg-annotation-store.js';
import {
  McpInvalidParamsError,
  McpRpcError,
  type McpInvocationContext,
  type McpTool,
} from './dispatcher.js';

export interface ProjectLock {
  runExclusive<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T>;
}

export interface AnnotationToolDependencies {
  readonly project: AuthorizedProject;
  readonly store: AnnotationStore;
  readonly projectLock: ProjectLock;
  readonly createServerValues: () => CreateAnnotationServerValues;
  readonly updateServerValues: () => UpdateAnnotationServerValues;
}

export interface AnnotationListResult {
  readonly page: PageIdentityInput;
  readonly revision: number;
  readonly annotations: PageFileV1['annotations'];
}

export interface AnnotationMutationResult {
  readonly replay: ReplayResult;
  readonly revision: number;
}

const UUID_V4_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const NON_BLANK_PATTERN = '^(?=[\\s\\S]*\\S)[\\s\\S]*$';
const NON_BLANK_NO_CONTROL_PATTERN = '^(?=[\\s\\S]*\\S)[^\\u0000-\\u001F\\u007F]+$';
const NO_ASCII_CONTROL_PATTERN = '^[^\\u0000-\\u001F\\u007F-\\u009F]+$';
const NO_NULL_OR_DELETE_PATTERN = '^[^\\u0000\\u007F]*$';

const UUID_V4_SCHEMA = Object.freeze({
  type: 'string',
  pattern: UUID_V4_PATTERN,
});
const SAFE_REVISION_SCHEMA = Object.freeze({
  type: 'integer',
  minimum: 0,
  maximum: MAX_SAFE_REVISION,
});
const DOM_ORDER_SCHEMA = Object.freeze({
  type: 'integer',
  minimum: 0,
  maximum: MAX_DOM_ORDER,
});
function pageIdentitySchema(
  limits: Pick<LimitValues, 'canonicalIdentityBytes' | 'routeBytes'>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    type: 'object',
    additionalProperties: false,
    required: ['policyVersion', 'canonicalIdentity', 'route', 'pageId'],
    properties: {
      policyVersion: { const: 1 },
      canonicalIdentity: {
        type: 'string',
        minLength: 1,
        maxLength: limits.canonicalIdentityBytes,
        pattern: NO_ASCII_CONTROL_PATTERN,
      },
      route: {
        type: 'string',
        minLength: 1,
        maxLength: limits.routeBytes,
        pattern: NO_ASCII_CONTROL_PATTERN,
      },
      pageId: {
        type: 'string',
        pattern: PAGE_ID_PATTERN_REGEXP.source,
      },
    },
  });
}
const LOCATOR_STABLE_ATTRIBUTE_SCHEMA = Object.freeze({
  type: 'array',
  minItems: 2,
  maxItems: 2,
  prefixItems: [
    {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      pattern: LOCATOR_STABLE_ATTRIBUTE_NAME_PATTERN.source,
    },
    {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      pattern: NO_NULL_OR_DELETE_PATTERN,
    },
  ],
  items: false,
});
const LOCATOR_FINGERPRINT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['tag', 'stableAttributes', 'ancestorSignatures', 'textDigest'],
  properties: {
    tag: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      pattern: LOCATOR_TAG_NAME_PATTERN.source,
    },
    stableAttributes: {
      type: 'array',
      items: LOCATOR_STABLE_ATTRIBUTE_SCHEMA,
    },
    ancestorSignatures: {
      type: 'array',
      maxItems: MAX_LOCATOR_ANCESTOR_SIGNATURES,
      items: {
        type: 'string',
        maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
        pattern: NON_BLANK_NO_CONTROL_PATTERN,
      },
    },
    textDigest: {
      type: 'string',
      pattern: SHA256_DIGEST_PATTERN_REGEXP.source,
    },
  },
});
const LOCATOR_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  properties: {
    dataScgId: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      pattern: NON_BLANK_NO_CONTROL_PATTERN,
    },
    fingerprint: LOCATOR_FINGERPRINT_SCHEMA,
  },
  anyOf: [{ required: ['dataScgId'] }, { required: ['fingerprint'] }],
});
const RESOLUTION_SCHEMA = Object.freeze({
  oneOf: [
    {
      type: 'object',
      additionalProperties: false,
      required: ['status', 'reason'],
      properties: {
        status: { const: 'resolved' },
        reason: { const: null },
      },
    },
    {
      type: 'object',
      additionalProperties: false,
      required: ['status', 'reason'],
      properties: {
        status: { const: 'ambiguous' },
        reason: { const: 'ambiguous' },
      },
    },
    {
      type: 'object',
      additionalProperties: false,
      required: ['status', 'reason'],
      properties: {
        status: { const: 'not-found' },
        reason: { const: 'not-found' },
      },
    },
  ],
});
const CONTEXT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['viewport', 'rect', 'tag', 'classes', 'cssPath', 'selectedText'],
  properties: {
    viewport: {
      type: 'array',
      items: { type: 'integer', minimum: 0 },
      minItems: 2,
      maxItems: 2,
    },
    rect: {
      type: 'array',
      items: { type: 'integer' },
      minItems: 4,
      maxItems: 4,
    },
    tag: {
      type: 'string',
      pattern: LOCATOR_TAG_NAME_PATTERN.source,
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
    },
    classes: {
      type: 'array',
      maxItems: 64,
      items: {
        type: 'string',
        minLength: 1,
        maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      },
    },
    cssPath: { type: 'string', maxLength: 4096 },
    selectedText: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.surroundingTextBytes,
    },
    sourceFile: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
    },
    componentTrail: {
      type: 'array',
      maxItems: 64,
      items: {
        type: 'string',
        minLength: 1,
        maxLength: BUILT_IN_LIMITS.locatorFieldBytes,
      },
    },
  },
});
function createSchema(
  pageSchema: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    type: 'object',
    additionalProperties: false,
    required: [
      'page',
      'expectedRevision',
      'operationId',
      'locator',
      'memo',
      'surroundingText',
      'domOrder',
      'resolution',
    ],
    properties: {
      page: pageSchema,
      expectedRevision: SAFE_REVISION_SCHEMA,
      operationId: UUID_V4_SCHEMA,
      locator: LOCATOR_SCHEMA,
      memo: {
        type: 'string',
        maxLength: BUILT_IN_LIMITS.memoBytes,
        pattern: NON_BLANK_PATTERN,
      },
      surroundingText: {
        type: 'string',
        maxLength: BUILT_IN_LIMITS.surroundingTextCodePoints,
      },
      domOrder: DOM_ORDER_SCHEMA,
      resolution: RESOLUTION_SCHEMA,
      context: CONTEXT_SCHEMA,
    },
  });
}
const UPDATE_PATCH_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  minProperties: 1,
  properties: {
    memo: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.memoBytes,
      pattern: NON_BLANK_PATTERN,
    },
    locator: LOCATOR_SCHEMA,
    surroundingText: {
      type: 'string',
      maxLength: BUILT_IN_LIMITS.surroundingTextCodePoints,
    },
    domOrder: DOM_ORDER_SCHEMA,
    resolution: RESOLUTION_SCHEMA,
    context: CONTEXT_SCHEMA,
  },
});
function updateSchema(
  pageSchema: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    type: 'object',
    additionalProperties: false,
    required: ['page', 'annotationId', 'expectedRevision', 'operationId', 'patch'],
    properties: {
      page: pageSchema,
      annotationId: UUID_V4_SCHEMA,
      expectedRevision: SAFE_REVISION_SCHEMA,
      operationId: UUID_V4_SCHEMA,
      patch: UPDATE_PATCH_SCHEMA,
    },
  });
}

function deleteSchema(
  pageSchema: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    type: 'object',
    additionalProperties: false,
    required: ['page', 'annotationId', 'expectedRevision', 'operationId'],
    properties: {
      page: pageSchema,
      annotationId: UUID_V4_SCHEMA,
      expectedRevision: SAFE_REVISION_SCHEMA,
      operationId: UUID_V4_SCHEMA,
    },
  });
}

function annotationListSchema(
  pageSchema: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    type: 'object',
    additionalProperties: false,
    required: ['page'],
    properties: { page: pageSchema },
  });
}

function annotationInputSchemas(
  limits: Pick<LimitValues, 'canonicalIdentityBytes' | 'routeBytes'>,
): Readonly<{
  readonly list: Readonly<Record<string, unknown>>;
  readonly create: Readonly<Record<string, unknown>>;
  readonly update: Readonly<Record<string, unknown>>;
  readonly delete: Readonly<Record<string, unknown>>;
}> {
  const pageSchema = pageIdentitySchema(limits);
  return Object.freeze({
    list: annotationListSchema(pageSchema),
    create: createSchema(pageSchema),
    update: updateSchema(pageSchema),
    delete: deleteSchema(pageSchema),
  });
}

/**
 * Builds the normal-scope annotation tool set. The caller owns lock selection,
 * storage authority, and every server-owned ID/timestamp value.
 */
export function createAnnotationTools(
  dependencies: AnnotationToolDependencies,
): readonly McpTool[] {
  assertAnnotationDependencies(dependencies);
  const schemas = annotationInputSchemas(dependencies.project.effectiveLimits);

  return Object.freeze([
    Object.freeze({
      name: 'annotations.list',
      description: 'Read the current annotation review for one canonical page.',
      inputSchema: schemas.list,
      execute: async (
        argumentsValue: unknown,
        context: McpInvocationContext,
      ): Promise<AnnotationListResult> => {
        context.signal.throwIfAborted();
        const page = await validatePageFromListArguments(argumentsValue, dependencies);
        context.signal.throwIfAborted();
        const stored = await dependencies.store.readPage(
          dependencies.project,
          page,
          context.signal,
        );
        context.signal.throwIfAborted();
        return reviewResult(stored, page);
      },
    }),
    Object.freeze({
      name: 'annotations.create',
      description: 'Create one annotation with an operation replay record.',
      inputSchema: schemas.create,
      execute: async (
        argumentsValue: unknown,
        context: McpInvocationContext,
      ): Promise<AnnotationMutationResult> => {
        context.signal.throwIfAborted();
        const input = await validateMutationInput(
          argumentsValue,
          parseCreateAnnotationInput,
          dependencies,
        );
        context.signal.throwIfAborted();
        return dependencies.projectLock.runExclusive(context.signal, async () => {
          context.signal.throwIfAborted();
          return executeCreate(dependencies, input, context.signal);
        });
      },
    }),
    Object.freeze({
      name: 'annotations.update',
      description: 'Update one annotation with an operation replay record.',
      inputSchema: schemas.update,
      execute: async (
        argumentsValue: unknown,
        context: McpInvocationContext,
      ): Promise<AnnotationMutationResult> => {
        context.signal.throwIfAborted();
        const input = await validateMutationInput(
          argumentsValue,
          parseUpdateAnnotationInput,
          dependencies,
        );
        context.signal.throwIfAborted();
        return dependencies.projectLock.runExclusive(context.signal, async () => {
          context.signal.throwIfAborted();
          return executeUpdate(dependencies, input, context.signal);
        });
      },
    }),
    Object.freeze({
      name: 'annotations.delete',
      description: 'Delete one annotation with an operation replay record.',
      inputSchema: schemas.delete,
      execute: async (
        argumentsValue: unknown,
        context: McpInvocationContext,
      ): Promise<AnnotationMutationResult> => {
        context.signal.throwIfAborted();
        const input = await validateMutationInput(
          argumentsValue,
          parseDeleteAnnotationInput,
          dependencies,
        );
        context.signal.throwIfAborted();
        return dependencies.projectLock.runExclusive(context.signal, async () => {
          context.signal.throwIfAborted();
          return executeDelete(dependencies, input, context.signal);
        });
      },
    }),
  ] satisfies readonly McpTool[]);
}

async function executeCreate(
  dependencies: AnnotationToolDependencies,
  input: CreateAnnotationInput,
  signal: AbortSignal,
): Promise<AnnotationMutationResult> {
  signal.throwIfAborted();
  const payload = createOperationPayload(input);
  return executeMutation(
    dependencies,
    input,
    'create',
    payload,
    (pageFile) =>
      createAnnotation(
        createScreenReview(pageFile.page, pageFile.annotations, pageFile.revision),
        input,
        dependencies.createServerValues(),
      ),
    signal,
  );
}

async function executeUpdate(
  dependencies: AnnotationToolDependencies,
  input: UpdateAnnotationInput,
  signal: AbortSignal,
): Promise<AnnotationMutationResult> {
  signal.throwIfAborted();
  const payload = updateOperationPayload(input);
  return executeMutation(
    dependencies,
    input,
    'update',
    payload,
    (pageFile) =>
      updateAnnotation(
        createScreenReview(pageFile.page, pageFile.annotations, pageFile.revision),
        input,
        dependencies.updateServerValues(),
      ),
    signal,
  );
}

async function executeDelete(
  dependencies: AnnotationToolDependencies,
  input: DeleteAnnotationInput,
  signal: AbortSignal,
): Promise<AnnotationMutationResult> {
  signal.throwIfAborted();
  const payload = deleteOperationPayload(input);
  return executeMutation(
    dependencies,
    input,
    'delete',
    payload,
    (pageFile) =>
      deleteAnnotation(
        createScreenReview(pageFile.page, pageFile.annotations, pageFile.revision),
        input,
      ),
    signal,
  );
}

async function executeMutation(
  dependencies: AnnotationToolDependencies,
  input: CreateAnnotationInput | UpdateAnnotationInput | DeleteAnnotationInput,
  kind: ReplayOperation['kind'],
  payload: unknown,
  mutate: (pageFile: PageFileV1) => ScreenReviewMutation,
  signal: AbortSignal,
): Promise<AnnotationMutationResult> {
  signal.throwIfAborted();
  const pageFile =
    (await dependencies.store.readPage(dependencies.project, input.page, signal)) ??
    emptyPageFile(input.page, dependencies);
  signal.throwIfAborted();
  const operation: ReplayOperation = Object.freeze({
    projectId: dependencies.project.projectId,
    operationId: input.operationId,
    kind,
    expectedRevision: input.expectedRevision,
    payload,
  });

  const replay = await resolveExistingReplay(pageFile, operation, signal);
  signal.throwIfAborted();
  if (replay !== undefined) {
    return replay;
  }
  if (input.expectedRevision !== pageFile.revision) {
    throw new McpRpcError('SCG_REVISION_CONFLICT', {
      currentRevision: pageFile.revision,
    });
  }

  const mutation = mutate(pageFile);
  signal.throwIfAborted();
  const decision = await prepareOperationReplay({
    pageFile,
    operation,
    annotations: mutation.review.annotations,
    result: mutation.result,
    limits: dependencies.project.effectiveLimits,
  });
  signal.throwIfAborted();

  switch (decision.status) {
    case 'exact-replay':
    case 'operation-id-reused':
      throw new McpRpcError('SCG_INTERNAL');
    case 'revision-conflict':
      throw new McpRpcError('SCG_REVISION_CONFLICT', {
        currentRevision: decision.currentRevision,
      });
    case 'no-write':
      throw new McpRpcError('SCG_LIMIT_FILE', {
        limit: decision.reason,
        pageFileBytes: decision.byteSizes.pageFile,
        replayLedgerBytes: decision.byteSizes.ledger,
        replayResultBytes: decision.byteSizes.result,
      });
    case 'apply': {
      signal.throwIfAborted();
      const candidate = validateCandidateBeforeCommit(
        decision.pageFile,
        decision.result,
        dependencies,
      );
      signal.throwIfAborted();
      await dependencies.store.commitPage(dependencies.project, candidate, signal);
      return Object.freeze({
        replay: decision.result,
        revision: decision.result.revision,
      });
    }
  }
}

async function resolveExistingReplay(
  pageFile: PageFileV1,
  operation: ReplayOperation,
  signal: AbortSignal,
): Promise<AnnotationMutationResult | undefined> {
  const record = pageFile.replayWindow.find(
    (candidate) => candidate.operationId === operation.operationId,
  );
  if (record === undefined) {
    return undefined;
  }
  const inputDigest = await digestOperationInput(pageFile, operation);
  signal.throwIfAborted();
  if (record.kind !== operation.kind || record.inputDigest !== inputDigest) {
    throw new McpRpcError('SCG_OPERATION_ID_REUSED');
  }
  return Object.freeze({
    replay: record.result,
    revision: record.result.revision,
  });
}

function validateCandidateBeforeCommit(
  candidate: PageFileV1,
  result: ReplayResult,
  dependencies: AnnotationToolDependencies,
): PageFileV1 {
  const parsed = parsePageFileV1(
    candidate,
    Object.freeze({
      ...dependencies.project.effectiveLimits,
      // Historical records remain valid under the built-in ceiling. The
      // effective result limit is enforced below for the new tail record.
      replayResultBytes: BUILT_IN_LIMITS.replayResultBytes,
    }),
  );
  const latestRecord = parsed.replayWindow.at(-1);
  if (
    latestRecord === undefined ||
    canonicalizeJson(latestRecord.result) !== canonicalizeJson(result)
  ) {
    throw new McpRpcError('SCG_INTERNAL');
  }
  parseReplayRecord(latestRecord, dependencies.project.effectiveLimits);

  const pageFileBytes = utf8Bytes(serializeCanonicalPageFileV1(parsed));
  const replayLedgerBytes = utf8Bytes(canonicalizeJson(parsed.replayWindow));
  const replayResultBytes = utf8Bytes(canonicalizeJson(latestRecord.result));
  if (
    pageFileBytes > dependencies.project.effectiveLimits.pageFileBytes ||
    replayLedgerBytes > dependencies.project.effectiveLimits.replayLedgerBytes ||
    replayResultBytes > dependencies.project.effectiveLimits.replayResultBytes
  ) {
    throw new McpRpcError('SCG_LIMIT_FILE', {
      pageFileBytes,
      replayLedgerBytes,
      replayResultBytes,
    });
  }
  return parsed;
}

async function validatePageFromListArguments(
  value: unknown,
  dependencies: AnnotationToolDependencies,
): Promise<PageIdentityInput> {
  try {
    const record = strictRecord(value, 'annotation list arguments');
    assertExactKeys(record, ['page'], 'annotation list arguments');
    return await validatePage(record.page, dependencies);
  } catch (error: unknown) {
    throw invalidParameters(error);
  }
}

async function validateMutationInput<T extends { readonly page: PageIdentityInput }>(
  value: unknown,
  parse: (input: unknown) => T,
  dependencies: AnnotationToolDependencies,
): Promise<T> {
  try {
    const input = parse(value);
    await validatePage(input.page, dependencies);
    return input;
  } catch (error: unknown) {
    throw invalidParameters(error);
  }
}

async function validatePage(
  value: unknown,
  dependencies: AnnotationToolDependencies,
): Promise<PageIdentityInput> {
  const page = parsePageIdentityInput(value);
  return validateCanonicalPageIdentity(page, dependencies.project.effectiveLimits);
}

function emptyPageFile(
  page: PageIdentityInput,
  dependencies: AnnotationToolDependencies,
): PageFileV1 {
  return parsePageFileV1(
    {
      schemaVersion: 1,
      page,
      revision: 0,
      annotations: [],
      replayWindow: [],
    },
    dependencies.project.effectiveLimits,
  );
}

function reviewResult(pageFile: PageFileV1 | null, page: PageIdentityInput): AnnotationListResult {
  return Object.freeze({
    page: pageFile?.page ?? page,
    revision: pageFile?.revision ?? 0,
    annotations: pageFile?.annotations ?? Object.freeze([]),
  });
}

function assertAnnotationDependencies(dependencies: AnnotationToolDependencies): void {
  if (
    dependencies === null ||
    typeof dependencies !== 'object' ||
    dependencies.project === undefined ||
    dependencies.store === undefined ||
    dependencies.projectLock === undefined ||
    typeof dependencies.projectLock.runExclusive !== 'function' ||
    typeof dependencies.createServerValues !== 'function' ||
    typeof dependencies.updateServerValues !== 'function'
  ) {
    throw new TypeError('annotation tool dependencies are invalid');
  }
}
function invalidParameters(error: unknown): unknown {
  if (error instanceof McpInvalidParamsError || error instanceof McpRpcError) {
    return error;
  }
  if (error instanceof SceneGlassContractError) {
    return new McpInvalidParamsError(error.code);
  }
  return error;
}

function strictRecord(value: unknown, name: string): Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new SceneGlassContractError('SCG_ANNOTATION_INVALID', `${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  record: Record<string, unknown>,
  keys: readonly string[],
  name: string,
): void {
  const expected = new Set(keys);
  if (Object.keys(record).length !== expected.size) {
    throw new SceneGlassContractError('SCG_ANNOTATION_INVALID', `${name} is invalid`);
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new SceneGlassContractError('SCG_ANNOTATION_INVALID', `${name} is invalid`);
    }
  }
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
