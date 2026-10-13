import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  MAX_SAFE_REVISION,
  serializeCanonicalPageFileV1,
  type PageFileV1,
  type UuidV4,
} from '@scene-glass/contracts';
import { resolvePageIdentity } from '../../packages/core/src/page-identity.js';
import { canonicalizeJson } from '../../packages/core/src/operation-replay.js';
import {
  createAnnotationTools,
  type AnnotationToolDependencies,
} from '../../packages/server/src/mcp/annotation-tools.js';
import { createPromptExportTool } from '../../packages/server/src/mcp/export-tool.js';
import { McpInvalidParamsError, type McpTool } from '../../packages/server/src/mcp/dispatcher.js';
import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import type { AnnotationStore } from '../../packages/server/src/storage/scg-annotation-store.js';

const ANNOTATION_ID = 'fedcba98-7654-4321-8abc-def012345678' as UuidV4;
const OPERATION_ID = '01234567-89ab-4cde-8fab-0123456789ab';
const DELETE_OPERATION_ID = '11111111-1111-4111-8111-111111111111';
const OVERSIZED_OPERATION_ID = '22222222-2222-4222-8222-222222222222';
const project: AuthorizedProject = Object.freeze({
  projectId: 'annotation-tool-schema-contract',
  effectiveLimits: BUILT_IN_LIMITS,
});
const REPLAY_BYTE_LIMIT_CASES = Object.freeze([
  Object.freeze({
    limitName: 'replayResultBytes' as const,
    byteSizeName: 'result' as const,
    sequence: 2,
  }),
  Object.freeze({
    limitName: 'replayLedgerBytes' as const,
    byteSizeName: 'ledger' as const,
    sequence: 3,
  }),
  Object.freeze({
    limitName: 'pageFileBytes' as const,
    byteSizeName: 'pageFile' as const,
    sequence: 4,
  }),
]);

interface AnnotationSchemaCase {
  readonly name:
    'annotations.list' | 'annotations.create' | 'annotations.update' | 'annotations.delete';
  readonly argumentsValue: Readonly<Record<string, unknown>>;
  readonly admitted: boolean;
}

describe('annotation tool schemas', () => {
  it('advertises the same structural admission contract as every annotation handler', async () => {
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/annotation-schema-parity',
    });

    for (const testCase of annotationSchemaCases(page)) {
      const tracking = trackingStore();
      const tool = findTool(createAnnotationTools(dependencies(tracking.store)), testCase.name);

      expect({
        schemaAdmitted: schemaAdmits(tool.inputSchema, testCase.argumentsValue),
        handlerAdmitted: await handlerAdmitsArguments(tool, testCase.argumentsValue),
        rejectedInputDidNotExecuteStore: testCase.admitted || tracking.executionCount() === 0,
      }).toEqual({
        schemaAdmitted: testCase.admitted,
        handlerAdmitted: testCase.admitted,
        rejectedInputDidNotExecuteStore: true,
      });
    }
  });
  it('preserves unexpected annotation parser failures without entering the lock or store', async () => {
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/annotation-hostile-input',
    });
    const tracking = trackingStore();
    let lockEntries = 0;
    const tool = findTool(
      createAnnotationTools({
        ...dependencies(tracking.store),
        projectLock: {
          runExclusive: async <T>(
            _signal: AbortSignal,
            operation: () => Promise<T>,
          ): Promise<T> => {
            lockEntries += 1;
            return operation();
          },
        },
      }),
      'annotations.create',
    );
    const parserFailure = new TypeError('unexpected annotation input reflection failure');
    const hostileInput = new Proxy<Record<string, unknown>>(
      { ...createRequest(page, OPERATION_ID) },
      {
        ownKeys: () => {
          throw parserFailure;
        },
      },
    );

    await expect(tool.execute(hostileInput, { signal: new AbortController().signal })).rejects.toBe(
      parserFailure,
    );
    expect(lockEntries).toBe(0);
    expect(tracking.executionCount()).toBe(0);
  });
  it('derives each page schema byte bound independently from effective project limits', () => {
    const canonicalIdentityBytes = 17;
    const routeBytes = 29;
    const tracking = trackingStore();
    const limitedProject: AuthorizedProject = Object.freeze({
      ...project,
      effectiveLimits: Object.freeze({
        ...BUILT_IN_LIMITS,
        canonicalIdentityBytes,
        routeBytes,
      }),
    });
    const tool = findTool(
      createAnnotationTools(dependencies(tracking.store, limitedProject)),
      'annotations.list',
    );
    const rootProperties = requireSchemaRecord(
      requireSchemaRecord(tool.inputSchema, 'tool input schema').properties,
      'tool properties',
    );
    const pageProperties = requireSchemaRecord(
      requireSchemaRecord(rootProperties.page, 'page schema').properties,
      'page properties',
    );

    expect(
      requireSchemaRecord(pageProperties.canonicalIdentity, 'canonical identity schema').maxLength,
    ).toBe(canonicalIdentityBytes);
    expect(requireSchemaRecord(pageProperties.route, 'route schema').maxLength).toBe(routeBytes);
    expect(canonicalIdentityBytes).not.toBe(routeBytes);
    expect(tracking.executionCount()).toBe(0);
  });

  it('returns the durable create result when cancellation arrives during commit completion', async () => {
    const controller = new AbortController();
    let committed: PageFileV1 | undefined;
    const tools = createAnnotationTools(
      dependencies({
        readPage: async () => null,
        async *listPages() {},
        commitPage: async (_project, page, signal) => {
          expect(signal).toBe(controller.signal);
          committed = page;
          controller.abort(new Error('cancelled after durable commit'));
        },
      }),
    );
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/annotation-tools-schema',
    });

    const result = await findTool(tools, 'annotations.create').execute(
      {
        page,
        expectedRevision: 0,
        operationId: OPERATION_ID,
        locator: { dataScgId: 'save-button' },
        memo: 'Review this control',
        surroundingText: 'Save changes',
        domOrder: 3,
        resolution: { status: 'resolved', reason: null },
      },
      { signal: controller.signal },
    );

    expect(controller.signal.aborted).toBe(true);
    expect(committed).toMatchObject({ revision: 1 });
    expect(result).toMatchObject({
      replay: { annotation: { id: ANNOTATION_ID }, kind: 'create', revision: 1 },
      revision: 1,
    });
  });
  it('grandfathers exact historical replays while enforcing tightened limits for new mutations', async () => {
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/annotation-replay-tightening',
    });
    let pageFile: PageFileV1 | null = null;
    let commitCount = 0;
    const store: AnnotationStore = {
      readPage: async () => pageFile,
      async *listPages() {},
      commitPage: async (_project, candidate) => {
        commitCount += 1;
        pageFile = candidate;
      },
    };
    const context = { signal: new AbortController().signal };
    const initialRequest = createRequest(page, OPERATION_ID);
    const create = findTool(createAnnotationTools(dependencies(store)), 'annotations.create');
    const initial = await create.execute(initialRequest, context);
    const initialPageFile = requireStoredPageFile(pageFile);
    const historicalResult = initialPageFile.replayWindow[0]!.result;
    if (historicalResult.kind !== 'create') {
      throw new Error('Expected the historical replay result to be a create');
    }
    const tightenedReplayResultBytes = 128;
    expect(utf8Bytes(canonicalizeJson(historicalResult))).toBeGreaterThan(
      tightenedReplayResultBytes,
    );

    const tightenedProject: AuthorizedProject = Object.freeze({
      ...project,
      effectiveLimits: Object.freeze({
        ...BUILT_IN_LIMITS,
        replayResultBytes: tightenedReplayResultBytes,
      }),
    });
    const tightenedTools = createAnnotationTools(dependencies(store, tightenedProject));
    const deleteTool = findTool(tightenedTools, 'annotations.delete');
    const tightenedCreateTool = findTool(tightenedTools, 'annotations.create');
    const beforeExactReplay = serializeCanonicalPageFileV1(initialPageFile);

    await expect(tightenedCreateTool.execute(initialRequest, context)).resolves.toEqual(initial);
    expect(commitCount).toBe(1);
    expect(serializeCanonicalPageFileV1(requireStoredPageFile(pageFile))).toBe(beforeExactReplay);

    const beforeReusedOperation = serializeCanonicalPageFileV1(requireStoredPageFile(pageFile));
    await expect(
      tightenedCreateTool.execute(
        { ...initialRequest, memo: 'A different replay payload' },
        context,
      ),
    ).rejects.toMatchObject({ code: 'SCG_OPERATION_ID_REUSED' });
    expect(commitCount).toBe(1);
    expect(serializeCanonicalPageFileV1(requireStoredPageFile(pageFile))).toBe(
      beforeReusedOperation,
    );

    const deleted = await deleteTool.execute(
      {
        page,
        annotationId: historicalResult.annotation.id,
        expectedRevision: 1,
        operationId: DELETE_OPERATION_ID,
      },
      context,
    );

    expect(initial).toMatchObject({ revision: 1 });
    expect(deleted).toMatchObject({ replay: { kind: 'delete', revision: 2 }, revision: 2 });
    expect(requireStoredPageFile(pageFile).revision).toBe(2);
    expect(requireStoredPageFile(pageFile).replayWindow).toHaveLength(2);
    expect(
      utf8Bytes(canonicalizeJson(requireStoredPageFile(pageFile).replayWindow[0]!.result)),
    ).toBeGreaterThan(tightenedReplayResultBytes);

    const beforeOversizedMutation = serializeCanonicalPageFileV1(requireStoredPageFile(pageFile));
    await expect(
      tightenedCreateTool.execute(createRequest(page, OVERSIZED_OPERATION_ID, 2), context),
    ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
    expect(commitCount).toBe(2);
    expect(serializeCanonicalPageFileV1(requireStoredPageFile(pageFile))).toBe(
      beforeOversizedMutation,
    );
  });
  it('commits candidates at each byte limit and preserves storage one byte over', async () => {
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/annotation-replay-byte-limits',
    });
    const context = { signal: new AbortController().signal };
    const previewStore = recordingStore();
    const previewTool = findTool(
      createAnnotationTools(dependencies(previewStore.store)),
      'annotations.create',
    );
    await previewTool.execute(createRequest(page, boundaryOperationId(1)), context);
    const byteSizes = candidateByteSizes(requireStoredPageFile(previewStore.pageFile()));

    for (const limitCase of REPLAY_BYTE_LIMIT_CASES) {
      const exactStore = recordingStore();
      const exactProject = projectWithLimit(limitCase.limitName, byteSizes[limitCase.byteSizeName]);
      const exactTool = findTool(
        createAnnotationTools(dependencies(exactStore.store, exactProject)),
        'annotations.create',
      );
      await expect(
        exactTool.execute(createRequest(page, boundaryOperationId(limitCase.sequence)), context),
      ).resolves.toMatchObject({ revision: 1 });
      expect(exactStore.commitCount()).toBe(1);
      expect(candidateByteSizes(requireStoredPageFile(exactStore.pageFile()))).toEqual(byteSizes);

      const rejectedStore = recordingStore();
      const rejectedProject = projectWithLimit(
        limitCase.limitName,
        byteSizes[limitCase.byteSizeName] - 1,
      );
      const rejectedTool = findTool(
        createAnnotationTools(dependencies(rejectedStore.store, rejectedProject)),
        'annotations.create',
      );
      await expect(
        rejectedTool.execute(
          createRequest(page, boundaryOperationId(limitCase.sequence + 10)),
          context,
        ),
      ).rejects.toMatchObject({ code: 'SCG_LIMIT_FILE' });
      expect(rejectedStore.commitCount()).toBe(0);
      expect(rejectedStore.pageFile()).toBeNull();
    }
  });
  it('advertises and accepts the exact page and project prompt export inputs', async () => {
    const page = await resolvePageIdentity({
      override: 'https://review.scene-glass.test/prompt-export-schema',
    });
    const pageFile: PageFileV1 = {
      schemaVersion: 1,
      page,
      revision: 0,
      annotations: [],
      replayWindow: [],
    };
    let lockEntries = 0;
    let storeEntries = 0;
    const tool = createPromptExportTool({
      project,
      store: {
        readPage: async () => null,
        async *listPages() {
          storeEntries += 1;
          yield pageFile;
        },
        commitPage: async () => {},
      },
      projectLock: {
        runExclusive: async <T>(_signal: AbortSignal, operation: () => Promise<T>): Promise<T> => {
          lockEntries += 1;
          return operation();
        },
      },
      exportTimeoutMs: 100,
    });
    const schema = tool.inputSchema;
    const pageRequest = { mode: 'page', pageId: page.pageId } as const;
    const projectRequest = { mode: 'project' } as const;
    const invalidRequests = [
      { mode: 'project', pageId: page.pageId },
      { mode: 'page' },
      { mode: 'page', pageId: 'not-a-page-id' },
      { ...pageRequest, unexpected: true },
    ] as const;
    const context = { signal: new AbortController().signal };

    expect(schemaAdmits(schema, projectRequest)).toBe(true);
    expect(schemaAdmits(schema, pageRequest)).toBe(true);
    for (const invalidRequest of invalidRequests) {
      expect(schemaAdmits(schema, invalidRequest)).toBe(false);
      await expect(tool.execute(invalidRequest, context)).rejects.toBeInstanceOf(
        McpInvalidParamsError,
      );
      expect(lockEntries).toBe(0);
      expect(storeEntries).toBe(0);
    }

    const parserFailure = new Error('unexpected export input reflection failure');
    const hostileInput = new Proxy<Record<string, unknown>>(
      { mode: 'project' },
      {
        ownKeys: () => {
          throw parserFailure;
        },
      },
    );
    await expect(tool.execute(hostileInput, context)).rejects.toBe(parserFailure);
    expect(lockEntries).toBe(0);
    expect(storeEntries).toBe(0);

    await expect(tool.execute(projectRequest, context)).resolves.toEqual({
      markdown: expect.any(String),
      mode: 'project',
    });
    await expect(tool.execute(pageRequest, context)).resolves.toEqual({
      markdown: expect.any(String),
      mode: 'page',
      pageId: page.pageId,
    });
    expect(lockEntries).toBe(2);
    expect(storeEntries).toBe(2);
  });
});

function annotationSchemaCases(page: PageFileV1['page']): readonly AnnotationSchemaCase[] {
  const create = createRequest(page, OPERATION_ID);
  const update = Object.freeze({
    page,
    annotationId: ANNOTATION_ID,
    expectedRevision: 0,
    operationId: DELETE_OPERATION_ID,
    patch: { memo: 'Updated review note' },
  });
  const remove = Object.freeze({
    page,
    annotationId: ANNOTATION_ID,
    expectedRevision: 0,
    operationId: OVERSIZED_OPERATION_ID,
  });
  const fingerprint = Object.freeze({
    tag: 'button',
    stableAttributes: [['aria-label', 'Save']] as const,
    ancestorSignatures: ['main'] as const,
    textDigest: `sha256:${'a'.repeat(64)}`,
  });
  const context = Object.freeze({
    viewport: [1440, 900] as const,
    rect: [12, 34, 320, 48] as const,
    tag: 'button',
    classes: ['primary', 'save-button'] as const,
    cssPath: 'main > form > button.save-button',
    selectedText: 'Save changes',
    sourceFile: 'src/components/SaveButton.tsx',
    componentTrail: ['App', 'SaveButton'] as const,
  });

  return [
    { name: 'annotations.list', argumentsValue: { page }, admitted: true },
    {
      name: 'annotations.list',
      argumentsValue: { page: { ...page, pageId: 'invalid-page-id' } },
      admitted: false,
    },
    {
      name: 'annotations.list',
      argumentsValue: {
        page: {
          policyVersion: 1,
          canonicalIdentity: page.canonicalIdentity,
          pageId: page.pageId,
        },
      },
      admitted: false,
    },
    {
      name: 'annotations.list',
      argumentsValue: { page: { ...page, unexpected: true } },
      admitted: false,
    },
    { name: 'annotations.create', argumentsValue: create, admitted: true },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, context },
      admitted: true,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, context: { ...context, unexpected: true } },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, context: { ...context, viewport: '1440x900' } },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, context: { ...context, rect: [12, 34, '320', 48] } },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        page,
        expectedRevision: 0,
        operationId: OPERATION_ID,
        memo: 'Review this control',
        surroundingText: 'Save changes',
        domOrder: 3,
        resolution: { status: 'resolved', reason: null },
      },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, locator: { unexpected: true } },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        ...create,
        locator: {
          fingerprint: {
            ...fingerprint,
            stableAttributes: [['aria-label', 'Save', 'unexpected']],
          },
        },
      },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        ...create,
        locator: { fingerprint: { ...fingerprint, textDigest: 'sha256:invalid' } },
      },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, memo: '   ' },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, locator: { dataScgId: '   ' } },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, domOrder: -1 },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        ...create,
        expectedRevision: MAX_SAFE_REVISION + 1,
      },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: { ...create, operationId: 'INVALID-UUID' },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        ...create,
        resolution: { status: 'resolved', reason: 'ambiguous' },
      },
      admitted: false,
    },
    {
      name: 'annotations.create',
      argumentsValue: {
        ...create,
        locator: { dataScgId: 'save-button', fingerprint },
      },
      admitted: true,
    },
    { name: 'annotations.update', argumentsValue: update, admitted: true },
    {
      name: 'annotations.update',
      argumentsValue: { ...update, annotationId: 'not-a-uuid' },
      admitted: false,
    },
    {
      name: 'annotations.update',
      argumentsValue: { ...update, expectedRevision: -1 },
      admitted: false,
    },
    {
      name: 'annotations.update',
      argumentsValue: { ...update, patch: {} },
      admitted: false,
    },
    {
      name: 'annotations.update',
      argumentsValue: { ...update, patch: { unexpected: true } },
      admitted: false,
    },
    {
      name: 'annotations.update',
      argumentsValue: {
        page,
        annotationId: ANNOTATION_ID,
        expectedRevision: 0,
        operationId: DELETE_OPERATION_ID,
      },
      admitted: false,
    },
    {
      name: 'annotations.update',
      argumentsValue: {
        ...update,
        patch: {
          locator: { fingerprint: { ...fingerprint, ancestorSignatures: ['', 'main'] } },
        },
      },
      admitted: false,
    },
    { name: 'annotations.delete', argumentsValue: remove, admitted: true },
    {
      name: 'annotations.delete',
      argumentsValue: { ...remove, annotationId: 'not-a-uuid' },
      admitted: false,
    },
    {
      name: 'annotations.delete',
      argumentsValue: { ...remove, expectedRevision: -1 },
      admitted: false,
    },
    {
      name: 'annotations.delete',
      argumentsValue: { page, annotationId: ANNOTATION_ID, expectedRevision: 0 },
      admitted: false,
    },
    {
      name: 'annotations.delete',
      argumentsValue: { ...remove, unexpected: true },
      admitted: false,
    },
  ];
}

function createRequest(
  page: PageFileV1['page'],
  operationId: string,
  expectedRevision = 0,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    page,
    expectedRevision,
    operationId,
    locator: { dataScgId: 'save-button' },
    memo: 'Review this control',
    surroundingText: 'Save changes',
    domOrder: 3,
    resolution: { status: 'resolved', reason: null },
  });
}

function trackingStore(): {
  readonly store: AnnotationStore;
  executionCount(): number;
} {
  let executions = 0;
  return {
    store: {
      readPage: async () => {
        executions += 1;
        return null;
      },
      async *listPages() {},
      commitPage: async () => {
        executions += 1;
      },
    },
    executionCount: () => executions,
  };
}

function recordingStore(): {
  readonly store: AnnotationStore;
  commitCount(): number;
  pageFile(): PageFileV1 | null;
} {
  let commits = 0;
  let storedPageFile: PageFileV1 | null = null;
  return {
    store: {
      readPage: async () => storedPageFile,
      async *listPages() {},
      commitPage: async (_project, candidate) => {
        commits += 1;
        storedPageFile = candidate;
      },
    },
    commitCount: () => commits,
    pageFile: () => storedPageFile,
  };
}

function requireStoredPageFile(pageFile: PageFileV1 | null): PageFileV1 {
  if (pageFile === null) {
    throw new Error('Expected annotation mutation to commit');
  }
  return pageFile;
}

function candidateByteSizes(pageFile: PageFileV1): {
  readonly result: number;
  readonly ledger: number;
  readonly pageFile: number;
} {
  const result = pageFile.replayWindow.at(-1)?.result;
  if (result === undefined) {
    throw new Error('Expected a replay result');
  }
  return Object.freeze({
    result: utf8Bytes(canonicalizeJson(result)),
    ledger: utf8Bytes(canonicalizeJson(pageFile.replayWindow)),
    pageFile: utf8Bytes(serializeCanonicalPageFileV1(pageFile)),
  });
}

function projectWithLimit(
  limitName: (typeof REPLAY_BYTE_LIMIT_CASES)[number]['limitName'],
  limit: number,
): AuthorizedProject {
  return Object.freeze({
    ...project,
    effectiveLimits: Object.freeze({ ...BUILT_IN_LIMITS, [limitName]: limit }),
  });
}

function boundaryOperationId(sequence: number): string {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}`;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

async function handlerAdmitsArguments(
  tool: McpTool,
  argumentsValue: Readonly<Record<string, unknown>>,
): Promise<boolean> {
  try {
    await tool.execute(argumentsValue, { signal: new AbortController().signal });
    return true;
  } catch (error: unknown) {
    return !(error instanceof McpInvalidParamsError);
  }
}

function dependencies(
  store: AnnotationStore,
  authorizedProject: AuthorizedProject = project,
): AnnotationToolDependencies {
  return {
    project: authorizedProject,
    store,
    projectLock: {
      runExclusive: async <T>(_signal: AbortSignal, operation: () => Promise<T>): Promise<T> =>
        operation(),
    },
    createServerValues: () =>
      Object.freeze({
        id: ANNOTATION_ID,
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      }),
    updateServerValues: () => Object.freeze({ updatedAt: '2026-01-01T00:00:01.000Z' }),
  };
}

function findTool(tools: readonly McpTool[], name: string): McpTool {
  const tool = tools.find((candidate) => candidate.name === name);
  if (tool === undefined) {
    throw new Error(`Tool ${name} is not registered`);
  }
  return tool;
}

function schemaAdmits(schemaValue: unknown, value: unknown): boolean {
  if (typeof schemaValue === 'boolean') {
    return schemaValue;
  }
  const schema = schemaRecord(schemaValue);
  if (schema === undefined || !schemaTypeAdmits(schema.type, value)) {
    return false;
  }
  if (
    (hasOwn(schema, 'const') && schema.const !== value) ||
    (schema.enum !== undefined &&
      (!Array.isArray(schema.enum) || !schema.enum.some((candidate) => candidate === value)))
  ) {
    return false;
  }
  if (!schemaCombinatorsAdmit(schema, value)) {
    return false;
  }
  if (typeof value === 'string' && !stringSchemaAdmits(schema, value)) {
    return false;
  }
  if (typeof value === 'number' && !numberSchemaAdmits(schema, value)) {
    return false;
  }
  if (Array.isArray(value) && !arraySchemaAdmits(schema, value)) {
    return false;
  }
  const objectValue = schemaRecord(value);
  if (objectValue !== undefined && !objectSchemaAdmits(schema, objectValue)) {
    return false;
  }
  return schema.not === undefined || !schemaAdmits(schema.not, value);
}

function schemaCombinatorsAdmit(
  schema: Readonly<Record<string, unknown>>,
  value: unknown,
): boolean {
  if (schema.anyOf !== undefined) {
    if (
      !Array.isArray(schema.anyOf) ||
      !schema.anyOf.some((branch) => schemaAdmits(branch, value))
    ) {
      return false;
    }
  }
  if (schema.oneOf !== undefined) {
    if (
      !Array.isArray(schema.oneOf) ||
      schema.oneOf.filter((branch) => schemaAdmits(branch, value)).length !== 1
    ) {
      return false;
    }
  }
  return true;
}

function stringSchemaAdmits(schema: Readonly<Record<string, unknown>>, value: string): boolean {
  const length = Array.from(value).length;
  if (
    (schema.minLength !== undefined &&
      (!isNonNegativeInteger(schema.minLength) || length < schema.minLength)) ||
    (schema.maxLength !== undefined &&
      (!isNonNegativeInteger(schema.maxLength) || length > schema.maxLength))
  ) {
    return false;
  }
  if (schema.pattern === undefined) {
    return true;
  }
  if (typeof schema.pattern !== 'string') {
    return false;
  }
  try {
    return new RegExp(schema.pattern).test(value);
  } catch {
    return false;
  }
}

function numberSchemaAdmits(schema: Readonly<Record<string, unknown>>, value: number): boolean {
  return (
    (schema.minimum === undefined ||
      (typeof schema.minimum === 'number' && value >= schema.minimum)) &&
    (schema.maximum === undefined ||
      (typeof schema.maximum === 'number' && value <= schema.maximum))
  );
}

function arraySchemaAdmits(
  schema: Readonly<Record<string, unknown>>,
  value: readonly unknown[],
): boolean {
  if (
    (schema.minItems !== undefined &&
      (!isNonNegativeInteger(schema.minItems) || value.length < schema.minItems)) ||
    (schema.maxItems !== undefined &&
      (!isNonNegativeInteger(schema.maxItems) || value.length > schema.maxItems))
  ) {
    return false;
  }
  const prefixItems = schema.prefixItems;
  if (prefixItems !== undefined && !Array.isArray(prefixItems)) {
    return false;
  }
  const prefixLength = prefixItems?.length ?? 0;
  for (let index = 0; index < prefixLength; index += 1) {
    const itemSchema = prefixItems?.[index];
    if (
      itemSchema === undefined ||
      value[index] === undefined ||
      !schemaAdmits(itemSchema, value[index])
    ) {
      return false;
    }
  }
  if (value.length <= prefixLength || schema.items === undefined) {
    return true;
  }
  if (schema.items === false) {
    return false;
  }
  if (schema.items === true) {
    return true;
  }
  return value.slice(prefixLength).every((item) => schemaAdmits(schema.items, item));
}

function objectSchemaAdmits(
  schema: Readonly<Record<string, unknown>>,
  value: Readonly<Record<string, unknown>>,
): boolean {
  const properties = schema.properties === undefined ? undefined : schemaRecord(schema.properties);
  if (schema.properties !== undefined && properties === undefined) {
    return false;
  }
  const required = schema.required === undefined ? [] : schema.required;
  if (!Array.isArray(required) || !required.every(isString)) {
    return false;
  }
  if (!required.every((key) => hasOwn(value, key))) {
    return false;
  }
  const keys = Object.keys(value);
  if (
    (schema.minProperties !== undefined &&
      (!isNonNegativeInteger(schema.minProperties) || keys.length < schema.minProperties)) ||
    (schema.maxProperties !== undefined &&
      (!isNonNegativeInteger(schema.maxProperties) || keys.length > schema.maxProperties))
  ) {
    return false;
  }
  for (const [key, propertyValue] of Object.entries(value)) {
    const propertySchema = properties?.[key];
    if (propertySchema === undefined) {
      if (schema.additionalProperties === false) {
        return false;
      }
      continue;
    }
    if (!schemaAdmits(propertySchema, propertyValue)) {
      return false;
    }
  }
  return true;
}

function schemaTypeAdmits(type: unknown, value: unknown): boolean {
  switch (type) {
    case undefined:
      return true;
    case 'array':
      return Array.isArray(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'null':
      return value === null;
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'object':
      return schemaRecord(value) !== undefined;
    case 'string':
      return typeof value === 'string';
    default:
      return false;
  }
}

function schemaRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as Readonly<Record<string, unknown>>;
}
function requireSchemaRecord(value: unknown, label: string): Readonly<Record<string, unknown>> {
  const record = schemaRecord(value);
  if (record === undefined) {
    throw new TypeError(`${label} must be an object schema`);
  }
  return record;
}

function hasOwn(value: Readonly<Record<string, unknown>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}
