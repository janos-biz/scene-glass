import { describe, expect, it } from 'vitest';
import {
  SceneGlassContractError,
  type SceneGlassContractErrorCode,
  parseCreateAnnotationInput,
  parseDeleteAnnotationInput,
  parseUpdateAnnotationInput,
  parseUpdateAnnotationPatch,
} from '@scene-glass/contracts';

const ANNOTATION_ID = 'fedcba98-7654-4321-8abc-def012345678';
const OPERATION_ID = '01234567-89ab-4cde-8fab-0123456789ab';
type MutationParser = (value: unknown) => unknown;
type MutationCase = readonly [kind: string, parse: MutationParser, input: Record<string, unknown>];

const mutationCases = [
  ['create', parseCreateAnnotationInput, createInput()],
  ['update', parseUpdateAnnotationInput, updateInput()],
  ['delete', parseDeleteAnnotationInput, deleteInput()],
] satisfies readonly MutationCase[];

function page() {
  return {
    policyVersion: 1,
    canonicalIdentity: '/contract-page',
    route: '/contract-page',
    pageId: `p_${'a'.repeat(64)}`,
  };
}

function createInput() {
  return {
    page: page(),
    expectedRevision: 0,
    operationId: OPERATION_ID,
    locator: { dataScgId: 'save-button' },
    memo: 'Review this control',
    surroundingText: 'Save changes',
    domOrder: 3,
    resolution: { status: 'not-found', reason: 'not-found' },
  };
}

function updateInput() {
  return {
    page: page(),
    annotationId: ANNOTATION_ID,
    expectedRevision: 4,
    operationId: OPERATION_ID,
    patch: { memo: 'Updated review note' },
  };
}

function deleteInput() {
  return {
    page: page(),
    annotationId: ANNOTATION_ID,
    expectedRevision: 4,
    operationId: OPERATION_ID,
  };
}

function expectContractError(action: () => unknown, code: SceneGlassContractErrorCode): void {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe(code);
}

describe('annotation mutation DTOs', () => {
  it('parses complete create, update, and delete DTOs', () => {
    expect(parseCreateAnnotationInput(createInput())).toEqual(createInput());
    expect(parseUpdateAnnotationInput(updateInput())).toEqual(updateInput());
    expect(parseDeleteAnnotationInput(deleteInput())).toEqual(deleteInput());
  });

  it.each(mutationCases)('rejects unknown top-level %s DTO properties', (_kind, parse, input) => {
    expect.hasAssertions();
    expectContractError(() => parse({ ...input, unexpected: true }), 'SCG_ANNOTATION_INVALID');
  });

  it('rejects server-owned annotation fields in client mutation DTOs', () => {
    expect.hasAssertions();
    expectContractError(
      () => parseCreateAnnotationInput({ ...createInput(), id: ANNOTATION_ID }),
      'SCG_ANNOTATION_INVALID',
    );
    expectContractError(
      () =>
        parseUpdateAnnotationInput({
          ...updateInput(),
          patch: { memo: 'Updated review note', createdAt: '2026-01-01T00:00:00Z' },
        }),
      'SCG_ANNOTATION_INVALID',
    );
    expectContractError(
      () =>
        parseDeleteAnnotationInput({
          ...deleteInput(),
          updatedAt: '2026-01-01T00:00:00Z',
        }),
      'SCG_ANNOTATION_INVALID',
    );
  });

  it.each(mutationCases)('requires every documented %s DTO field', (_kind, parse, input) => {
    expect.hasAssertions();
    const withoutOperationId: Record<string, unknown> = { ...input };
    delete withoutOperationId.operationId;
    expectContractError(() => parse(withoutOperationId), 'SCG_ANNOTATION_INVALID');
  });

  it('requires a nonempty update patch', () => {
    expect.hasAssertions();
    expectContractError(() => parseUpdateAnnotationPatch({}), 'SCG_ANNOTATION_INVALID');
    expectContractError(
      () => parseUpdateAnnotationInput({ ...updateInput(), patch: {} }),
      'SCG_ANNOTATION_INVALID',
    );
  });

  it('rejects blank create and update memos with the memo-specific error code', () => {
    expect.hasAssertions();
    expectContractError(
      () => parseCreateAnnotationInput({ ...createInput(), memo: ' \t\n ' }),
      'SCG_MEMO_BLANK',
    );
    expectContractError(() => parseUpdateAnnotationPatch({ memo: '\t' }), 'SCG_MEMO_BLANK');
  });
});
