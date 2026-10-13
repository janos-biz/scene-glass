import { describe, expect, it } from 'vitest';
import {
  MAX_SAFE_REVISION,
  type CreateAnnotationInput,
  type DeleteAnnotationInput,
  type ElementAnnotation,
  type PageId,
  type PageIdentityInput,
  type UpdateAnnotationInput,
  type UuidV4,
} from '@scene-glass/contracts';
import {
  ScreenReviewError,
  createAnnotation,
  createScreenReview,
  deleteAnnotation,
  updateAnnotation,
  type ScreenReview,
  type ScreenReviewErrorCode,
} from '@scene-glass/core/screen-review';

const PAGE_ID = `p_${'3'.repeat(64)}` as PageId;
const PAGE: PageIdentityInput = {
  policyVersion: 1,
  canonicalIdentity: 'https://review.scene-glass.test/account',
  route: '/account',
  pageId: PAGE_ID,
};

function uuid(sequence: number): UuidV4 {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}` as UuidV4;
}

function annotation(sequence = 1): ElementAnnotation {
  return {
    id: uuid(sequence),
    locator: { dataScgId: `account-${sequence}` },
    memo: `Review account ${sequence}`,
    surroundingText: `Account ${sequence}`,
    domOrder: sequence,
    resolution: { status: 'resolved', reason: null },
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
  };
}

function createInput(expectedRevision: number, memo = 'Initial memo'): CreateAnnotationInput {
  return {
    page: PAGE,
    expectedRevision,
    operationId: uuid(100),
    locator: { dataScgId: 'account-target' },
    memo,
    surroundingText: 'Account settings',
    domOrder: 2,
    resolution: { status: 'resolved', reason: null },
  };
}

function updateInput(
  annotationId: UuidV4,
  expectedRevision: number,
  patch: UpdateAnnotationInput['patch'],
): UpdateAnnotationInput {
  return {
    page: PAGE,
    annotationId,
    expectedRevision,
    operationId: uuid(101),
    patch,
  };
}

function deleteInput(annotationId: UuidV4, expectedRevision: number): DeleteAnnotationInput {
  return {
    page: PAGE,
    annotationId,
    expectedRevision,
    operationId: uuid(102),
  };
}

function captureReview(review: ScreenReview) {
  return {
    review: structuredClone(review),
    serialized: JSON.stringify(review),
  };
}

function expectReviewUnchanged(
  review: ScreenReview,
  before: ReturnType<typeof captureReview>,
): void {
  expect(review).toEqual(before.review);
  expect(review.page).toEqual(before.review.page);
  expect(review.revision).toBe(before.review.revision);
  expect(review.annotations).toEqual(before.review.annotations);
  expect(JSON.stringify(review)).toBe(before.serialized);
}

function expectReviewFailure(
  review: ScreenReview,
  code: ScreenReviewErrorCode,
  mutation: () => unknown,
): void {
  const before = captureReview(review);
  let received: unknown;
  try {
    mutation();
  } catch (error: unknown) {
    received = error;
  }

  expect(received).toBeInstanceOf(ScreenReviewError);
  expect((received as ScreenReviewError).code).toBe(code);
  expectReviewUnchanged(review, before);
}

describe('screen review mutations', () => {
  it('creates, updates, and deletes at the expected revision with server-owned IDs and timestamps', () => {
    const emptyReview = createScreenReview(PAGE);
    const emptyBefore = captureReview(emptyReview);
    const created = createAnnotation(emptyReview, createInput(0), {
      id: uuid(1),
      createdAt: '2026-01-01T00:00:01Z',
      updatedAt: '2026-01-01T00:00:02Z',
    });

    expectReviewUnchanged(emptyReview, emptyBefore);
    expect(created.review.revision).toBe(1);
    expect(created.result).toEqual({
      kind: 'create',
      revision: 1,
      annotation: created.review.annotations[0],
    });
    expect(created.review.annotations[0]).toMatchObject({
      id: uuid(1),
      createdAt: '2026-01-01T00:00:01Z',
      updatedAt: '2026-01-01T00:00:02Z',
    });

    const createdBefore = captureReview(created.review);
    const existing = created.review.annotations[0];
    if (existing === undefined) {
      throw new Error('create mutation did not produce an annotation');
    }
    const updated = updateAnnotation(
      created.review,
      updateInput(existing.id, 1, {
        locator: { dataScgId: 'account-updated' },
        memo: 'Updated memo',
        surroundingText: 'Updated account settings',
        domOrder: 4,
        resolution: { status: 'not-found', reason: 'not-found' },
      }),
      { updatedAt: '2026-01-01T00:00:03Z' },
    );

    expectReviewUnchanged(created.review, createdBefore);
    expect(updated.review.revision).toBe(2);
    expect(updated.result).toEqual({
      kind: 'update',
      revision: 2,
      annotation: updated.review.annotations[0],
    });
    expect(updated.review.annotations[0]).toMatchObject({
      id: existing.id,
      createdAt: existing.createdAt,
      updatedAt: '2026-01-01T00:00:03Z',
      locator: { dataScgId: 'account-updated' },
      memo: 'Updated memo',
      surroundingText: 'Updated account settings',
      domOrder: 4,
      resolution: { status: 'not-found', reason: 'not-found' },
    });

    const updatedBefore = captureReview(updated.review);
    const deleted = deleteAnnotation(updated.review, deleteInput(existing.id, 2));

    expectReviewUnchanged(updated.review, updatedBefore);
    expect(deleted.review).toMatchObject({ revision: 3, annotations: [] });
    expect(deleted.result).toEqual({
      kind: 'delete',
      revision: 3,
      annotationId: existing.id,
    });
  });

  it('rejects blank create and update memos without writing', () => {
    expect.assertions(14);
    const emptyReview = createScreenReview(PAGE);
    expectReviewFailure(emptyReview, 'SCG_MEMO_BLANK', () =>
      createAnnotation(emptyReview, createInput(0, ' \t\n '), {
        id: uuid(2),
        createdAt: '2026-01-01T00:00:01Z',
        updatedAt: '2026-01-01T00:00:01Z',
      }),
    );

    const review = createScreenReview(PAGE, [annotation()]);
    expectReviewFailure(review, 'SCG_MEMO_BLANK', () =>
      updateAnnotation(review, updateInput(uuid(1), 0, { memo: ' \t' }), {
        updatedAt: '2026-01-01T00:00:02Z',
      }),
    );
  });

  it('does not write for missing annotation IDs', () => {
    expect.assertions(14);
    const review = createScreenReview(PAGE, [annotation()]);
    const missingId = uuid(99);

    expectReviewFailure(review, 'SCG_ANNOTATION_NOT_FOUND', () =>
      updateAnnotation(review, updateInput(missingId, 0, { memo: 'Never applied' }), {
        updatedAt: '2026-01-01T00:00:02Z',
      }),
    );
    expectReviewFailure(review, 'SCG_ANNOTATION_NOT_FOUND', () =>
      deleteAnnotation(review, deleteInput(missingId, 0)),
    );
  });

  it('does not write for stale revisions across create, update, and delete', () => {
    expect.assertions(21);
    const review = createScreenReview(PAGE, [annotation()], 1);

    expectReviewFailure(review, 'SCG_REVISION_CONFLICT', () =>
      createAnnotation(review, createInput(0), {
        id: uuid(2),
        createdAt: '2026-01-01T00:00:01Z',
        updatedAt: '2026-01-01T00:00:01Z',
      }),
    );
    expectReviewFailure(review, 'SCG_REVISION_CONFLICT', () =>
      updateAnnotation(review, updateInput(uuid(1), 0, { memo: 'Never applied' }), {
        updatedAt: '2026-01-01T00:00:02Z',
      }),
    );
    expectReviewFailure(review, 'SCG_REVISION_CONFLICT', () =>
      deleteAnnotation(review, deleteInput(uuid(1), 0)),
    );
  });

  it('does not write when any mutation would exceed the maximum revision', () => {
    expect.assertions(21);
    const review = createScreenReview(PAGE, [annotation()], MAX_SAFE_REVISION);

    expectReviewFailure(review, 'SCG_REVISION_EXHAUSTED', () =>
      createAnnotation(review, createInput(MAX_SAFE_REVISION), {
        id: uuid(2),
        createdAt: '2026-01-01T00:00:01Z',
        updatedAt: '2026-01-01T00:00:01Z',
      }),
    );
    expectReviewFailure(review, 'SCG_REVISION_EXHAUSTED', () =>
      updateAnnotation(review, updateInput(uuid(1), MAX_SAFE_REVISION, { memo: 'Never applied' }), {
        updatedAt: '2026-01-01T00:00:02Z',
      }),
    );
    expectReviewFailure(review, 'SCG_REVISION_EXHAUSTED', () =>
      deleteAnnotation(review, deleteInput(uuid(1), MAX_SAFE_REVISION)),
    );
  });
});
