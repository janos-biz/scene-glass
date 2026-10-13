import {
  MAX_SAFE_REVISION,
  type CreateAnnotationInput,
  type DeleteAnnotationInput,
  type ElementAnnotation,
  type PageIdentityInput,
  type ReplayResult,
  type UpdateAnnotationInput,
  type UuidV4,
  assertSafeRevision,
  parseElementAnnotation,
  parsePageIdentityInput,
} from '@scene-glass/contracts';

export interface ScreenReview {
  readonly page: PageIdentityInput;
  readonly revision: number;
  readonly annotations: readonly ElementAnnotation[];
}

export interface CreateAnnotationServerValues {
  readonly id: UuidV4;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface UpdateAnnotationServerValues {
  readonly updatedAt: string;
}

export interface ScreenReviewMutation {
  readonly review: ScreenReview;
  readonly result: ReplayResult;
}

export type ScreenReviewErrorCode =
  | 'SCG_ANNOTATION_EXISTS'
  | 'SCG_ANNOTATION_INVALID'
  | 'SCG_ANNOTATION_NOT_FOUND'
  | 'SCG_MEMO_BLANK'
  | 'SCG_PAGE_MISMATCH'
  | 'SCG_REVISION_CONFLICT'
  | 'SCG_REVISION_EXHAUSTED';

export class ScreenReviewError extends Error {
  public readonly code: ScreenReviewErrorCode;

  public constructor(code: ScreenReviewErrorCode, message: string) {
    super(message);
    this.name = 'ScreenReviewError';
    this.code = code;
  }
}

export function createScreenReview(
  page: PageIdentityInput,
  annotations: readonly ElementAnnotation[] = [],
  revision = 0,
): ScreenReview {
  const parsedPage = parsePageIdentityInput(page);
  assertSafeRevision(revision, 'review revision');
  const parsedAnnotations = annotations.map((annotation) => parseElementAnnotation(annotation));
  assertUniqueAnnotationIds(parsedAnnotations);

  return Object.freeze({
    page: parsedPage,
    revision,
    annotations: Object.freeze(parsedAnnotations),
  });
}

export function createAnnotation(
  review: ScreenReview,
  input: CreateAnnotationInput,
  server: CreateAnnotationServerValues,
): ScreenReviewMutation {
  assertMutationPage(review, input.page);
  assertExpectedRevision(review, input.expectedRevision);
  assertNonBlankMemo(input.memo);

  if (review.annotations.some((annotation) => annotation.id === server.id)) {
    throw reviewError('SCG_ANNOTATION_EXISTS', 'annotation id already exists');
  }

  const revision = nextRevision(review.revision);
  const annotation = parseElementAnnotation({
    id: server.id,
    locator: input.locator,
    memo: input.memo,
    surroundingText: input.surroundingText,
    domOrder: input.domOrder,
    resolution: input.resolution,
    ...(input.context === undefined ? {} : { context: input.context }),
    createdAt: server.createdAt,
    updatedAt: server.updatedAt,
  });
  const nextReview = withMutation(review, revision, [...review.annotations, annotation]);

  return Object.freeze({
    review: nextReview,
    result: Object.freeze({ kind: 'create' as const, revision, annotation }),
  });
}

export function updateAnnotation(
  review: ScreenReview,
  input: UpdateAnnotationInput,
  server: UpdateAnnotationServerValues,
): ScreenReviewMutation {
  assertMutationPage(review, input.page);
  assertExpectedRevision(review, input.expectedRevision);
  if (Object.keys(input.patch).length === 0) {
    throw reviewError('SCG_ANNOTATION_INVALID', 'annotation patch must not be empty');
  }

  const index = review.annotations.findIndex((annotation) => annotation.id === input.annotationId);
  if (index === -1) {
    throw reviewError('SCG_ANNOTATION_NOT_FOUND', 'annotation does not exist');
  }

  const existing = review.annotations[index];
  if (existing === undefined) {
    throw reviewError('SCG_ANNOTATION_NOT_FOUND', 'annotation does not exist');
  }
  const memo = input.patch.memo ?? existing.memo;
  assertNonBlankMemo(memo);
  const annotation = parseElementAnnotation({
    id: existing.id,
    locator: input.patch.locator ?? existing.locator,
    memo,
    surroundingText: input.patch.surroundingText ?? existing.surroundingText,
    domOrder: input.patch.domOrder ?? existing.domOrder,
    resolution: input.patch.resolution ?? existing.resolution,
    ...((input.patch.context ?? existing.context) === undefined
      ? {}
      : { context: input.patch.context ?? existing.context }),
    createdAt: existing.createdAt,
    updatedAt: server.updatedAt,
  });
  const revision = nextRevision(review.revision);
  const nextAnnotations = [...review.annotations];
  nextAnnotations[index] = annotation;
  const nextReview = withMutation(review, revision, nextAnnotations);

  return Object.freeze({
    review: nextReview,
    result: Object.freeze({ kind: 'update' as const, revision, annotation }),
  });
}

export function deleteAnnotation(
  review: ScreenReview,
  input: DeleteAnnotationInput,
): ScreenReviewMutation {
  assertMutationPage(review, input.page);
  assertExpectedRevision(review, input.expectedRevision);

  const index = review.annotations.findIndex((annotation) => annotation.id === input.annotationId);
  if (index === -1) {
    throw reviewError('SCG_ANNOTATION_NOT_FOUND', 'annotation does not exist');
  }

  const revision = nextRevision(review.revision);
  const nextReview = withMutation(
    review,
    revision,
    review.annotations.filter((annotation) => annotation.id !== input.annotationId),
  );

  return Object.freeze({
    review: nextReview,
    result: Object.freeze({
      kind: 'delete' as const,
      revision,
      annotationId: input.annotationId,
    }),
  });
}

function withMutation(
  review: ScreenReview,
  revision: number,
  annotations: readonly ElementAnnotation[],
): ScreenReview {
  return Object.freeze({
    page: review.page,
    revision,
    annotations: Object.freeze(annotations),
  });
}

function assertMutationPage(review: ScreenReview, page: PageIdentityInput): void {
  if (
    review.page.policyVersion !== page.policyVersion ||
    review.page.canonicalIdentity !== page.canonicalIdentity ||
    review.page.route !== page.route ||
    review.page.pageId !== page.pageId
  ) {
    throw reviewError('SCG_PAGE_MISMATCH', 'mutation page does not match review page');
  }
}

function assertExpectedRevision(review: ScreenReview, expectedRevision: number): void {
  assertSafeRevision(expectedRevision, 'expectedRevision');
  if (expectedRevision !== review.revision) {
    throw reviewError('SCG_REVISION_CONFLICT', 'expected revision does not match review');
  }
}

function nextRevision(revision: number): number {
  assertSafeRevision(revision, 'review revision');
  if (revision === MAX_SAFE_REVISION) {
    throw reviewError('SCG_REVISION_EXHAUSTED', 'review revision cannot be incremented');
  }
  return revision + 1;
}

function assertNonBlankMemo(memo: string): void {
  if (memo.trim().length === 0) {
    throw reviewError('SCG_MEMO_BLANK', 'memo must not be blank');
  }
}

function assertUniqueAnnotationIds(annotations: readonly ElementAnnotation[]): void {
  const ids = new Set<string>();
  for (const annotation of annotations) {
    if (ids.has(annotation.id)) {
      throw reviewError('SCG_ANNOTATION_EXISTS', 'annotation ids must be unique');
    }
    ids.add(annotation.id);
  }
}

function reviewError(code: ScreenReviewErrorCode, message: string): ScreenReviewError {
  return new ScreenReviewError(code, message);
}
