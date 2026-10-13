export {
  LOCATOR_ANCESTOR_WEIGHT,
  LOCATOR_ATTRIBUTE_WEIGHT,
  LOCATOR_SCORE_GAP,
  LOCATOR_SCORE_THRESHOLD,
  LOCATOR_TAG_WEIGHT,
  LOCATOR_TEXT_WEIGHT,
  resolveLocator,
  scoreLocatorCandidate,
} from './locator.js';
export type { LocatorCandidate, LocatorResolution, ScoredLocatorCandidate } from './locator.js';

export {
  derivePageId,
  resolvePageIdentity,
  validateCanonicalPageIdentity,
} from './page-identity.js';
export type {
  PageIdentityLimits,
  PageIdentityPolicy,
  PageIdentitySource,
} from './page-identity.js';

export {
  ScreenReviewError,
  createAnnotation,
  createScreenReview,
  deleteAnnotation,
  updateAnnotation,
} from './screen-review.js';
export type {
  CreateAnnotationServerValues,
  ScreenReview,
  ScreenReviewErrorCode,
  ScreenReviewMutation,
  UpdateAnnotationServerValues,
} from './screen-review.js';

export {
  canonicalizeJson,
  createOperationPayload,
  deleteOperationPayload,
  digestOperationInput,
  prepareOperationReplay,
  updateOperationPayload,
} from './operation-replay.js';
export type {
  CanonicalJsonValue,
  ReplayByteSizes,
  ReplayCandidateInput,
  ReplayDecision,
  ReplayNoWriteReason,
  ReplayOperation,
} from './operation-replay.js';

export {
  exportCurrentPageReviewMarkdown,
  exportProjectReviewMarkdown,
  exportReviewMarkdown,
} from './prompt-export.js';
export type { PromptExportMode, PromptExportOptions } from './prompt-export.js';
