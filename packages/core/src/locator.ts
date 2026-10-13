import {
  RESOLUTION_GAP_THRESHOLD,
  RESOLUTION_SCORE_THRESHOLD,
  type LocatorFingerprint,
  type LocatorInput,
  type ResolutionInput,
} from '@scene-glass/contracts';

export const LOCATOR_SCORE_THRESHOLD = RESOLUTION_SCORE_THRESHOLD;
export const LOCATOR_SCORE_GAP = RESOLUTION_GAP_THRESHOLD;
export const LOCATOR_TAG_WEIGHT = 25;
export const LOCATOR_ATTRIBUTE_WEIGHT = 35;
export const LOCATOR_ANCESTOR_WEIGHT = 20;
export const LOCATOR_TEXT_WEIGHT = 20;

export interface LocatorCandidate<T> {
  readonly value: T;
  readonly dataScgId?: string;
  readonly fingerprint?: LocatorFingerprint;
}

export interface ScoredLocatorCandidate<T> {
  readonly candidate: LocatorCandidate<T>;
  readonly score: number;
  readonly index: number;
}

export type LocatorResolution<T> =
  | {
      readonly status: 'resolved';
      readonly candidate: T;
      readonly strategy: 'data-scg-id' | 'fingerprint';
      readonly score: number;
      readonly gap: number;
      readonly resolution: ResolutionInput;
    }
  | {
      readonly status: 'not-found';
      readonly resolution: ResolutionInput;
    }
  | {
      readonly status: 'ambiguous';
      readonly score: number;
      readonly gap: number;
      readonly resolution: ResolutionInput;
    };

/**
 * Resolves only when the result is safe to bind. A duplicate data-scg-id may
 * fall back to fingerprint matching, but can never select an arbitrary match.
 */
export function resolveLocator<T>(
  locator: LocatorInput,
  candidates: readonly LocatorCandidate<T>[],
): LocatorResolution<T> {
  const fingerprint = locator.fingerprint;
  if (locator.dataScgId !== undefined) {
    const idMatches = candidates.filter((candidate) => candidate.dataScgId === locator.dataScgId);
    const idMatch = idMatches[0];
    if (idMatches.length === 1 && idMatch !== undefined) {
      return resolved(idMatch, 'data-scg-id', 100, 100);
    }
    if (fingerprint === undefined) {
      if (idMatches.length === 0) {
        return notFound();
      }
      return ambiguous(100, 0);
    }
  }

  if (fingerprint === undefined || candidates.length === 0) {
    return notFound();
  }

  const ranked = candidates
    .map((candidate, index) => ({
      candidate,
      index,
      score: scoreLocatorCandidate(fingerprint, candidate),
    }))
    .sort(compareScoredCandidates);
  const best = ranked[0];
  if (best === undefined) {
    return notFound();
  }
  const gap = best.score - (ranked[1]?.score ?? 0);

  if (best.score < LOCATOR_SCORE_THRESHOLD || gap < LOCATOR_SCORE_GAP) {
    return ambiguous(best.score, gap);
  }

  return resolved(best.candidate, 'fingerprint', best.score, gap);
}

export function scoreLocatorCandidate(
  expected: LocatorFingerprint,
  candidate: LocatorCandidate<unknown>,
): number {
  const actual = candidate.fingerprint;
  if (actual === undefined) {
    return 0;
  }

  const tagScore = expected.tag === actual.tag ? LOCATOR_TAG_WEIGHT : 0;
  const attributeScore = proportionalScore(
    expected.stableAttributes.length,
    expected.stableAttributes.filter(([name, value]) =>
      actual.stableAttributes.some(
        ([candidateName, candidateValue]) => candidateName === name && candidateValue === value,
      ),
    ).length,
    LOCATOR_ATTRIBUTE_WEIGHT,
  );
  const ancestorScore = proportionalScore(
    expected.ancestorSignatures.length,
    expected.ancestorSignatures.filter(
      (signature, index) => signature === actual.ancestorSignatures[index],
    ).length,
    LOCATOR_ANCESTOR_WEIGHT,
  );
  const textScore = expected.textDigest === actual.textDigest ? LOCATOR_TEXT_WEIGHT : 0;

  return tagScore + attributeScore + ancestorScore + textScore;
}

function resolved<T>(
  candidate: LocatorCandidate<T>,
  strategy: 'data-scg-id' | 'fingerprint',
  score: number,
  gap: number,
): LocatorResolution<T> {
  return Object.freeze({
    status: 'resolved' as const,
    candidate: candidate.value,
    strategy,
    score,
    gap,
    resolution: Object.freeze({ status: 'resolved' as const, reason: null }),
  });
}

function notFound<T>(): LocatorResolution<T> {
  return Object.freeze({
    status: 'not-found' as const,
    resolution: Object.freeze({
      status: 'not-found' as const,
      reason: 'not-found' as const,
    }),
  });
}

function ambiguous<T>(score: number, gap: number): LocatorResolution<T> {
  return Object.freeze({
    status: 'ambiguous' as const,
    score,
    gap,
    resolution: Object.freeze({
      status: 'ambiguous' as const,
      reason: 'ambiguous' as const,
    }),
  });
}

function proportionalScore(total: number, matched: number, weight: number): number {
  if (total === 0) {
    return weight;
  }
  return Math.floor((matched * weight) / total);
}

function compareScoredCandidates<T>(
  left: ScoredLocatorCandidate<T>,
  right: ScoredLocatorCandidate<T>,
): number {
  return right.score - left.score || left.index - right.index;
}
