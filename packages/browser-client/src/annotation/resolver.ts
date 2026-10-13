import type { LocatorInput, ResolutionInput } from '@scene-glass/contracts';
import {
  resolveLocator,
  type LocatorCandidate,
  type LocatorResolution as CoreLocatorResolution,
} from '@scene-glass/core/locator';

import { captureElementFingerprint, isMountedLightDomElement } from './locator.js';

export type LocatorSearchRoot = Document | Element;

export interface ResolvedElementLocator {
  readonly status: 'resolved';
  readonly element: Element;
  readonly strategy: 'data-scg-id' | 'fingerprint';
  readonly score: number;
  readonly gap: number;
  readonly resolution: ResolutionInput;
}

export interface UnresolvedElementLocator {
  readonly status: 'unresolved';
  readonly reason: 'ambiguous' | 'not-found';
  readonly score?: number;
  readonly gap?: number;
  readonly resolution: ResolutionInput;
}

export type LocatorResolution = ResolvedElementLocator | UnresolvedElementLocator;

/**
 * Resolves only against mounted light-DOM candidates. Exact data-scg-id is
 * accepted only for a single candidate; duplicate ids fall through to the
 * core scorer when a fingerprint is available and otherwise stay unresolved.
 */
export async function resolveElementLocator(
  locator: LocatorInput,
  root: LocatorSearchRoot | undefined = currentDocument(),
): Promise<LocatorResolution> {
  const candidates = candidatesFor(root);
  if (candidates.length === 0) {
    return notFound();
  }

  const idMatches =
    locator.dataScgId === undefined
      ? []
      : candidates.filter((element) => element.getAttribute('data-scg-id') === locator.dataScgId);
  if (idMatches.length === 1) {
    const element = idMatches[0];
    if (element !== undefined) {
      return resolved(element, 'data-scg-id', 100, 100);
    }
  }
  if (locator.dataScgId !== undefined && locator.fingerprint === undefined) {
    return idMatches.length === 0 ? notFound() : ambiguous(100, 0);
  }

  if (locator.fingerprint === undefined) {
    return notFound();
  }

  try {
    const coreCandidates = await Promise.all(
      candidates.map(async (element): Promise<LocatorCandidate<Element>> => {
        const dataScgId = element.getAttribute('data-scg-id');
        return Object.freeze({
          value: element,
          ...(dataScgId === null ? {} : { dataScgId }),
          fingerprint: await captureElementFingerprint(element),
        });
      }),
    );
    return fromCoreResolution(resolveLocator(locator, coreCandidates));
  } catch {
    // Resolution must fail closed when a complete candidate comparison cannot
    // be produced (for example, Web Crypto is unavailable).
    return notFound();
  }
}

function candidatesFor(root: LocatorSearchRoot | undefined): Element[] {
  if (root === undefined) {
    return [];
  }

  const candidates: Element[] = [];
  if (isElement(root) && isResolvableCandidate(root)) {
    candidates.push(root);
  }
  for (const element of root.querySelectorAll('*')) {
    if (isResolvableCandidate(element)) {
      candidates.push(element);
    }
  }
  return candidates;
}

function isResolvableCandidate(element: Element): boolean {
  return (
    element.getAttribute('data-scg-selector-overlay') !== 'true' &&
    isMountedLightDomElement(element)
  );
}

function fromCoreResolution(result: CoreLocatorResolution<Element>): LocatorResolution {
  if (result.status === 'resolved') {
    return resolved(result.candidate, result.strategy, result.score, result.gap);
  }
  if (result.status === 'ambiguous') {
    return ambiguous(result.score, result.gap);
  }
  return notFound();
}

function resolved(
  element: Element,
  strategy: 'data-scg-id' | 'fingerprint',
  score: number,
  gap: number,
): ResolvedElementLocator {
  return Object.freeze({
    status: 'resolved',
    element,
    strategy,
    score,
    gap,
    resolution: Object.freeze({ status: 'resolved', reason: null }),
  });
}

function ambiguous(score: number, gap: number): UnresolvedElementLocator {
  return Object.freeze({
    status: 'unresolved',
    reason: 'ambiguous',
    score,
    gap,
    resolution: Object.freeze({ status: 'ambiguous', reason: 'ambiguous' }),
  });
}

function notFound(): UnresolvedElementLocator {
  return Object.freeze({
    status: 'unresolved',
    reason: 'not-found',
    resolution: Object.freeze({ status: 'not-found', reason: 'not-found' }),
  });
}

function currentDocument(): Document | undefined {
  return typeof globalThis.document === 'undefined' ? undefined : globalThis.document;
}
function isElement(value: unknown): value is Element {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { readonly nodeType?: unknown }).nodeType === 1
  );
}
