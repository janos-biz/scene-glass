import { describe, expect, it } from 'vitest';
import {
  parseSha256Digest,
  type LocatorFingerprint,
  type LocatorInput,
  type LocatorStableAttribute,
  type Sha256Digest,
} from '../../packages/contracts/src/annotations.js';
import {
  type LocatorCandidate,
  resolveLocator,
  scoreLocatorCandidate,
} from '../../packages/core/src/locator.js';

const DIGESTS = {
  button: parseSha256Digest(`sha256:${'b'.repeat(64)}`),
  locatorText: parseSha256Digest(`sha256:${'a'.repeat(64)}`),
  other: parseSha256Digest(`sha256:${'d'.repeat(64)}`),
  threshold: parseSha256Digest(`sha256:${'e'.repeat(64)}`),
  unrelated: parseSha256Digest(`sha256:${'c'.repeat(64)}`),
} as const;

function fingerprint(
  tag: string,
  stableAttributes: readonly LocatorStableAttribute[],
  ancestorSignatures: readonly string[],
  textDigest: Sha256Digest = DIGESTS.locatorText,
): LocatorFingerprint {
  return { tag, stableAttributes, ancestorSignatures, textDigest };
}

function candidate(
  value: string,
  fingerprintValue?: LocatorFingerprint,
  dataScgId?: string,
): LocatorCandidate<string> {
  return {
    value,
    ...(fingerprintValue === undefined ? {} : { fingerprint: fingerprintValue }),
    ...(dataScgId === undefined ? {} : { dataScgId }),
  };
}

function resolve(locator: LocatorInput, candidates: readonly LocatorCandidate<string>[]) {
  return resolveLocator(locator, candidates);
}

const buttonAttributes = [
  ['aria-label', 'Save'],
  ['data-kind', 'save'],
] as const satisfies readonly LocatorStableAttribute[];
const buttonAncestors = ['["section",[["id","editor"]]]', '["main",[["role","main"]]]'] as const;
const buttonFingerprint = fingerprint('button', buttonAttributes, buttonAncestors, DIGESTS.button);

describe('locator resolution contract', () => {
  it('gives a unique data-scg-id priority over a stronger fingerprint candidate', () => {
    const result = resolve({ dataScgId: 'stable-save', fingerprint: buttonFingerprint }, [
      candidate('fingerprint-target', buttonFingerprint),
      candidate('data-id-target', fingerprint('div', [], [], DIGESTS.unrelated), 'stable-save'),
    ]);

    expect(result).toEqual({
      status: 'resolved',
      candidate: 'data-id-target',
      strategy: 'data-scg-id',
      score: 100,
      gap: 100,
      resolution: { status: 'resolved', reason: null },
    });
  });

  it('scores fingerprint candidates deterministically without DOM inputs', () => {
    const exact = candidate('exact', buttonFingerprint);
    const textMismatch = candidate(
      'text-mismatch',
      fingerprint('button', buttonAttributes, buttonAncestors, DIGESTS.other),
    );
    const partial = candidate(
      'partial',
      fingerprint('button', [buttonAttributes[0]], [buttonAncestors[0]], DIGESTS.button),
    );

    expect(scoreLocatorCandidate(buttonFingerprint, exact)).toBe(100);
    expect(scoreLocatorCandidate(buttonFingerprint, textMismatch)).toBe(80);
    expect(scoreLocatorCandidate(buttonFingerprint, partial)).toBe(72);
    expect(resolve({ fingerprint: buttonFingerprint }, [partial, textMismatch, exact])).toEqual({
      status: 'resolved',
      candidate: 'exact',
      strategy: 'fingerprint',
      score: 100,
      gap: 20,
      resolution: { status: 'resolved', reason: null },
    });
    expect(resolve({ fingerprint: buttonFingerprint }, [exact, partial, textMismatch])).toEqual({
      status: 'resolved',
      candidate: 'exact',
      strategy: 'fingerprint',
      score: 100,
      gap: 20,
      resolution: { status: 'resolved', reason: null },
    });
  });

  it('resolves at the score threshold of 70 and remains unresolved below it', () => {
    const score70Attributes = Array.from({ length: 7 }, (_, index): LocatorStableAttribute => [
      `data-${index.toString().padStart(2, '0')}`,
      `${index}`,
    ]);
    const score69Attributes = Array.from({ length: 20 }, (_, index): LocatorStableAttribute => [
      `data-${index.toString().padStart(2, '0')}`,
      `${index}`,
    ]);
    const ancestor = ['["article",[]]'] as const;
    const score70Fingerprint = fingerprint(
      'button',
      score70Attributes,
      ancestor,
      DIGESTS.threshold,
    );
    const score69Fingerprint = fingerprint(
      'button',
      score69Attributes,
      ancestor,
      DIGESTS.threshold,
    );
    const atThreshold = candidate(
      'at-threshold',
      fingerprint('button', score70Attributes.slice(0, 5), [], DIGESTS.threshold),
    );
    const belowThreshold = candidate(
      'below-threshold',
      fingerprint('button', score69Attributes.slice(0, 14), [], DIGESTS.threshold),
    );

    expect(scoreLocatorCandidate(score70Fingerprint, atThreshold)).toBe(70);
    expect(scoreLocatorCandidate(score69Fingerprint, belowThreshold)).toBe(69);
    expect(resolve({ fingerprint: score70Fingerprint }, [atThreshold])).toEqual({
      status: 'resolved',
      candidate: 'at-threshold',
      strategy: 'fingerprint',
      score: 70,
      gap: 70,
      resolution: { status: 'resolved', reason: null },
    });

    const unresolved = resolve({ fingerprint: score69Fingerprint }, [belowThreshold]);
    expect(unresolved).toEqual({
      status: 'ambiguous',
      score: 69,
      gap: 69,
      resolution: { status: 'ambiguous', reason: 'ambiguous' },
    });
    expect('candidate' in unresolved).toBe(false);
  });

  it('requires a top-two score gap of at least 15', () => {
    const ancestors = [
      '["section",[["data-a","1"]]]',
      '["main",[["data-b","2"]]]',
      '["body",[["data-c","3"]]]',
      '["html",[["lang","en"]]]',
    ] as const;
    const expected = fingerprint('button', [['type', 'button']], ancestors, DIGESTS.locatorText);
    const best = candidate('best', expected);
    const gap15 = candidate(
      'gap-15',
      fingerprint('button', [['type', 'button']], [ancestors[0]], DIGESTS.locatorText),
    );
    const gap10 = candidate(
      'gap-10',
      fingerprint(
        'button',
        [['type', 'button']],
        [ancestors[0], ancestors[1]],
        DIGESTS.locatorText,
      ),
    );

    expect(resolve({ fingerprint: expected }, [best, gap15])).toEqual({
      status: 'resolved',
      candidate: 'best',
      strategy: 'fingerprint',
      score: 100,
      gap: 15,
      resolution: { status: 'resolved', reason: null },
    });

    const unresolved = resolve({ fingerprint: expected }, [best, gap10]);
    expect(unresolved).toEqual({
      status: 'ambiguous',
      score: 100,
      gap: 10,
      resolution: { status: 'ambiguous', reason: 'ambiguous' },
    });
    expect('candidate' in unresolved).toBe(false);
  });

  it('leaves missing and ambiguous locators unresolved instead of selecting a wrong element', () => {
    const notFound = resolve({ dataScgId: 'missing' }, [candidate('wrong', undefined, 'present')]);
    const ambiguous = resolve({ dataScgId: 'duplicate' }, [
      candidate('wrong-first', undefined, 'duplicate'),
      candidate('wrong-second', undefined, 'duplicate'),
    ]);

    expect(notFound).toEqual({
      status: 'not-found',
      resolution: { status: 'not-found', reason: 'not-found' },
    });
    expect('candidate' in notFound).toBe(false);
    expect(ambiguous).toEqual({
      status: 'ambiguous',
      score: 100,
      gap: 0,
      resolution: { status: 'ambiguous', reason: 'ambiguous' },
    });
    expect('candidate' in ambiguous).toBe(false);
  });
});
