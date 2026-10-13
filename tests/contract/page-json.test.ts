import { describe, expect, it } from 'vitest';
import {
  MAX_SAFE_REVISION,
  REPLAY_RECORD_COUNT,
  SceneGlassContractError,
  parsePageFileV1,
  parseReplayRecord,
  serializeCanonicalPageFileV1,
  type SceneGlassContractErrorCode,
} from '@scene-glass/contracts';

const PAGE_ID = 'p_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const INPUT_DIGEST = 'sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const ANNOTATION_ID = '11111111-1111-4111-8111-111111111111';
const CREATED_AT = '2026-01-02T03:04:05.006Z';

type ReplayKind = 'create' | 'update' | 'delete';

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

function page(): Record<string, unknown> {
  return {
    policyVersion: 1,
    canonicalIdentity: 'https://app.example.test/caf\u00e9',
    route: '/documents/caf\u00e9',
    pageId: PAGE_ID,
  };
}

function annotation(id = ANNOTATION_ID): Record<string, unknown> {
  return {
    id,
    locator: { dataScgId: 'document-title' },
    memo: 'Check the publication date.',
    surroundingText: 'Publication date: 2026-01-02',
    domOrder: 0,
    resolution: { status: 'not-found', reason: 'not-found' },
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
}

function operationId(sequence: number): string {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}`;
}

function replayRecord(
  appliedRevision: number,
  kind: ReplayKind = 'delete',
  operationSequence = appliedRevision,
): Record<string, unknown> {
  const result =
    kind === 'delete'
      ? {
          kind: 'delete',
          revision: appliedRevision,
          annotationId: ANNOTATION_ID,
        }
      : {
          kind,
          revision: appliedRevision,
          annotation: annotation(),
        };

  return {
    operationId: operationId(operationSequence),
    kind,
    inputDigest: INPUT_DIGEST,
    appliedRevision,
    result,
  };
}

function pageFile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    page: page(),
    revision: 0,
    annotations: [],
    replayWindow: [],
    ...overrides,
  };
}
function replayTail(pageRevision: number): Record<string, unknown>[] {
  const length = Math.min(pageRevision, REPLAY_RECORD_COUNT);
  return Array.from({ length }, (_, index) =>
    replayRecord(pageRevision - length + index + 1, 'delete', index + 1),
  );
}

function reverseObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reverseObjectKeys);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .reverse()
        .map(([key, nested]) => [key, reverseObjectKeys(nested)]),
    );
  }
  return value;
}

describe('page JSON v1 contracts', () => {
  it('parses complete v1 page data with a fixed digest-shaped pageId', () => {
    const parsed = parsePageFileV1(
      pageFile({ revision: 1, annotations: [annotation()], replayWindow: replayTail(1) }),
    );

    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.page).toEqual({
      policyVersion: 1,
      canonicalIdentity: 'https://app.example.test/caf\u00e9',
      route: '/documents/caf\u00e9',
      pageId: PAGE_ID,
    });
    expect(parsed.revision).toBe(1);
    expect(parsed.annotations).toHaveLength(1);
  });

  it.each(['schemaVersion', 'page', 'revision', 'annotations', 'replayWindow'] as const)(
    'requires the v1 page file field %s',
    (field) => {
      expect.hasAssertions();
      const input = pageFile();
      delete input[field];

      expectContractError(() => parsePageFileV1(input), 'SCG_PAGE_FILE_INVALID');
    },
  );

  it.each(['policyVersion', 'canonicalIdentity', 'route', 'pageId'] as const)(
    'requires the v1 page identity field %s',
    (field) => {
      expect.hasAssertions();
      const identity = page();
      delete identity[field];

      expectContractError(
        () => parsePageFileV1(pageFile({ page: identity })),
        'SCG_ANNOTATION_INVALID',
      );
    },
  );

  it('rejects unsupported v1 fields and schema versions', () => {
    expect.hasAssertions();
    expectContractError(
      () => parsePageFileV1(pageFile({ schemaVersion: 2 })),
      'SCG_PAGE_FILE_INVALID',
    );
    expectContractError(
      () => parsePageFileV1(pageFile({ futureField: true })),
      'SCG_PAGE_FILE_INVALID',
    );
    expectContractError(
      () => parsePageFileV1(pageFile({ page: { ...page(), futureField: true } })),
      'SCG_ANNOTATION_INVALID',
    );
  });

  it('accepts NFC page data and rejects a decomposed canonical identity', () => {
    expect(parsePageFileV1(pageFile()).page.canonicalIdentity).toBe(
      'https://app.example.test/caf\u00e9',
    );

    expectContractError(
      () =>
        parsePageFileV1(
          pageFile({
            page: {
              ...page(),
              canonicalIdentity: 'https://app.example.test/cafe\u0301',
            },
          }),
        ),
      'SCG_ANNOTATION_INVALID',
    );
  });

  it('requires a fixed lowercase digest-shaped pageId', () => {
    expect.hasAssertions();
    expectContractError(
      () => parsePageFileV1(pageFile({ page: { ...page(), pageId: `p_${'a'.repeat(63)}` } })),
      'SCG_ID_INVALID',
    );
  });

  it('accepts only safe page revisions', () => {
    expect(
      parsePageFileV1(
        pageFile({ revision: MAX_SAFE_REVISION, replayWindow: replayTail(MAX_SAFE_REVISION) }),
      ).revision,
    ).toBe(MAX_SAFE_REVISION);

    for (const revision of [-1, 1.5, MAX_SAFE_REVISION + 1]) {
      expectContractError(() => parsePageFileV1(pageFile({ revision })), 'SCG_SCALAR_INVALID');
    }
  });

  it('rejects duplicate annotation and replay operation IDs', () => {
    expect.hasAssertions();
    expectContractError(
      () => parsePageFileV1(pageFile({ annotations: [annotation(), annotation()] })),
      'SCG_PAGE_FILE_INVALID',
    );

    const first = replayRecord(1);
    const duplicateOperation = {
      ...replayRecord(2),
      operationId: first.operationId,
    };
    expectContractError(
      () =>
        parsePageFileV1(
          pageFile({
            revision: 2,
            replayWindow: [first, duplicateOperation],
          }),
        ),
      'SCG_PAGE_FILE_INVALID',
    );
  });

  it.each([0, 1, 31, 32, 33])('accepts the exact replay tail for revision %d', (revision) => {
    const replayWindow = replayTail(revision);
    const parsed = parsePageFileV1(pageFile({ revision, replayWindow }));

    expect(parsed.replayWindow.map((record) => record.appliedRevision)).toEqual(
      replayWindow.map((record) => record.appliedRevision),
    );
  });

  it('rejects stale, gapped, and short replay tails', () => {
    expect.hasAssertions();
    expectContractError(
      () => parsePageFileV1(pageFile({ revision: 33, replayWindow: replayTail(32) })),
      'SCG_PAGE_FILE_INVALID',
    );

    const gapped = replayTail(33);
    gapped[15] = replayRecord(18, 'delete', 99);
    expectContractError(
      () => parsePageFileV1(pageFile({ revision: 33, replayWindow: gapped })),
      'SCG_PAGE_FILE_INVALID',
    );

    expectContractError(
      () => parsePageFileV1(pageFile({ revision: 33, replayWindow: replayTail(33).slice(1) })),
      'SCG_PAGE_FILE_INVALID',
    );
  });

  it('serializes strict page files in explicit, insertion-order-independent schema order', () => {
    const value = pageFile({
      revision: 1,
      annotations: [annotation()],
      replayWindow: [replayRecord(1, 'create')],
    });
    const canonical = serializeCanonicalPageFileV1(value);

    expect(canonical).toMatch(/^\{\n {2}"schemaVersion": 1,\n {2}"page": \{\n/);
    expect(canonical).toContain('    "policyVersion": 1,');
    expect(canonical.startsWith('\uFEFF')).toBe(false);
    expect(canonical.endsWith('\n')).toBe(true);
    expect(canonical.endsWith('\n\n')).toBe(false);
    expect(serializeCanonicalPageFileV1(reverseObjectKeys(value))).toBe(canonical);
  });

  it('enforces pageFileBytes against UTF-8 canonical pretty JSON boundaries', () => {
    const value = pageFile();
    const serialized = serializeCanonicalPageFileV1(value);
    const pageFileBytes = new TextEncoder().encode(serialized).byteLength;

    expect(pageFileBytes).toBeGreaterThan(serialized.length);
    expectContractError(
      () =>
        parsePageFileV1(value, {
          annotationsPerPage: 1,
          pageFileBytes: pageFileBytes - 1,
          replayLedgerBytes: 2,
          replayResultBytes: 1,
        }),
      'SCG_LIMIT_FILE',
    );
    expect(
      parsePageFileV1(value, {
        annotationsPerPage: 1,
        pageFileBytes,
        replayLedgerBytes: 2,
        replayResultBytes: 1,
      }).revision,
    ).toBe(0);
  });

  it.each(['create', 'update', 'delete'] as const)(
    'parses the strict %s replay result variant',
    (kind) => {
      const parsed = parseReplayRecord(replayRecord(1, kind));

      expect(parsed.kind).toBe(kind);
      expect(parsed.result.kind).toBe(kind);
      expect(parsed.result.revision).toBe(1);
      const resultAnnotationId =
        parsed.result.kind === 'delete' ? parsed.result.annotationId : parsed.result.annotation.id;
      expect(resultAnnotationId).toBe(ANNOTATION_ID);
    },
  );

  it.each(['create', 'update', 'delete'] as const)(
    'rejects missing, mismatched, and unknown fields in the %s replay result variant',
    (kind) => {
      expect.hasAssertions();
      const missingVariantField = replayRecord(1, kind);
      const missingResult = missingVariantField.result as Record<string, unknown>;
      delete missingResult[kind === 'delete' ? 'annotationId' : 'annotation'];
      expectContractError(() => parseReplayRecord(missingVariantField), 'SCG_PAGE_FILE_INVALID');

      const mismatchedKind = replayRecord(1, kind);
      (mismatchedKind.result as Record<string, unknown>).kind =
        kind === 'delete' ? 'create' : 'delete';
      expectContractError(() => parseReplayRecord(mismatchedKind), 'SCG_PAGE_FILE_INVALID');

      const unknownResultField = replayRecord(1, kind);
      (unknownResultField.result as Record<string, unknown>).futureField = true;
      expectContractError(() => parseReplayRecord(unknownResultField), 'SCG_PAGE_FILE_INVALID');
    },
  );

  it('rejects corrupt persisted replay digests and revision results', () => {
    expect.hasAssertions();
    const corruptDigest = replayRecord(1);
    corruptDigest.inputDigest = 'sha256:not-a-valid-digest';
    expectContractError(
      () => parsePageFileV1(pageFile({ revision: 1, replayWindow: [corruptDigest] })),
      'SCG_ID_INVALID',
    );

    const corruptRevision = replayRecord(1);
    (corruptRevision.result as Record<string, unknown>).revision = 2;
    expectContractError(
      () => parsePageFileV1(pageFile({ revision: 1, replayWindow: [corruptRevision] })),
      'SCG_PAGE_FILE_INVALID',
    );
  });
});
