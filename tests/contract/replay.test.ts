import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  REPLAY_RECORD_COUNT,
  parsePageFileV1,
  serializeCanonicalPageFileV1,
  type ElementAnnotation,
  type PageFileV1,
  type PageFileValidationLimits,
  type PageId,
  type PageIdentityInput,
  type ReplayResult,
  type UuidV4,
} from '@scene-glass/contracts';
import {
  digestOperationInput,
  prepareOperationReplay,
  type ReplayCandidateInput,
  type ReplayDecision,
  type ReplayNoWriteReason,
  type ReplayOperation,
} from '@scene-glass/core/operation-replay';

const PAGE_ID = `p_${'1'.repeat(64)}` as PageId;
const OTHER_PAGE_ID = `p_${'2'.repeat(64)}` as PageId;
const MUTATION_KINDS = ['create', 'update', 'delete'] as const;
const BYTE_DOMAINS = ['result', 'ledger', 'pageFile'] as const;

type MutationKind = (typeof MUTATION_KINDS)[number];
type ByteDomain = (typeof BYTE_DOMAINS)[number];
type AppliedDecision = Extract<ReplayDecision, { readonly status: 'apply' }>;

function uuid(sequence: number): UuidV4 {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}` as UuidV4;
}

function page(pageId = PAGE_ID): PageIdentityInput {
  return {
    policyVersion: 1,
    canonicalIdentity: 'https://review.scene-glass.test/orders',
    route: '/orders',
    pageId,
  };
}

function annotation(sequence: number): ElementAnnotation {
  const second = (sequence % 60).toString().padStart(2, '0');
  return {
    id: uuid(sequence),
    locator: { dataScgId: `order-${sequence}` },
    memo: `Review order ${sequence}`,
    surroundingText: `Order ${sequence}`,
    domOrder: sequence,
    resolution: { status: 'resolved', reason: null },
    createdAt: `2026-01-01T00:00:${second}Z`,
    updatedAt: `2026-01-01T00:00:${second}Z`,
  };
}

function emptyPageFile(pageId = PAGE_ID): PageFileV1 {
  return {
    schemaVersion: 1,
    page: page(pageId),
    revision: 0,
    annotations: [],
    replayWindow: [],
  };
}

function operation(
  kind: MutationKind,
  sequence: number,
  expectedRevision: number,
  payload: unknown = { kind, sequence },
  projectId = 'project-a',
): ReplayOperation {
  return {
    projectId,
    operationId: uuid(10_000 + sequence),
    kind,
    expectedRevision,
    payload,
  };
}

function mutationCandidate(
  pageFile: PageFileV1,
  kind: MutationKind,
  operationSequence: number,
  limits: PageFileValidationLimits = BUILT_IN_LIMITS,
): ReplayCandidateInput {
  const revision = pageFile.revision + 1;
  let annotations: readonly ElementAnnotation[];
  let result: ReplayResult;

  switch (kind) {
    case 'create': {
      const created = annotation(pageFile.annotations.length + 1);
      annotations = [...pageFile.annotations, created];
      result = { kind, revision, annotation: created };
      break;
    }
    case 'update': {
      const current = pageFile.annotations[0];
      if (current === undefined) {
        throw new Error('update candidate requires an annotation');
      }
      const updated = {
        ...current,
        memo: `${current.memo} updated`,
        updatedAt: '2026-01-01T00:01:00Z',
      };
      annotations = [updated, ...pageFile.annotations.slice(1)];
      result = { kind, revision, annotation: updated };
      break;
    }
    case 'delete': {
      const current = pageFile.annotations[0];
      if (current === undefined) {
        throw new Error('delete candidate requires an annotation');
      }
      annotations = pageFile.annotations.slice(1);
      result = { kind, revision, annotationId: current.id };
      break;
    }
    default:
      throw new Error('unsupported annotation mutation kind');
  }

  return {
    pageFile,
    operation: operation(kind, operationSequence, pageFile.revision),
    annotations,
    result,
    limits,
  };
}

async function applyCandidate(candidate: ReplayCandidateInput): Promise<AppliedDecision> {
  const decision = await prepareOperationReplay(candidate);
  if (decision.status !== 'apply') {
    throw new Error(`expected ${candidate.operation.kind} to apply, got ${decision.status}`);
  }
  return decision;
}

async function pageFileWithRecords(count: number): Promise<PageFileV1> {
  let pageFile = emptyPageFile();
  for (let sequence = 1; sequence <= count; sequence += 1) {
    pageFile = (await applyCandidate(mutationCandidate(pageFile, 'create', sequence))).pageFile;
  }
  return pageFile;
}

function replayLimits(
  byteSizes: { readonly result: number; readonly ledger: number; readonly pageFile: number },
  overrides: Partial<PageFileValidationLimits> = {},
): PageFileValidationLimits {
  return {
    annotationsPerPage: overrides.annotationsPerPage ?? BUILT_IN_LIMITS.annotationsPerPage,
    replayResultBytes: overrides.replayResultBytes ?? byteSizes.result,
    replayLedgerBytes: overrides.replayLedgerBytes ?? byteSizes.ledger,
    pageFileBytes: overrides.pageFileBytes ?? byteSizes.pageFile,
  };
}

function byteDomainLimits(domain: ByteDomain, maximum: number): PageFileValidationLimits {
  switch (domain) {
    case 'result':
      return { ...BUILT_IN_LIMITS, replayResultBytes: maximum };
    case 'ledger':
      return { ...BUILT_IN_LIMITS, replayLedgerBytes: maximum };
    case 'pageFile':
      return { ...BUILT_IN_LIMITS, pageFileBytes: maximum };
  }
}

function compactJson(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new Error('expected compact JSON serialization');
  }
  return serialized;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function exactByteSizes(
  pageFile: PageFileV1,
  result: ReplayResult,
): { readonly result: number; readonly ledger: number; readonly pageFile: number } {
  return {
    result: utf8ByteLength(compactJson(result)),
    ledger: utf8ByteLength(compactJson(pageFile.replayWindow)),
    pageFile: utf8ByteLength(serializeCanonicalPageFileV1(pageFile)),
  };
}

function capturePageFile(pageFile: PageFileV1) {
  return {
    identity: pageFile,
    annotations: pageFile.annotations,
    replayWindow: pageFile.replayWindow,
    snapshot: structuredClone(pageFile),
    serialized: serializeCanonicalPageFileV1(pageFile),
  };
}

function expectPageFileUnchanged(
  pageFile: PageFileV1,
  before: ReturnType<typeof capturePageFile>,
): void {
  expect(pageFile).toBe(before.identity);
  expect(pageFile).toEqual(before.snapshot);
  expect(pageFile.annotations).toBe(before.annotations);
  expect(pageFile.replayWindow).toBe(before.replayWindow);
  expect(pageFile.revision).toBe(before.snapshot.revision);
  expect(serializeCanonicalPageFileV1(pageFile)).toBe(before.serialized);
}

function expectNoWrite(
  decision: ReplayDecision,
  pageFile: PageFileV1,
  before: ReturnType<typeof capturePageFile>,
  reason: ReplayNoWriteReason,
  byteSizes: { readonly result: number; readonly ledger: number; readonly pageFile: number },
): void {
  expect(decision.status).toBe('no-write');
  if (decision.status !== 'no-write') {
    throw new Error(`Expected no-write decision, received ${decision.status}`);
  }
  expect(decision.reason).toBe(reason);
  expect(decision.currentPageFile).not.toBe(pageFile);
  expect(decision.currentPageFile).toEqual(before.snapshot);
  expect(decision.byteSizes).toEqual(byteSizes);
  expectPageFileUnchanged(pageFile, before);
}

function expectedTail(nextRevision: number): number[] {
  const count = Math.min(nextRevision, REPLAY_RECORD_COUNT);
  const firstRevision = nextRevision - count + 1;
  return Array.from({ length: count }, (_, index) => firstRevision + index);
}

function expectApplied(
  decision: ReplayDecision,
  candidate: ReplayCandidateInput,
): asserts decision is AppliedDecision {
  expect(decision.status).toBe('apply');
  if (decision.status !== 'apply') {
    throw new Error(`Expected apply decision, received ${decision.status}`);
  }

  const pageFile = decision.pageFile;
  expect(decision.result).toEqual(candidate.result);
  expect(decision.result).not.toBe(candidate.result);
  expect(decision.record.result).toBe(decision.result);
  expect(pageFile.revision).toBe(candidate.pageFile.revision + 1);
  expect(pageFile.annotations).toEqual(candidate.annotations);
  expect(pageFile.replayWindow.at(-1)).toBe(decision.record);
  expect(pageFile.replayWindow.map((record) => record.appliedRevision)).toEqual(
    expectedTail(pageFile.revision),
  );
  expect(decision.byteSizes).toEqual(exactByteSizes(pageFile, decision.result));
  expect(serializeCanonicalPageFileV1(pageFile)).toBe(
    serializeCanonicalPageFileV1(parsePageFileV1(pageFile)),
  );
}

describe('operation replay', () => {
  it('runs the generated transition matrix across all byte domains and mutation kinds', async () => {
    let operationSequence = 100;

    for (const kind of MUTATION_KINDS) {
      for (const currentRevision of [31, REPLAY_RECORD_COUNT]) {
        const pageFile = await pageFileWithRecords(currentRevision);
        const candidate = mutationCandidate(pageFile, kind, operationSequence);
        operationSequence += 1;

        const preview = await applyCandidate(candidate);
        expectApplied(preview, candidate);
        expect(preview.pageFile.replayWindow.map((record) => record.appliedRevision)).toEqual(
          currentRevision === 31
            ? Array.from({ length: REPLAY_RECORD_COUNT }, (_, index) => index + 1)
            : Array.from({ length: REPLAY_RECORD_COUNT }, (_, index) => index + 2),
        );

        for (const domain of BYTE_DOMAINS) {
          const size = preview.byteSizes[domain];
          for (const delta of [-1, 0, 1]) {
            const limits = byteDomainLimits(domain, size + delta);
            const before = capturePageFile(pageFile);
            const decision = await prepareOperationReplay({ ...candidate, limits });

            if (delta === -1) {
              expectNoWrite(
                decision,
                pageFile,
                before,
                domain === 'result'
                  ? 'result-bytes'
                  : domain === 'ledger'
                    ? 'ledger-bytes'
                    : 'page-file-bytes',
                preview.byteSizes,
              );
              expectReplayTail(pageFile, expectedTail(currentRevision));
            } else {
              expectApplied(decision, candidate);
            }
          }
        }
      }
    }
  });
  it('grandfathers oversized historical results while rejecting an oversized new result', async () => {
    const pageFile = await pageFileWithRecords(REPLAY_RECORD_COUNT);
    const compliantCandidate = mutationCandidate(pageFile, 'delete', 150);
    const compliantPreview = await applyCandidate(compliantCandidate);
    const tightenedLimits = replayLimits(compliantPreview.byteSizes, {
      replayResultBytes: compliantPreview.byteSizes.result,
    });

    expect(
      pageFile.replayWindow.every(
        (record) => utf8ByteLength(compactJson(record.result)) > tightenedLimits.replayResultBytes,
      ),
    ).toBe(true);
    expect(
      parsePageFileV1(pageFile, {
        ...BUILT_IN_LIMITS,
        replayResultBytes: tightenedLimits.replayResultBytes,
      }),
    ).toEqual(pageFile);

    const beforeCompliantWrite = capturePageFile(pageFile);
    const compliantDecision = await prepareOperationReplay({
      ...compliantCandidate,
      limits: tightenedLimits,
    });

    expectApplied(compliantDecision, compliantCandidate);
    expect(compliantDecision.pageFile.replayWindow).toHaveLength(REPLAY_RECORD_COUNT);
    expectReplayTail(
      compliantDecision.pageFile,
      Array.from({ length: REPLAY_RECORD_COUNT }, (_, index) => index + 2),
    );
    expect(
      compliantDecision.pageFile.replayWindow
        .slice(0, -1)
        .every(
          (record) =>
            utf8ByteLength(compactJson(record.result)) > tightenedLimits.replayResultBytes,
        ),
    ).toBe(true);
    expectPageFileUnchanged(pageFile, beforeCompliantWrite);

    const oversizedCandidate = mutationCandidate(pageFile, 'create', 151);
    const oversizedPreview = await applyCandidate(oversizedCandidate);
    expect(oversizedPreview.byteSizes.result).toBeGreaterThan(tightenedLimits.replayResultBytes);
    const beforeOversizedWrite = capturePageFile(pageFile);
    const oversizedDecision = await prepareOperationReplay({
      ...oversizedCandidate,
      limits: replayLimits(oversizedPreview.byteSizes, {
        replayResultBytes: tightenedLimits.replayResultBytes,
      }),
    });

    expectNoWrite(
      oversizedDecision,
      pageFile,
      beforeOversizedWrite,
      'result-bytes',
      oversizedPreview.byteSizes,
    );
    expectReplayTail(pageFile, expectedTail(REPLAY_RECORD_COUNT));
  });

  it('uses candidate annotation cardinality as a no-write limit and does not charge updates or deletes as creates', async () => {
    const pageFile = await pageFileWithRecords(31);
    const create = mutationCandidate(pageFile, 'create', 200);
    const createPreview = await applyCandidate(create);
    const exactCreateLimits = replayLimits(createPreview.byteSizes, {
      annotationsPerPage: create.annotations.length,
    });
    const exactCreate = await prepareOperationReplay({ ...create, limits: exactCreateLimits });
    expectApplied(exactCreate, create);

    const before = capturePageFile(pageFile);
    const overLimit = await prepareOperationReplay({
      ...create,
      limits: replayLimits(createPreview.byteSizes, {
        annotationsPerPage: create.annotations.length - 1,
      }),
    });
    expectNoWrite(overLimit, pageFile, before, 'annotation-count', createPreview.byteSizes);

    const update = mutationCandidate(pageFile, 'update', 201);
    const updatePreview = await applyCandidate(update);
    const updateLimits = replayLimits(updatePreview.byteSizes, {
      annotationsPerPage: pageFile.annotations.length,
    });
    const updated = await prepareOperationReplay({ ...update, limits: updateLimits });
    expectApplied(updated, update);

    const remove = mutationCandidate(pageFile, 'delete', 202);
    const deletePreview = await applyCandidate(remove);
    const deleteLimits = replayLimits(deletePreview.byteSizes, {
      annotationsPerPage: remove.annotations.length,
    });
    const deleted = await prepareOperationReplay({ ...remove, limits: deleteLimits });
    expectApplied(deleted, remove);
    expect([exactCreate.status, overLimit.status, updated.status, deleted.status]).toEqual([
      'apply',
      'no-write',
      'apply',
      'apply',
    ]);
  });
  it('returns annotation-count no-write for the built-in 1000 to 1001 transition', async () => {
    const pageFile: PageFileV1 = {
      ...emptyPageFile(),
      annotations: Array.from({ length: BUILT_IN_LIMITS.annotationsPerPage }, (_, index) =>
        annotation(index + 1),
      ),
    };
    const candidate = mutationCandidate(pageFile, 'create', 250);
    const before = capturePageFile(pageFile);

    const decision = await prepareOperationReplay(candidate);

    expect(decision.status).toBe('no-write');
    if (decision.status !== 'no-write') {
      throw new Error(`Expected no-write decision, received ${decision.status}`);
    }
    expect(decision.reason).toBe('annotation-count');
    expect(decision.byteSizes.pageFile).toBeGreaterThan(
      utf8ByteLength(serializeCanonicalPageFileV1(pageFile)),
    );
    expect(decision.currentPageFile).not.toBe(pageFile);
    expect(decision.currentPageFile).toEqual(before.snapshot);
    expectPageFileUnchanged(pageFile, before);
  });

  it('returns parsed frozen replay decisions without mutable source aliases', async () => {
    const pageFile = emptyPageFile();
    const candidate = mutationCandidate(pageFile, 'create', 251);
    const sourceAnnotation = candidate.annotations[0]! as {
      memo: string;
      locator: { dataScgId?: string };
    };
    const sourceResult = candidate.result as {
      revision: number;
    };
    const originalRoute = pageFile.page.route;
    const originalMemo = sourceAnnotation.memo;
    const originalLocator = sourceAnnotation.locator.dataScgId;
    const decision = await prepareOperationReplay(candidate);

    expectApplied(decision, candidate);
    expect(decision.pageFile).not.toBe(pageFile);
    expect(decision.pageFile.page).not.toBe(pageFile.page);
    expect(decision.pageFile.annotations[0]).not.toBe(sourceAnnotation);
    expect(decision.result).not.toBe(candidate.result);
    expect(decision.record).toBe(decision.pageFile.replayWindow.at(-1));
    expect(decision.result).toBe(decision.record.result);

    (pageFile.page as { route: string }).route = '/mutated';
    sourceAnnotation.memo = 'mutated';
    sourceAnnotation.locator.dataScgId = 'mutated';
    sourceResult.revision = 99;

    expect(decision.pageFile.page.route).toBe(originalRoute);
    expect(decision.pageFile.annotations[0]?.memo).toBe(originalMemo);
    expect(decision.pageFile.annotations[0]?.locator.dataScgId).toBe(originalLocator);
    expect(decision.result.revision).toBe(1);
    expect(Object.isFrozen(decision.pageFile)).toBe(true);
    expect(Object.isFrozen(decision.pageFile.annotations[0]!)).toBe(true);
    expect(Object.isFrozen(decision.record)).toBe(true);
    expect(Object.isFrozen(decision.result)).toBe(true);
  });

  it('returns an oversized historical exact replay before candidate limit validation', async () => {
    const initialPageFile = emptyPageFile();
    const candidate = mutationCandidate(initialPageFile, 'create', 300);
    const applied = await applyCandidate(candidate);
    const before = capturePageFile(applied.pageFile);
    const tightenedLimits = {
      ...BUILT_IN_LIMITS,
      replayResultBytes: utf8ByteLength(compactJson(applied.result)) - 1,
    };
    expect(utf8ByteLength(compactJson(applied.result))).toBeGreaterThan(
      tightenedLimits.replayResultBytes,
    );
    const ignoredCandidateResult: ReplayResult = {
      kind: 'create',
      revision: 999,
      annotation: annotation(2),
    };

    const replay = await prepareOperationReplay({
      pageFile: applied.pageFile,
      operation: candidate.operation,
      annotations: [],
      result: ignoredCandidateResult,
      limits: tightenedLimits,
    });

    expect(replay.status).toBe('exact-replay');
    if (replay.status !== 'exact-replay') {
      throw new Error(`Expected exact replay, received ${replay.status}`);
    }
    expect(replay.result).toEqual(applied.result);
    expect(replay.result).not.toBe(applied.result);
    expect(replay.result).not.toEqual(ignoredCandidateResult);
    expect(replay.record).toEqual(applied.record);
    expect(replay.record).not.toBe(applied.record);
    expectPageFileUnchanged(applied.pageFile, before);
  });

  it('rejects mismatched reuse of an operation ID without writing', async () => {
    const pageFile = await pageFileWithRecords(1);
    const before = capturePageFile(pageFile);
    const original = operation('create', 1, 0);

    const decision = await prepareOperationReplay({
      pageFile,
      operation: operation('create', 1, 0, { action: 'different' }),
      annotations: [annotation(1), annotation(2)],
      result: { kind: 'create', revision: 2, annotation: annotation(2) },
      limits: BUILT_IN_LIMITS,
    });

    expect(decision.status).toBe('operation-id-reused');
    if (decision.status !== 'operation-id-reused') {
      throw new Error(`Expected operation-id-reused decision, received ${decision.status}`);
    }
    expect(decision.record.operationId).toBe(original.operationId);
    expectPageFileUnchanged(pageFile, before);

    const expectedRevisionReuse = await prepareOperationReplay({
      pageFile,
      operation: operation('create', 1, 1),
      annotations: [annotation(1), annotation(2)],
      result: { kind: 'create', revision: 2, annotation: annotation(2) },
      limits: BUILT_IN_LIMITS,
    });

    expect(expectedRevisionReuse.status).toBe('operation-id-reused');
    if (expectedRevisionReuse.status !== 'operation-id-reused') {
      throw new Error(
        `Expected changed expectedRevision to reuse the operation ID, received ${expectedRevisionReuse.status}`,
      );
    }
    expect(expectedRevisionReuse.record.operationId).toBe(original.operationId);
    expectPageFileUnchanged(pageFile, before);
  });
  it('returns revision-conflict for a fresh stale operation without writing', async () => {
    const pageFile = await pageFileWithRecords(1);
    const before = capturePageFile(pageFile);
    const freshOperation = operation('create', 2, 0);
    const nextAnnotation = annotation(2);

    expect(
      pageFile.replayWindow.some((record) => record.operationId === freshOperation.operationId),
    ).toBe(false);
    expect(freshOperation.expectedRevision).not.toBe(pageFile.revision);

    const decision = await prepareOperationReplay({
      pageFile,
      operation: freshOperation,
      annotations: [...pageFile.annotations, nextAnnotation],
      result: { kind: 'create', revision: 2, annotation: nextAnnotation },
      limits: BUILT_IN_LIMITS,
    });

    expect(decision.status).toBe('revision-conflict');
    if (decision.status !== 'revision-conflict') {
      throw new Error(`Expected revision-conflict decision, received ${decision.status}`);
    }
    expect(decision.currentRevision).toBe(1);
    expectPageFileUnchanged(pageFile, before);
  });

  it('hashes canonical operation input deterministically within its project and page scope', async () => {
    const first = operation(
      'create',
      7,
      4,
      { z: [3, { beta: true, alpha: 'one' }], alpha: 1 },
      'project-a',
    );
    const reordered = operation(
      'create',
      7,
      4,
      { alpha: 1, z: [3, { alpha: 'one', beta: true }] },
      'project-a',
    );

    const digest = await digestOperationInput(emptyPageFile(), first);
    const reorderedDigest = await digestOperationInput(emptyPageFile(), reordered);
    const otherProjectDigest = await digestOperationInput(
      emptyPageFile(),
      operation('create', 7, 4, reordered.payload, 'project-b'),
    );
    const otherPageDigest = await digestOperationInput(emptyPageFile(OTHER_PAGE_ID), reordered);

    expect(reorderedDigest).toBe(digest);
    expect(otherProjectDigest).not.toBe(digest);
    expect(otherPageDigest).not.toBe(digest);
  });
});
function expectReplayTail(pageFile: PageFileV1, revisions: readonly number[]): void {
  expect(pageFile.replayWindow.map((record) => record.appliedRevision)).toEqual(revisions);
}
