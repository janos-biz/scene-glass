import {
  BUILT_IN_LIMITS,
  MAX_SAFE_REVISION,
  REPLAY_RECORD_COUNT,
  SceneGlassContractError,
  appendReplayRecord,
  assertSafeRevision,
  parseElementAnnotation,
  parsePageFileV1,
  parseReplayRecord,
  serializeCanonicalPageFileV1,
  utf8ByteLength,
  type AnnotationMutationKind,
  type CreateAnnotationInput,
  type DeleteAnnotationInput,
  type ElementAnnotation,
  type PageFileV1,
  type PageFileValidationLimits,
  type ReplayRecord,
  type ReplayResult,
  type Sha256Digest,
  type UpdateAnnotationInput,
  type UuidV4,
} from '@scene-glass/contracts';

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalJsonValue[]
  | { readonly [key: string]: CanonicalJsonValue };

export interface ReplayOperation {
  readonly projectId: string;
  readonly operationId: UuidV4;
  readonly kind: AnnotationMutationKind;
  readonly expectedRevision: number;
  readonly payload: unknown;
}

export interface ReplayCandidateInput {
  readonly pageFile: PageFileV1;
  readonly operation: ReplayOperation;
  readonly annotations: readonly ElementAnnotation[];
  readonly result: ReplayResult;
  readonly limits: PageFileValidationLimits;
}

export interface ReplayByteSizes {
  readonly result: number;
  readonly ledger: number;
  readonly pageFile: number;
}

export type ReplayNoWriteReason =
  'annotation-count' | 'result-bytes' | 'ledger-bytes' | 'page-file-bytes';

export type ReplayDecision =
  | {
      readonly status: 'exact-replay';
      readonly record: ReplayRecord;
      readonly result: ReplayResult;
    }
  | {
      readonly status: 'operation-id-reused';
      readonly record: ReplayRecord;
    }
  | {
      readonly status: 'revision-conflict';
      readonly currentRevision: number;
    }
  | {
      readonly status: 'no-write';
      readonly reason: ReplayNoWriteReason;
      readonly currentPageFile: PageFileV1;
      readonly byteSizes: ReplayByteSizes;
    }
  | {
      readonly status: 'apply';
      readonly pageFile: PageFileV1;
      readonly record: ReplayRecord;
      readonly result: ReplayResult;
      readonly byteSizes: ReplayByteSizes;
    };

/**
 * Builds a no-write/apply decision. Existing operation IDs are resolved before
 * revision checks, and the input PageFile is never mutated or early-evicted.
 */
export async function prepareOperationReplay(input: ReplayCandidateInput): Promise<ReplayDecision> {
  const currentPageFile = parsePageFileV1(input.pageFile);
  const inputDigest = await digestOperationInput(currentPageFile, input.operation);
  const existingRecord = currentPageFile.replayWindow.find(
    (record) => record.operationId === input.operation.operationId,
  );
  if (existingRecord !== undefined) {
    if (
      existingRecord.kind === input.operation.kind &&
      existingRecord.inputDigest === inputDigest
    ) {
      return Object.freeze({
        status: 'exact-replay' as const,
        record: existingRecord,
        result: existingRecord.result,
      });
    }
    return Object.freeze({
      status: 'operation-id-reused' as const,
      record: existingRecord,
    });
  }

  assertSafeRevision(input.operation.expectedRevision, 'expectedRevision');
  if (input.operation.expectedRevision !== currentPageFile.revision) {
    return Object.freeze({
      status: 'revision-conflict' as const,
      currentRevision: currentPageFile.revision,
    });
  }
  if (currentPageFile.revision === MAX_SAFE_REVISION) {
    throw replayError('page revision cannot be incremented');
  }
  if (currentPageFile.replayWindow.length > REPLAY_RECORD_COUNT) {
    throw replayError('replay window exceeds the exact record count');
  }

  const revision = currentPageFile.revision + 1;
  assertResult(input.result, input.operation.kind, revision);
  const record = parseReplayRecord({
    operationId: input.operation.operationId,
    kind: input.operation.kind,
    inputDigest,
    appliedRevision: revision,
    result: input.result,
  });
  const replayWindow = appendReplayRecord(currentPageFile.replayWindow, record);
  const candidate = Object.freeze({
    schemaVersion: 1 as const,
    page: currentPageFile.page,
    revision,
    annotations: Object.freeze(
      input.annotations.map((annotation) => parseElementAnnotation(annotation)),
    ),
    replayWindow,
  });
  const byteSizes = Object.freeze({
    result: utf8ByteLength(compactJson(record.result)),
    ledger: utf8ByteLength(compactJson(replayWindow)),
    pageFile: canonicalPageFileByteLength(candidate),
  });

  if (candidate.annotations.length > input.limits.annotationsPerPage) {
    return noWrite(currentPageFile, 'annotation-count', byteSizes);
  }
  if (byteSizes.result > input.limits.replayResultBytes) {
    return noWrite(currentPageFile, 'result-bytes', byteSizes);
  }
  if (byteSizes.ledger > input.limits.replayLedgerBytes) {
    return noWrite(currentPageFile, 'ledger-bytes', byteSizes);
  }
  if (byteSizes.pageFile > input.limits.pageFileBytes) {
    return noWrite(currentPageFile, 'page-file-bytes', byteSizes);
  }

  // Effective byte limits apply to this candidate's new result, full ledger,
  // and canonical file above. Reapplying replayResultBytes here would reject
  // an authoritative historical record under a newly tightened limit.
  const pageFile = parsePageFileV1(candidate);
  const parsedRecord = pageFile.replayWindow.at(-1);
  if (parsedRecord === undefined) {
    throw replayError('candidate replay window is missing its tail record');
  }

  return Object.freeze({
    status: 'apply' as const,
    pageFile,
    record: parsedRecord,
    result: parsedRecord.result,
    byteSizes,
  });
}

export async function digestOperationInput(
  pageFile: Pick<PageFileV1, 'page'>,
  operation: ReplayOperation,
): Promise<Sha256Digest> {
  const canonicalInput = canonicalizeJson({
    expectedRevision: operation.expectedRevision,
    kind: operation.kind,
    pageId: operationPageId(pageFile),
    payload: operation.payload,
    projectId: operation.projectId,
  });
  const digest = await sha256Hex(canonicalInput);
  return `sha256:${digest}` as Sha256Digest;
}

export function createOperationPayload(input: CreateAnnotationInput): unknown {
  return Object.freeze({
    domOrder: input.domOrder,
    locator: input.locator,
    memo: input.memo,
    resolution: input.resolution,
    surroundingText: input.surroundingText,
  });
}

export function updateOperationPayload(input: UpdateAnnotationInput): unknown {
  return Object.freeze({
    annotationId: input.annotationId,
    patch: input.patch,
  });
}

export function deleteOperationPayload(input: DeleteAnnotationInput): unknown {
  return Object.freeze({ annotationId: input.annotationId });
}

/** RFC 8785-style JSON: finite JSON primitives, sorted object members, no whitespace. */
export function canonicalizeJson(value: unknown): string {
  return serializeCanonicalJson(value, new Set<object>());
}

function noWrite(
  currentPageFile: PageFileV1,
  reason: ReplayNoWriteReason,
  byteSizes: ReplayByteSizes,
): ReplayDecision {
  return Object.freeze({
    status: 'no-write' as const,
    reason,
    currentPageFile,
    byteSizes,
  });
}
function canonicalPageFileByteLength(pageFile: PageFileV1): number {
  if (pageFile.annotations.length <= BUILT_IN_LIMITS.annotationsPerPage) {
    return utf8ByteLength(serializeCanonicalPageFileV1(pageFile));
  }

  // The candidate is reconstructed by contract parsers above. The contract
  // serializer deliberately rejects this over-cap graph, but count no-write
  // telemetry still uses its exact canonical PageFile representation.
  return utf8ByteLength(`${JSON.stringify(pageFile, null, 2)}\n`);
}

function assertResult(result: ReplayResult, kind: AnnotationMutationKind, revision: number): void {
  if (result.kind !== kind || result.revision !== revision) {
    throw replayError('replay result does not match the candidate operation');
  }
}

function operationPageId(pageFile: Pick<PageFileV1, 'page'>): string {
  return pageFile.page.pageId;
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw replayError('Web Crypto SHA-256 is unavailable');
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function serializeCanonicalJson(value: unknown, stack: Set<object>): string {
  switch (typeof value) {
    case 'string':
      assertWellFormedUnicode(value);
      return serializeString(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw replayError('canonical JSON cannot contain a non-finite number');
      }
      return serializeString(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object':
      if (value === null) {
        return 'null';
      }
      if (stack.has(value)) {
        throw replayError('canonical JSON cannot contain a cycle');
      }
      stack.add(value);
      try {
        if (Array.isArray(value)) {
          const serialized: string[] = [];
          for (let index = 0; index < value.length; index += 1) {
            if (!Object.prototype.hasOwnProperty.call(value, index)) {
              throw replayError('canonical JSON cannot contain an array hole');
            }
            serialized.push(serializeCanonicalJson(value[index], stack));
          }
          return `[${serialized.join(',')}]`;
        }
        if (!isPlainObject(value)) {
          throw replayError('canonical JSON requires plain objects');
        }
        const keys = Object.keys(value).sort(compareUtf16);
        const serialized = keys.map((key) => {
          assertWellFormedUnicode(key);
          return `${serializeString(key)}:${serializeCanonicalJson(value[key], stack)}`;
        });
        return `{${serialized.join(',')}}`;
      } finally {
        stack.delete(value);
      }
    default:
      throw replayError('canonical JSON contains an unsupported value');
  }
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function compareUtf16(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function serializeString(value: string | number): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw replayError('canonical JSON stringification failed');
  }
  return serialized;
}

function assertWellFormedUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw replayError('canonical JSON contains an unpaired surrogate');
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw replayError('canonical JSON contains an unpaired surrogate');
    }
  }
}

function compactJson(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw replayError('compact JSON stringification failed');
  }
  return serialized;
}

function replayError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_PAGE_FILE_INVALID', message);
}
