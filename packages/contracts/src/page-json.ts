import {
  type AnnotationMutationKind,
  type ElementAnnotation,
  type PageIdentityInput,
  type Sha256Digest,
  type UuidV4,
  parseElementAnnotation,
  parsePageIdentityInput,
  parseSha256Digest,
} from './annotations.js';
import {
  BUILT_IN_LIMITS,
  REPLAY_RECORD_COUNT,
  SceneGlassContractError,
  type LimitValues,
  type PageFileValidationLimits,
  assertLowercaseUuidV4,
  assertSafeRevision,
  isRecord,
  utf8ByteLength,
} from './limits.js';

export type PageIdentityV1 = PageIdentityInput;

export interface CreateReplayResult {
  readonly kind: 'create';
  readonly revision: number;
  readonly annotation: ElementAnnotation;
}

export interface UpdateReplayResult {
  readonly kind: 'update';
  readonly revision: number;
  readonly annotation: ElementAnnotation;
}

export interface DeleteReplayResult {
  readonly kind: 'delete';
  readonly revision: number;
  readonly annotationId: UuidV4;
}

export type ReplayResult = CreateReplayResult | UpdateReplayResult | DeleteReplayResult;

export interface ReplayRecord {
  readonly operationId: UuidV4;
  readonly kind: AnnotationMutationKind;
  readonly inputDigest: Sha256Digest;
  readonly appliedRevision: number;
  readonly result: ReplayResult;
}

export interface PageFileV1 {
  readonly schemaVersion: 1;
  readonly page: PageIdentityV1;
  readonly revision: number;
  readonly annotations: readonly ElementAnnotation[];
  readonly replayWindow: readonly ReplayRecord[];
}

const PAGE_FILE_KEYS = new Set([
  'schemaVersion',
  'page',
  'revision',
  'annotations',
  'replayWindow',
]);
const REPLAY_RECORD_KEYS = new Set([
  'operationId',
  'kind',
  'inputDigest',
  'appliedRevision',
  'result',
]);
const CREATE_RESULT_KEYS = new Set(['kind', 'revision', 'annotation']);
const UPDATE_RESULT_KEYS = new Set(['kind', 'revision', 'annotation']);
const DELETE_RESULT_KEYS = new Set(['kind', 'revision', 'annotationId']);

export function parsePageIdentityV1(value: unknown): PageIdentityV1 {
  return parsePageIdentityInput(value);
}

/**
 * Parses persisted PageFile v1 state. Replay records are historical once they
 * are in a page file, so their result sizes are bounded by the immutable v1
 * ceiling. Commit paths must separately apply effective replayResultBytes to
 * records not proven identical to persisted history.
 */
export function parsePageFileV1(
  value: unknown,
  limits: PageFileValidationLimits = BUILT_IN_LIMITS,
): PageFileV1 {
  const pageFile = parsePageFileV1Value(value, limits);
  assertSerializedPageFileLimits(pageFile, limits);
  return pageFile;
}

export function serializeCanonicalPageFileV1(value: unknown): string {
  return `${JSON.stringify(parsePageFileV1Value(value, BUILT_IN_LIMITS), null, 2)}\n`;
}

function parsePageFileV1Value(value: unknown, limits: PageFileValidationLimits): PageFileV1 {
  const record = pageFileRecord(value, 'page file');
  rejectUnknownKeys(record, PAGE_FILE_KEYS, 'page file');
  requireKeys(record, PAGE_FILE_KEYS, 'page file');
  if (record.schemaVersion !== 1) {
    throw pageFileError('schemaVersion must be 1');
  }
  if (!Array.isArray(record.annotations) || !Array.isArray(record.replayWindow)) {
    throw pageFileError('annotations and replayWindow must be arrays');
  }
  const revision = assertSafeRevision(record.revision, 'page revision');
  if (record.annotations.length > limits.annotationsPerPage) {
    throw new SceneGlassContractError(
      'SCG_LIMIT_FILE',
      'annotation count exceeds its effective limit',
    );
  }
  if (record.replayWindow.length > REPLAY_RECORD_COUNT) {
    throw pageFileError('replayWindow exceeds the exact replay record limit');
  }

  const annotations = record.annotations.map((annotation) => parseElementAnnotation(annotation));
  assertUniqueAnnotationIds(annotations);
  const replayWindow = record.replayWindow.map((replayRecord) =>
    parseReplayRecord(replayRecord, BUILT_IN_LIMITS),
  );
  assertReplayWindow(replayWindow, revision);

  return Object.freeze({
    schemaVersion: 1,
    page: parsePageIdentityV1(record.page),
    revision,
    annotations: Object.freeze(annotations),
    replayWindow: Object.freeze(replayWindow),
  });
}

export function parseReplayRecord(
  value: unknown,
  limits: Pick<LimitValues, 'replayResultBytes'> = BUILT_IN_LIMITS,
): ReplayRecord {
  const record = pageFileRecord(value, 'replay record');
  rejectUnknownKeys(record, REPLAY_RECORD_KEYS, 'replay record');
  requireKeys(record, REPLAY_RECORD_KEYS, 'replay record');
  if (record.kind !== 'create' && record.kind !== 'update' && record.kind !== 'delete') {
    throw pageFileError('replay record kind is invalid');
  }

  const kind = record.kind;
  const appliedRevision = assertSafeRevision(record.appliedRevision, 'replay appliedRevision');
  const result = parseReplayResult(record.result, kind);
  if (result.revision !== appliedRevision) {
    throw pageFileError('replay result revision must equal appliedRevision');
  }
  if (utf8ByteLength(JSON.stringify(result)) > limits.replayResultBytes) {
    throw new SceneGlassContractError(
      'SCG_LIMIT_FILE',
      'replay result exceeds its effective byte limit',
    );
  }

  return Object.freeze({
    operationId: assertLowercaseUuidV4(record.operationId, 'operationId'),
    kind,
    inputDigest: parseSha256Digest(record.inputDigest),
    appliedRevision,
    result,
  });
}

export function appendReplayRecord(
  currentWindow: readonly ReplayRecord[],
  nextRecord: ReplayRecord,
): readonly ReplayRecord[] {
  if (currentWindow.length > REPLAY_RECORD_COUNT) {
    throw pageFileError('replayWindow exceeds the exact replay record limit');
  }
  return Object.freeze(
    currentWindow.length === REPLAY_RECORD_COUNT
      ? [...currentWindow.slice(1), nextRecord]
      : [...currentWindow, nextRecord],
  );
}

export function isPageFileV1(value: unknown): value is PageFileV1 {
  return parsesAs(value, (input) => parsePageFileV1(input));
}

export function isReplayRecord(value: unknown): value is ReplayRecord {
  return parsesAs(value, (input) => parseReplayRecord(input));
}

export function isPageIdentityV1(value: unknown): value is PageIdentityV1 {
  return parsesAs(value, parsePageIdentityV1);
}

function parseReplayResult(value: unknown, expectedKind: AnnotationMutationKind): ReplayResult {
  const record = pageFileRecord(value, 'replay result');
  switch (expectedKind) {
    case 'create':
      rejectUnknownKeys(record, CREATE_RESULT_KEYS, 'create replay result');
      requireKeys(record, CREATE_RESULT_KEYS, 'create replay result');
      if (record.kind !== 'create') {
        throw pageFileError('create replay result kind is invalid');
      }
      return Object.freeze({
        kind: 'create' as const,
        revision: assertSafeRevision(record.revision, 'create replay revision'),
        annotation: parseElementAnnotation(record.annotation),
      });
    case 'update':
      rejectUnknownKeys(record, UPDATE_RESULT_KEYS, 'update replay result');
      requireKeys(record, UPDATE_RESULT_KEYS, 'update replay result');
      if (record.kind !== 'update') {
        throw pageFileError('update replay result kind is invalid');
      }
      return Object.freeze({
        kind: 'update' as const,
        revision: assertSafeRevision(record.revision, 'update replay revision'),
        annotation: parseElementAnnotation(record.annotation),
      });
    case 'delete':
      rejectUnknownKeys(record, DELETE_RESULT_KEYS, 'delete replay result');
      requireKeys(record, DELETE_RESULT_KEYS, 'delete replay result');
      if (record.kind !== 'delete') {
        throw pageFileError('delete replay result kind is invalid');
      }
      return Object.freeze({
        kind: 'delete' as const,
        revision: assertSafeRevision(record.revision, 'delete replay revision'),
        annotationId: assertLowercaseUuidV4(record.annotationId, 'delete replay annotationId'),
      });
  }
  throw pageFileError('replay result kind is invalid');
}

function assertReplayWindow(replayWindow: readonly ReplayRecord[], pageRevision: number): void {
  const expectedReplayCount = Math.min(pageRevision, REPLAY_RECORD_COUNT);
  if (replayWindow.length !== expectedReplayCount) {
    throw pageFileError('replayWindow must contain the exact replay tail');
  }

  const firstReplayRevision = pageRevision - expectedReplayCount + 1;
  const operationIds = new Set<string>();
  for (const [index, replayRecord] of replayWindow.entries()) {
    if (operationIds.has(replayRecord.operationId)) {
      throw pageFileError('replayWindow operationIds must be unique');
    }
    operationIds.add(replayRecord.operationId);
    if (replayRecord.appliedRevision !== firstReplayRevision + index) {
      throw pageFileError('replayWindow must contain contiguous revisions ending at page revision');
    }
  }
}

function assertUniqueAnnotationIds(annotations: readonly ElementAnnotation[]): void {
  const annotationIds = new Set<string>();
  for (const annotation of annotations) {
    if (annotationIds.has(annotation.id)) {
      throw pageFileError('annotation ids must be unique');
    }
    annotationIds.add(annotation.id);
  }
}

function assertSerializedPageFileLimits(
  pageFile: PageFileV1,
  limits: PageFileValidationLimits,
): void {
  const replayLedgerBytes = utf8ByteLength(JSON.stringify(pageFile.replayWindow));
  if (replayLedgerBytes > limits.replayLedgerBytes) {
    throw new SceneGlassContractError(
      'SCG_LIMIT_FILE',
      'replay ledger exceeds its effective byte limit',
    );
  }
  if (utf8ByteLength(serializeCanonicalPageFileV1(pageFile)) > limits.pageFileBytes) {
    throw new SceneGlassContractError(
      'SCG_LIMIT_FILE',
      'page file exceeds its effective byte limit',
    );
  }
}

function pageFileRecord(value: unknown, name: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw pageFileError(`${name} must be an object`);
  }
  return value;
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>,
  name: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) {
      throw pageFileError(`${name} contains an unknown field`);
    }
  }
}

function requireKeys(
  record: Record<string, unknown>,
  requiredKeys: ReadonlySet<string>,
  name: string,
): void {
  for (const key of requiredKeys) {
    if (!hasOwn(record, key)) {
      throw pageFileError(`${name} is missing ${key}`);
    }
  }
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function pageFileError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_PAGE_FILE_INVALID', message);
}

function parsesAs<T>(value: unknown, parser: (input: unknown) => T): boolean {
  try {
    parser(value);
    return true;
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      return false;
    }
    throw error;
  }
}
