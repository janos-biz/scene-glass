import {
  BUILT_IN_LIMITS,
  SceneGlassContractError,
  type LowercaseUuidV4,
  assertDomOrder,
  assertLowercaseUuidV4,
  assertSafeRevision,
  assertString,
  assertUtf8ByteLimit,
  isRecord,
  unicodeCodePointLength,
  utf8ByteLength,
} from './limits.js';

export type UuidV4 = LowercaseUuidV4;

export type PageId = string & {
  readonly __sceneGlassPageId: 'PageId';
};

export type Sha256Digest = string & {
  readonly __sceneGlassSha256Digest: 'Sha256Digest';
};

export interface PageIdentityInput {
  readonly policyVersion: 1;
  readonly canonicalIdentity: string;
  readonly route: string;
  readonly pageId: PageId;
}

export type LocatorStableAttribute = readonly [name: string, value: string];

export interface LocatorFingerprint {
  readonly tag: string;
  readonly stableAttributes: readonly LocatorStableAttribute[];
  readonly ancestorSignatures: readonly string[];
  readonly textDigest: Sha256Digest;
}

export interface LocatorInput {
  readonly dataScgId?: string;
  readonly fingerprint?: LocatorFingerprint;
}

export type ResolutionStatus = 'ambiguous' | 'not-found' | 'resolved';

export type ResolutionInput =
  | {
      readonly status: 'resolved';
      readonly reason: null;
    }
  | {
      readonly status: 'ambiguous';
      readonly reason: 'ambiguous';
    }
  | {
      readonly status: 'not-found';
      readonly reason: 'not-found';
    };

export interface AnnotationContext {
  readonly viewport: readonly [width: number, height: number];
  readonly rect: readonly [x: number, y: number, width: number, height: number];
  readonly tag: string;
  readonly classes: readonly string[];
  readonly cssPath: string;
  readonly selectedText: string;
  readonly sourceFile?: string;
  readonly componentTrail?: readonly string[];
}

export interface ElementAnnotation {
  readonly id: UuidV4;
  readonly locator: LocatorInput;
  readonly memo: string;
  readonly surroundingText: string;
  readonly domOrder: number;
  readonly resolution: ResolutionInput;
  readonly context?: AnnotationContext;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateAnnotationInput {
  readonly page: PageIdentityInput;
  readonly expectedRevision: number;
  readonly operationId: UuidV4;
  readonly locator: LocatorInput;
  readonly memo: string;
  readonly surroundingText: string;
  readonly domOrder: number;
  readonly resolution: ResolutionInput;
  readonly context?: AnnotationContext;
}

export interface UpdateAnnotationPatch {
  readonly memo?: string;
  readonly locator?: LocatorInput;
  readonly surroundingText?: string;
  readonly domOrder?: number;
  readonly resolution?: ResolutionInput;
  readonly context?: AnnotationContext;
}

export interface UpdateAnnotationInput {
  readonly page: PageIdentityInput;
  readonly annotationId: UuidV4;
  readonly expectedRevision: number;
  readonly operationId: UuidV4;
  readonly patch: UpdateAnnotationPatch;
}

export interface DeleteAnnotationInput {
  readonly page: PageIdentityInput;
  readonly annotationId: UuidV4;
  readonly expectedRevision: number;
  readonly operationId: UuidV4;
}

export type AnnotationMutationKind = 'create' | 'delete' | 'update';

export const PAGE_ID_PATTERN = /^p_[0-9a-f]{64}$/;
export const SHA256_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const LOCATOR_TAG_NAME_PATTERN = /^[a-z][a-z0-9:-]*$/;
export const LOCATOR_STABLE_ATTRIBUTE_NAME_PATTERN = /^[a-z][a-z0-9:_-]*$/;
export const MAX_LOCATOR_ANCESTOR_SIGNATURES = 4;
const PAGE_IDENTITY_KEYS = new Set(['policyVersion', 'canonicalIdentity', 'route', 'pageId']);
const LOCATOR_KEYS = new Set(['dataScgId', 'fingerprint']);
const FINGERPRINT_KEYS = new Set(['tag', 'stableAttributes', 'ancestorSignatures', 'textDigest']);
const RESOLUTION_KEYS = new Set(['status', 'reason']);
const ANNOTATION_KEYS = new Set([
  'id',
  'locator',
  'memo',
  'surroundingText',
  'domOrder',
  'resolution',
  'context',
  'createdAt',
  'updatedAt',
]);
const CREATE_KEYS = new Set([
  'page',
  'expectedRevision',
  'operationId',
  'locator',
  'memo',
  'surroundingText',
  'domOrder',
  'resolution',
  'context',
]);
const UPDATE_KEYS = new Set(['page', 'annotationId', 'expectedRevision', 'operationId', 'patch']);
const DELETE_KEYS = new Set(['page', 'annotationId', 'expectedRevision', 'operationId']);
const UPDATE_PATCH_KEYS = new Set([
  'memo',
  'locator',
  'surroundingText',
  'domOrder',
  'resolution',
  'context',
]);
const CONTEXT_KEYS = new Set([
  'viewport',
  'rect',
  'tag',
  'classes',
  'cssPath',
  'selectedText',
  'sourceFile',
  'componentTrail',
]);
const CONTEXT_REQUIRED_KEYS = new Set([
  'viewport',
  'rect',
  'tag',
  'classes',
  'cssPath',
  'selectedText',
]);
const MAX_CONTEXT_CLASSES = 64;
const MAX_CONTEXT_COMPONENT_TRAIL = 64;
const MAX_CONTEXT_CSS_PATH_BYTES = 4_096;
const MAX_CONTEXT_SERIALIZED_BYTES = 16 * 1024;
const ANNOTATION_REQUIRED_KEYS = new Set([
  'id',
  'locator',
  'memo',
  'surroundingText',
  'domOrder',
  'resolution',
  'createdAt',
  'updatedAt',
]);
const CREATE_REQUIRED_KEYS = new Set([
  'page',
  'expectedRevision',
  'operationId',
  'locator',
  'memo',
  'surroundingText',
  'domOrder',
  'resolution',
]);

export function parseAnnotationContext(value: unknown): AnnotationContext {
  const record = annotationRecord(value, 'annotation context');
  rejectUnknownKeys(record, CONTEXT_KEYS, 'annotation context');
  requireKeys(record, CONTEXT_REQUIRED_KEYS, 'annotation context');

  const context: {
    viewport: readonly [number, number];
    rect: readonly [number, number, number, number];
    tag: string;
    classes: readonly string[];
    cssPath: string;
    selectedText: string;
    sourceFile?: string;
    componentTrail?: readonly string[];
  } = {
    viewport: parseViewport(record.viewport),
    rect: parseRect(record.rect),
    tag: parseTagName(record.tag, 'annotation context tag'),
    classes: parseContextStringList(
      record.classes,
      MAX_CONTEXT_CLASSES,
      'annotation context class',
    ),
    cssPath: parseContextText(
      record.cssPath,
      'annotation context cssPath',
      MAX_CONTEXT_CSS_PATH_BYTES,
    ),
    selectedText: parseContextSelectedText(record.selectedText),
  };
  if (hasOwn(record, 'sourceFile')) {
    context.sourceFile = parseContextText(
      record.sourceFile,
      'annotation context sourceFile',
      BUILT_IN_LIMITS.locatorFieldBytes,
    );
  }
  if (hasOwn(record, 'componentTrail')) {
    context.componentTrail = parseContextStringList(
      record.componentTrail,
      MAX_CONTEXT_COMPONENT_TRAIL,
      'annotation context component',
    );
  }

  const frozen = Object.freeze(context) as AnnotationContext;
  if (utf8ByteLength(JSON.stringify(frozen)) > MAX_CONTEXT_SERIALIZED_BYTES) {
    throw annotationError('annotation context exceeds its serialized byte limit');
  }
  return frozen;
}

function parseContextSafeInteger(value: unknown, name: string, allowNegative: boolean): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || (!allowNegative && value < 0)) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be a ${allowNegative ? 'safe' : 'non-negative safe'} integer`,
    );
  }
  return value;
}

function parseViewport(value: unknown): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw annotationError('annotation context viewport must be a two-number tuple');
  }
  return Object.freeze([
    parseContextSafeInteger(value[0], 'annotation context viewport width', false),
    parseContextSafeInteger(value[1], 'annotation context viewport height', false),
  ] as [number, number]);
}

function parseRect(value: unknown): readonly [number, number, number, number] {
  if (!Array.isArray(value) || value.length !== 4) {
    throw annotationError('annotation context rect must be a four-number tuple');
  }
  return Object.freeze([
    parseContextSafeInteger(value[0], 'annotation context rect x', true),
    parseContextSafeInteger(value[1], 'annotation context rect y', true),
    parseContextSafeInteger(value[2], 'annotation context rect width', false),
    parseContextSafeInteger(value[3], 'annotation context rect height', false),
  ] as [number, number, number, number]);
}

function parseContextStringList(value: unknown, maximum: number, name: string): readonly string[] {
  if (!Array.isArray(value)) {
    throw annotationError(`${name} list must be an array`);
  }
  if (value.length > maximum) {
    throw annotationError(`${name} list exceeds its limit`);
  }
  return Object.freeze(value.map((item) => parseNonBlankField(item, name)));
}

function parseContextText(value: unknown, name: string, maximumBytes: number): string {
  const parsed = assertUtf8ByteLimit(value, maximumBytes, name);
  if (containsAsciiControlCharacter(parsed)) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be free of control characters`,
    );
  }
  return parsed;
}

function parseContextSelectedText(value: unknown): string {
  const text = assertUtf8ByteLimit(
    value,
    BUILT_IN_LIMITS.surroundingTextBytes,
    'annotation context selectedText',
  );
  if (unicodeCodePointLength(text) > BUILT_IN_LIMITS.surroundingTextCodePoints) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      'annotation context selectedText exceeds its code point limit',
    );
  }
  return text;
}

export function parseCreateAnnotationInput(value: unknown): CreateAnnotationInput {
  const record = annotationRecord(value, 'create annotation input');
  rejectUnknownKeys(record, CREATE_KEYS, 'create annotation input');
  requireKeys(record, CREATE_REQUIRED_KEYS, 'create annotation input');

  return Object.freeze({
    page: parsePageIdentityInput(record.page),
    expectedRevision: assertSafeRevision(record.expectedRevision, 'expectedRevision'),
    operationId: assertLowercaseUuidV4(record.operationId, 'operationId'),
    locator: parseLocatorInput(record.locator),
    memo: parseMemo(record.memo),
    surroundingText: parseSurroundingText(record.surroundingText),
    domOrder: assertDomOrder(record.domOrder),
    resolution: parseResolutionInput(record.resolution),
    ...(hasOwn(record, 'context') ? { context: parseAnnotationContext(record.context) } : {}),
  });
}

export function parseUpdateAnnotationInput(value: unknown): UpdateAnnotationInput {
  const record = annotationRecord(value, 'update annotation input');
  rejectUnknownKeys(record, UPDATE_KEYS, 'update annotation input');
  requireKeys(record, UPDATE_KEYS, 'update annotation input');

  return Object.freeze({
    page: parsePageIdentityInput(record.page),
    annotationId: assertLowercaseUuidV4(record.annotationId, 'annotationId'),
    expectedRevision: assertSafeRevision(record.expectedRevision, 'expectedRevision'),
    operationId: assertLowercaseUuidV4(record.operationId, 'operationId'),
    patch: parseUpdateAnnotationPatch(record.patch),
  });
}

export function parseDeleteAnnotationInput(value: unknown): DeleteAnnotationInput {
  const record = annotationRecord(value, 'delete annotation input');
  rejectUnknownKeys(record, DELETE_KEYS, 'delete annotation input');
  requireKeys(record, DELETE_KEYS, 'delete annotation input');

  return Object.freeze({
    page: parsePageIdentityInput(record.page),
    annotationId: assertLowercaseUuidV4(record.annotationId, 'annotationId'),
    expectedRevision: assertSafeRevision(record.expectedRevision, 'expectedRevision'),
    operationId: assertLowercaseUuidV4(record.operationId, 'operationId'),
  });
}

export function parseUpdateAnnotationPatch(value: unknown): UpdateAnnotationPatch {
  const record = annotationRecord(value, 'update annotation patch');
  rejectUnknownKeys(record, UPDATE_PATCH_KEYS, 'update annotation patch');
  if (Object.keys(record).length === 0) {
    throw annotationError('update annotation patch must not be empty');
  }

  const patch: {
    memo?: string;
    locator?: LocatorInput;
    surroundingText?: string;
    domOrder?: number;
    resolution?: ResolutionInput;
    context?: AnnotationContext;
  } = {};
  if (hasOwn(record, 'memo')) {
    patch.memo = parseMemo(record.memo);
  }
  if (hasOwn(record, 'locator')) {
    patch.locator = parseLocatorInput(record.locator);
  }
  if (hasOwn(record, 'surroundingText')) {
    patch.surroundingText = parseSurroundingText(record.surroundingText);
  }
  if (hasOwn(record, 'domOrder')) {
    patch.domOrder = assertDomOrder(record.domOrder);
  }
  if (hasOwn(record, 'resolution')) {
    patch.resolution = parseResolutionInput(record.resolution);
  }
  if (hasOwn(record, 'context')) {
    patch.context = parseAnnotationContext(record.context);
  }
  return Object.freeze(patch);
}

export function parseElementAnnotation(value: unknown): ElementAnnotation {
  const record = annotationRecord(value, 'element annotation');
  rejectUnknownKeys(record, ANNOTATION_KEYS, 'element annotation');
  requireKeys(record, ANNOTATION_REQUIRED_KEYS, 'element annotation');

  const createdAt = parseTimestamp(record.createdAt, 'createdAt');
  const updatedAt = parseTimestamp(record.updatedAt, 'updatedAt');
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw annotationError('updatedAt must not precede createdAt');
  }

  return Object.freeze({
    id: assertLowercaseUuidV4(record.id, 'annotation id'),
    locator: parseLocatorInput(record.locator),
    memo: parseMemo(record.memo),
    surroundingText: parseSurroundingText(record.surroundingText),
    domOrder: assertDomOrder(record.domOrder),
    resolution: parseResolutionInput(record.resolution),
    ...(hasOwn(record, 'context') ? { context: parseAnnotationContext(record.context) } : {}),
    createdAt,
    updatedAt,
  });
}

export function parsePageIdentityInput(value: unknown): PageIdentityInput {
  const record = annotationRecord(value, 'page identity');
  rejectUnknownKeys(record, PAGE_IDENTITY_KEYS, 'page identity');
  requireKeys(record, PAGE_IDENTITY_KEYS, 'page identity');

  if (record.policyVersion !== 1) {
    throw annotationError('page identity policyVersion must be 1');
  }
  const canonicalIdentity = parseIdentityString(
    record.canonicalIdentity,
    'canonicalIdentity',
    BUILT_IN_LIMITS.canonicalIdentityBytes,
  );
  if (canonicalIdentity.normalize('NFC') !== canonicalIdentity) {
    throw annotationError('canonicalIdentity must be NFC normalized');
  }

  return Object.freeze({
    policyVersion: 1,
    canonicalIdentity,
    route: parseIdentityString(record.route, 'route', BUILT_IN_LIMITS.routeBytes),
    pageId: parsePageId(record.pageId),
  });
}

export function parsePageId(value: unknown): PageId {
  if (typeof value !== 'string' || !PAGE_ID_PATTERN.test(value)) {
    throw new SceneGlassContractError(
      'SCG_ID_INVALID',
      'pageId must be p_ followed by 64 lowercase hexadecimal characters',
    );
  }
  return value as PageId;
}

export function parseSha256Digest(value: unknown): Sha256Digest {
  if (typeof value !== 'string' || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new SceneGlassContractError('SCG_ID_INVALID', 'digest must be a lowercase sha256 digest');
  }
  return value as Sha256Digest;
}

export function parseLocatorInput(value: unknown): LocatorInput {
  const record = annotationRecord(value, 'locator');
  rejectUnknownKeys(record, LOCATOR_KEYS, 'locator');
  if (!hasOwn(record, 'dataScgId') && !hasOwn(record, 'fingerprint')) {
    throw annotationError('locator requires dataScgId or fingerprint');
  }

  const dataScgId = hasOwn(record, 'dataScgId')
    ? parseNonBlankField(record.dataScgId, 'dataScgId')
    : undefined;
  const fingerprint = hasOwn(record, 'fingerprint')
    ? parseLocatorFingerprint(record.fingerprint)
    : undefined;

  const locator: LocatorInput = {
    ...(dataScgId === undefined ? {} : { dataScgId }),
    ...(fingerprint === undefined ? {} : { fingerprint }),
  };
  assertLocatorSerializedBytes(locator);
  return Object.freeze(locator);
}

export function parseLocatorFingerprint(value: unknown): LocatorFingerprint {
  const record = annotationRecord(value, 'locator fingerprint');
  rejectUnknownKeys(record, FINGERPRINT_KEYS, 'locator fingerprint');
  requireKeys(record, FINGERPRINT_KEYS, 'locator fingerprint');
  if (!Array.isArray(record.stableAttributes) || !Array.isArray(record.ancestorSignatures)) {
    throw annotationError(
      'locator fingerprint stableAttributes and ancestorSignatures must be arrays',
    );
  }
  if (record.ancestorSignatures.length > MAX_LOCATOR_ANCESTOR_SIGNATURES) {
    throw annotationError('locator fingerprint may contain at most four ancestor signatures');
  }

  const stableAttributes = record.stableAttributes.map((attribute) =>
    parseLocatorStableAttribute(attribute),
  );
  assertSortedUniqueStableAttributes(stableAttributes, 'locator fingerprint stableAttributes');
  const ancestorSignatures = record.ancestorSignatures.map((signature) =>
    parseNonBlankField(signature, 'locator ancestor signature'),
  );

  return Object.freeze({
    tag: parseTagName(record.tag, 'locator fingerprint tag'),
    stableAttributes: Object.freeze(stableAttributes),
    ancestorSignatures: Object.freeze(ancestorSignatures),
    textDigest: parseSha256Digest(record.textDigest),
  });
}

export function parseResolutionInput(value: unknown): ResolutionInput {
  const record = annotationRecord(value, 'resolution');
  rejectUnknownKeys(record, RESOLUTION_KEYS, 'resolution');
  if (
    record.status !== 'resolved' &&
    record.status !== 'not-found' &&
    record.status !== 'ambiguous'
  ) {
    throw annotationError('resolution status is invalid');
  }

  if (record.status === 'resolved') {
    if (record.reason !== null) {
      throw annotationError('resolved resolution reason must be null');
    }
    return Object.freeze({ status: 'resolved' as const, reason: null });
  }
  if (record.status === 'not-found') {
    if (record.reason !== 'not-found') {
      throw annotationError('not-found resolution reason is invalid');
    }
    return Object.freeze({
      status: 'not-found' as const,
      reason: 'not-found' as const,
    });
  }
  if (record.reason !== 'ambiguous') {
    throw annotationError('ambiguous resolution reason is invalid');
  }
  return Object.freeze({
    status: 'ambiguous' as const,
    reason: 'ambiguous' as const,
  });
}

export function isCreateAnnotationInput(value: unknown): value is CreateAnnotationInput {
  return parsesAs(value, parseCreateAnnotationInput);
}

export function isUpdateAnnotationInput(value: unknown): value is UpdateAnnotationInput {
  return parsesAs(value, parseUpdateAnnotationInput);
}

export function isDeleteAnnotationInput(value: unknown): value is DeleteAnnotationInput {
  return parsesAs(value, parseDeleteAnnotationInput);
}

export function isElementAnnotation(value: unknown): value is ElementAnnotation {
  return parsesAs(value, parseElementAnnotation);
}

function parseLocatorStableAttribute(value: unknown): LocatorStableAttribute {
  if (!Array.isArray(value) || value.length !== 2) {
    throw annotationError('locator stable attribute must be a two-item name and value tuple');
  }
  const [rawName, rawValue] = value;
  const name = parseNonBlankField(rawName, 'locator stable attribute name');
  if (!LOCATOR_STABLE_ATTRIBUTE_NAME_PATTERN.test(name)) {
    throw annotationError('locator stable attribute name must be lowercase ASCII');
  }
  const attributeValue = parseField(rawValue, 'locator stable attribute value');
  return Object.freeze([name, attributeValue] as [string, string]);
}

function parseTagName(value: unknown, name: string): string {
  const parsed = parseNonBlankField(value, name);
  if (!LOCATOR_TAG_NAME_PATTERN.test(parsed)) {
    throw annotationError(`${name} must be lowercase ASCII`);
  }
  return parsed;
}

function parseMemo(value: unknown): string {
  const memo = assertUtf8ByteLimit(value, BUILT_IN_LIMITS.memoBytes, 'memo');
  if (memo.trim().length === 0) {
    throw new SceneGlassContractError('SCG_MEMO_BLANK', 'memo must not be blank');
  }
  return memo;
}

function parseSurroundingText(value: unknown): string {
  const text = assertUtf8ByteLimit(value, BUILT_IN_LIMITS.surroundingTextBytes, 'surroundingText');
  if (unicodeCodePointLength(text) > BUILT_IN_LIMITS.surroundingTextCodePoints) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      'surroundingText exceeds its code point limit',
    );
  }
  return text;
}

function parseIdentityString(value: unknown, name: string, maximumBytes: number): string {
  const parsed = assertUtf8ByteLimit(value, maximumBytes, name);
  if (parsed.length === 0 || containsAsciiControlCharacter(parsed)) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} contains an empty or control value`,
    );
  }
  return parsed;
}

function parseNonBlankField(value: unknown, name: string): string {
  const parsed = assertUtf8ByteLimit(value, BUILT_IN_LIMITS.locatorFieldBytes, name);
  if (parsed.trim().length === 0 || containsAsciiControlCharacter(parsed)) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be non-blank and free of control characters`,
    );
  }
  return parsed;
}

function parseField(value: unknown, name: string): string {
  const parsed = assertUtf8ByteLimit(value, BUILT_IN_LIMITS.locatorFieldBytes, name);
  if (containsNullOrDeleteCharacter(parsed)) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be free of null and delete characters`,
    );
  }
  return parsed;
}

function containsAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) {
      return true;
    }
  }
  return false;
}

function containsNullOrDeleteCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit === 0 || codeUnit === 0x7f) {
      return true;
    }
  }
  return false;
}

function parseTimestamp(value: unknown, name: string): string {
  const timestamp = assertString(value, name);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(timestamp) ||
    Number.isNaN(Date.parse(timestamp))
  ) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be an exact UTC ISO timestamp`,
    );
  }
  return timestamp;
}

function assertLocatorSerializedBytes(locator: LocatorInput): void {
  const serialized = JSON.stringify(locator);
  if (utf8ByteLength(serialized) > BUILT_IN_LIMITS.locatorSerializedBytes) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      'locator exceeds its serialized byte limit',
    );
  }
}

function assertSortedUniqueStableAttributes(
  attributes: readonly LocatorStableAttribute[],
  name: string,
): void {
  let previous: string | undefined;
  for (const [attributeName, attributeValue] of attributes) {
    const current = `${attributeName}\u0000${attributeValue}`;
    if (previous !== undefined && previous >= current) {
      throw annotationError(`${name} must be strictly sorted and unique`);
    }
    previous = current;
  }
}

function annotationRecord(value: unknown, name: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw annotationError(`${name} must be an object`);
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
      throw annotationError(`${name} contains an unknown field`);
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
      throw annotationError(`${name} is missing ${key}`);
    }
  }
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function annotationError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_ANNOTATION_INVALID', message);
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
