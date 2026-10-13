export const REPLAY_RECORD_COUNT = 32;

export const MAX_SAFE_REVISION = Number.MAX_SAFE_INTEGER;
export const MAX_DOM_ORDER = 2_147_483_647;
export const RESOLUTION_SCORE_THRESHOLD = 70;
export const RESOLUTION_GAP_THRESHOLD = 15;

export type SceneGlassContractErrorCode =
  | 'SCG_ANNOTATION_INVALID'
  | 'SCG_CONFIG_INVALID'
  | 'SCG_CONFIG_LIMIT_INVALID'
  | 'SCG_ID_INVALID'
  | 'SCG_LIMIT_FILE'
  | 'SCG_MEMO_BLANK'
  | 'SCG_PAGE_FILE_INVALID'
  | 'SCG_SCALAR_INVALID'
  | 'SCG_STARTUP_PREFLIGHT_FAILED'
  | 'SCG_TOKEN_INVALID'
  | 'SCG_PROVENANCE_CONFLICT'
  | 'SCG_STATIC_DESCRIPTOR_INVALID'
  | 'SCG_VITE_CONFIG_UNSUPPORTED'
  | 'SCG_VITE_NON_DEV_UNSUPPORTED';

export class SceneGlassContractError extends Error {
  public readonly code: SceneGlassContractErrorCode;

  public constructor(code: SceneGlassContractErrorCode, message: string) {
    super(message);
    this.name = 'SceneGlassContractError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const LIMIT_DEFAULTS = {
  httpBodyBytes: 1 * 1024 * 1024,
  canonicalIdentityBytes: 2_048,
  routeBytes: 2_048,
  memoBytes: 16 * 1024,
  surroundingTextCodePoints: 500,
  surroundingTextBytes: 4 * 1024,
  locatorFieldBytes: 512,
  locatorSerializedBytes: 16 * 1024,
  annotationsPerPage: 1_000,
  pageFileBytes: 8 * 1024 * 1024,
  replayLedgerBytes: 2 * 1024 * 1024,
  replayResultBytes: 64 * 1024,
  pagesPerProject: 2_000,
  exportScanBytes: 64 * 1024 * 1024,
  exportRenderBytes: 16 * 1024 * 1024,
  concurrentRequestsPerProject: 16,
  concurrentRequestsGlobal: 64,
  normalSessionsPerProject: 32,
  normalSessionsGlobal: 128,
  sessionMaxAgeMs: 30 * 60 * 1_000,
  sessionIdleMs: 5 * 60 * 1_000,
  diagnosticActiveRunsPerProject: 4,
  diagnosticActiveRunsGlobal: 16,
  diagnosticRunsPerProjectPerMinute: 5,
  requestTimeoutMs: 30 * 1_000,
  exportTimeoutMs: 60 * 1_000,
} as const;

export type LimitValues = {
  readonly [Name in keyof typeof LIMIT_DEFAULTS]: number;
};

export type LimitName = keyof LimitValues;

export const BUILT_IN_LIMITS: Readonly<LimitValues> = Object.freeze(LIMIT_DEFAULTS);

export type PageFileByteLimits = Pick<
  LimitValues,
  'pageFileBytes' | 'replayLedgerBytes' | 'replayResultBytes'
>;

export type PageFileValidationLimits = PageFileByteLimits & Pick<LimitValues, 'annotationsPerPage'>;

export type LowerLimitOverrides = Partial<LimitValues>;

const GLOBAL_ONLY_LIMIT_NAMES = [
  'httpBodyBytes',
  'concurrentRequestsGlobal',
  'normalSessionsGlobal',
  'diagnosticActiveRunsGlobal',
] as const satisfies readonly LimitName[];

export type GlobalOnlyLimitName = (typeof GLOBAL_ONLY_LIMIT_NAMES)[number];

export type ProjectLowerLimitName = Exclude<LimitName, GlobalOnlyLimitName>;
export type ProjectLowerLimitOverrides = Partial<Pick<LimitValues, ProjectLowerLimitName>>;

const GLOBAL_ONLY_LIMIT_NAME_SET: ReadonlySet<LimitName> = new Set<LimitName>(
  GLOBAL_ONLY_LIMIT_NAMES,
);

export const GLOBAL_LIMIT_OVERRIDE_KEYS: readonly LimitName[] = Object.freeze(
  Object.keys(BUILT_IN_LIMITS) as LimitName[],
);

export const PROJECT_LIMIT_OVERRIDE_KEYS: readonly ProjectLowerLimitName[] = Object.freeze(
  GLOBAL_LIMIT_OVERRIDE_KEYS.filter(
    (key): key is ProjectLowerLimitName => !GLOBAL_ONLY_LIMIT_NAME_SET.has(key),
  ),
);

export const REPLAY_RECORD_COUNT_OVERRIDE_ALIASES = Object.freeze([
  'replayRecordCount',
  'replayRecordsCount',
  'replayWindowSize',
  'replayWindowCount',
  'replayCount',
  'replayCountLimit',
  'recordCount',
  'replayRecords',
] as const);

export type LowercaseUuidV4 = string & {
  readonly __sceneGlassLowercaseUuidV4: 'LowercaseUuidV4';
};

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isReplayRecordCountOverrideKey(key: string): boolean {
  const normalized = key.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  return (
    REPLAY_RECORD_COUNT_OVERRIDE_ALIASES.some((alias) => alias.toLowerCase() === normalized) ||
    (normalized.includes('replay') &&
      (normalized.includes('record') || normalized.includes('window')))
  );
}

export function parseGlobalLowerLimitOverrides(value: unknown): LowerLimitOverrides {
  return parseLowerLimitOverrides(value, GLOBAL_LIMIT_OVERRIDE_KEYS);
}

export function parseProjectLowerLimitOverrides(value: unknown): ProjectLowerLimitOverrides {
  return parseLowerLimitOverrides(value, PROJECT_LIMIT_OVERRIDE_KEYS);
}

export function effectiveLimits(
  globalLimits?: LowerLimitOverrides,
  projectLimits?: ProjectLowerLimitOverrides,
): Readonly<LimitValues> {
  const global =
    globalLimits === undefined ? undefined : parseGlobalLowerLimitOverrides(globalLimits);
  const project =
    projectLimits === undefined ? undefined : parseProjectLowerLimitOverrides(projectLimits);
  const result: { [Key in LimitName]: number } = { ...BUILT_IN_LIMITS };

  for (const key of GLOBAL_LIMIT_OVERRIDE_KEYS) {
    const globalValue = global?.[key];
    if (globalValue !== undefined) {
      result[key] = Math.min(result[key], globalValue);
    }
  }

  for (const key of PROJECT_LIMIT_OVERRIDE_KEYS) {
    const projectValue = project?.[key];
    if (projectValue !== undefined) {
      result[key] = Math.min(result[key], projectValue);
    }
  }

  return Object.freeze(result);
}

export function assertSafeRevision(value: unknown, name = 'revision'): number {
  return assertIntegerInRange(value, 0, MAX_SAFE_REVISION, name);
}

export function assertDomOrder(value: unknown, name = 'domOrder'): number {
  return assertIntegerInRange(value, 0, MAX_DOM_ORDER, name);
}

export function assertResolutionScore(value: unknown, name = 'resolution score'): number {
  return assertIntegerInRange(value, 0, 100, name);
}

export function assertPositiveSafeInteger(value: unknown, name = 'value'): number {
  return assertIntegerInRange(value, 1, Number.MAX_SAFE_INTEGER, name);
}

export function assertIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
  name = 'value',
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new SceneGlassContractError(
      'SCG_SCALAR_INVALID',
      `${name} must be a safe integer from ${minimum} through ${maximum}`,
    );
  }
  return value;
}

export function assertString(value: unknown, name = 'value'): string {
  if (typeof value !== 'string') {
    throw new SceneGlassContractError('SCG_SCALAR_INVALID', `${name} must be a string`);
  }
  assertWellFormedUnicode(value, name);
  return value;
}

export function assertNonBlankString(value: unknown, name = 'value'): string {
  const parsed = assertString(value, name);
  if (parsed.trim().length === 0) {
    throw new SceneGlassContractError('SCG_SCALAR_INVALID', `${name} must not be blank`);
  }
  return parsed;
}

export function assertUtf8ByteLimit(value: unknown, maximum: number, name = 'value'): string {
  const parsed = assertString(value, name);
  if (utf8ByteLength(parsed) > maximum) {
    throw new SceneGlassContractError('SCG_SCALAR_INVALID', `${name} exceeds its UTF-8 byte limit`);
  }
  return parsed;
}

export function assertLowercaseUuidV4(value: unknown, name = 'id'): LowercaseUuidV4 {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw new SceneGlassContractError('SCG_ID_INVALID', `${name} must be a lowercase UUID v4`);
  }
  return value as LowercaseUuidV4;
}

export function isLowercaseUuidV4(value: unknown): value is LowercaseUuidV4 {
  try {
    assertLowercaseUuidV4(value);
    return true;
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      return false;
    }
    throw error;
  }
}

export function utf8ByteLength(value: string): number {
  let length = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x7f) {
      length += 1;
    } else if (codeUnit <= 0x7ff) {
      length += 2;
    } else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new SceneGlassContractError(
          'SCG_SCALAR_INVALID',
          'value contains an unpaired surrogate',
        );
      }
      length += 4;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new SceneGlassContractError(
        'SCG_SCALAR_INVALID',
        'value contains an unpaired surrogate',
      );
    } else {
      length += 3;
    }
  }
  return length;
}

export function unicodeCodePointLength(value: string): number {
  assertWellFormedUnicode(value, 'value');
  let length = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      index += 1;
    }
    length += 1;
  }
  return length;
}

function parseLowerLimitOverrides<Key extends LimitName>(
  value: unknown,
  allowedKeys: readonly Key[],
): Partial<Pick<LimitValues, Key>> {
  if (!isRecord(value)) {
    throw configLimitError('limit overrides must be an object');
  }

  const allowed = new Set<string>(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      if (isReplayRecordCountOverrideKey(key)) {
        throw configLimitError('replay record count is not configurable');
      }
      throw configLimitError('limit override contains an unknown field');
    }
  }

  const parsed: Partial<Pick<LimitValues, Key>> = {};
  for (const key of allowedKeys) {
    if (hasOwn(value, key)) {
      const override = value[key];
      const maximum = BUILT_IN_LIMITS[key];
      if (
        typeof override !== 'number' ||
        !Number.isSafeInteger(override) ||
        override <= 0 ||
        override > maximum
      ) {
        throw configLimitError(
          'limit override must be a positive safe integer at most its built-in maximum',
        );
      }
      parsed[key] = override;
    }
  }
  return Object.freeze(parsed);
}

function assertWellFormedUnicode(value: string, name: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new SceneGlassContractError(
          'SCG_SCALAR_INVALID',
          `${name} contains an unpaired surrogate`,
        );
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new SceneGlassContractError(
        'SCG_SCALAR_INVALID',
        `${name} contains an unpaired surrogate`,
      );
    }
  }
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function configLimitError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_CONFIG_LIMIT_INVALID', message);
}
