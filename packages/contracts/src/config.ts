import {
  GLOBAL_LIMIT_OVERRIDE_KEYS,
  PROJECT_LIMIT_OVERRIDE_KEYS,
  type LowerLimitOverrides,
  type ProjectLowerLimitOverrides,
  SceneGlassContractError,
  isRecord,
  parseGlobalLowerLimitOverrides,
  isReplayRecordCountOverrideKey,
  parseProjectLowerLimitOverrides,
} from './limits.js';

export type ProjectFramework = 'html' | 'vue3' | 'react';

export interface ProjectConfigV1 {
  readonly projectId: string;
  readonly root: string;
  readonly allowedOrigins: readonly string[];
  readonly tokenEnv: string;
  readonly limits?: ProjectLowerLimitOverrides;
  /** Schema-v1 compatibility normalizes omitted framework values to `html`. */
  readonly framework: ProjectFramework;
}

export interface ServerConfigV1 {
  readonly schemaVersion: 1;
  readonly globalLimits?: LowerLimitOverrides;
  readonly projects: readonly ProjectConfigV1[];
}

const SERVER_CONFIG_KEYS = new Set(['schemaVersion', 'globalLimits', 'projects']);
const PROJECT_CONFIG_KEYS = new Set([
  'projectId',
  'root',
  'allowedOrigins',
  'tokenEnv',
  'limits',
  'framework',
]);

type ConfigValidationProvenance = {
  readonly errors: WeakSet<SceneGlassContractError>;
};

export function parseServerConfigV1(value: unknown): ServerConfigV1 {
  return parseServerConfigV1Internal(value);
}

function parseServerConfigV1Internal(
  value: unknown,
  provenance?: ConfigValidationProvenance,
  requireExplicitFramework = false,
): ServerConfigV1 {
  const record = configRecord(value, 'server config', provenance);
  rejectUnknownKeys(record, SERVER_CONFIG_KEYS, 'server config', provenance);

  if (!hasOwn(record, 'schemaVersion') || record.schemaVersion !== 1) {
    throw configError('schemaVersion must be 1', provenance);
  }

  const projectValues = hasOwn(record, 'projects') ? record.projects : undefined;
  if (!Array.isArray(projectValues)) {
    throw configError('projects must be an array', provenance);
  }

  const globalLimits = hasOwn(record, 'globalLimits')
    ? parseGlobalLimits(record.globalLimits, provenance)
    : undefined;
  const projects: ProjectConfigV1[] = [];
  for (let index = 0; index < projectValues.length; index += 1) {
    if (!hasOwn(projectValues, index)) {
      throw configError('projects must not be sparse', provenance);
    }
    projects.push(
      parseProjectConfigV1Internal(projectValues[index], provenance, requireExplicitFramework),
    );
  }
  assertUniqueProjectIds(projects, provenance);
  assertUniqueOrigins(projects, provenance);

  return Object.freeze({
    schemaVersion: 1,
    ...(globalLimits === undefined ? {} : { globalLimits }),
    projects: Object.freeze(projects),
  });
}

export function isServerConfigV1(value: unknown): value is ServerConfigV1 {
  const provenance: ConfigValidationProvenance = { errors: new WeakSet() };
  try {
    parseServerConfigV1Internal(value, provenance, true);
    return true;
  } catch (error: unknown) {
    if (isConfigValidationError(error, provenance)) {
      return false;
    }
    throw error;
  }
}

export function parseProjectConfigV1(value: unknown): ProjectConfigV1 {
  return parseProjectConfigV1Internal(value);
}

function parseProjectConfigV1Internal(
  value: unknown,
  provenance?: ConfigValidationProvenance,
  requireExplicitFramework = false,
): ProjectConfigV1 {
  const record = configRecord(value, 'project config', provenance);
  rejectUnknownKeys(record, PROJECT_CONFIG_KEYS, 'project config', provenance);

  const projectId = parseProjectIdInternal(
    hasOwn(record, 'projectId') ? record.projectId : undefined,
    provenance,
  );
  const root = parseRoot(hasOwn(record, 'root') ? record.root : undefined, provenance);
  const allowedOrigins = parseAllowedOrigins(
    hasOwn(record, 'allowedOrigins') ? record.allowedOrigins : undefined,
    provenance,
  );
  const tokenEnv = parseTokenEnvironmentNameInternal(
    hasOwn(record, 'tokenEnv') ? record.tokenEnv : undefined,
    provenance,
  );
  const limits = hasOwn(record, 'limits')
    ? parseProjectLimits(record.limits, provenance)
    : undefined;
  let framework: ProjectFramework;
  if (hasOwn(record, 'framework')) {
    framework = parseFramework(record.framework, provenance);
  } else {
    if (requireExplicitFramework) {
      throw configError('framework must be explicitly set to html, vue3, or react', provenance);
    }
    framework = 'html';
  }

  return Object.freeze({
    projectId,
    root,
    allowedOrigins: Object.freeze(allowedOrigins),
    tokenEnv,
    ...(limits === undefined ? {} : { limits }),
    framework,
  });
}

function parseGlobalLimits(
  value: unknown,
  provenance?: ConfigValidationProvenance,
): LowerLimitOverrides {
  const snapshot = snapshotLimitOverrides(value, GLOBAL_LIMIT_OVERRIDE_KEYS, provenance);
  try {
    return parseGlobalLowerLimitOverrides(snapshot);
  } catch (error: unknown) {
    rethrowCurrentLimitValidationError(error, provenance);
  }
}

function parseProjectLimits(
  value: unknown,
  provenance?: ConfigValidationProvenance,
): ProjectLowerLimitOverrides {
  const snapshot = snapshotLimitOverrides(value, PROJECT_LIMIT_OVERRIDE_KEYS, provenance);
  try {
    return parseProjectLowerLimitOverrides(snapshot);
  } catch (error: unknown) {
    rethrowCurrentLimitValidationError(error, provenance);
  }
}

function snapshotLimitOverrides(
  value: unknown,
  allowedKeys: readonly string[],
  provenance?: ConfigValidationProvenance,
): unknown {
  if (!isRecord(value)) {
    return value;
  }

  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowedKeys.includes(key)) {
      if (typeof key === 'string' && isReplayRecordCountOverrideKey(key)) {
        throw configLimitError('replay record count is not configurable', provenance);
      }
      throw configLimitError('limit override contains an unknown field', provenance);
    }
  }

  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    if (hasOwn(value, key)) {
      snapshot[key] = value[key];
    }
  }
  return snapshot;
}

function rethrowCurrentLimitValidationError(
  error: unknown,
  provenance?: ConfigValidationProvenance,
): never {
  if (error instanceof SceneGlassContractError) {
    provenance?.errors.add(error);
  }
  throw error;
}

export function isExactHttpOrigin(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    const origin = new URL(value);
    return (
      (origin.protocol === 'http:' || origin.protocol === 'https:') &&
      origin.username.length === 0 &&
      origin.password.length === 0 &&
      origin.pathname === '/' &&
      origin.search.length === 0 &&
      origin.hash.length === 0 &&
      origin.origin === value
    );
  } catch {
    return false;
  }
}

export function parseExactHttpOrigin(value: unknown): string {
  return parseExactHttpOriginInternal(value);
}

function parseExactHttpOriginInternal(
  value: unknown,
  provenance?: ConfigValidationProvenance,
): string {
  if (!isExactHttpOrigin(value)) {
    throw configError(
      'allowed origin must be an exact serialized http or https origin',
      provenance,
    );
  }
  return value;
}

export function isProjectId(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,127}$/.test(value);
}

export function parseProjectId(value: unknown): string {
  return parseProjectIdInternal(value);
}

function parseProjectIdInternal(value: unknown, provenance?: ConfigValidationProvenance): string {
  if (!isProjectId(value)) {
    throw configError(
      'projectId must contain 1 through 128 lowercase ASCII letters, digits, underscores, or hyphens',
      provenance,
    );
  }
  return value;
}

export function isTokenEnvironmentName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

export function parseTokenEnvironmentName(value: unknown): string {
  return parseTokenEnvironmentNameInternal(value);
}

function parseTokenEnvironmentNameInternal(
  value: unknown,
  provenance?: ConfigValidationProvenance,
): string {
  if (!isTokenEnvironmentName(value)) {
    throw configError('tokenEnv must be an environment variable name', provenance);
  }
  return value;
}

function parseRoot(value: unknown, provenance?: ConfigValidationProvenance): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw configError('root must be a non-blank string', provenance);
  }
  if (value.includes('\u0000') || hasUnpairedSurrogate(value)) {
    throw configError('root must be a well-formed path string', provenance);
  }
  return value;
}

function parseAllowedOrigins(value: unknown, provenance?: ConfigValidationProvenance): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw configError('allowedOrigins must be a non-empty array', provenance);
  }

  const origins: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!hasOwn(value, index)) {
      throw configError('allowedOrigins must not be sparse', provenance);
    }
    origins.push(parseExactHttpOriginInternal(value[index], provenance));
  }
  if (new Set(origins).size !== origins.length) {
    throw configError('allowedOrigins must not contain duplicates', provenance);
  }
  return origins;
}

function parseFramework(value: unknown, provenance?: ConfigValidationProvenance): ProjectFramework {
  if (value !== 'html' && value !== 'vue3' && value !== 'react') {
    throw configError('framework must be html, vue3, or react', provenance);
  }
  return value;
}

function assertUniqueProjectIds(
  projects: readonly ProjectConfigV1[],
  provenance?: ConfigValidationProvenance,
): void {
  const projectIds = new Set<string>();
  for (const project of projects) {
    if (projectIds.has(project.projectId)) {
      throw configError('projectIds must be unique', provenance);
    }
    projectIds.add(project.projectId);
  }
}

function assertUniqueOrigins(
  projects: readonly ProjectConfigV1[],
  provenance?: ConfigValidationProvenance,
): void {
  const origins = new Set<string>();
  for (const project of projects) {
    for (const origin of project.allowedOrigins) {
      if (origins.has(origin)) {
        throw configError('allowed origins must be unique across projects', provenance);
      }
      origins.add(origin);
    }
  }
}

function configRecord(
  value: unknown,
  name: string,
  provenance?: ConfigValidationProvenance,
): Record<string, unknown> {
  if (!isOrdinaryConfigRecord(value)) {
    throw configError(`${name} must be an object`, provenance);
  }
  return value;
}

function isOrdinaryConfigRecord(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>,
  name: string,
  provenance?: ConfigValidationProvenance,
): void {
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== 'string' || !allowedKeys.has(key)) {
      if (typeof key === 'string' && isReplayRecordCountOverrideKey(key)) {
        throw configLimitError('replay record count is not configurable', provenance);
      }
      throw configError(`${name} contains an unknown field`, provenance);
    }
  }
}

function hasOwn(record: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function isConfigValidationError(
  error: unknown,
  provenance: ConfigValidationProvenance,
): error is SceneGlassContractError {
  return error instanceof SceneGlassContractError && provenance.errors.has(error);
}

function configError(
  message: string,
  provenance?: ConfigValidationProvenance,
): SceneGlassContractError {
  return configValidationError('SCG_CONFIG_INVALID', message, provenance);
}

function configLimitError(
  message: string,
  provenance?: ConfigValidationProvenance,
): SceneGlassContractError {
  return configValidationError('SCG_CONFIG_LIMIT_INVALID', message, provenance);
}

function configValidationError(
  code: 'SCG_CONFIG_INVALID' | 'SCG_CONFIG_LIMIT_INVALID',
  message: string,
  provenance?: ConfigValidationProvenance,
): SceneGlassContractError {
  const error = new SceneGlassContractError(code, message);
  provenance?.errors.add(error);
  return error;
}
