import {
  parseProjectConfigV1,
  parseServerConfigV1,
  type ProjectConfigV1,
  type ServerConfigV1,
} from '@scene-glass/contracts';

export const DEFAULT_CONFIG_MODE = 0o600;
export const MAX_CONFIG_BYTES = 1024 * 1024;

const SERVER_TOKEN_ENV_PREFIX = 'SCENE_GLASS_SERVER_TOKEN_';
const BASE32_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface SetupProjectSeed {
  readonly projectId: string;
  readonly root: string;
  readonly framework: ProjectConfigV1['framework'];
  readonly allowedOrigins: ProjectConfigV1['allowedOrigins'];
}

/** Canonical, injective server-only binding for newly inserted projects. */
export function canonicalServerTokenEnvForProjectId(projectId: string): string {
  const parsed = parseProjectConfigV1({
    projectId,
    root: '/',
    framework: 'html',
    allowedOrigins: ['http://127.0.0.1:1'],
    tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
  });
  const bytes = new TextEncoder().encode(parsed.projectId);
  let output = '';
  let accumulator = 0;
  let bits = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_UPPER[(accumulator >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_UPPER[(accumulator << (5 - bits)) & 31]!;
  const result = `${SERVER_TOKEN_ENV_PREFIX}${output}`;
  if (result.length > 255)
    throw new LifecycleConfigError('generated server token binding is too long');
  return result;
}

/**
 * Selects the server token binding only after the current config is known.
 * Existing records retain their exact binding; absent records use the canonical
 * generated binding and cannot collide with a peer record.
 */
export function projectConfigForSetup(
  seed: SetupProjectSeed,
  current: ServerConfigV1,
): ProjectConfigV1 {
  const candidate = parseProjectConfigV1({
    projectId: seed.projectId,
    root: seed.root,
    framework: seed.framework,
    allowedOrigins: seed.allowedOrigins,
    tokenEnv: 'SCENE_GLASS_HOST_TOKEN',
  });
  const config = parseServerConfigV1(current);
  const existing = config.projects.find((project) => project.projectId === candidate.projectId);
  const tokenEnv = existing?.tokenEnv ?? canonicalServerTokenEnvForProjectId(candidate.projectId);
  if (
    config.projects.some(
      (project) => project.projectId !== candidate.projectId && project.tokenEnv === tokenEnv,
    )
  ) {
    throw new LifecycleConfigError('server token binding collides with another project');
  }
  return parseProjectConfigV1({ ...candidate, tokenEnv });
}
export type ConfigHomeOperation = 'config-create' | 'legacy-move' | 'new-use';
export type ProjectOperation = 'project-noop' | 'project-insert' | 'project-update';

/** Facts are supplied by a host; this module never reads a path itself. */
export interface ConfigFileFact {
  readonly bytes: Uint8Array;
  readonly mode: number;
}

export interface ConfigHomeFacts {
  readonly legacyPath: string;
  readonly newPath: string;
  readonly legacy: ConfigFileFact | undefined;
  readonly new: ConfigFileFact | undefined;
}

export interface ConfigHomeInspection {
  readonly operation: ConfigHomeOperation;
  readonly legacyPath: string;
  readonly newPath: string;
  readonly selectedPath: string | undefined;
  readonly selectedMode: number | undefined;
  readonly config: ServerConfigV1 | undefined;
  /** Present only for a legacy-only home and copied without reinterpretation. */
  readonly legacyMove: ConfigFileFact | undefined;
}

export interface AppliedProjectOperation {
  readonly operation: ProjectOperation;
  readonly config: ServerConfigV1;
}

export interface ConfigWriteIntent {
  readonly kind: 'write-config' | 'move-config';
  readonly path: string;
  readonly sourcePath: string | undefined;
  readonly mode: number;
  readonly bytes: Uint8Array;
  /** True only when a legacy-only, no-project-change move preserves raw bytes. */
  readonly preservesSourceBytes: boolean;
}

export interface ConfigOperationPlan {
  readonly configOperation: ConfigHomeOperation;
  readonly projectOperation: ProjectOperation;
  readonly config: ServerConfigV1;
  readonly writes: readonly ConfigWriteIntent[];
  /** Both-present homes deliberately leave this false. */
  readonly mutatesLegacy: boolean;
}
export interface StrictLegacyBootstrapInput {
  readonly homes: ConfigHomeFacts;
  readonly selectedProject: unknown;
  readonly registryPresent: boolean;
}

export interface ConfigOperationInput {
  readonly homes: ConfigHomeFacts;
  readonly project: unknown;
}

export class LifecycleConfigError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LifecycleConfigError';
  }
}

/**
 * Selects a schema-v1 config entirely from caller-provided facts. A current
 * config wins over a legacy config, even when the ignored legacy bytes are bad.
 */
export function inspectConfigHomes(input: ConfigHomeFacts): ConfigHomeInspection {
  const homes = snapshotConfigHomes(input);
  if (homes.new !== undefined) {
    const selected = homes.new;
    return Object.freeze({
      operation: 'new-use',
      legacyPath: homes.legacyPath,
      newPath: homes.newPath,
      selectedPath: homes.newPath,
      selectedMode: selected.mode,
      config: parseConfigBytes(selected.bytes),
      legacyMove: undefined,
    });
  }

  if (homes.legacy !== undefined) {
    const selected = homes.legacy;
    return Object.freeze({
      operation: 'legacy-move',
      legacyPath: homes.legacyPath,
      newPath: homes.newPath,
      selectedPath: homes.legacyPath,
      selectedMode: selected.mode,
      config: parseConfigBytes(selected.bytes),
      legacyMove: selected,
    });
  }

  return Object.freeze({
    operation: 'config-create',
    legacyPath: homes.legacyPath,
    newPath: homes.newPath,
    selectedPath: undefined,
    selectedMode: undefined,
    config: undefined,
    legacyMove: undefined,
  });
}
/**
 * The only missing-registry migration path is an approved setup from one
 * legacy project. Callers must still defer the returned move intent until
 * approval; this predicate performs no I/O or mutation.
 */
export function isStrictLegacyBootstrap(input: StrictLegacyBootstrapInput): boolean {
  const homes = snapshotConfigHomes(input.homes);
  if (homes.new !== undefined || homes.legacy === undefined || input.registryPresent) {
    return false;
  }
  const selected = parseProjectConfigV1(input.selectedProject);
  const legacy = parseConfigBytes(homes.legacy.bytes);
  return legacy.projects.length === 1 && sameProject(legacy.projects[0]!, selected);
}

/** Returns a canonical, newline-terminated schema-v1 config document. */
export function serializeConfigV1(value: unknown): string {
  return `${JSON.stringify(parseServerConfigV1(value), null, 2)}\n`;
}

/** Applies one project desired-state to a parsed config without mutating it. */
export function applyProjectOperation(
  config: ServerConfigV1,
  project: unknown,
): AppliedProjectOperation {
  const current = parseServerConfigV1(config);
  const desired = parseProjectConfigV1(project);
  const existingIndex = current.projects.findIndex(
    (candidate) => candidate.projectId === desired.projectId,
  );

  if (existingIndex === -1) {
    return Object.freeze({
      operation: 'project-insert',
      config: parseServerConfigV1({
        schemaVersion: 1,
        ...(current.globalLimits === undefined ? {} : { globalLimits: current.globalLimits }),
        projects: [...current.projects, desired],
      }),
    });
  }

  const existing = current.projects[existingIndex];
  if (existing === undefined) {
    throw new LifecycleConfigError('project index disappeared while planning');
  }
  if (sameProject(existing, desired)) {
    return Object.freeze({ operation: 'project-noop', config: current });
  }

  const projects = [...current.projects];
  projects[existingIndex] = desired;
  return Object.freeze({
    operation: 'project-update',
    config: parseServerConfigV1({
      schemaVersion: 1,
      ...(current.globalLimits === undefined ? {} : { globalLimits: current.globalLimits }),
      projects,
    }),
  });
}

/**
 * Crosses the home decision with the project decision. No file action occurs
 * here: returned bytes are a deterministic write intent for a later host.
 */
export function planConfigOperation(input: ConfigOperationInput): ConfigOperationPlan {
  const inspection = inspectConfigHomes(input.homes);
  const base =
    inspection.config ??
    parseServerConfigV1({
      schemaVersion: 1,
      projects: [],
    });
  const project = applyProjectOperation(base, input.project);
  const canonicalBytes = encodeUtf8(serializeConfigV1(project.config));

  if (inspection.operation === 'config-create') {
    return freezePlan({
      configOperation: inspection.operation,
      projectOperation: project.operation,
      config: project.config,
      writes: [
        {
          kind: 'write-config',
          path: inspection.newPath,
          sourcePath: undefined,
          mode: DEFAULT_CONFIG_MODE,
          bytes: canonicalBytes,
          preservesSourceBytes: false,
        },
      ],
      mutatesLegacy: false,
    });
  }

  if (inspection.operation === 'legacy-move') {
    const legacy = inspection.legacyMove;
    if (legacy === undefined) {
      throw new LifecycleConfigError('legacy move is missing source facts');
    }
    const preservesSourceBytes = project.operation === 'project-noop';
    return freezePlan({
      configOperation: inspection.operation,
      projectOperation: project.operation,
      config: project.config,
      writes: [
        {
          kind: 'move-config',
          path: inspection.newPath,
          sourcePath: inspection.legacyPath,
          mode: legacy.mode,
          bytes: preservesSourceBytes ? copyBytes(legacy.bytes) : canonicalBytes,
          preservesSourceBytes,
        },
      ],
      mutatesLegacy: true,
    });
  }

  if (project.operation === 'project-noop') {
    return freezePlan({
      configOperation: inspection.operation,
      projectOperation: project.operation,
      config: project.config,
      writes: [],
      mutatesLegacy: false,
    });
  }

  const mode = inspection.selectedMode;
  if (mode === undefined) {
    throw new LifecycleConfigError('current config is missing mode facts');
  }
  return freezePlan({
    configOperation: inspection.operation,
    projectOperation: project.operation,
    config: project.config,
    writes: [
      {
        kind: 'write-config',
        path: inspection.newPath,
        sourcePath: undefined,
        mode,
        bytes: canonicalBytes,
        preservesSourceBytes: false,
      },
    ],
    mutatesLegacy: false,
  });
}

function snapshotConfigHomes(input: ConfigHomeFacts): ConfigHomeFacts {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new LifecycleConfigError('config home facts must be an object');
  }
  const legacyPath = parsePath(input.legacyPath, 'legacyPath');
  const newPath = parsePath(input.newPath, 'newPath');
  if (legacyPath === newPath) {
    throw new LifecycleConfigError('legacyPath and newPath must differ');
  }
  return Object.freeze({
    legacyPath,
    newPath,
    legacy: input.legacy === undefined ? undefined : snapshotFileFact(input.legacy, 'legacy'),
    new: input.new === undefined ? undefined : snapshotFileFact(input.new, 'new'),
  });
}

function snapshotFileFact(value: ConfigFileFact, name: string): ConfigFileFact {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LifecycleConfigError(`${name} config fact must be an object`);
  }
  if (!(value.bytes instanceof Uint8Array)) {
    throw new LifecycleConfigError(`${name} config bytes must be Uint8Array`);
  }
  if (value.bytes.byteLength > MAX_CONFIG_BYTES) {
    throw new LifecycleConfigError(`${name} config exceeds its byte limit`);
  }
  if (!Number.isSafeInteger(value.mode) || value.mode < 0 || value.mode > 0o7777) {
    throw new LifecycleConfigError(`${name} config mode must be a permission mode`);
  }
  return Object.freeze({ bytes: copyBytes(value.bytes), mode: value.mode });
}

function parseConfigBytes(bytes: Uint8Array): ServerConfigV1 {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new LifecycleConfigError('config bytes must be valid UTF-8');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new LifecycleConfigError('config bytes must be valid JSON');
  }
  return parseServerConfigV1(parsed);
}

function sameProject(left: ProjectConfigV1, right: ProjectConfigV1): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function parsePath(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 4096 ||
    value.includes('\u0000')
  ) {
    throw new LifecycleConfigError(`${name} must be a bounded path string`);
  }
  return value;
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

function freezePlan(plan: {
  readonly configOperation: ConfigHomeOperation;
  readonly projectOperation: ProjectOperation;
  readonly config: ServerConfigV1;
  readonly writes: readonly ConfigWriteIntent[];
  readonly mutatesLegacy: boolean;
}): ConfigOperationPlan {
  return Object.freeze({
    ...plan,
    writes: Object.freeze(
      plan.writes.map((write) =>
        Object.freeze({
          ...write,
          bytes: copyBytes(write.bytes),
        }),
      ),
    ),
  });
}
