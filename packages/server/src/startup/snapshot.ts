import { env as processEnvironment } from 'node:process';

import type { ProjectFramework, ServerConfigV1 } from '@scene-glass/contracts';

import {
  createEffectiveLimitsSnapshot,
  type EffectiveLimitsSnapshot,
} from '../config/effective-limits.js';
import {
  type EnvironmentSnapshot,
  type ValidatedProjectConfig,
  type ValidatedServerConfig,
  validateServerConfig,
} from '../config/validator.js';
import { loadServerConfig } from '../config/loader.js';
import { SceneGlassLogger } from '../observability/logger.js';
import {
  PLATFORM_UNSUPPORTED_CODE,
  probeProjectRoot,
  type ProjectRootProbeResult,
} from '../platform/probe.js';

export type ProjectRootProbe = (root: string) => Promise<ProjectRootProbeResult>;

export class PlatformStartupError extends Error {
  public readonly code = PLATFORM_UNSUPPORTED_CODE;

  public constructor() {
    super(PLATFORM_UNSUPPORTED_CODE);
    this.name = 'PlatformStartupError';
  }
}

export interface BuildSceneGlassStartupSnapshotOptions {
  readonly configPath: string;
  readonly environment?: EnvironmentSnapshot;
  readonly logger?: SceneGlassLogger;
}

/** @internal Test-only root-probe injection; production code must use the native builder. */
export interface BuildSceneGlassStartupSnapshotForTestOptions extends BuildSceneGlassStartupSnapshotOptions {
  readonly projectRootProbe: ProjectRootProbe;
}

interface NormalizedValidatedProjectConfig extends Omit<ValidatedProjectConfig, 'framework'> {
  readonly framework: ProjectFramework;
}

interface NormalizedValidatedServerConfig extends Omit<ValidatedServerConfig, 'projects'> {
  readonly projects: readonly NormalizedValidatedProjectConfig[];
}

export interface SceneGlassStartupSnapshot {
  readonly effectiveLimits: EffectiveLimitsSnapshot;
  readonly validated: NormalizedValidatedServerConfig;
  readonly lifecycleBinding: LifecycleSemanticConfigBinding;
}
/** Internal immutable representation used to bind lifecycle startup authority to persisted config. */
export interface LifecycleSemanticConfigBinding {
  readonly schemaVersion: 1;
  readonly globalLimits?: Readonly<Record<string, number>>;
  readonly projects: readonly Readonly<{
    readonly projectId: string;
    readonly root: string;
    readonly framework: ProjectFramework;
    readonly tokenEnv: string;
    readonly allowedOrigins: readonly string[];
    readonly limits?: Readonly<Record<string, number>>;
  }>[];
}

/** Deliberately excludes environment tokens and runtime-only validation facts. */
export function lifecycleSemanticConfigBinding(
  config: ServerConfigV1,
  validated: NormalizedValidatedServerConfig,
): LifecycleSemanticConfigBinding {
  if (config.projects.length !== validated.projects.length) {
    throw new TypeError('lifecycle semantic config binding is invalid');
  }
  const globalLimits = copyNumberRecord(config.globalLimits);
  return Object.freeze({
    schemaVersion: config.schemaVersion,
    ...(globalLimits === undefined ? {} : { globalLimits }),
    projects: Object.freeze(
      config.projects.map((project, index) => {
        const validatedProject = validated.projects[index];
        if (validatedProject === undefined || validatedProject.projectId !== project.projectId) {
          throw new TypeError('lifecycle semantic config binding is invalid');
        }
        const limits = copyNumberRecord(project.limits);
        return Object.freeze({
          projectId: project.projectId,
          root: validatedProject.canonicalRoot,
          framework: validatedProject.framework,
          tokenEnv: project.tokenEnv,
          allowedOrigins: Object.freeze([...project.allowedOrigins]),
          ...(limits === undefined ? {} : { limits }),
        });
      }),
    ),
  });
}
function copyNumberRecord(value: object | undefined): Readonly<Record<string, number>> | undefined {
  if (value === undefined) return undefined;
  const result: Record<string, number> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== 'number') {
      throw new TypeError('lifecycle semantic config binding is invalid');
    }
    result[key] = entry;
  }
  return Object.freeze(result);
}

/**
 * Performs every startup validation that must complete before the local
 * authority begins constructing request or storage state.
 */
export async function buildSceneGlassStartupSnapshot(
  options: BuildSceneGlassStartupSnapshotOptions,
): Promise<SceneGlassStartupSnapshot> {
  return buildStartupSnapshot(options, probeProjectRoot);
}

/** @internal Test-only helper for controlled root-probe conformance tests. */
export async function buildSceneGlassStartupSnapshotForTest(
  options: BuildSceneGlassStartupSnapshotForTestOptions,
): Promise<SceneGlassStartupSnapshot> {
  return buildStartupSnapshot(options, options.projectRootProbe);
}

async function buildStartupSnapshot(
  options: BuildSceneGlassStartupSnapshotOptions,
  projectRootProbe: ProjectRootProbe,
): Promise<SceneGlassStartupSnapshot> {
  let effectiveLimits: EffectiveLimitsSnapshot;
  let validated: NormalizedValidatedServerConfig;
  let config!: ServerConfigV1;

  try {
    config = await loadServerConfig(options.configPath);
    effectiveLimits = createEffectiveLimitsSnapshot(config);
    const environment = snapshotProjectEnvironment(config, options.environment);
    validated = normalizeValidatedServerConfig(await validateServerConfig(config, environment));
  } catch (error: unknown) {
    options.logger?.emit('config.rejected');
    throw error;
  }

  try {
    await assertSupportedProjectRoots(validated.projects, projectRootProbe);
  } catch (error: unknown) {
    options.logger?.emit('root.rejected');
    throw error;
  }

  return Object.freeze({
    effectiveLimits,
    validated,
    lifecycleBinding: lifecycleSemanticConfigBinding(config, validated),
  });
}
function normalizeValidatedServerConfig(
  validated: ValidatedServerConfig,
): NormalizedValidatedServerConfig {
  return Object.freeze({
    schemaVersion: validated.schemaVersion,
    projects: Object.freeze(
      validated.projects.map((project) =>
        Object.freeze({
          ...project,
          framework: project.framework ?? 'html',
        }),
      ),
    ),
  });
}

function snapshotProjectEnvironment(
  config: ServerConfigV1,
  environment: EnvironmentSnapshot | undefined,
): EnvironmentSnapshot {
  const source: unknown = environment === undefined ? processEnvironment : environment;
  if (!isEnvironmentRecord(source)) {
    throw new TypeError('startup environment must be an object');
  }

  const snapshot: Record<string, string | undefined> = Object.create(null);
  for (const project of config.projects) {
    const value = hasOwn(source, project.tokenEnv) ? source[project.tokenEnv] : undefined;
    if (typeof value !== 'string' && value !== undefined) {
      throw new TypeError('startup environment bindings must be strings or undefined');
    }
    snapshot[project.tokenEnv] = value;
  }
  return Object.freeze(snapshot);
}

async function assertSupportedProjectRoots(
  projects: readonly { readonly canonicalRoot: string }[],
  projectRootProbe: ProjectRootProbe,
): Promise<void> {
  for (const project of projects) {
    const result = await projectRootProbe(project.canonicalRoot);
    if (
      result.supported !== true ||
      result.code !== null ||
      result.facts === null ||
      result.facts.realPath !== project.canonicalRoot
    ) {
      throw new PlatformStartupError();
    }
  }
}
function isEnvironmentRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}
