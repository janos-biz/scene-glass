import {
  BUILT_IN_LIMITS,
  effectiveLimits,
  parseServerConfigV1,
  type LimitValues,
  type ServerConfigV1,
} from '@scene-glass/contracts';

/**
 * Immutable built-in, global, and per-project lower-only limit values for one
 * server lifetime. Project values are intentionally only retrievable by ID.
 */
export interface EffectiveLimitsSnapshot {
  readonly builtIn: Readonly<LimitValues>;
  readonly global: Readonly<LimitValues>;
  getProject(projectId: string): Readonly<LimitValues> | undefined;
}

class StaticEffectiveLimitsSnapshot implements EffectiveLimitsSnapshot {
  public readonly builtIn: Readonly<LimitValues>;
  public readonly global: Readonly<LimitValues>;
  readonly #projectLimits: ReadonlyMap<string, Readonly<LimitValues>>;

  public constructor(
    builtIn: Readonly<LimitValues>,
    global: Readonly<LimitValues>,
    projectLimits: ReadonlyMap<string, Readonly<LimitValues>>,
  ) {
    this.builtIn = builtIn;
    this.global = global;
    this.#projectLimits = projectLimits;
    Object.freeze(this);
  }

  public getProject(projectId: string): Readonly<LimitValues> | undefined {
    return this.#projectLimits.get(projectId);
  }
}

/**
 * Computes the complete static limit snapshot. Re-parsing through contracts
 * rejects unsupported keys, including every replay record/window count alias.
 */
export function createEffectiveLimitsSnapshot(config: ServerConfigV1): EffectiveLimitsSnapshot {
  const parsed = parseServerConfigV1(config);
  const projectLimits = new Map<string, Readonly<LimitValues>>();

  for (const project of parsed.projects) {
    projectLimits.set(project.projectId, effectiveLimits(parsed.globalLimits, project.limits));
  }

  return new StaticEffectiveLimitsSnapshot(
    Object.freeze({ ...BUILT_IN_LIMITS }),
    effectiveLimits(parsed.globalLimits),
    projectLimits,
  );
}
