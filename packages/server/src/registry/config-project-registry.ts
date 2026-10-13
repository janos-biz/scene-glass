import type { LimitValues } from '@scene-glass/contracts';

import type { AuthContext } from '../auth/auth-context.js';
import { LocalTokenVerifier } from '../auth/local-token-verifier.js';
import {
  createEffectiveLimitsSnapshot,
  type EffectiveLimitsSnapshot,
} from '../config/effective-limits.js';
import { loadServerConfig } from '../config/loader.js';
import { type EnvironmentSnapshot, validateServerConfig } from '../config/validator.js';
import { MemoryProjectRegistry } from './memory-project-registry.js';

// Config validation issues only restart-bound credentials, which have no managed revocation callback.
const noRestartBoundRevocationFailure = (): undefined => undefined;

/**
 * A root-free, exact-Origin policy used by CORS preflight and the first phase
 * of actual-request authorization.
 */
export interface OriginPolicy {
  readonly projectId: string;
  allowsOrigin(origin: string): boolean;
}

/**
 * A server-only result of origin, credential, and project authorization.
 * Its filesystem root is intentionally not a public property.
 */
export interface AuthorizedProject {
  readonly projectId: string;
  readonly effectiveLimits: Readonly<LimitValues>;
}
/**
 * Immutable request-admission limits without an authorized filesystem-root capability.
 * Callers must authenticate the request before looking up this public metadata.
 */
export interface RequestAdmissionProject {
  readonly projectId: string;
  readonly effectiveLimits: Readonly<LimitValues>;
}

export interface ProjectRegistry {
  getOriginPolicy(projectId: string): OriginPolicy | undefined;
  /**
   * Returns only immutable request-admission metadata. It never authorizes a
   * credential or grants access to a project root. Diagnostics-enabled MCP
   * route registration requires this optional capability.
   */
  getRequestAdmissionProject?(projectId: string): RequestAdmissionProject | undefined;
  resolveAuthorizedProject(auth: AuthContext): AuthorizedProject | undefined;
}

/**
 * Static startup registry built from one explicit config path and one
 * environment snapshot. It has no mutation or reload path.
 */
export class ConfigProjectRegistry implements ProjectRegistry {
  readonly #registry: MemoryProjectRegistry;

  public readonly effectiveLimits: EffectiveLimitsSnapshot;
  public readonly normalTokenVerifier: LocalTokenVerifier;

  private constructor(
    registry: MemoryProjectRegistry,
    effectiveLimits: EffectiveLimitsSnapshot,
    normalTokenVerifier: LocalTokenVerifier,
  ) {
    this.#registry = registry;
    this.effectiveLimits = effectiveLimits;
    this.normalTokenVerifier = normalTokenVerifier;
    Object.freeze(this);
  }

  public getOriginPolicy(projectId: string): OriginPolicy | undefined {
    return this.#registry.getOriginPolicy(projectId);
  }

  public resolveAuthorizedProject(auth: AuthContext): AuthorizedProject | undefined {
    return this.#registry.resolveAuthorizedProject(auth);
  }
  public getRequestAdmissionProject(projectId: string): RequestAdmissionProject | undefined {
    return this.#registry.getRequestAdmissionProject(projectId);
  }

  /**
   * All config, environment, root, identity, and effective-limit validation
   * completes before this immutable registry becomes observable.
   */
  public static async load(
    configPath: string,
    environment?: EnvironmentSnapshot,
  ): Promise<ConfigProjectRegistry> {
    const config = await loadServerConfig(configPath);
    const validated = await validateServerConfig(config, environment);
    const effectiveLimits = createEffectiveLimitsSnapshot(config);
    const registry = new MemoryProjectRegistry(validated, effectiveLimits);
    const normalTokenVerifier = new LocalTokenVerifier(
      validated.projects.map((project) => project.normalCredential),
      { onRevocationCheckFailed: noRestartBoundRevocationFailure },
    );

    return new ConfigProjectRegistry(registry, effectiveLimits, normalTokenVerifier);
  }
}

export function createConfigProjectRegistry(
  configPath: string,
  environment?: EnvironmentSnapshot,
): Promise<ConfigProjectRegistry> {
  return ConfigProjectRegistry.load(configPath, environment);
}
