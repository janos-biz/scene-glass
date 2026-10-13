import { isExactHttpOrigin, isProjectId } from '@scene-glass/contracts';

import { AuthContext } from '../auth/auth-context.js';
import { SCENE_GLASS_AUDIENCE } from '../auth/credential-subject.js';
import type { TokenDigest } from '../auth/local-token-verifier.js';
import type { EffectiveLimitsSnapshot } from '../config/effective-limits.js';
import type { ValidatedServerConfig } from '../config/validator.js';
import type {
  AuthorizedProject,
  OriginPolicy,
  ProjectRegistry,
  RequestAdmissionProject,
} from './config-project-registry.js';

interface RegistryEntry {
  readonly canonicalRoot: string;
  readonly tokenDigest: TokenDigest;
  readonly originPolicy: OriginPolicy;
  readonly requestAdmission: RequestAdmissionProject;
}

const rootsByAuthorizedProject = new WeakMap<AuthorizedProjectHandle, string>();

class ExactOriginPolicy implements OriginPolicy {
  readonly #origins: ReadonlySet<string>;

  public readonly projectId: string;

  public constructor(projectId: string, origins: readonly string[]) {
    this.projectId = projectId;
    this.#origins = new Set(origins);
    Object.freeze(this);
  }

  public allowsOrigin(origin: string): boolean {
    return isExactHttpOrigin(origin) && this.#origins.has(origin);
  }
}

class AuthorizedProjectHandle implements AuthorizedProject {
  public readonly projectId: string;
  public readonly effectiveLimits: AuthorizedProject['effectiveLimits'];

  public constructor(entry: RegistryEntry) {
    this.projectId = entry.requestAdmission.projectId;
    this.effectiveLimits = entry.requestAdmission.effectiveLimits;
    rootsByAuthorizedProject.set(this, entry.canonicalRoot);
    Object.freeze(this);
  }
}

/**
 * In-memory implementation of the static registry. Maps and canonical roots
 * stay private, so preflight policy lookup cannot resolve or expose a root.
 */
export class MemoryProjectRegistry implements ProjectRegistry {
  readonly #entriesByProjectId: ReadonlyMap<string, RegistryEntry>;

  public constructor(config: ValidatedServerConfig, effectiveLimits: EffectiveLimitsSnapshot) {
    const entries = buildEntries(config, effectiveLimits);
    this.#entriesByProjectId = new Map(
      entries.map((entry) => [entry.requestAdmission.projectId, entry]),
    );
    Object.freeze(this);
  }

  public getOriginPolicy(projectId: string): OriginPolicy | undefined {
    if (!isProjectId(projectId)) {
      return undefined;
    }
    return this.#entriesByProjectId.get(projectId)?.originPolicy;
  }
  public getRequestAdmissionProject(projectId: string): RequestAdmissionProject | undefined {
    if (!isProjectId(projectId)) {
      return undefined;
    }
    return this.#entriesByProjectId.get(projectId)?.requestAdmission;
  }

  /**
   * Root construction is deliberately last: exact Origin, active credential,
   * and project binding all complete against private verifier state first.
   */
  public resolveAuthorizedProject(auth: AuthContext): AuthorizedProject | undefined {
    if (!(auth instanceof AuthContext)) {
      return undefined;
    }

    const originPolicy = this.getOriginPolicy(auth.projectId);
    if (originPolicy === undefined || !originPolicy.allowsOrigin(auth.origin)) {
      return undefined;
    }

    const entry = this.#entriesByProjectId.get(auth.projectId);
    if (
      entry === undefined ||
      !auth.isActiveAt(Date.now()) ||
      !entry.tokenDigest.equals(auth.credentialDigest)
    ) {
      return undefined;
    }
    if (
      auth.audience !== SCENE_GLASS_AUDIENCE ||
      auth.subject.audience !== SCENE_GLASS_AUDIENCE ||
      auth.subject.projectId !== entry.requestAdmission.projectId
    ) {
      return undefined;
    }

    return new AuthorizedProjectHandle(entry);
  }
}

/**
 * The sole root accessor accepts only a handle produced after full request
 * authorization. It rejects structural lookalikes and has no preflight use.
 */
export function getAuthorizedProjectRoot(project: AuthorizedProject): string {
  if (!(project instanceof AuthorizedProjectHandle)) {
    throw new TypeError('authorized project handle is invalid');
  }
  const root = rootsByAuthorizedProject.get(project);
  if (root === undefined) {
    throw new TypeError('authorized project root is unavailable');
  }
  return root;
}

function buildEntries(
  config: ValidatedServerConfig,
  effectiveLimits: EffectiveLimitsSnapshot,
): readonly RegistryEntry[] {
  const entries: RegistryEntry[] = [];
  const projectIds = new Set<string>();
  const canonicalRoots = new Set<string>();
  const origins = new Set<string>();

  for (const project of config.projects) {
    if (!isProjectId(project.projectId) || projectIds.has(project.projectId)) {
      throw new TypeError('configured project IDs must be unique and valid');
    }
    if (
      typeof project.canonicalRoot !== 'string' ||
      project.canonicalRoot.length === 0 ||
      canonicalRoots.has(project.canonicalRoot)
    ) {
      throw new TypeError('configured roots must be unique and valid');
    }

    const projectLimits = effectiveLimits.getProject(project.projectId);
    if (projectLimits === undefined) {
      throw new TypeError('configured project limits are unavailable');
    }
    if (
      !Array.isArray(project.allowedOrigins) ||
      project.allowedOrigins.length === 0 ||
      project.allowedOrigins.some((origin) => !isExactHttpOrigin(origin) || origins.has(origin))
    ) {
      throw new TypeError('configured origins must be unique and valid');
    }
    if (entries.some((entry) => entry.tokenDigest.equals(project.normalCredential.tokenDigest))) {
      throw new TypeError('configured token digests must be unique');
    }

    const originPolicy = new ExactOriginPolicy(project.projectId, project.allowedOrigins);
    const requestAdmission = Object.freeze({
      projectId: project.projectId,
      effectiveLimits: projectLimits,
    });
    entries.push(
      Object.freeze({
        canonicalRoot: project.canonicalRoot,
        tokenDigest: project.normalCredential.tokenDigest,
        originPolicy,
        requestAdmission,
      }),
    );
    projectIds.add(project.projectId);
    canonicalRoots.add(project.canonicalRoot);
    for (const origin of project.allowedOrigins) {
      origins.add(origin);
    }
  }

  return Object.freeze(entries);
}
