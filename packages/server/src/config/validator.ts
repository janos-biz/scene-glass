import { realpath, stat } from 'node:fs/promises';
import { env as processEnvironment } from 'node:process';

import {
  parseServerConfigV1,
  type ProjectFramework,
  type ServerConfigV1,
} from '@scene-glass/contracts';

import { SCENE_GLASS_AUDIENCE, createCredentialSubject } from '../auth/credential-subject.js';
import {
  createLocalTokenCredential,
  type LocalTokenCredential,
} from '../auth/local-token-verifier.js';
import { redactConfigurationError } from './loader.js';

export type EnvironmentSnapshot = Readonly<Record<string, string | undefined>>;

/** A raw-token-free project candidate suitable for building a registry. */
export interface ValidatedProjectConfig {
  readonly projectId: string;
  readonly canonicalRoot: string;
  readonly allowedOrigins: readonly string[];
  readonly normalCredential: LocalTokenCredential;
  readonly framework?: ProjectFramework;
}

/**
 * The validated startup input. It contains canonical roots and token verifier
 * state only; config paths, token environment names, and raw environment
 * values are deliberately discarded.
 */
export interface ValidatedServerConfig {
  readonly schemaVersion: 1;
  readonly projects: readonly ValidatedProjectConfig[];
}

/**
 * Resolves every configured environment name once and validates every root
 * before returning a raw-token-free, immutable startup candidate.
 */
export async function validateServerConfig(
  config: ServerConfigV1,
  environment: EnvironmentSnapshot = processEnvironment,
): Promise<ValidatedServerConfig> {
  try {
    const parsed = parseServerConfigV1(config);
    const projects = await Promise.all(
      parsed.projects.map((project) => validateProject(project, environment)),
    );
    assertUniqueProjectIds(projects);

    assertUniqueCanonicalRoots(projects);
    assertUniqueTokenDigests(projects);
    assertUniqueOrigins(projects);

    return Object.freeze({
      schemaVersion: 1,
      projects: Object.freeze(projects),
    });
  } catch (error: unknown) {
    throw redactConfigurationError(error);
  }
}

async function validateProject(
  project: ServerConfigV1['projects'][number],
  environment: EnvironmentSnapshot,
): Promise<ValidatedProjectConfig> {
  const normalCredential = createLocalTokenCredential({
    mode: 'restart-bound',
    token: requiredToken(environment[project.tokenEnv]),
    subject: createCredentialSubject({
      audience: SCENE_GLASS_AUDIENCE,
      projectId: project.projectId,
    }),
  });
  const canonicalRoot = await canonicalDirectory(project.root);

  return Object.freeze({
    projectId: project.projectId,
    canonicalRoot,
    allowedOrigins: Object.freeze([...project.allowedOrigins]),
    normalCredential,
    ...(project.framework === undefined ? {} : { framework: project.framework }),
  });
}

async function canonicalDirectory(root: string): Promise<string> {
  let canonicalRoot: string;
  try {
    canonicalRoot = await realpath(root);
  } catch {
    throw new TypeError('configured root is unavailable');
  }

  try {
    if (!(await stat(canonicalRoot)).isDirectory()) {
      throw new TypeError('configured root is not a directory');
    }
  } catch (error: unknown) {
    if (error instanceof TypeError) {
      throw error;
    }
    throw new TypeError('configured root is not a directory');
  }

  return canonicalRoot;
}

function requiredToken(value: unknown): string {
  if (typeof value !== 'string') {
    throw new TypeError('configured token is unavailable');
  }
  return value;
}

function assertUniqueProjectIds(projects: readonly ValidatedProjectConfig[]): void {
  const projectIds = new Set<string>();
  for (const project of projects) {
    if (projectIds.has(project.projectId)) {
      throw new TypeError('configured project IDs must be unique');
    }
    projectIds.add(project.projectId);
  }
}
function assertUniqueCanonicalRoots(projects: readonly ValidatedProjectConfig[]): void {
  const roots = new Set<string>();
  for (const project of projects) {
    if (roots.has(project.canonicalRoot)) {
      throw new TypeError('configured roots must be unique');
    }
    roots.add(project.canonicalRoot);
  }
}

function assertUniqueTokenDigests(projects: readonly ValidatedProjectConfig[]): void {
  for (let index = 0; index < projects.length; index += 1) {
    const project = projects[index];
    if (project === undefined) {
      continue;
    }
    for (let otherIndex = 0; otherIndex < index; otherIndex += 1) {
      const other = projects[otherIndex];
      if (
        other !== undefined &&
        project.normalCredential.tokenDigest.equals(other.normalCredential.tokenDigest)
      ) {
        throw new TypeError('configured token digests must be unique');
      }
    }
  }
}

function assertUniqueOrigins(projects: readonly ValidatedProjectConfig[]): void {
  const origins = new Set<string>();
  for (const project of projects) {
    for (const origin of project.allowedOrigins) {
      if (origins.has(origin)) {
        throw new TypeError('configured origins must be unique');
      }
      origins.add(origin);
    }
  }
}
