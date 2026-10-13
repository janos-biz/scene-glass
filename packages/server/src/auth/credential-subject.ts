import { isProjectId } from '@scene-glass/contracts';

export const SCENE_GLASS_AUDIENCE = 'scene-glass' as const;
export const DIAGNOSTICS_AUDIENCE = 'diagnostics' as const;

export type CredentialAudience = typeof SCENE_GLASS_AUDIENCE | typeof DIAGNOSTICS_AUDIENCE;

/**
 * A non-secret identifier for the credential that authenticated a request.
 * It deliberately never includes bearer material or a token digest.
 */
export interface CredentialSubject {
  readonly audience: CredentialAudience;
  readonly projectId: string;
  readonly id: string;
}

export interface CredentialSubjectInput {
  readonly audience: CredentialAudience;
  readonly projectId: string;
  /**
   * A stable, non-secret issuer identifier. Normal project credentials use a
   * deterministic default; short-lived diagnostic credentials should use the
   * issuer's non-secret run identifier.
   */
  readonly id?: string;
}

const SUBJECT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;

export function isCredentialAudience(value: unknown): value is CredentialAudience {
  return value === SCENE_GLASS_AUDIENCE || value === DIAGNOSTICS_AUDIENCE;
}

export function createCredentialSubject(input: CredentialSubjectInput): CredentialSubject {
  if (!isCredentialAudience(input.audience)) {
    throw new TypeError('credential audience is invalid');
  }
  if (!isProjectId(input.projectId)) {
    throw new TypeError('credential projectId is invalid');
  }

  const id = input.id ?? `${input.audience}:${input.projectId}`;
  if (!SUBJECT_ID_PATTERN.test(id)) {
    throw new TypeError('credential subject id is invalid');
  }

  return Object.freeze({
    audience: input.audience,
    projectId: input.projectId,
    id,
  });
}

export function isCredentialSubject(value: unknown): value is CredentialSubject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const candidate = value as Partial<CredentialSubject>;
  return (
    isCredentialAudience(candidate.audience) &&
    isProjectId(candidate.projectId) &&
    typeof candidate.id === 'string' &&
    SUBJECT_ID_PATTERN.test(candidate.id)
  );
}

export function sameCredentialSubject(left: CredentialSubject, right: CredentialSubject): boolean {
  return (
    left.audience === right.audience && left.projectId === right.projectId && left.id === right.id
  );
}
