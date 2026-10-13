import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { BUILT_IN_LIMITS, type LimitValues } from '@scene-glass/contracts';

import { AuthContext } from '../../packages/server/src/auth/auth-context.js';
import {
  SCENE_GLASS_AUDIENCE,
  createCredentialSubject,
} from '../../packages/server/src/auth/credential-subject.js';
import {
  LocalTokenVerifier,
  createLocalTokenCredential,
} from '../../packages/server/src/auth/local-token-verifier.js';
import type { AuthorizedProject } from '../../packages/server/src/registry/config-project-registry.js';
import {
  getAuthorizedProjectRoot,
  MemoryProjectRegistry,
} from '../../packages/server/src/registry/memory-project-registry.js';
import type { EffectiveLimitsSnapshot } from '../../packages/server/src/config/effective-limits.js';
import type {
  ValidatedProjectConfig,
  ValidatedServerConfig,
} from '../../packages/server/src/config/validator.js';

function opaqueToken(byte: number): string {
  return createHash('sha256').update(`token-${byte}`, 'utf8').digest('base64url');
}

function project(input: {
  readonly projectId: string;
  readonly canonicalRoot: string;
  readonly origin: string;
  readonly token: string;
}): ValidatedProjectConfig {
  return Object.freeze({
    projectId: input.projectId,
    canonicalRoot: input.canonicalRoot,
    allowedOrigins: Object.freeze([input.origin]),
    normalCredential: createLocalTokenCredential({
      mode: 'restart-bound',
      token: input.token,
      subject: createCredentialSubject({
        audience: SCENE_GLASS_AUDIENCE,
        projectId: input.projectId,
      }),
      origin: input.origin,
    }),
  });
}

function config(projects: readonly ValidatedProjectConfig[]): ValidatedServerConfig {
  return Object.freeze({ schemaVersion: 1, projects: Object.freeze([...projects]) });
}

function limitsFor(projects: readonly ValidatedProjectConfig[]): EffectiveLimitsSnapshot {
  const limits: Readonly<LimitValues> = Object.freeze({ ...BUILT_IN_LIMITS });
  const byProject = new Map<string, Readonly<LimitValues>>(
    projects.map((configured) => [configured.projectId, limits]),
  );
  return Object.freeze({
    builtIn: limits,
    global: limits,
    getProject(projectId: string): Readonly<LimitValues> | undefined {
      return byProject.get(projectId);
    },
  });
}

function expectRegistryConstructionFailure(
  projects: readonly ValidatedProjectConfig[],
  message: string,
): void {
  expect(() => new MemoryProjectRegistry(config(projects), limitsFor(projects))).toThrow(message);
}

describe('static project registry uniqueness', () => {
  it('rejects duplicate project IDs before creating a registry', () => {
    expect.hasAssertions();
    expectRegistryConstructionFailure(
      [
        project({
          projectId: 'alpha',
          canonicalRoot: '/canonical/alpha',
          origin: 'https://alpha.example.test',
          token: opaqueToken(1),
        }),
        project({
          projectId: 'alpha',
          canonicalRoot: '/canonical/beta',
          origin: 'https://beta.example.test',
          token: opaqueToken(2),
        }),
      ],
      'configured project IDs must be unique and valid',
    );
  });

  it('rejects duplicate token digests, canonical roots, and Origins', () => {
    expect.hasAssertions();
    const sharedToken = opaqueToken(3);
    expectRegistryConstructionFailure(
      [
        project({
          projectId: 'alpha',
          canonicalRoot: '/canonical/alpha',
          origin: 'https://alpha.example.test',
          token: sharedToken,
        }),
        project({
          projectId: 'beta',
          canonicalRoot: '/canonical/beta',
          origin: 'https://beta.example.test',
          token: sharedToken,
        }),
      ],
      'configured token digests must be unique',
    );
    expectRegistryConstructionFailure(
      [
        project({
          projectId: 'alpha',
          canonicalRoot: '/canonical/shared',
          origin: 'https://alpha.example.test',
          token: opaqueToken(4),
        }),
        project({
          projectId: 'beta',
          canonicalRoot: '/canonical/shared',
          origin: 'https://beta.example.test',
          token: opaqueToken(5),
        }),
      ],
      'configured roots must be unique and valid',
    );
    expectRegistryConstructionFailure(
      [
        project({
          projectId: 'alpha',
          canonicalRoot: '/canonical/alpha',
          origin: 'https://shared.example.test',
          token: opaqueToken(6),
        }),
        project({
          projectId: 'beta',
          canonicalRoot: '/canonical/beta',
          origin: 'https://shared.example.test',
          token: opaqueToken(7),
        }),
      ],
      'configured origins must be unique and valid',
    );
  });

  it('rejects weak and missing bearer values with the stable auth failure code', () => {
    const alpha = project({
      projectId: 'alpha',
      canonicalRoot: '/canonical/alpha',
      origin: 'https://alpha.example.test',
      token: opaqueToken(8),
    });
    expect(() =>
      createLocalTokenCredential({
        mode: 'restart-bound',
        token: 'not-enough-entropy',
        subject: alpha.normalCredential.subject,
      }),
    ).toThrow('token must be canonical base64url encoding of at least 32 bytes');

    const verifier = new LocalTokenVerifier([alpha.normalCredential], {
      onRevocationCheckFailed: () => {},
    });
    for (const authorization of [undefined, 'Bearer not-enough-entropy']) {
      expect(verifier.verify({ authorization, origin: 'https://alpha.example.test' })).toEqual({
        ok: false,
        status: 401,
        code: 'SCG_AUTH_INVALID',
      });
    }
  });

  it('keeps preflight root-free and fails origin or credential mismatches before binding', () => {
    const alpha = project({
      projectId: 'alpha',
      canonicalRoot: '/canonical/alpha',
      origin: 'https://alpha.example.test',
      token: opaqueToken(9),
    });
    const beta = project({
      projectId: 'beta',
      canonicalRoot: '/canonical/beta',
      origin: 'https://beta.example.test',
      token: opaqueToken(10),
    });
    const registry = new MemoryProjectRegistry(config([alpha, beta]), limitsFor([alpha, beta]));
    const policy = registry.getOriginPolicy('alpha');

    expect(policy?.allowsOrigin('https://alpha.example.test')).toBe(true);
    expect(policy).not.toHaveProperty('canonicalRoot');
    expect(() => getAuthorizedProjectRoot(policy as unknown as AuthorizedProject)).toThrow(
      'authorized project handle is invalid',
    );

    let revocationChecks = 0;
    const originMismatch = new AuthContext({
      origin: 'https://beta.example.test',
      subject: alpha.normalCredential.subject,
      credentialDigest: alpha.normalCredential.tokenDigest,
      expiresAt: Number.POSITIVE_INFINITY,
      isRevoked: () => {
        revocationChecks += 1;
        return false;
      },
    });
    expect(registry.resolveAuthorizedProject(originMismatch)).toBeUndefined();
    expect(revocationChecks).toBe(0);

    const forgedProjectBinding = new AuthContext({
      origin: 'https://beta.example.test',
      subject: beta.normalCredential.subject,
      credentialDigest: alpha.normalCredential.tokenDigest,
      expiresAt: Number.POSITIVE_INFINITY,
    });
    expect(registry.resolveAuthorizedProject(forgedProjectBinding)).toBeUndefined();

    const verifier = new LocalTokenVerifier([alpha.normalCredential], {
      onRevocationCheckFailed: () => {},
    });
    const verified = verifier.verify({
      authorization: `Bearer ${opaqueToken(9)}`,
      origin: 'https://alpha.example.test',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      throw new Error('Expected valid credential verification');
    }

    const authorized = registry.resolveAuthorizedProject(verified.context);
    expect(authorized?.projectId).toBe('alpha');
    expect(getAuthorizedProjectRoot(authorized as AuthorizedProject)).toBe('/canonical/alpha');
  });
});
