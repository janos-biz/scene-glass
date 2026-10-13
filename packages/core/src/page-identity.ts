import {
  BUILT_IN_LIMITS,
  SceneGlassContractError,
  type LimitValues,
  type PageId,
  type PageIdentityInput,
} from '@scene-glass/contracts';

export interface PageIdentityPolicy {
  readonly includeQuery?: boolean;
  readonly includeHash?: boolean;
}

export interface PageIdentitySource {
  readonly pathname?: string;
  readonly query?: string;
  readonly hash?: string;
  readonly override?: string;
  readonly policy?: PageIdentityPolicy;
}

export type PageIdentityLimits = Pick<LimitValues, 'canonicalIdentityBytes' | 'routeBytes'>;

const DEFAULT_IDENTITY_LIMITS: PageIdentityLimits = {
  canonicalIdentityBytes: BUILT_IN_LIMITS.canonicalIdentityBytes,
  routeBytes: BUILT_IN_LIMITS.routeBytes,
};

export async function resolvePageIdentity(
  source: PageIdentitySource,
  limits: PageIdentityLimits = DEFAULT_IDENTITY_LIMITS,
): Promise<PageIdentityInput> {
  const canonicalIdentity = normalizeIdentity(
    source.override ?? composeLocationIdentity(source),
    limits.canonicalIdentityBytes,
    'canonicalIdentity',
  );
  assertIdentityContents(canonicalIdentity, limits.routeBytes, 'route');

  return Object.freeze({
    policyVersion: 1,
    canonicalIdentity,
    route: canonicalIdentity,
    pageId: await derivePageIdUnchecked(canonicalIdentity),
  });
}

export async function derivePageId(
  canonicalIdentity: string,
  maximumBytes = BUILT_IN_LIMITS.canonicalIdentityBytes,
): Promise<PageId> {
  assertCanonicalIdentity(canonicalIdentity, maximumBytes, 'canonicalIdentity');

  return derivePageIdUnchecked(canonicalIdentity);
}

/**
 * Validates server- or file-supplied identity without coercing it. Stored data
 * must already be canonical; validation checks NFC but never rewrites it.
 */
export async function validateCanonicalPageIdentity(
  identity: PageIdentityInput,
  limits: PageIdentityLimits = DEFAULT_IDENTITY_LIMITS,
): Promise<PageIdentityInput> {
  if (identity.policyVersion !== 1) {
    throw identityError('page identity policyVersion must be 1');
  }

  assertCanonicalIdentity(
    identity.canonicalIdentity,
    limits.canonicalIdentityBytes,
    'canonicalIdentity',
  );
  assertCanonicalIdentity(identity.route, limits.routeBytes, 'route');

  const derivedPageId = await derivePageIdUnchecked(identity.canonicalIdentity);
  if (identity.pageId !== derivedPageId) {
    throw identityError('pageId does not match canonicalIdentity');
  }

  return identity;
}

function composeLocationIdentity(source: PageIdentitySource): string {
  if (source.pathname === undefined) {
    throw identityError('pathname is required when no identity override is supplied');
  }

  const includeQuery = source.policy?.includeQuery === true;
  const includeHash = source.policy?.includeHash === true;
  return `${source.pathname}${includeQuery ? (source.query ?? '') : ''}${includeHash ? (source.hash ?? '') : ''}`;
}

function normalizeIdentity(value: string, maximumBytes: number, name: string): string {
  assertWellFormedUnicode(value, name);
  const normalized = value.normalize('NFC');
  assertIdentityContents(normalized, maximumBytes, name);
  return normalized;
}

function assertCanonicalIdentity(value: string, maximumBytes: number, name: string): void {
  assertWellFormedUnicode(value, name);
  if (value.length === 0) {
    throw identityError(`${name} must not be empty`);
  }
  if (value.normalize('NFC') !== value) {
    throw identityError(`${name} must already be NFC normalized`);
  }
  assertIdentityContents(value, maximumBytes, name);
}

function assertIdentityContents(value: string, maximumBytes: number, name: string): void {
  if (value.length === 0) {
    throw identityError(`${name} must not be empty`);
  }
  if (containsControl(value)) {
    throw identityError(`${name} must not contain control characters`);
  }
  if (new TextEncoder().encode(value).byteLength > maximumBytes) {
    throw identityError(`${name} exceeds its UTF-8 byte limit`);
  }
}

async function derivePageIdUnchecked(canonicalIdentity: string): Promise<PageId> {
  if (!globalThis.crypto?.subtle) {
    throw identityError('Web Crypto SHA-256 is unavailable');
  }

  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalIdentity),
  );
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );

  return `p_${hex}` as PageId;
}

function assertWellFormedUnicode(value: string, name: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw identityError(`${name} contains an unpaired surrogate`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw identityError(`${name} contains an unpaired surrogate`);
    }
  }
}

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || (codeUnit >= 0x7f && codeUnit <= 0x9f)) {
      return true;
    }
  }
  return false;
}

function identityError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_SCALAR_INVALID', message);
}
