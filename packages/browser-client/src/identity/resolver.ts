import type { PageIdentityInput } from '@scene-glass/contracts';
import {
  resolvePageIdentity as resolveCorePageIdentity,
  type PageIdentityLimits,
  type PageIdentityPolicy,
  type PageIdentitySource,
} from '@scene-glass/core/page-identity';

export interface PageIdentityLocationSnapshot {
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
}

export interface PageIdentityResolverContext {
  readonly location: PageIdentityLocationSnapshot;
  readonly navigationGeneration: number;
}

export type PageIdentityResolver = (
  context: PageIdentityResolverContext,
) => string | undefined | Promise<string | undefined>;

export interface PageIdentityAuthority {
  readonly override?: string | PageIdentityResolver;
  readonly policy?: PageIdentityPolicy;
}

export interface BrowserPageIdentityOptions {
  readonly location?: PageIdentityLocationSnapshot;
  readonly override?: string;
  readonly policy?: PageIdentityPolicy;
  readonly limits?: PageIdentityLimits;
}

/**
 * Resolves the active browser location through the core identity authority.
 * Core owns the single NFC normalization, scalar validation, and Web Crypto
 * SHA-256 derivation used by both browser and server-facing code.
 */
export async function resolvePageIdentity(
  options: BrowserPageIdentityOptions = {},
): Promise<PageIdentityInput> {
  const location = options.location ?? globalThis.location;
  const source: PageIdentitySource = {
    pathname: location.pathname,
    query: location.search,
    hash: location.hash,
    ...(options.override === undefined ? {} : { override: options.override }),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
  };

  return resolveCorePageIdentity(source, options.limits);
}
