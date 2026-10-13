import { describe, expect, it } from 'vitest';
import { SceneGlassContractError, type SceneGlassContractErrorCode } from '@scene-glass/contracts';
import { resolvePageIdentity } from '@scene-glass/core/page-identity';

async function expectPageIdentityError(
  action: () => Promise<unknown>,
  code: SceneGlassContractErrorCode,
): Promise<void> {
  let caught: unknown;
  try {
    await action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe(code);
}

describe('page identity resolution', () => {
  it('normalizes NFC and NFD paths to the same exact page identity', async () => {
    const nfc = await resolvePageIdentity({ pathname: '/café' });
    const nfd = await resolvePageIdentity({ pathname: '/cafe\u0301' });

    expect(nfc).toEqual({
      policyVersion: 1,
      canonicalIdentity: '/café',
      route: '/café',
      pageId: 'p_a434c8fb44ab6b773c8921e9a11683a9139a2572c1cd1b2b65ab4eab3e2ffa5e',
    });
    expect(nfd).toEqual(nfc);
    expect(nfc.pageId).toMatch(/^p_[0-9a-f]{64}$/);
  });

  it('keeps punctuation and case-distinct paths in different identity domains', async () => {
    const [atSign, letterZ, upperCase, lowerCase] = await Promise.all([
      resolvePageIdentity({ pathname: '/a@' }),
      resolvePageIdentity({ pathname: '/aZ' }),
      resolvePageIdentity({ pathname: '/A' }),
      resolvePageIdentity({ pathname: '/a' }),
    ]);

    expect(atSign.pageId).toBe(
      'p_bde62ad353e5538fffad94b8d604ddea07b60deae60234038a4d8470534c6aed',
    );
    expect(letterZ.pageId).toBe(
      'p_e8227a58d1beefca8b2dd878cb97c74f7afd95fa091dbec1b69f505093b56646',
    );
    expect(upperCase.pageId).toBe(
      'p_7436eae81cb77ce33ca185411f49e3d13966979e6a599922f5e196172a3d7625',
    );
    expect(lowerCase.pageId).toBe(
      'p_6a50dc8584134c7de537c0052ff6d236bf874355e050c90523e0c5ff2a543a28',
    );
    expect(atSign.pageId).not.toBe(letterZ.pageId);
    expect(upperCase.pageId).not.toBe(lowerCase.pageId);
  });

  it.each([
    {
      label: 'the default pathname-only policy',
      policy: undefined,
      canonicalIdentity: '/café',
    },
    {
      label: 'an explicit query-only policy',
      policy: { includeQuery: true },
      canonicalIdentity: '/café?tab=activity',
    },
    {
      label: 'an explicit hash-only policy',
      policy: { includeHash: true },
      canonicalIdentity: '/café#note-1',
    },
    {
      label: 'an explicit query-and-hash policy',
      policy: { includeQuery: true, includeHash: true },
      canonicalIdentity: '/café?tab=activity#note-1',
    },
    {
      label: 'an explicit false query-and-hash policy',
      policy: { includeQuery: false, includeHash: false },
      canonicalIdentity: '/café',
    },
  ])('uses $label', async ({ policy, canonicalIdentity }) => {
    const identity = await resolvePageIdentity({
      pathname: '/café',
      query: '?tab=activity',
      hash: '#note-1',
      ...(policy === undefined ? {} : { policy }),
    });

    expect(identity.canonicalIdentity).toBe(canonicalIdentity);
    expect(identity.route).toBe(canonicalIdentity);
  });

  it('uses a non-empty override ahead of pathname, query, hash, and policy', async () => {
    const [overridden, expected] = await Promise.all([
      resolvePageIdentity({
        pathname: '/host-route',
        query: '?host-query=ignored',
        hash: '#host-hash',
        override: '/configured-page',
        policy: { includeQuery: true, includeHash: true },
      }),
      resolvePageIdentity({ pathname: '/configured-page' }),
    ]);

    expect(overridden).toEqual(expected);
  });

  it.each([
    ['a C0 control', '/valid\u0000path'],
    ['a C1 control', '/valid\u0085path'],
    ['an unpaired high surrogate', '/valid\ud800'],
    ['an unpaired low surrogate', '/valid\udc00'],
  ])('rejects %s with the scalar contract error code', async (_label, pathname) => {
    expect.hasAssertions();
    await expectPageIdentityError(() => resolvePageIdentity({ pathname }), 'SCG_SCALAR_INVALID');
  });

  it('enforces byte ceilings rather than code-unit counts', async () => {
    expect.hasAssertions();
    await expectPageIdentityError(
      () => resolvePageIdentity({ pathname: '/é' }, { canonicalIdentityBytes: 3, routeBytes: 2 }),
      'SCG_SCALAR_INVALID',
    );
  });
});
