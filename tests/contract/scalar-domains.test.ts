import { describe, expect, it } from 'vitest';
import {
  MAX_DOM_ORDER,
  MAX_SAFE_REVISION,
  SceneGlassContractError,
  type SceneGlassContractErrorCode,
  assertDomOrder,
  assertLowercaseUuidV4,
  assertResolutionScore,
  assertSafeRevision,
  assertUtf8ByteLimit,
  parseSha256Digest,
  unicodeCodePointLength,
  utf8ByteLength,
} from '@scene-glass/contracts';

const UUID_V4 = '01234567-89ab-4cde-8fab-0123456789ab';

function expectContractError(action: () => unknown, code: SceneGlassContractErrorCode): void {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }

  if (!(caught instanceof SceneGlassContractError)) {
    throw new Error(`Expected SceneGlassContractError, received ${String(caught)}`);
  }
  expect(caught.code).toBe(code);
}

describe('scalar domains', () => {
  it('accepts the safe revision endpoints', () => {
    expect(assertSafeRevision(0)).toBe(0);
    expect(assertSafeRevision(MAX_SAFE_REVISION)).toBe(MAX_SAFE_REVISION);
  });

  it.each([
    ['negative', -1],
    ['fractional', 1.5],
    ['NaN', Number.NaN],
    ['positive infinity', Number.POSITIVE_INFINITY],
    ['negative infinity', Number.NEGATIVE_INFINITY],
    ['the first unsafe integer', MAX_SAFE_REVISION + 1],
  ])('rejects a %s revision', (_label, value) => {
    expect.assertions(1);
    expectContractError(() => assertSafeRevision(value), 'SCG_SCALAR_INVALID');
  });

  it('accepts domOrder through its inclusive maximum', () => {
    expect(assertDomOrder(0)).toBe(0);
    expect(assertDomOrder(MAX_DOM_ORDER)).toBe(MAX_DOM_ORDER);
    expectContractError(() => assertDomOrder(MAX_DOM_ORDER + 1), 'SCG_SCALAR_INVALID');
  });

  it.each(['score', 'gap'])('bounds %s from zero through one hundred', (name) => {
    expect(assertResolutionScore(0, name)).toBe(0);
    expect(assertResolutionScore(100, name)).toBe(100);
    expectContractError(() => assertResolutionScore(-1, name), 'SCG_SCALAR_INVALID');
    expectContractError(() => assertResolutionScore(100.5, name), 'SCG_SCALAR_INVALID');
    expectContractError(() => assertResolutionScore(101, name), 'SCG_SCALAR_INVALID');
  });

  it('measures UTF-8 bytes separately from Unicode code points', () => {
    expect(unicodeCodePointLength('é😀')).toBe(2);
    expect(utf8ByteLength('é😀')).toBe(6);
    expect(assertUtf8ByteLimit('é', 2, 'memo')).toBe('é');
    expectContractError(() => assertUtf8ByteLimit('é', 1, 'memo'), 'SCG_SCALAR_INVALID');
  });

  it('accepts only lowercase UUID v4 operation identifiers', () => {
    expect(assertLowercaseUuidV4(UUID_V4)).toBe(UUID_V4);
    expectContractError(() => assertLowercaseUuidV4(UUID_V4.toUpperCase()), 'SCG_ID_INVALID');
    expectContractError(
      () => assertLowercaseUuidV4('01234567-89ab-5cde-8fab-0123456789ab'),
      'SCG_ID_INVALID',
    );
  });

  it('requires lowercase 64-hex SHA-256 digests', () => {
    const digest = `sha256:${'ab'.repeat(32)}`;
    expect(parseSha256Digest(digest)).toBe(digest);
    expectContractError(() => parseSha256Digest(`sha256:${'AB'.repeat(32)}`), 'SCG_ID_INVALID');
    expectContractError(() => parseSha256Digest(`sha256:${'a'.repeat(63)}`), 'SCG_ID_INVALID');
  });
});
