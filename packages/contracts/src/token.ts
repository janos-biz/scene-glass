import { SceneGlassContractError } from './limits.js';

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const MINIMUM_OPAQUE_TOKEN_BYTES = 32;
const TOKEN_INVALID_MESSAGE = 'token must be canonical base64url encoding of at least 32 bytes';

export function isCanonicalOpaqueToken(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  const remainder = value.length % 4;
  if (remainder === 1) {
    return false;
  }

  let finalSextet = 0;
  for (let index = 0; index < value.length; index += 1) {
    const sextet = BASE64URL_ALPHABET.indexOf(value.charAt(index));
    if (sextet === -1) {
      return false;
    }
    finalSextet = sextet;
  }

  const decodedByteLength =
    Math.floor(value.length / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
  if (decodedByteLength < MINIMUM_OPAQUE_TOKEN_BYTES) {
    return false;
  }

  if (remainder === 2) {
    return (finalSextet & 0b1111) === 0;
  }
  if (remainder === 3) {
    return (finalSextet & 0b11) === 0;
  }
  return true;
}

export function parseCanonicalOpaqueToken(value: unknown): string {
  if (!isCanonicalOpaqueToken(value)) {
    throw new SceneGlassContractError('SCG_TOKEN_INVALID', TOKEN_INVALID_MESSAGE);
  }
  return value;
}
