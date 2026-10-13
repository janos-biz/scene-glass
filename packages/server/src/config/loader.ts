import { readFile } from 'node:fs/promises';

import {
  SceneGlassContractError,
  parseServerConfigV1,
  type ServerConfigV1,
} from '@scene-glass/contracts';

const INVALID_CONFIGURATION_MESSAGE = 'server configuration is invalid';
const INVALID_LIMIT_CONFIGURATION_MESSAGE = 'server configuration limits are invalid';

/**
 * Loads the only supported configuration version from an explicit startup path.
 * The returned contract object is frozen by the contracts package.
 */
export async function loadServerConfig(configPath: string): Promise<ServerConfigV1> {
  if (!isConfigPath(configPath)) {
    throw invalidConfigurationError();
  }

  let source: string;
  try {
    source = await readFile(configPath, 'utf8');
  } catch {
    throw invalidConfigurationError();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw invalidConfigurationError();
  }

  try {
    return parseServerConfigV1(parsed);
  } catch (error: unknown) {
    throw redactConfigurationError(error);
  }
}

/**
 * Keeps startup errors actionable by contract code without retaining paths,
 * configuration values, roots, or token material in an error cause.
 */
export function redactConfigurationError(error: unknown): SceneGlassContractError {
  if (error instanceof SceneGlassContractError && error.code === 'SCG_CONFIG_LIMIT_INVALID') {
    return new SceneGlassContractError(
      'SCG_CONFIG_LIMIT_INVALID',
      INVALID_LIMIT_CONFIGURATION_MESSAGE,
    );
  }

  return invalidConfigurationError();
}

function invalidConfigurationError(): SceneGlassContractError {
  return new SceneGlassContractError('SCG_CONFIG_INVALID', INVALID_CONFIGURATION_MESSAGE);
}

function isConfigPath(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0 && !value.includes('\u0000');
}
