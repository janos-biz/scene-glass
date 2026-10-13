import { isAbsolute, join } from 'node:path';

export interface ConfigPathInput {
  /** Explicit CLI configuration path, when supplied. */
  readonly configPath?: string;
  /** Explicit environment values; never read from process state here. */
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** Deferred host-owned home-directory lookup for the default location. */
  readonly homeDirectory: () => string | undefined;
}

export class ConfigPathInputError extends Error {
  public constructor() {
    super('Scene Glass config path is invalid');
    this.name = 'ConfigPathInputError';
  }
}

/**
 * Resolves the configuration path without inspecting process state or the
 * filesystem. Explicit values are validated before lower-precedence sources
 * are considered so invalid overrides fail closed.
 */
export function resolveSceneGlassConfigPath(input: ConfigPathInput): string {
  if (input.configPath !== undefined) {
    return assertExplicitConfigPath(input.configPath);
  }

  const environmentPath = input.environment?.SCENE_GLASS_CONFIG_PATH;
  if (environmentPath !== undefined) {
    return assertExplicitConfigPath(environmentPath);
  }

  return resolveDefaultConfigPath(input.homeDirectory);
}

function assertExplicitConfigPath(value: unknown): string {
  if (!isAbsolutePath(value)) {
    throw new ConfigPathInputError();
  }
  return value;
}

function resolveDefaultConfigPath(homeDirectory: ConfigPathInput['homeDirectory']): string {
  let home: string | undefined;
  try {
    home = homeDirectory();
  } catch {
    throw new ConfigPathInputError();
  }

  if (!isAbsolutePath(home)) {
    throw new ConfigPathInputError();
  }

  return join(home, '.scg', 'config.json');
}

function isAbsolutePath(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length > 0 && !value.includes('\u0000') && isAbsolute(value)
  );
}
