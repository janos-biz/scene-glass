import { describe, expect, it, vi } from 'vitest';

import {
  ConfigPathInputError,
  resolveSceneGlassConfigPath,
} from '../../packages/server/src/startup/config-path.js';
import { parseStartupOptions } from '../../apps/mcp-server/src/main.js';

describe('resolveSceneGlassConfigPath', () => {
  it('uses an explicit CLI path before the environment without inspecting home', () => {
    const homeDirectory = vi.fn(() => '/Users/scene-glass');

    expect(
      resolveSceneGlassConfigPath({
        configPath: '/cli/config.json',
        environment: { SCENE_GLASS_CONFIG_PATH: '/environment/config.json' },
        homeDirectory,
      }),
    ).toBe('/cli/config.json');
    expect(homeDirectory).not.toHaveBeenCalled();
  });

  it('uses a valid environment path without inspecting home', () => {
    const homeDirectory = vi.fn(() => '/Users/scene-glass');

    expect(
      resolveSceneGlassConfigPath({
        environment: { SCENE_GLASS_CONFIG_PATH: '/environment/config.json' },
        homeDirectory,
      }),
    ).toBe('/environment/config.json');
    expect(homeDirectory).not.toHaveBeenCalled();
  });

  it('uses the injected home directory only when no explicit path is present', () => {
    const homeDirectory = vi.fn(() => '/Users/scene-glass');

    expect(resolveSceneGlassConfigPath({ homeDirectory })).toBe(
      '/Users/scene-glass/.scg/config.json',
    );
    expect(homeDirectory).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['', 'empty'],
    ['relative/config.json', 'relative'],
    ['/invalid\u0000config.json', 'NUL-containing'],
  ])('fails closed for an invalid CLI path (%s)', (configPath) => {
    const homeDirectory = vi.fn(() => '/Users/scene-glass');

    expect(() =>
      resolveSceneGlassConfigPath({
        configPath,
        environment: { SCENE_GLASS_CONFIG_PATH: '/environment/config.json' },
        homeDirectory,
      }),
    ).toThrow(ConfigPathInputError);
    expect(homeDirectory).not.toHaveBeenCalled();
  });

  it.each([
    ['', 'empty'],
    ['relative/config.json', 'relative'],
    ['/invalid\u0000config.json', 'NUL-containing'],
  ])('fails closed for an invalid environment path (%s)', (environmentPath) => {
    const homeDirectory = vi.fn(() => '/Users/scene-glass');

    expect(() =>
      resolveSceneGlassConfigPath({
        environment: { SCENE_GLASS_CONFIG_PATH: environmentPath },
        homeDirectory,
      }),
    ).toThrow(ConfigPathInputError);
    expect(homeDirectory).not.toHaveBeenCalled();
  });

  it.each([
    { home: undefined, label: 'missing' },
    { home: '', label: 'empty' },
    { home: 'relative-home', label: 'relative' },
    { home: '/invalid\u0000home', label: 'NUL-containing' },
  ])('rejects a $label home directory', ({ home }) => {
    expect(() => resolveSceneGlassConfigPath({ homeDirectory: () => home })).toThrow(
      ConfigPathInputError,
    );
  });
});

describe('parseStartupOptions', () => {
  it('retains an explicit port zero', () => {
    expect(
      parseStartupOptions(['--config', '/cli/config.json', '--port', '0'], {
        SCENE_GLASS_CONFIG_PATH: '/environment/config.json',
      }),
    ).toEqual({ configPath: '/cli/config.json', port: 0 });
  });
});
