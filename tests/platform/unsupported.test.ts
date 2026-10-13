import { describe, expect, it } from 'vitest';
import {
  PLATFORM_UNSUPPORTED_CODE,
  probeProjectRoot,
  type PlatformFileSystem,
} from '../../packages/server/src/platform/probe.js';

describe('unsupported platform probes', () => {
  it.each([
    ['win32', 'windows-unsupported'],
    ['freebsd', 'unknown-platform'],
  ] as const)(
    'fails %s before it reads configured-root facts',
    async (platform, failStopReason) => {
      const calls: string[] = [];
      const result = await probeProjectRoot('/configured/root', {
        platform,
        fs: forbiddenFileSystem(calls),
      });

      expect(result).toEqual({
        platform,
        supported: false,
        authority: 'unsupported',
        code: PLATFORM_UNSUPPORTED_CODE,
        failStopReason,
        facts: null,
      });
      expect(calls).toEqual([]);
    },
  );

  it('fails a non-directory fact before it probes filesystem or volume facts', async () => {
    const calls: string[] = [];
    const fs: PlatformFileSystem = {
      realpath: async (path) => {
        calls.push(`realpath:${path}`);
        return '/canonical/root';
      },
      stat: async (path) => {
        calls.push(`stat:${path}`);
        return {
          dev: 7,
          ino: 11,
          isDirectory: () => false,
        };
      },
      statfs: async (path) => {
        calls.push(`statfs:${path}`);
        return { type: 26 };
      },
    };
    let volumeInspections = 0;

    const result = await probeProjectRoot('/configured/root', {
      platform: 'darwin',
      fs,
      macosVolumeInspector: async () => {
        volumeInspections += 1;
        return { network: false, removable: false };
      },
    });

    expect(result).toEqual({
      platform: 'darwin',
      supported: false,
      authority: 'unsupported',
      code: PLATFORM_UNSUPPORTED_CODE,
      failStopReason: 'root-not-directory',
      facts: null,
    });
    expect(calls).toEqual(['realpath:/configured/root', 'stat:/canonical/root']);
    expect(volumeInspections).toBe(0);
  });

  it('rejects an injected unsupported filesystem before volume inspection', async () => {
    const calls: string[] = [];
    const fs: PlatformFileSystem = {
      realpath: async (path) => {
        calls.push(`realpath:${path}`);
        return '/canonical/root';
      },
      stat: async (path) => {
        calls.push(`stat:${path}`);
        return {
          dev: 7,
          ino: 11,
          isDirectory: () => true,
        };
      },
      statfs: async (path) => {
        calls.push(`statfs:${path}`);
        return { type: 0xdead };
      },
    };
    let volumeInspections = 0;

    const result = await probeProjectRoot('/configured/root', {
      platform: 'darwin',
      fs,
      macosVolumeInspector: async () => {
        volumeInspections += 1;
        return { network: false, removable: false };
      },
    });

    expect(result).toMatchObject({
      platform: 'darwin',
      supported: false,
      authority: 'unsupported',
      code: PLATFORM_UNSUPPORTED_CODE,
      failStopReason: 'unsupported-filesystem',
      facts: {
        realPath: '/canonical/root',
        device: 7,
        inode: 11,
        fileSystemType: 0xdead,
        identityStableAtProbe: true,
      },
    });
    expect(calls).toEqual([
      'realpath:/configured/root',
      'stat:/canonical/root',
      'stat:/configured/root',
      'statfs:/canonical/root',
      'stat:/configured/root',
    ]);
    expect(volumeInspections).toBe(0);
  });
});

function forbiddenFileSystem(calls: string[]): PlatformFileSystem {
  const called = (operation: string): never => {
    calls.push(operation);
    throw new Error(`unsupported platforms must not inspect roots: ${operation}`);
  };

  return {
    realpath: async (path) => called(`realpath:${path}`),
    stat: async (path) => called(`stat:${path}`),
    statfs: async (path) => called(`statfs:${path}`),
  };
}
