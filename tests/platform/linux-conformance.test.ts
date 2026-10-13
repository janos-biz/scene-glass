import { mkdtemp, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { probeProjectRoot } from '../../packages/server/src/platform/probe.js';

const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe.skipIf(process.platform !== 'linux')('Linux secondary conformance', () => {
  it('reports an injected local filesystem as secondary while probing a real temporary root', async () => {
    const root = await createTemporaryRoot();
    await writeFile(join(root, 'conformance-sentinel'), 'secondary only', 'utf8');

    const result = await probeProjectRoot(root, {
      platform: 'linux',
      fs: {
        realpath,
        stat,
        statfs: async () => ({ type: 0xef53 }),
      },
      linuxDeviceInspector: async () => ({ removable: false }),
    });

    expect(result).toMatchObject({
      platform: 'linux',
      supported: true,
      authority: 'linux-secondary',
      code: null,
      failStopReason: null,
    });
    expect(result.facts?.realPath).toBe(root);
    expect(result.facts?.device).toBeGreaterThan(0);
    expect(result.facts?.inode).toBeGreaterThan(0);
    expect(result.facts?.identityStableAtProbe).toBe(true);
  });
});

async function createTemporaryRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scene-glass-linux-')));
  temporaryRoots.push(root);
  return root;
}
