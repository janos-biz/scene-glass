import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  type DeviceDriftPort,
  type DeviceDriftStat,
  repairDeviceDrift,
} from '../../packages/onboarding/src/lifecycle/device-drift.js';

const MANIFEST_PATH = '/home/user/project/.scg/onboarding/manifest.v1.json';
const REGISTRY_PATH = '/home/user/.scg/credential-authorities.v1.json';
const DESCRIPTOR_PATH = '/home/user/project/.scg/runtime/host-descriptor.v1.json';
const RUNTIME_PATH = '/home/user/project/.scg/runtime';
const CREDENTIAL_PATH = '/home/user/project/.env.development.local';
const ROOT_PATH = '/home/user/project';

const STALE_DEVICE = '16777232';
const LIVE_DEVICE = '16777226';
const CREDENTIAL_INODE = '65570568';
const RUNTIME_INODE = '65570564';
const ROOT_INODE = '43861914';

function serialize(document: unknown): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

function fingerprint(text: string): string {
  return `sha256:${createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex')}`;
}

function descriptorDocument(device: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    framework: 'vue3',
    projectId: 'alpha',
    credentialProjectId: 'alpha',
    approvedRootIdentity: { device, inode: ROOT_INODE },
    credentialAuthorities: [
      { projectId: 'alpha', path: CREDENTIAL_PATH, device, inode: CREDENTIAL_INODE },
    ],
  };
}

function registryDocument(device: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    projects: [
      {
        projectId: 'alpha',
        tokenEnv: 'SCENE_GLASS_SERVER_TOKEN_ALPHA',
        canonicalRoot: ROOT_PATH,
        credentialPath: CREDENTIAL_PATH,
        device,
        inode: CREDENTIAL_INODE,
      },
    ],
  };
}

function manifestDocument(device: string, descriptorFingerprint: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'scene-glass-setup-manifest',
    installId: 'scg-test',
    state: 'active',
    artifacts: [
      {
        path: DESCRIPTOR_PATH,
        kind: 'file',
        fingerprint: descriptorFingerprint,
        hunks: [{ id: 'scg-vue3-descriptor-1', fingerprint: descriptorFingerprint }],
        inverse: { kind: 'delete-created-file', expectedFingerprint: descriptorFingerprint },
      },
      {
        path: CREDENTIAL_PATH,
        kind: 'credential',
        identity: { device, inode: CREDENTIAL_INODE },
        inverse: {
          kind: 'delete-created-credential',
          identity: { device, inode: CREDENTIAL_INODE },
        },
      },
      {
        path: REGISTRY_PATH,
        kind: 'credential-authority-registry',
        postimage: {
          schemaVersion: 1,
          projects: [
            {
              projectId: 'alpha',
              credentialPath: CREDENTIAL_PATH,
              device,
              inode: CREDENTIAL_INODE,
            },
          ],
        },
      },
      {
        path: RUNTIME_PATH,
        kind: 'directory',
        identity: { device, inode: RUNTIME_INODE },
      },
    ],
  };
}

interface LiveEntry {
  readonly device: string;
  readonly inode: string;
  readonly kind: 'file' | 'directory';
}

/** Recorded device numbers per document, so partial repairs can be modelled. */
interface WorldOptions {
  readonly manifestDevice?: string;
  readonly registryDevice?: string;
  readonly descriptorDevice?: string;
  readonly live?: Readonly<Record<string, LiveEntry | undefined>>;
}

function liveDefaults(): Record<string, LiveEntry> {
  return {
    [CREDENTIAL_PATH]: { device: LIVE_DEVICE, inode: CREDENTIAL_INODE, kind: 'file' },
    [RUNTIME_PATH]: { device: LIVE_DEVICE, inode: RUNTIME_INODE, kind: 'directory' },
    [ROOT_PATH]: { device: LIVE_DEVICE, inode: ROOT_INODE, kind: 'directory' },
  };
}

function createWorld(options: WorldOptions = {}): {
  readonly port: DeviceDriftPort;
  readonly files: Map<string, string>;
} {
  const descriptorDevice = options.descriptorDevice ?? STALE_DEVICE;
  const manifestDevice = options.manifestDevice ?? STALE_DEVICE;
  // The manifest records the descriptor as setup wrote it: every device stale.
  const originalDescriptor = serialize(descriptorDocument(STALE_DEVICE));
  const files = new Map<string, string>([
    [DESCRIPTOR_PATH, serialize(descriptorDocument(descriptorDevice))],
    [REGISTRY_PATH, serialize(registryDocument(options.registryDevice ?? STALE_DEVICE))],
    [MANIFEST_PATH, serialize(manifestDocument(manifestDevice, fingerprint(originalDescriptor)))],
  ]);
  const live = { ...liveDefaults(), ...(options.live ?? {}) };
  const port: DeviceDriftPort = {
    lstat: async (path) => {
      const entry = live[path];
      if (entry === undefined) throw new Error(`ENOENT ${path}`);
      return {
        dev: Number(entry.device),
        ino: Number(entry.inode),
        isFile: () => entry.kind === 'file',
        isDirectory: () => entry.kind === 'directory',
        isSymbolicLink: () => false,
      } satisfies DeviceDriftStat;
    },
    readUtf8: async (path) => files.get(path),
    writeUtf8: async (path, text) => {
      files.set(path, text);
    },
  };
  return { port, files };
}

function devicesIn(text: string): string[] {
  const found: string[] = [];
  JSON.parse(text, (key, value: unknown) => {
    if (key === 'device' && typeof value === 'string') found.push(value);
    return value;
  });
  return found;
}

describe('device drift reconciliation', () => {
  it('repoints every recorded device at the volume the recorded inodes now live on', async () => {
    const { port, files } = createWorld();

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('repaired');

    for (const path of [MANIFEST_PATH, REGISTRY_PATH, DESCRIPTOR_PATH]) {
      const devices = devicesIn(files.get(path)!);
      expect(devices.length).toBeGreaterThan(0);
      expect(devices.every((device) => device === LIVE_DEVICE)).toBe(true);
    }
  });

  it('rewrites the manifest fingerprints to match the descriptor it just wrote', async () => {
    const { port, files } = createWorld();

    await repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH });

    const expected = fingerprint(files.get(DESCRIPTOR_PATH)!);
    const manifest = JSON.parse(files.get(MANIFEST_PATH)!) as {
      artifacts: {
        path: string;
        fingerprint?: string;
        hunks?: { fingerprint: string }[];
        inverse?: { expectedFingerprint?: string };
      }[];
    };
    const artifact = manifest.artifacts.find((item) => item.path === DESCRIPTOR_PATH)!;
    expect(artifact.fingerprint).toBe(expected);
    expect(artifact.hunks?.[0]?.fingerprint).toBe(expected);
    expect(artifact.inverse?.expectedFingerprint).toBe(expected);
  });

  it('reports unchanged and writes nothing when the recorded devices are already live', async () => {
    const { port, files } = createWorld({
      manifestDevice: LIVE_DEVICE,
      registryDevice: LIVE_DEVICE,
      descriptorDevice: LIVE_DEVICE,
    });
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unchanged');

    expect([...files]).toStrictEqual([...before]);
  });

  it('completes a run interrupted after the descriptor was written', async () => {
    // The crash window: descriptor already reconciled, manifest still stale.
    const { port, files } = createWorld({ descriptorDevice: LIVE_DEVICE });

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('repaired');

    expect(devicesIn(files.get(MANIFEST_PATH)!).every((device) => device === LIVE_DEVICE)).toBe(
      true,
    );
    const manifest = JSON.parse(files.get(MANIFEST_PATH)!) as {
      artifacts: { path: string; fingerprint?: string }[];
    };
    expect(manifest.artifacts.find((item) => item.path === DESCRIPTOR_PATH)?.fingerprint).toBe(
      fingerprint(files.get(DESCRIPTOR_PATH)!),
    );
  });

  it('leaves the records alone when a recorded inode no longer matches', async () => {
    const { port, files } = createWorld({
      live: { [CREDENTIAL_PATH]: { device: LIVE_DEVICE, inode: '999', kind: 'file' } },
    });
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unrepairable');

    expect([...files]).toStrictEqual([...before]);
  });

  it('leaves the records alone when the credential path became a directory', async () => {
    const { port, files } = createWorld({
      live: {
        [CREDENTIAL_PATH]: { device: LIVE_DEVICE, inode: CREDENTIAL_INODE, kind: 'directory' },
      },
    });
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unrepairable');

    expect([...files]).toStrictEqual([...before]);
  });

  it('leaves the records alone when the recorded identities span two volumes', async () => {
    const { port, files } = createWorld({
      live: { [RUNTIME_PATH]: { device: '16777299', inode: RUNTIME_INODE, kind: 'directory' } },
    });
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unrepairable');

    expect([...files]).toStrictEqual([...before]);
  });

  it('leaves the records alone when the descriptor changed beyond its device numbers', async () => {
    const { port, files } = createWorld();
    const tampered = descriptorDocument(STALE_DEVICE);
    tampered['loaderUrl'] = 'http://attacker.example/loader.js';
    files.set(DESCRIPTOR_PATH, serialize(tampered));
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unrepairable');

    expect([...files]).toStrictEqual([...before]);
  });

  it('leaves the records alone when a document is not canonically serialized', async () => {
    const { port, files } = createWorld();
    files.set(REGISTRY_PATH, JSON.stringify(registryDocument(STALE_DEVICE)));
    const before = new Map(files);

    await expect(
      repairDeviceDrift(port, { manifestPath: MANIFEST_PATH, registryPath: REGISTRY_PATH }),
    ).resolves.toBe('unrepairable');

    expect([...files]).toStrictEqual([...before]);
  });
});
