import { readFile, realpath } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import {
  rootSupportedResult,
  rootUnsupportedResult,
  type FileSystemProbeFacts,
  type ProjectRootProbeResult,
} from './probe.js';

const LOCAL_FILE_SYSTEM_TYPES = new Set<bigint>([
  0xef53n, // ext2/ext3/ext4
  0x58465342n, // XFS
  0x9123683en, // Btrfs
  0xf2f52010n, // F2FS
  0x2fc12fc1n, // OpenZFS
]);

const NETWORK_FILE_SYSTEM_TYPES = new Set<bigint>([
  0x6969n, // NFS
  0x564c4e52n, // NFSv4
  0xff534d42n, // CIFS
  0xfe534d42n, // SMB2
  0x01021997n, // 9P
  0x5346414fn, // AFS
  0x73757245n, // Coda
]);

export interface LinuxDeviceFacts {
  /** null means sysfs could not establish removable-media status. */
  readonly removable: boolean | null;
}

export type LinuxDeviceInspector = (device: number | bigint) => Promise<LinuxDeviceFacts>;

/**
 * Uses the stat device's Linux major:minor number to inspect its sysfs block
 * ancestry. A missing classification is not assumed to be a fixed local disk.
 */
export async function inspectLinuxDevice(device: number | bigint): Promise<LinuxDeviceFacts> {
  const deviceNumber = toDeviceNumber(device);
  if (deviceNumber === null) {
    return Object.freeze({ removable: null });
  }

  const { major, minor } = splitLinuxDevice(deviceNumber);
  let current: string;
  try {
    current = await realpath(`/sys/dev/block/${major}:${minor}`);
  } catch {
    return Object.freeze({ removable: null });
  }

  for (let index = 0; index < 16 && current.startsWith('/sys/'); index += 1) {
    try {
      const value = (await readFile(join(current, 'removable'), 'utf8')).trim();
      if (value === '0') {
        return Object.freeze({ removable: false });
      }
      if (value === '1') {
        return Object.freeze({ removable: true });
      }
      return Object.freeze({ removable: null });
    } catch {
      const parent = dirname(current);
      if (parent === current) {
        break;
      }
      current = parent;
    }
  }

  return Object.freeze({ removable: null });
}

/**
 * Linux is admitted only as a local-filesystem conformance/smoke surface. A
 * successful result remains explicitly secondary and must not be treated as
 * authority for the macOS durability contract.
 */
export async function probeLinuxFileSystem(
  facts: FileSystemProbeFacts,
  inspector: LinuxDeviceInspector = inspectLinuxDevice,
): Promise<ProjectRootProbeResult> {
  const fileSystemType = toFileSystemType(facts.fileSystemType);
  if (fileSystemType === null) {
    return unsupportedLinuxResult('device-facts-invalid', facts);
  }
  if (NETWORK_FILE_SYSTEM_TYPES.has(fileSystemType)) {
    return unsupportedLinuxResult('network-filesystem', facts);
  }
  if (!LOCAL_FILE_SYSTEM_TYPES.has(fileSystemType)) {
    return unsupportedLinuxResult('unsupported-filesystem', facts);
  }

  let device: LinuxDeviceFacts;
  try {
    device = await inspector(facts.device);
  } catch {
    return unsupportedLinuxResult('device-facts-unavailable', facts);
  }
  if (device.removable === true) {
    return unsupportedLinuxResult('removable-filesystem', facts);
  }
  if (device.removable !== false) {
    return unsupportedLinuxResult('device-facts-unavailable', facts);
  }

  return rootSupportedResult('linux', 'linux-secondary', facts);
}

function unsupportedLinuxResult(
  reason:
    | 'device-facts-invalid'
    | 'device-facts-unavailable'
    | 'network-filesystem'
    | 'removable-filesystem'
    | 'unsupported-filesystem',
  facts: FileSystemProbeFacts,
): ProjectRootProbeResult {
  return rootUnsupportedResult(
    {
      platform: 'linux',
      supported: true,
      authority: 'linux-secondary',
      code: null,
      failStopReason: null,
    },
    reason,
    facts,
  );
}

function toFileSystemType(value: number | bigint): bigint | null {
  if (typeof value === 'bigint') {
    return value >= 0n ? value : null;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    return null;
  }
  return BigInt(value);
}

function toDeviceNumber(value: number | bigint): bigint | null {
  if (typeof value === 'bigint') {
    return value >= 0n ? value : null;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    return null;
  }
  return BigInt(value);
}

function splitLinuxDevice(device: bigint): {
  readonly major: bigint;
  readonly minor: bigint;
} {
  return {
    major: ((device >> 8n) & 0xfffn) | ((device >> 32n) & 0xfffff000n),
    minor: (device & 0xffn) | ((device >> 12n) & 0xffffff00n),
  };
}
