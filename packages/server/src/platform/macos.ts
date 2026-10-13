import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import {
  rootSupportedResult,
  rootUnsupportedResult,
  type FileSystemProbeFacts,
  type ProjectRootProbeResult,
} from './probe.js';

const execFileAsync = promisify(execFile);

/** Darwin VFS type values reported by Node's fs.statfs. */
const APFS_FILE_SYSTEM_TYPE = 26;
const HFS_FILE_SYSTEM_TYPE = 17;

export interface MacosVolumeFacts {
  /** null means the system could not establish the fact. */
  readonly removable: boolean | null;
  /** null means the volume did not report a filesystem personality. */
  readonly network: boolean | null;
}

export type MacosVolumeInspector = (realPath: string) => Promise<MacosVolumeFacts>;

/**
 * Establishes the Darwin-specific mount facts needed to reject network and
 * removable volumes. diskutil receives the canonical path as an argv value,
 * never through a shell.
 */
export async function inspectMacosVolume(realPath: string): Promise<MacosVolumeFacts> {
  try {
    const source = await macosMountSource(realPath);
    if (source === null) {
      return Object.freeze({ removable: null, network: null });
    }
    if (!source.startsWith('/dev/')) {
      return Object.freeze({
        removable: null,
        network: isNetworkMountSource(source),
      });
    }

    const { stdout } = await execFileAsync('/usr/sbin/diskutil', ['info', '-plist', source]);
    const removable = anyPlistBoolean(String(stdout), [
      'Removable Media',
      'RemovableMedia',
      'Ejectable',
    ]);
    const fileSystemPersonality = firstPlistString(String(stdout), [
      'FileSystemPersonality',
      'FilesystemType',
    ]);

    return Object.freeze({
      removable,
      network:
        fileSystemPersonality === null ? null : isNetworkFileSystemName(fileSystemPersonality),
    });
  } catch {
    return Object.freeze({ removable: null, network: null });
  }
}

/**
 * macOS is the release-authoritative platform only for a known local
 * filesystem with established device media facts. This test is deliberately
 * fail-closed; it does not turn an unclassified Darwin mount into support.
 */
export async function probeMacosFileSystem(
  facts: FileSystemProbeFacts,
  inspector: MacosVolumeInspector = inspectMacosVolume,
): Promise<ProjectRootProbeResult> {
  if (!isSupportedMacosFileSystemType(facts.fileSystemType)) {
    return rootUnsupportedResult(
      {
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
      },
      'unsupported-filesystem',
      facts,
    );
  }

  let volume: MacosVolumeFacts;
  try {
    volume = await inspector(facts.realPath);
  } catch {
    return rootUnsupportedResult(
      {
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
      },
      'device-facts-unavailable',
      facts,
    );
  }
  if (volume.network === true) {
    return rootUnsupportedResult(
      {
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
      },
      'network-filesystem',
      facts,
    );
  }
  if (volume.removable === true) {
    return rootUnsupportedResult(
      {
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
      },
      'removable-filesystem',
      facts,
    );
  }
  if (volume.network !== false || volume.removable !== false) {
    return rootUnsupportedResult(
      {
        platform: 'darwin',
        supported: true,
        authority: 'macos-authoritative',
        code: null,
        failStopReason: null,
      },
      'device-facts-unavailable',
      facts,
    );
  }

  return rootSupportedResult('darwin', 'macos-authoritative', facts);
}

function isSupportedMacosFileSystemType(value: number | bigint): boolean {
  return (
    value === APFS_FILE_SYSTEM_TYPE ||
    value === HFS_FILE_SYSTEM_TYPE ||
    value === BigInt(APFS_FILE_SYSTEM_TYPE) ||
    value === BigInt(HFS_FILE_SYSTEM_TYPE)
  );
}

function isNetworkFileSystemName(value: string): boolean {
  return /^(afp|nfs|smb|smbfs|webdav)$/i.test(value.trim());
}
async function macosMountSource(realPath: string): Promise<string | null> {
  const { stdout } = await execFileAsync('/bin/df', ['-P', realPath]);
  const rows = String(stdout)
    .split(/\r?\n/)
    .map((row) => row.trim())
    .filter((row) => row.length > 0);
  const row = rows.at(-1);
  if (row === undefined) {
    return null;
  }
  const source = row.split(/\s+/)[0];
  return source === undefined ? null : source;
}

function isNetworkMountSource(source: string): boolean {
  return source.startsWith('//') || source.includes(':');
}

function anyPlistBoolean(plist: string, keys: readonly string[]): boolean | null {
  let found = false;
  for (const key of keys) {
    const match = new RegExp(`<key>${escapeRegExp(key)}</key>\\s*<(true|false)\\s*/>`, 'i').exec(
      plist,
    );
    if (match?.[1] === 'true') {
      return true;
    }
    if (match?.[1] === 'false') {
      found = true;
    }
  }
  return found ? false : null;
}

function firstPlistString(plist: string, keys: readonly string[]): string | null {
  for (const key of keys) {
    const match = new RegExp(
      `<key>${escapeRegExp(key)}</key>\\s*<string>([^<]*)</string>`,
      'i',
    ).exec(plist);
    if (match?.[1] !== undefined) {
      return match[1];
    }
  }
  return null;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
