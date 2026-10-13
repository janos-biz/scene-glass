import { realpath, stat, statfs } from 'node:fs/promises';
import process from 'node:process';

import { probeMacosFileSystem, type MacosVolumeInspector } from './macos.js';
import { probeLinuxFileSystem, type LinuxDeviceInspector } from './linux.js';

export const PLATFORM_UNSUPPORTED_CODE = 'SCG_PLATFORM_UNSUPPORTED' as const;

export type PlatformAuthority = 'macos-authoritative' | 'linux-secondary' | 'unsupported';

export type PlatformFailStopReason =
  | 'windows-unsupported'
  | 'unknown-platform'
  | 'root-realpath-failed'
  | 'root-stat-failed'
  | 'root-not-directory'
  | 'root-identity-changed'
  | 'statfs-failed'
  | 'device-facts-invalid'
  | 'device-facts-unavailable'
  | 'network-filesystem'
  | 'removable-filesystem'
  | 'unsupported-filesystem';

export interface PlatformProbeResult {
  readonly platform: string;
  readonly supported: boolean;
  readonly authority: PlatformAuthority;
  readonly code: typeof PLATFORM_UNSUPPORTED_CODE | null;
  readonly failStopReason: PlatformFailStopReason | null;
}

export interface FileSystemProbeFacts {
  /**
   * The canonical root selected before bind. This is operational data, never
   * log it directly; observability redaction removes it by field name.
   */
  readonly realPath: string;
  readonly device: number | bigint;
  readonly inode: number | bigint;
  readonly fileSystemType: number | bigint;
  /**
   * A matching second stat only detects a replacement that is observed during
   * probing. It is not descriptor-relative same-user race protection.
   */
  readonly identityStableAtProbe: boolean;
}

export interface ProjectRootProbeResult extends PlatformProbeResult {
  readonly facts: FileSystemProbeFacts | null;
}

export interface PlatformFileSystem {
  readonly realpath: (path: string) => Promise<string>;
  readonly stat: (path: string) => Promise<PlatformStats>;
  readonly statfs: (path: string) => Promise<PlatformStatFs>;
}

export interface PlatformStats {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
  isDirectory(): boolean;
}

export interface PlatformStatFs {
  readonly type: number | bigint;
}

export interface PlatformProbeOptions {
  /** Override only for controlled conformance tests. */
  readonly platform?: string;
}

export interface ProjectRootProbeOptions extends PlatformProbeOptions {
  readonly fs?: PlatformFileSystem;
  readonly macosVolumeInspector?: MacosVolumeInspector;
  readonly linuxDeviceInspector?: LinuxDeviceInspector;
}

const defaultFileSystem: PlatformFileSystem = {
  realpath: async (path) => realpath(path),
  stat: async (path) => stat(path),
  statfs: async (path) => statfs(path),
};

/**
 * Checks the operating-system posture before a listener is created. A passing
 * Linux result is intentionally secondary conformance evidence, never a
 * macOS-equivalent durability claim.
 */
export function probePlatform(options: PlatformProbeOptions = {}): PlatformProbeResult {
  const platform = options.platform ?? process.platform;

  switch (platform) {
    case 'darwin':
      return supportedResult(platform, 'macos-authoritative');
    case 'linux':
      return supportedResult(platform, 'linux-secondary');
    case 'win32':
      return unsupportedResult(platform, 'windows-unsupported');
    default:
      return unsupportedResult(platform, 'unknown-platform');
  }
}

/**
 * Resolves and classifies one configured project root before bind. The probe
 * intentionally returns a fail-stop result instead of weakening durability or
 * local-authority assumptions when a fact cannot be established.
 */
export async function probeProjectRoot(
  root: string,
  options: ProjectRootProbeOptions = {},
): Promise<ProjectRootProbeResult> {
  const platformResult = probePlatform(options);
  if (!platformResult.supported) {
    return rootUnsupportedResult(platformResult, platformResult.failStopReason!, null);
  }

  const fs = options.fs ?? defaultFileSystem;
  let canonicalRoot: string;
  try {
    canonicalRoot = await fs.realpath(root);
  } catch {
    return rootUnsupportedResult(platformResult, 'root-realpath-failed', null);
  }

  let canonicalStats: PlatformStats;
  try {
    canonicalStats = await fs.stat(canonicalRoot);
  } catch {
    return rootUnsupportedResult(platformResult, 'root-stat-failed', null);
  }

  if (!canonicalStats.isDirectory()) {
    return rootUnsupportedResult(platformResult, 'root-not-directory', null);
  }

  let requestedStats: PlatformStats;
  try {
    requestedStats = await fs.stat(root);
  } catch {
    return rootUnsupportedResult(platformResult, 'root-stat-failed', null);
  }

  const identityStableAtProbe = sameFileIdentity(canonicalStats, requestedStats);
  if (!identityStableAtProbe) {
    return rootUnsupportedResult(platformResult, 'root-identity-changed', null);
  }

  let fileSystem: PlatformStatFs;
  try {
    fileSystem = await fs.statfs(canonicalRoot);
  } catch {
    return rootUnsupportedResult(platformResult, 'statfs-failed', null);
  }

  if (
    !isUsableDeviceFact(canonicalStats.dev) ||
    !isUsableDeviceFact(canonicalStats.ino) ||
    !isUsableFileSystemType(fileSystem.type)
  ) {
    return rootUnsupportedResult(platformResult, 'device-facts-invalid', null);
  }

  let finalRequestedStats: PlatformStats;
  try {
    finalRequestedStats = await fs.stat(root);
  } catch {
    return rootUnsupportedResult(platformResult, 'root-stat-failed', null);
  }
  if (!sameFileIdentity(canonicalStats, finalRequestedStats)) {
    return rootUnsupportedResult(platformResult, 'root-identity-changed', null);
  }
  const facts: FileSystemProbeFacts = Object.freeze({
    realPath: canonicalRoot,
    device: canonicalStats.dev,
    inode: canonicalStats.ino,
    fileSystemType: fileSystem.type,
    identityStableAtProbe,
  });

  if (platformResult.platform === 'darwin') {
    return probeMacosFileSystem(facts, options.macosVolumeInspector);
  }

  return probeLinuxFileSystem(facts, options.linuxDeviceInspector);
}

export function supportedResult(
  platform: string,
  authority: Exclude<PlatformAuthority, 'unsupported'>,
): PlatformProbeResult {
  return Object.freeze({
    platform,
    supported: true,
    authority,
    code: null,
    failStopReason: null,
  });
}

export function rootSupportedResult(
  platform: string,
  authority: Exclude<PlatformAuthority, 'unsupported'>,
  facts: FileSystemProbeFacts,
): ProjectRootProbeResult {
  return Object.freeze({
    ...supportedResult(platform, authority),
    facts,
  });
}

export function unsupportedResult(
  platform: string,
  failStopReason: PlatformFailStopReason,
): PlatformProbeResult {
  return Object.freeze({
    platform,
    supported: false,
    authority: 'unsupported',
    code: PLATFORM_UNSUPPORTED_CODE,
    failStopReason,
  });
}

export function rootUnsupportedResult(
  platformResult: PlatformProbeResult,
  failStopReason: PlatformFailStopReason,
  facts: FileSystemProbeFacts | null,
): ProjectRootProbeResult {
  return Object.freeze({
    ...unsupportedResult(platformResult.platform, failStopReason),
    facts,
  });
}

function sameFileIdentity(left: PlatformStats, right: PlatformStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function isUsableDeviceFact(value: number | bigint): boolean {
  return typeof value === 'bigint' ? value > 0n : Number.isSafeInteger(value) && value > 0;
}

function isUsableFileSystemType(value: number | bigint): boolean {
  return typeof value === 'bigint' ? value > 0n : Number.isSafeInteger(value) && value > 0;
}
