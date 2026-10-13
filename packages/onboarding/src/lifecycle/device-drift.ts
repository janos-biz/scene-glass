/*
 * A volume's st_dev is assigned at mount time, so on macOS every reboot can
 * renumber the device that setup recorded while leaving each file otherwise
 * untouched. The recorded (device, inode) pairs then fail identity validation
 * even though nothing was replaced, and setup cannot re-establish them because
 * it returns early on an active install.
 *
 * This reconciles that one shape and nothing else. Every recorded inode must
 * still match the live entry at its recorded path, every live entry must sit on
 * one shared device, and the descriptor's recorded fingerprint must be
 * reproducible from its current bytes with the device values wound back. A
 * single mismatched inode, a wrong entry kind, identities spread across
 * volumes, or any descriptor edit that is not a device value leaves the stored
 * records alone so ordinary validation reports the real conflict.
 */
import { createHash } from 'node:crypto';
import { basename, join } from 'node:path';

const DESCRIPTOR_BASENAME = 'host-descriptor.v1.json';
const MAX_DRIFT_DOCUMENT_BYTES = 1024 * 1024;

export type DeviceDriftOutcome = 'unchanged' | 'repaired' | 'unrepairable';

export interface DeviceDriftStat {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
  isFile: () => boolean;
  isDirectory: () => boolean;
  isSymbolicLink: () => boolean;
}

export interface DeviceDriftPort {
  /** Must not follow symlinks. */
  readonly lstat: (path: string) => Promise<DeviceDriftStat>;
  /** Resolves undefined when the path is absent or not a readable regular file. */
  readonly readUtf8: (path: string) => Promise<string | undefined>;
  /** Must replace the target atomically and preserve mode 0600. */
  readonly writeUtf8: (path: string, text: string) => Promise<void>;
}

type JsonRecord = Record<string, unknown>;

/** One recorded identity, paired with the live path that must still carry it. */
interface IdentitySite {
  readonly holder: JsonRecord;
  readonly inode: string;
  /** Candidate paths; exactly one must be a live entry with `inode`. */
  readonly candidates: readonly string[];
  readonly kind: 'file' | 'directory';
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function recordArray(value: unknown): readonly JsonRecord[] {
  return Array.isArray(value) ? value.filter((item): item is JsonRecord => isRecord(item)) : [];
}

function decimalField(holder: JsonRecord, key: string): string | undefined {
  const value = holder[key];
  return typeof value === 'string' && /^(?:0|[1-9]\d*)$/.test(value) ? value : undefined;
}

/** Collects `holder` when it carries a decimal device/inode pair. */
function identitySite(
  holder: unknown,
  candidates: readonly string[],
  kind: IdentitySite['kind'],
): IdentitySite | undefined {
  if (!isRecord(holder) || candidates.length === 0) return undefined;
  const inode = decimalField(holder, 'inode');
  if (inode === undefined || decimalField(holder, 'device') === undefined) return undefined;
  return { holder, inode, candidates, kind };
}

function pushSite(target: IdentitySite[], site: IdentitySite | undefined): void {
  if (site !== undefined) target.push(site);
}

/**
 * Registry entries carry their own credential path; the enclosing document only
 * supplies it for the manifest's embedded registry images.
 */
function collectRegistryProjectSites(
  projects: readonly JsonRecord[],
  target: IdentitySite[],
): void {
  for (const project of projects) {
    const path = project['credentialPath'];
    if (typeof path !== 'string' || path.length === 0) continue;
    pushSite(target, identitySite(project, [path], 'file'));
  }
}

function collectManifestSites(manifest: JsonRecord, target: IdentitySite[]): void {
  for (const artifact of recordArray(manifest['artifacts'])) {
    const path = artifact['path'];
    const kind = artifact['kind'] === 'directory' ? 'directory' : 'file';
    if (typeof path === 'string' && path.length !== 0) {
      pushSite(target, identitySite(artifact['identity'], [path], kind));
      const inverse = artifact['inverse'];
      if (isRecord(inverse)) {
        pushSite(target, identitySite(inverse['identity'], [path], kind));
      }
    }
    for (const image of [
      artifact['postimage'],
      (artifact['inverse'] as JsonRecord)?.['postimage'],
    ]) {
      if (isRecord(image)) collectRegistryProjectSites(recordArray(image['projects']), target);
    }
  }
}

/**
 * The approved root is the project root for framework hosts and its `public`
 * directory for static ones. Rather than reproduce that branch, offer both and
 * let the recorded inode select.
 */
function collectDescriptorSites(
  descriptor: JsonRecord,
  registryProjects: readonly JsonRecord[],
  target: IdentitySite[],
): void {
  for (const authority of recordArray(descriptor['credentialAuthorities'])) {
    const path = authority['path'];
    if (typeof path !== 'string' || path.length === 0) continue;
    pushSite(target, identitySite(authority, [path], 'file'));
  }
  const projectId = descriptor['credentialProjectId'] ?? descriptor['projectId'];
  const project = registryProjects.find((entry) => entry['projectId'] === projectId);
  const root = project?.['canonicalRoot'];
  if (typeof root !== 'string' || root.length === 0) return;
  pushSite(
    target,
    identitySite(descriptor['approvedRootIdentity'], [root, join(root, 'public')], 'directory'),
  );
}

/**
 * Resolves the one live device shared by every recorded identity, or undefined
 * when any site fails to verify or the identities span more than one volume.
 */
async function liveDevice(
  port: DeviceDriftPort,
  sites: readonly IdentitySite[],
): Promise<string | undefined> {
  let device: string | undefined;
  for (const site of sites) {
    let matched = false;
    for (const candidate of site.candidates) {
      let stat: DeviceDriftStat;
      try {
        stat = await port.lstat(candidate);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;
      if (!(site.kind === 'directory' ? stat.isDirectory() : stat.isFile())) continue;
      if (String(stat.ino) !== site.inode) continue;
      const live = String(stat.dev);
      if (device !== undefined && device !== live) return undefined;
      device = live;
      matched = true;
      break;
    }
    if (!matched) return undefined;
  }
  return device;
}

function sha256Fingerprint(text: string): string {
  return `sha256:${createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex')}`;
}

/** Canonical form for every document this repairs; verified against the read bytes. */
function serialize(document: unknown): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

async function readDocument(
  port: DeviceDriftPort,
  path: string,
): Promise<{ readonly document: JsonRecord; readonly text: string } | undefined> {
  const text = await port.readUtf8(path);
  if (text === undefined || text.length > MAX_DRIFT_DOCUMENT_BYTES) return undefined;
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return undefined;
  }
  // A document this cannot reproduce byte for byte is not one it may rewrite.
  if (!isRecord(document) || serialize(document) !== text) return undefined;
  return { document, text };
}

function descriptorPathFrom(manifest: JsonRecord): string | undefined {
  for (const artifact of recordArray(manifest['artifacts'])) {
    const path = artifact['path'];
    if (typeof path === 'string' && basename(path) === DESCRIPTOR_BASENAME) return path;
  }
  return undefined;
}

/** The artifact's own fingerprint, its hunk fingerprints, and its inverse expectation. */
function descriptorFingerprintSlots(manifest: JsonRecord, descriptorPath: string): JsonRecord[] {
  const slots: JsonRecord[] = [];
  for (const artifact of recordArray(manifest['artifacts'])) {
    if (artifact['path'] !== descriptorPath) continue;
    if (typeof artifact['fingerprint'] === 'string') slots.push(artifact);
    for (const hunk of recordArray(artifact['hunks'])) {
      if (typeof hunk['fingerprint'] === 'string') slots.push(hunk);
    }
    const inverse = artifact['inverse'];
    if (isRecord(inverse) && typeof inverse['expectedFingerprint'] === 'string') {
      slots.push(inverse);
    }
  }
  return slots;
}

function fingerprintOf(slot: JsonRecord): string {
  return (slot['fingerprint'] ?? slot['expectedFingerprint']) as string;
}

function setFingerprint(slot: JsonRecord, value: string): void {
  if (typeof slot['fingerprint'] === 'string') slot['fingerprint'] = value;
  else slot['expectedFingerprint'] = value;
}

/**
 * Proves the descriptor's recorded fingerprint is reachable from its current
 * bytes by winding the device values back to one of the devices still recorded
 * somewhere. Any other edit to the descriptor leaves this unproven.
 */
function descriptorFingerprintIsDeviceOnly(
  descriptor: JsonRecord,
  descriptorSites: readonly IdentitySite[],
  recorded: string,
  candidateDevices: ReadonlySet<string>,
): boolean {
  const current = descriptorSites.map((site) => site.holder['device']);
  try {
    for (const device of candidateDevices) {
      for (const site of descriptorSites) site.holder['device'] = device;
      if (sha256Fingerprint(serialize(descriptor)) === recorded) return true;
    }
    return false;
  } finally {
    descriptorSites.forEach((site, index) => {
      site.holder['device'] = current[index];
    });
  }
}

/**
 * Reconciles recorded device numbers with the volume the recorded inodes now
 * live on. Returns 'unchanged' when nothing drifted and 'unrepairable' when the
 * drift is not a plain renumbering, in which case no file is touched.
 */
export async function repairDeviceDrift(
  port: DeviceDriftPort,
  input: Readonly<{ readonly manifestPath: string; readonly registryPath: string }>,
): Promise<DeviceDriftOutcome> {
  const manifestRead = await readDocument(port, input.manifestPath);
  const registryRead = await readDocument(port, input.registryPath);
  if (manifestRead === undefined || registryRead === undefined) return 'unrepairable';

  const descriptorPath = descriptorPathFrom(manifestRead.document);
  if (descriptorPath === undefined) return 'unrepairable';
  const descriptorRead = await readDocument(port, descriptorPath);
  if (descriptorRead === undefined) return 'unrepairable';

  const registryProjects = recordArray(registryRead.document['projects']);
  const manifestSites: IdentitySite[] = [];
  const registrySites: IdentitySite[] = [];
  const descriptorSites: IdentitySite[] = [];
  collectManifestSites(manifestRead.document, manifestSites);
  collectRegistryProjectSites(registryProjects, registrySites);
  collectDescriptorSites(descriptorRead.document, registryProjects, descriptorSites);

  const sites = [...manifestSites, ...registrySites, ...descriptorSites];
  if (sites.length === 0) return 'unrepairable';

  const device = await liveDevice(port, sites);
  if (device === undefined) return 'unrepairable';
  if (sites.every((site) => site.holder['device'] === device)) return 'unchanged';

  const fingerprintSlots = descriptorFingerprintSlots(manifestRead.document, descriptorPath);
  if (fingerprintSlots.length === 0) return 'unrepairable';
  const recordedFingerprint = fingerprintOf(fingerprintSlots[0]!);
  if (fingerprintSlots.some((slot) => fingerprintOf(slot) !== recordedFingerprint)) {
    return 'unrepairable';
  }
  const candidateDevices = new Set(sites.map((site) => String(site.holder['device'])));
  if (
    !descriptorFingerprintIsDeviceOnly(
      descriptorRead.document,
      descriptorSites,
      recordedFingerprint,
      candidateDevices,
    )
  ) {
    return 'unrepairable';
  }

  for (const site of sites) site.holder['device'] = device;
  const descriptorText = serialize(descriptorRead.document);
  for (const slot of fingerprintSlots) setFingerprint(slot, sha256Fingerprint(descriptorText));

  /*
   * Descriptor first, manifest last: the manifest is the only document that
   * carries the descriptor's fingerprint, so an interrupted run leaves the
   * fingerprint still reachable by winding devices back and the next run
   * completes. The reverse order would strand it.
   */
  await port.writeUtf8(descriptorPath, descriptorText);
  await port.writeUtf8(input.registryPath, serialize(registryRead.document));
  await port.writeUtf8(input.manifestPath, serialize(manifestRead.document));
  return 'repaired';
}
