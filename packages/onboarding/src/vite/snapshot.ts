import { createHash, randomUUID } from 'node:crypto';
import type { Dirent } from 'node:fs';
import { lstat, opendir } from 'node:fs/promises';
import { basename, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';

import { parseCanonicalOpaqueToken, SceneGlassContractError } from '@scene-glass/contracts';

import {
  MAX_CREDENTIAL_AUTHORITIES,
  MAX_NATIVE_READ_BYTES,
  OnboardingNativeError,
  secureReadBeneath,
  zeroizeBuffer,
} from '../native.js';
import type { CredentialAuthority, FileIdentity } from '../types.js';

export const VITE_SNAPSHOT_MAX_FILES = 1_000;
export const VITE_SNAPSHOT_MAX_BYTES = 64 * 1024 * 1024;
export const VITE_SNAPSHOT_MAX_DEPTH = 8;
export const VITE_SNAPSHOT_MAX_DIRECTORY_ENTRIES =
  VITE_SNAPSHOT_MAX_FILES * (VITE_SNAPSHOT_MAX_DEPTH + 1) + 2;
export const VITE_SNAPSHOT_ROOT_DIRECTORY = '.scg/runtime/vite-root';
export const VITE_SNAPSHOT_CANARY_MAX_BYTES = 4 * 1024;
export const VITE_SNAPSHOT_COMMITMENT_MAX_BYTES = 1024 * 1024;
export const VITE_SNAPSHOT_COMMITMENT_DIRECTORY = '.scg/runtime/vite-provenance';

export const VITE_SNAPSHOT_AUTHORITY_MAX_BYTES = 1024;
const STAGING_DIRECTORY = '.scg/runtime/vite-staging';
const DECIMAL_STRING = /^(?:0|[1-9][0-9]*)$/;
const MAX_UNSIGNED_64 = 18_446_744_073_709_551_615n;
const MAX_SNAPSHOT_AUTHORITY_IDENTITY_DIGITS = 20;
const GENERATED_PACKAGE_JSON =
  '{"name":"scene-glass-vite-snapshot","private":true,"type":"module"}\n';
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });
const SOURCE_MAP_URL_SUFFIX = String.fromCodePoint(85, 82, 76);
const SOURCE_MAP_DIRECTIVE = new RegExp(
  String.raw`\/\/\s*# sourceMapping${SOURCE_MAP_URL_SUFFIX}=|\/\*# sourceMapping${SOURCE_MAP_URL_SUFFIX}=`,
  'i',
);
const FORBIDDEN_TEXT = [
  'data-scg-token',
  'SCENE_GLASS_HOST_TOKEN',
  'VITE_SCENE_GLASS_',
  'scene-glass:static-loader',
] as const;
const FORBIDDEN_TEXT_BYTES = Object.freeze(
  FORBIDDEN_TEXT.map((value) => new TextEncoder().encode(value)),
);
const SOURCE_EXTENSIONS = new Set([
  '.css',
  '.cts',
  '.d.ts',
  '.gif',
  '.ico',
  '.jpeg',
  '.jpg',
  '.js',
  '.json',
  '.jsx',
  '.mjs',
  '.mts',
  '.png',
  '.svg',
  '.ts',
  '.tsx',
  '.vue',
  '.webp',
  '.woff',
  '.woff2',
]);
const PUBLIC_EXTENSIONS = new Set([
  '.css',
  '.gif',
  '.ico',
  '.jpeg',
  '.jpg',
  '.js',
  '.json',
  '.mjs',
  '.png',
  '.svg',
  '.txt',
  '.webp',
  '.woff',
  '.woff2',
]);

export interface SameFdSnapshotReadRequest {
  readonly root: string;
  readonly rootIdentity: FileIdentity;
  readonly relativePath: string;
  readonly deniedIdentities: readonly FileIdentity[];
  readonly maxBytes: number;
}

/**
 * The native authority adapter must return bytes from the same no-follow file
 * descriptor it checked. The snapshot never reads host content through Node's
 * path-based read APIs.
 */
export interface SameFdSnapshotReader {
  read(request: SameFdSnapshotReadRequest): Promise<SameFdSnapshotReadResult>;
}

export type SameFdSnapshotReadResult =
  | {
      readonly status: 'ok';
      readonly bytes: Buffer;
      readonly identity: FileIdentity;
      readonly linkCount: number;
      readonly regularFile: true;
    }
  | {
      readonly status: 'missing' | 'replaced' | 'unsafe' | 'too-large' | 'denied';
    };
export interface ViteSnapshotStagingAuthority {
  readonly stagingRoot: string;
  writeFile(input: {
    readonly relativePath: string;
    readonly bytes: Uint8Array;
    readonly mode: number;
  }): Promise<void>;
}

export interface ViteSnapshotPublishedAuthority {
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
}

/**
 * This authority owns retained no-follow directory descriptors for the project
 * root, staging root, snapshot root, and provenance directory. Its operations
 * must be relative to those descriptors and must never fall back to paths.
 */
export interface ViteSnapshotPublicationAuthority {
  createStaging(input: {
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
    readonly stagingName: string;
  }): Promise<ViteSnapshotStagingAuthority>;
  publish(input: {
    readonly approvedRootIdentity: FileIdentity;
    readonly installId: string;
    readonly staging: ViteSnapshotStagingAuthority;
  }): Promise<ViteSnapshotPublishedAuthority>;
  persistCommitment(input: {
    readonly installId: string;
    readonly bytes: Uint8Array;
    readonly published: ViteSnapshotPublishedAuthority;
  }): Promise<void>;
  discardStaging(input: { readonly staging: ViteSnapshotStagingAuthority }): Promise<void>;
  removePublished(input: { readonly published: ViteSnapshotPublishedAuthority }): Promise<void>;
}

export interface ViteSnapshotCredentialCanary {
  readonly projectId: string;
  readonly bytes: Uint8Array;
}

export interface ViteSnapshotInput {
  readonly projectRoot: string;
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
  readonly credentialCanaries: readonly ViteSnapshotCredentialCanary[];
  readonly installId: string;
  readonly reader?: SameFdSnapshotReader;
  /**
   * Retained descriptor authority for every snapshot write, publication, and
   * cleanup operation. There is intentionally no path-based fallback.
   */
  readonly publicationAuthority: ViteSnapshotPublicationAuthority;
}

export interface ViteSnapshotFile {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface ViteSnapshotProvenance {
  readonly sourceRootIdentity: FileIdentity;
  readonly files: readonly ViteSnapshotFile[];
  readonly fileCount: number;
  readonly totalBytes: number;
}
export interface CommittedViteSnapshotFile extends ViteSnapshotFile {
  readonly identity: FileIdentity;
  readonly linkCount: number;
}

export interface CommittedViteSnapshotProvenance {
  readonly version: 1;
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
  readonly files: readonly CommittedViteSnapshotFile[];
  /** SHA-256 of the canonical commitment fields, excluding this digest. */
  readonly commitmentDigest: string;
}

export interface ViteSnapshotAuthority {
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
  readonly commitmentDigest: string;
}
/**
 * Canonical, bounded transport for the setup/WAL-owned snapshot authority.
 * This carries no filesystem-derived fallback facts at runtime.
 */
export function serializeViteSnapshotAuthorityJson(authority: ViteSnapshotAuthority): string {
  const canonical = freezeSnapshotAuthorityTransport(authority);
  const serialized = `${JSON.stringify(
    {
      syntheticRoot: canonical.syntheticRoot,
      rootIdentity: {
        device: canonical.rootIdentity.device,
        inode: canonical.rootIdentity.inode,
      },
      commitmentDigest: canonical.commitmentDigest,
    },
    null,
    2,
  )}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > VITE_SNAPSHOT_AUTHORITY_MAX_BYTES) {
    snapshotAuthorityTransportError();
  }
  return serialized;
}

/**
 * Accepts only the exact canonical authority issued by setup/WAL for one
 * already-derived descriptor synthetic root.
 */
export function parseViteSnapshotAuthorityJson(
  serialized: string,
  expectedSyntheticRoot: string,
): ViteSnapshotAuthority {
  if (
    typeof serialized !== 'string' ||
    Buffer.byteLength(serialized, 'utf8') > VITE_SNAPSHOT_AUTHORITY_MAX_BYTES ||
    !isCanonicalSnapshotAuthorityRoot(expectedSyntheticRoot)
  ) {
    snapshotAuthorityTransportError();
  }

  let candidate: unknown;
  try {
    candidate = JSON.parse(serialized);
  } catch {
    snapshotAuthorityTransportError();
  }
  const authority = freezeSnapshotAuthorityTransport(candidate);
  if (
    authority.syntheticRoot !== expectedSyntheticRoot ||
    serializeViteSnapshotAuthorityJson(authority) !== serialized
  ) {
    snapshotAuthorityTransportError();
  }
  return authority;
}

export interface ViteSnapshotCleanupFailure extends AggregateError {
  /** Retries the retained opaque cleanup handle without republishing a snapshot. */
  readonly retryCleanup: () => Promise<void>;
}

export interface PreparedViteSnapshot {
  /** The tokenless root Vite receives after commit. */
  readonly syntheticRoot: string;
  /** Setup/WAL owns this temporary path until commit or discard. */
  readonly stagingRoot: string;
  readonly provenance: ViteSnapshotProvenance;
  commit(): Promise<CommittedViteSnapshotProvenance>;
  discard(): Promise<void>;
  /**
   * Retries a pending cleanup through the exact retained authority handle.
   * This is a no-op after terminal cleanup release.
   */
  retryCleanup(): Promise<void>;
}

interface CandidateFile {
  readonly relativePath: string;
}

type ViteSnapshotLifecycleState =
  | 'preparing'
  | 'ready'
  | 'publishing'
  | 'published'
  | 'staging-cleanup'
  | 'published-cleanup'
  | 'released'
  | 'committed';
interface SnapshotPreparationFacts {
  readonly projectRoot: string;
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
  readonly credentialCanaries: readonly Buffer[];
  readonly installId: string;
  readonly reader: SameFdSnapshotReader;
  readonly publicationAuthority: ViteSnapshotPublicationAuthority;
}
interface SnapshotTraversalBudget {
  entries: number;
}
function snapshotViteSnapshotInput(input: unknown): SnapshotPreparationFacts {
  if (!isRecord(input)) {
    snapshotError('snapshot input is invalid');
  }
  let credentialCanaries: readonly Buffer[] = [];
  try {
    const projectRoot = canonicalSnapshotProjectRoot(input.projectRoot);
    const approvedRootIdentity = copySnapshotFileIdentity(input.approvedRootIdentity);
    const credentialAuthorities = snapshotCredentialAuthorities(input.credentialAuthorities);
    credentialCanaries = assertAuthorityCompleteCanaries(
      credentialAuthorities,
      input.credentialCanaries,
    );
    const installId = parseSnapshotInstallId(input.installId);
    const reader =
      input.reader === undefined
        ? createNativeSameFdSnapshotReader()
        : snapshotSameFdSnapshotReader(input.reader);
    const publicationAuthority = assertPublicationAuthority(input.publicationAuthority);
    return Object.freeze({
      projectRoot,
      approvedRootIdentity,
      credentialAuthorities,
      credentialCanaries,
      installId,
      reader,
      publicationAuthority,
    });
  } catch (error: unknown) {
    zeroizeSnapshotCanaries(credentialCanaries);
    throw error;
  }
}
function canonicalSnapshotProjectRoot(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    snapshotError('snapshot project root is invalid');
  }
  const projectRoot = resolve(value);
  if (projectRoot === '/') {
    snapshotError('snapshot project root is invalid');
  }
  return projectRoot;
}
function copySnapshotFileIdentity(value: unknown): FileIdentity {
  if (!isSnapshotAuthorityIdentity(value)) {
    snapshotError('snapshot file identity is invalid');
  }
  return Object.freeze({ device: value.device, inode: value.inode });
}
function snapshotCredentialAuthorities(value: unknown): readonly CredentialAuthority[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_CREDENTIAL_AUTHORITIES) {
    snapshotError('credential authorities must be non-empty');
  }
  const authorities: CredentialAuthority[] = [];
  const projectIds = new Set<string>();
  const paths = new Set<string>();
  const identities = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const source = value[index];
    if (!isRecord(source)) {
      snapshotError('credential authority is invalid');
    }
    const projectId = source.projectId;
    const path = source.path;
    const device = source.device;
    const inode = source.inode;
    if (
      typeof projectId !== 'string' ||
      projectId.length === 0 ||
      projectId.includes('\0') ||
      Buffer.byteLength(projectId, 'utf8') > 128 ||
      typeof path !== 'string' ||
      path.length === 0 ||
      Buffer.byteLength(path, 'utf8') > 4 * 1024 ||
      path.includes('\0') ||
      !path.startsWith('/') ||
      path === '/' ||
      resolve(path) !== path
    ) {
      snapshotError('credential authority is invalid');
    }
    const identity = copySnapshotFileIdentity(Object.freeze({ device, inode }));
    const identityKey = `${identity.device}\u0000${identity.inode}`;
    if (projectIds.has(projectId) || paths.has(path) || identities.has(identityKey)) {
      snapshotError('credential authorities must be distinct');
    }
    projectIds.add(projectId);
    paths.add(path);
    identities.add(identityKey);
    authorities.push(
      Object.freeze({
        projectId,
        path,
        device: identity.device,
        inode: identity.inode,
      }),
    );
  }
  return Object.freeze(authorities);
}
function snapshotDeniedIdentities(value: unknown): readonly FileIdentity[] {
  if (!Array.isArray(value) || value.length > MAX_CREDENTIAL_AUTHORITIES) {
    snapshotError('snapshot denied identities are invalid');
  }
  const identities: FileIdentity[] = [];
  const known = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const identity = copySnapshotFileIdentity(value[index]);
    const key = `${identity.device}\u0000${identity.inode}`;
    if (known.has(key)) {
      snapshotError('snapshot denied identities are invalid');
    }
    known.add(key);
    identities.push(identity);
  }
  return Object.freeze(identities);
}
function parseSnapshotInstallId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 128 ||
    /[^a-zA-Z0-9_-]/.test(value)
  ) {
    snapshotError('snapshot installId is invalid');
  }
  return value;
}
function snapshotSameFdSnapshotReader(value: unknown): SameFdSnapshotReader {
  if (!isRecord(value) || typeof value.read !== 'function') {
    snapshotError('snapshot reader is invalid');
  }
  const read = value.read;
  return Object.freeze<SameFdSnapshotReader>({
    async read(request: SameFdSnapshotReadRequest): Promise<SameFdSnapshotReadResult> {
      return Reflect.apply(read, value, [request]) as Promise<SameFdSnapshotReadResult>;
    },
  });
}

/**
 * Copies only the supported Vite input closure into a setup-owned synthetic
 * root. This is intentionally a prepare/commit pair so WAL publication can
 * own the final root transition. No credential is read by this operation.
 */
export async function prepareViteSnapshot(input: ViteSnapshotInput): Promise<PreparedViteSnapshot> {
  const facts = snapshotViteSnapshotInput(input);
  try {
    const {
      projectRoot,
      approvedRootIdentity,
      credentialAuthorities,
      credentialCanaries,
      installId,
      reader,
      publicationAuthority,
    } = facts;
    await assertNoFollowDirectoryIdentity(projectRoot, approvedRootIdentity);
    await assertNoFollowSetupAncestors(projectRoot);

    const syntheticRoot = join(projectRoot, VITE_SNAPSHOT_ROOT_DIRECTORY, installId);
    const stagingName = `${installId}-${randomUUID()}`;
    const stagingRoot = join(projectRoot, STAGING_DIRECTORY, stagingName);
    const deniedIdentities = Object.freeze(
      credentialAuthorities.map(({ device, inode }) => Object.freeze({ device, inode })),
    );
    const files = await collectCandidates(projectRoot);
    let totalBytes = 0;
    const provenanceFiles: ViteSnapshotFile[] = [];
    let staging: ViteSnapshotStagingAuthority | undefined;
    let published: ViteSnapshotPublishedAuthority | undefined;
    let lifecycleState: ViteSnapshotLifecycleState = 'preparing';
    let primaryFailure: unknown;
    let hasPrimaryFailure = false;
    let cleanupAttempt: Promise<void> | undefined;

    async function releasePendingCleanup(): Promise<void> {
      if (lifecycleState === 'staging-cleanup') {
        if (staging === undefined) {
          snapshotError('snapshot staging cleanup handle is unavailable');
        }
        await publicationAuthority.discardStaging({ staging });
      } else if (lifecycleState === 'published-cleanup') {
        if (published === undefined) {
          snapshotError('snapshot publication cleanup handle is unavailable');
        }
        await publicationAuthority.removePublished({ published });
      } else {
        snapshotError('snapshot cleanup is not pending');
      }

      lifecycleState = 'released';
      hasPrimaryFailure = false;
      primaryFailure = undefined;
    }

    async function retryCleanup(): Promise<void> {
      if (lifecycleState === 'released') {
        return;
      }
      if (cleanupAttempt !== undefined) {
        return cleanupAttempt;
      }

      const attempt = (async (): Promise<void> => {
        try {
          await releasePendingCleanup();
        } catch (cleanupError: unknown) {
          if (hasPrimaryFailure) {
            throw snapshotCleanupFailure(
              primaryFailure,
              cleanupError,
              lifecycleState === 'staging-cleanup'
                ? 'Vite snapshot preparation failed and staging cleanup also failed'
                : 'Vite snapshot commit failed and publication cleanup also failed',
              retryCleanup,
            );
          }
          throw cleanupError;
        } finally {
          cleanupAttempt = undefined;
        }
      })();
      cleanupAttempt = attempt;
      return attempt;
    }

    try {
      staging = await publicationAuthority.createStaging({
        approvedRootIdentity,
        installId,
        stagingName,
      });
      if (resolve(staging.stagingRoot) !== stagingRoot) {
        snapshotError('snapshot publication authority returned an invalid staging root');
      }
      await staging.writeFile({
        relativePath: 'package.json',
        bytes: Buffer.from(GENERATED_PACKAGE_JSON, 'utf8'),
        mode: 0o600,
      });

      for (const file of files) {
        const remainingBytes = VITE_SNAPSHOT_MAX_BYTES - totalBytes;
        const result = await reader.read({
          root: projectRoot,
          rootIdentity: approvedRootIdentity,
          relativePath: file.relativePath,
          deniedIdentities,
          maxBytes: Math.min(remainingBytes, MAX_NATIVE_READ_BYTES),
        });
        if (result.status !== 'ok') {
          snapshotError(`native read rejected ${file.relativePath} as ${result.status}`);
        }
        try {
          if (!result.regularFile || result.linkCount !== 1) {
            snapshotError(
              `snapshot input must be a non-hardlinked regular file: ${file.relativePath}`,
            );
          }
          if (matchesIdentity(result.identity, deniedIdentities)) {
            snapshotError(`snapshot input is a credential authority: ${file.relativePath}`);
          }
          if (result.bytes.byteLength > remainingBytes) {
            snapshotError('snapshot exceeds the aggregate byte limit');
          }
          assertSafeContent(file.relativePath, result.bytes, credentialCanaries);
          await staging.writeFile({
            relativePath: file.relativePath,
            bytes: result.bytes,
            mode: 0o600,
          });

          totalBytes += result.bytes.byteLength;
          provenanceFiles.push(
            Object.freeze({
              path: file.relativePath,
              sha256: sha256(result.bytes),
              bytes: result.bytes.byteLength,
            }),
          );
        } finally {
          zeroizeBuffer(result.bytes);
        }
      }
    } catch (error: unknown) {
      if (staging === undefined) {
        throw error;
      }
      lifecycleState = 'staging-cleanup';
      hasPrimaryFailure = true;
      primaryFailure = error;
      await retryCleanup();
      throw error;
    }

    if (staging === undefined) {
      snapshotError('snapshot publication authority did not create a staging root');
    }
    const preparedStaging = staging;
    const provenance = Object.freeze({
      sourceRootIdentity: approvedRootIdentity,
      files: Object.freeze(provenanceFiles),
      fileCount: provenanceFiles.length,
      totalBytes,
    });
    lifecycleState = 'ready';

    return Object.freeze({
      syntheticRoot,
      stagingRoot,
      provenance,
      async commit(): Promise<CommittedViteSnapshotProvenance> {
        if (lifecycleState === 'published-cleanup') {
          if (!hasPrimaryFailure) {
            snapshotError('snapshot cleanup state is invalid');
          }
          const originalFailure = primaryFailure;
          await retryCleanup();
          throw originalFailure;
        }
        if (lifecycleState !== 'ready') {
          snapshotError('snapshot transaction was already completed');
        }

        lifecycleState = 'publishing';
        try {
          published = await publicationAuthority.publish({
            approvedRootIdentity,
            installId,
            staging: preparedStaging,
          });
        } catch (error: unknown) {
          lifecycleState = 'ready';
          throw error;
        }
        lifecycleState = 'published';

        try {
          const publishedHandle = published;
          if (publishedHandle === undefined) {
            snapshotError('snapshot publication authority did not return a published handle');
          }
          const publishedSnapshot = snapshotPublishedAuthority(publishedHandle, syntheticRoot);
          const commitment = await createCommittedViteSnapshotProvenance({
            syntheticRoot,
            rootIdentity: publishedSnapshot.rootIdentity,
            files: [
              ...provenanceFiles,
              Object.freeze({
                path: 'package.json',
                sha256: sha256(Buffer.from(GENERATED_PACKAGE_JSON, 'utf8')),
                bytes: Buffer.byteLength(GENERATED_PACKAGE_JSON, 'utf8'),
              }),
            ],
            deniedIdentities,
            reader,
          });
          const serialized = Buffer.from(JSON.stringify(commitment), 'utf8');
          try {
            await publicationAuthority.persistCommitment({
              installId,
              bytes: serialized,
              published: publishedHandle,
            });
          } finally {
            zeroizeBuffer(serialized);
          }
          lifecycleState = 'committed';
          return commitment;
        } catch (error: unknown) {
          lifecycleState = 'published-cleanup';
          hasPrimaryFailure = true;
          primaryFailure = error;
          await retryCleanup();
          throw error;
        }
      },
      async discard(): Promise<void> {
        if (lifecycleState === 'staging-cleanup') {
          await retryCleanup();
          return;
        }
        if (lifecycleState !== 'ready') {
          snapshotError('snapshot transaction was already completed');
        }

        lifecycleState = 'staging-cleanup';
        hasPrimaryFailure = false;
        primaryFailure = undefined;
        await retryCleanup();
      },
      retryCleanup,
    });
  } finally {
    zeroizeSnapshotCanaries(facts.credentialCanaries);
  }
}

function snapshotCleanupFailure(
  primaryError: unknown,
  cleanupError: unknown,
  message: string,
  retryCleanup: () => Promise<void>,
): ViteSnapshotCleanupFailure {
  const failure = new AggregateError([primaryError, cleanupError], message, {
    cause: primaryError,
  }) as ViteSnapshotCleanupFailure;
  Object.defineProperty(failure, 'retryCleanup', {
    configurable: false,
    enumerable: false,
    value: retryCleanup,
    writable: false,
  });
  return failure;
}

export interface VerifyCommittedViteSnapshotInput {
  readonly projectRoot: string;
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
  readonly installId: string;
  readonly reader?: SameFdSnapshotReader;
  /**
   * Stored outside the mutable snapshot/provenance tree by the setup/WAL
   * authority. This is never derived from the on-disk commitment at startup.
   */
  readonly snapshotAuthority: ViteSnapshotAuthority;
}

export interface ReadCommittedViteSnapshotFileInput {
  readonly provenance: CommittedViteSnapshotProvenance;
  readonly relativePath: string;
  readonly deniedIdentities: readonly FileIdentity[];
  readonly reader?: SameFdSnapshotReader;
}

/** Reopens the setup-owned commitment through same-FD reads before Vite starts. */
export async function verifyCommittedViteSnapshot(
  input: VerifyCommittedViteSnapshotInput,
): Promise<CommittedViteSnapshotProvenance> {
  if (!isRecord(input)) {
    snapshotError('snapshot input is invalid');
  }
  const projectRoot = canonicalSnapshotProjectRoot(input.projectRoot);
  const approvedRootIdentity = copySnapshotFileIdentity(input.approvedRootIdentity);
  const credentialAuthorities = snapshotCredentialAuthorities(input.credentialAuthorities);
  const installId = parseSnapshotInstallId(input.installId);
  const expectedSyntheticRoot = join(projectRoot, VITE_SNAPSHOT_ROOT_DIRECTORY, installId);
  const snapshotAuthority = assertSnapshotAuthority(input.snapshotAuthority, expectedSyntheticRoot);
  const reader =
    input.reader === undefined
      ? createNativeSameFdSnapshotReader()
      : snapshotSameFdSnapshotReader(input.reader);
  const deniedIdentities = Object.freeze(
    credentialAuthorities.map(({ device, inode }) => Object.freeze({ device, inode })),
  );

  await assertNoFollowDirectoryIdentity(projectRoot, approvedRootIdentity);
  const serialized = await readSnapshotBytes(
    reader,
    projectRoot,
    approvedRootIdentity,
    `${VITE_SNAPSHOT_COMMITMENT_DIRECTORY}/${installId}.json`,
    deniedIdentities,
    VITE_SNAPSHOT_COMMITMENT_MAX_BYTES,
  );
  let parsed: CommittedViteSnapshotProvenance;
  try {
    parsed = parseCommittedViteSnapshotProvenance(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(serialized)),
      expectedSyntheticRoot,
    );
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      throw error;
    }
    snapshotError('committed Vite snapshot provenance is invalid');
  } finally {
    zeroizeBuffer(serialized);
  }

  if (
    !matchesIdentity(parsed.rootIdentity, [snapshotAuthority.rootIdentity]) ||
    parsed.commitmentDigest !== snapshotAuthority.commitmentDigest
  ) {
    snapshotError('committed Vite snapshot does not match its external authority');
  }
  await assertCommittedViteSnapshotFiles({
    syntheticRoot: parsed.syntheticRoot,
    rootIdentity: snapshotAuthority.rootIdentity,
    files: parsed.files,
    deniedIdentities,
    reader,
  });
  return parsed;
}

/** Reads only a committed snapshot file from the same no-follow descriptor it verifies. */
export async function readCommittedViteSnapshotFile(
  input: ReadCommittedViteSnapshotFileInput,
): Promise<Buffer | null> {
  const expected = input.provenance.files.find((file) => file.path === input.relativePath);
  if (expected === undefined) {
    return null;
  }
  const reader =
    input.reader === undefined
      ? createNativeSameFdSnapshotReader()
      : snapshotSameFdSnapshotReader(input.reader);
  const result = await reader.read({
    root: input.provenance.syntheticRoot,
    rootIdentity: input.provenance.rootIdentity,
    relativePath: expected.path,
    deniedIdentities: snapshotDeniedIdentities(input.deniedIdentities),
    maxBytes: Math.max(expected.bytes, 1),
  });
  if (result.status !== 'ok') {
    snapshotError('committed Vite snapshot file is unavailable');
  }
  try {
    if (
      !result.regularFile ||
      result.linkCount !== expected.linkCount ||
      !matchesIdentity(result.identity, [expected.identity]) ||
      result.bytes.byteLength !== expected.bytes ||
      sha256(result.bytes) !== expected.sha256
    ) {
      snapshotError('committed Vite snapshot file provenance changed');
    }
    return result.bytes;
  } catch (error: unknown) {
    zeroizeBuffer(result.bytes);
    throw error;
  }
}

async function createCommittedViteSnapshotProvenance(input: {
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
  readonly files: readonly ViteSnapshotFile[];
  readonly deniedIdentities: readonly FileIdentity[];
  readonly reader: SameFdSnapshotReader;
}): Promise<CommittedViteSnapshotProvenance> {
  const committedFiles = await assertCommittedViteSnapshotFiles(input);
  const unsigned = Object.freeze({
    version: 1 as const,
    syntheticRoot: input.syntheticRoot,
    rootIdentity: Object.freeze({ ...input.rootIdentity }),
    files: committedFiles,
  });
  return Object.freeze({
    ...unsigned,
    commitmentDigest: committedViteSnapshotDigest(unsigned),
  });
}

async function assertCommittedViteSnapshotFiles(input: {
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
  readonly files: readonly ViteSnapshotFile[];
  readonly deniedIdentities: readonly FileIdentity[];
  readonly reader: SameFdSnapshotReader;
}): Promise<readonly CommittedViteSnapshotFile[]> {
  const committed: CommittedViteSnapshotFile[] = [];
  const seenPaths = new Set<string>();
  for (const file of input.files) {
    assertCommittedSnapshotFile(file, seenPaths);
    const result = await input.reader.read({
      root: input.syntheticRoot,
      rootIdentity: input.rootIdentity,
      relativePath: file.path,
      deniedIdentities: input.deniedIdentities,
      maxBytes: Math.max(file.bytes, 1),
    });
    if (result.status !== 'ok') {
      snapshotError('committed Vite snapshot file is unavailable');
    }
    try {
      const expectedIdentity = (file as Partial<CommittedViteSnapshotFile>).identity;
      if (
        !result.regularFile ||
        result.linkCount !== 1 ||
        (expectedIdentity !== undefined && !matchesIdentity(result.identity, [expectedIdentity])) ||
        result.bytes.byteLength !== file.bytes ||
        sha256(result.bytes) !== file.sha256
      ) {
        snapshotError('committed Vite snapshot file provenance changed');
      }
      committed.push(
        Object.freeze({
          ...file,
          identity: Object.freeze({ ...result.identity }),
          linkCount: result.linkCount,
        }),
      );
    } finally {
      zeroizeBuffer(result.bytes);
    }
  }
  return Object.freeze(committed);
}

async function readSnapshotBytes(
  reader: SameFdSnapshotReader,
  root: string,
  rootIdentity: FileIdentity,
  relativePath: string,
  deniedIdentities: readonly FileIdentity[],
  maxBytes: number,
): Promise<Buffer> {
  const result = await reader.read({
    root,
    rootIdentity,
    relativePath,
    deniedIdentities,
    maxBytes,
  });
  if (result.status !== 'ok') {
    snapshotError('committed Vite snapshot read is unavailable');
  }
  if (!result.regularFile || result.linkCount !== 1) {
    zeroizeBuffer(result.bytes);
    snapshotError('committed Vite snapshot read is unsafe');
  }
  if (matchesIdentity(result.identity, deniedIdentities)) {
    zeroizeBuffer(result.bytes);
    snapshotError('committed Vite snapshot read is a credential authority');
  }
  return result.bytes;
}

export function parseCommittedViteSnapshotProvenance(
  value: unknown,
  expectedSyntheticRoot: string,
): CommittedViteSnapshotProvenance {
  if (
    !isExactRecord(value, ['version', 'syntheticRoot', 'rootIdentity', 'files', 'commitmentDigest'])
  ) {
    snapshotError('committed Vite snapshot provenance is invalid');
  }
  const rootIdentity = value.rootIdentity;
  const commitmentDigest = value.commitmentDigest;
  if (
    value.version !== 1 ||
    value.syntheticRoot !== expectedSyntheticRoot ||
    !isFileIdentity(rootIdentity) ||
    typeof commitmentDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(commitmentDigest)
  ) {
    snapshotError('committed Vite snapshot provenance is invalid');
  }
  if (
    !Array.isArray(value.files) ||
    value.files.length === 0 ||
    value.files.length > VITE_SNAPSHOT_MAX_FILES + 1
  ) {
    snapshotError('committed Vite snapshot provenance is invalid');
  }

  const files: CommittedViteSnapshotFile[] = [];
  const paths = new Set<string>();
  for (const file of value.files) {
    if (!isExactRecord(file, ['path', 'sha256', 'bytes', 'identity', 'linkCount'])) {
      snapshotError('committed Vite snapshot provenance is invalid');
    }
    const candidate: ViteSnapshotFile = {
      path: file.path as string,
      sha256: file.sha256 as string,
      bytes: file.bytes as number,
    };
    assertCommittedSnapshotFile(candidate, paths);
    const identity = file.identity;
    if (
      !isFileIdentity(identity) ||
      !Number.isSafeInteger(file.linkCount) ||
      file.linkCount !== 1
    ) {
      snapshotError('committed Vite snapshot provenance is invalid');
    }
    files.push(
      Object.freeze({
        ...candidate,
        identity: Object.freeze({ ...identity }),
        linkCount: file.linkCount,
      }),
    );
  }
  const unsigned = Object.freeze({
    version: 1 as const,
    syntheticRoot: expectedSyntheticRoot,
    rootIdentity: Object.freeze({ ...rootIdentity }),
    files: Object.freeze(files),
  });
  if (committedViteSnapshotDigest(unsigned) !== commitmentDigest) {
    snapshotError('committed Vite snapshot provenance digest is invalid');
  }
  return Object.freeze({
    ...unsigned,
    commitmentDigest,
  });
}

function assertCommittedSnapshotFile(file: ViteSnapshotFile, paths: Set<string>): void {
  if (
    typeof file.path !== 'string' ||
    file.path.length === 0 ||
    file.path.includes('\\') ||
    file.path
      .split('/')
      .some((segment) => segment.length === 0 || segment === '.' || segment === '..') ||
    typeof file.sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(file.sha256) ||
    !Number.isSafeInteger(file.bytes) ||
    file.bytes < 0 ||
    paths.has(file.path)
  ) {
    snapshotError('committed Vite snapshot provenance is invalid');
  }
  paths.add(file.path);
}
/** Returns the source files that may be copied; it never traverses host metadata. */
async function collectCandidates(projectRoot: string): Promise<readonly CandidateFile[]> {
  const candidates: CandidateFile[] = [{ relativePath: 'index.html' }];
  const traversalBudget: SnapshotTraversalBudget = { entries: 0 };

  await assertRegularCandidate(projectRoot, 'index.html', new Set(['.html']));
  await collectDirectoryCandidates(
    projectRoot,
    'src',
    SOURCE_EXTENSIONS,
    candidates,
    traversalBudget,
    1,
    false,
  );
  await collectDirectoryCandidates(
    projectRoot,
    'public',
    PUBLIC_EXTENSIONS,
    candidates,
    traversalBudget,
    1,
    true,
  );

  const tsconfig = await optionalSupportedTsconfig(projectRoot);
  if (tsconfig !== null) {
    candidates.push({ relativePath: tsconfig });
  }

  if (candidates.length > VITE_SNAPSHOT_MAX_FILES) {
    snapshotError('snapshot exceeds the file-count limit');
  }
  return Object.freeze(candidates);
}

async function collectDirectoryCandidates(
  projectRoot: string,
  relativeDirectory: string,
  extensionSet: ReadonlySet<string>,
  candidates: CandidateFile[],
  traversalBudget: SnapshotTraversalBudget,
  depth: number,
  optional: boolean,
): Promise<void> {
  const absoluteDirectory = join(projectRoot, ...relativeDirectory.split('/'));
  let directoryStat: Awaited<ReturnType<typeof lstat>>;
  try {
    directoryStat = await lstat(absoluteDirectory);
  } catch (error: unknown) {
    if (isMissing(error)) {
      if (optional) {
        return;
      }
      snapshotError(`required snapshot directory is missing: ${relativeDirectory}`);
    }
    throw error;
  }
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    snapshotError(`snapshot directory is unsafe: ${relativeDirectory}`);
  }
  if (depth > VITE_SNAPSHOT_MAX_DEPTH) {
    snapshotError('snapshot exceeds the directory-depth limit');
  }

  const entries = await readBoundedSnapshotDirectory(absoluteDirectory, traversalBudget);
  for (const entry of entries) {
    assertSafeSegment(entry.name, relativeDirectory);
    const candidate = `${relativeDirectory}/${entry.name}`;
    if (entry.isDirectory()) {
      await collectDirectoryCandidates(
        projectRoot,
        candidate,
        extensionSet,
        candidates,
        traversalBudget,
        depth + 1,
        false,
      );
      continue;
    }
    if (!entry.isFile() || entry.isSymbolicLink()) {
      snapshotError(`snapshot input is not a regular file: ${candidate}`);
    }
    if (isLifecycleTransactionSidecar(entry.name)) {
      continue;
    }
    await assertRegularCandidate(projectRoot, candidate, extensionSet);
    candidates.push({ relativePath: candidate });
    if (candidates.length > VITE_SNAPSHOT_MAX_FILES) {
      snapshotError('snapshot exceeds the file-count limit');
    }
  }
}

function isLifecycleTransactionSidecar(name: string): boolean {
  return /\.scene-glass-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9]+\.(?:rollback|stage)$/u.test(
    name,
  );
}
async function readBoundedSnapshotDirectory(
  absoluteDirectory: string,
  traversalBudget: SnapshotTraversalBudget,
): Promise<readonly Dirent[]> {
  const directory = await opendir(absoluteDirectory);
  const entries: Dirent[] = [];
  try {
    while (true) {
      const entry = await directory.read();
      if (entry === null) {
        break;
      }
      if (traversalBudget.entries >= VITE_SNAPSHOT_MAX_DIRECTORY_ENTRIES) {
        snapshotError('snapshot exceeds the directory-entry limit');
      }
      traversalBudget.entries += 1;
      entries.push(entry);
    }
  } finally {
    await directory.close();
  }
  entries.sort((left, right) => compareAscii(left.name, right.name));
  return Object.freeze(entries);
}

async function optionalSupportedTsconfig(projectRoot: string): Promise<string | null> {
  const names = ['tsconfig.json', 'tsconfig.app.json'] as const;
  const present: string[] = [];
  for (const name of names) {
    try {
      await assertRegularCandidate(projectRoot, name, new Set(['.json']));
      present.push(name);
    } catch (error: unknown) {
      if (!isSnapshotError(error) || !error.message.includes('missing')) {
        throw error;
      }
    }
  }
  if (present.length > 1) {
    snapshotError('only one supported tsconfig file may be present');
  }
  return present[0] ?? null;
}

async function assertRegularCandidate(
  projectRoot: string,
  relativePath: string,
  extensions: ReadonlySet<string>,
): Promise<void> {
  const absolutePath = join(projectRoot, ...relativePath.split('/'));
  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(absolutePath);
  } catch (error: unknown) {
    if (isMissing(error)) {
      snapshotError(`required snapshot file is missing: ${relativePath}`);
    }
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    snapshotError(`snapshot input is unsafe: ${relativePath}`);
  }
  assertSupportedExtension(relativePath, extensions);
}

function assertSafeContent(
  relativePath: string,
  bytes: Uint8Array,
  credentialCanaries: readonly Uint8Array[],
): void {
  for (const sequence of FORBIDDEN_TEXT_BYTES) {
    if (containsBytes(bytes, sequence)) {
      snapshotError(`snapshot input contains forbidden Scene Glass material: ${relativePath}`);
    }
  }
  for (const sequence of credentialCanaries) {
    if (sequence.byteLength === 0) {
      snapshotError('snapshot credential canary must not be empty');
    }
    if (containsBytes(bytes, sequence)) {
      snapshotError(`snapshot input contains a credential canary: ${relativePath}`);
    }
  }

  if (!isTextSnapshotPath(relativePath)) {
    return;
  }
  let text: string;
  try {
    text = TEXT_DECODER.decode(bytes);
  } catch {
    snapshotError(`text snapshot input must be valid UTF-8: ${relativePath}`);
  }
  if (relativePath === 'tsconfig.json' || relativePath === 'tsconfig.app.json') {
    assertSupportedTsconfig(text, relativePath);
  }
  if (relativePath === 'index.html') {
    assertTokenlessManagedViteHtml(text);
  }
  if (relativePath.startsWith('src/') && SOURCE_MAP_DIRECTIVE.test(text)) {
    snapshotError(`source maps are unsupported: ${relativePath}`);
  }
  if (basename(relativePath).startsWith('.env')) {
    snapshotError(`environment files are unsupported: ${relativePath}`);
  }
  if (relativePath.endsWith('.map')) {
    snapshotError(`source maps are unsupported: ${relativePath}`);
  }
}
export function assertTokenlessManagedViteHtml(html: string): void {
  assertManagedViteHtmlDocument(html);
}

export function assertCanonicalManagedViteHtml(
  html: string,
  expectedLoader: { readonly loaderUrl: string; readonly projectId: string },
): void {
  assertManagedViteHtmlDocument(html, expectedLoader);
}

interface ParsedHtmlAttribute {
  readonly name: string;
  readonly value: string | null;
}

interface ParsedHtmlTag {
  readonly attributes: readonly ParsedHtmlAttribute[];
  readonly closing: boolean;
  readonly name: string;
  readonly selfClosing: boolean;
}

function assertManagedViteHtmlDocument(
  html: string,
  expectedLoader?: { readonly loaderUrl: string; readonly projectId: string },
): void {
  if (typeof html !== 'string') {
    snapshotError('managed Vite index.html must be a string');
  }

  const stack: string[] = [];
  let bodyClosed = false;
  let bodySeen = false;
  let headClosed = false;
  let headSeen = false;
  let htmlSeen = false;
  let canonicalLoaderCount = 0;
  let index = 0;
  while (index < html.length) {
    const opening = html.indexOf('<', index);
    if (opening === -1) {
      assertManagedHtmlTextContext(html.slice(index), htmlSeen, bodySeen, bodyClosed, stack.at(-1));
      break;
    }
    assertManagedHtmlTextContext(
      html.slice(index, opening),
      htmlSeen,
      bodySeen,
      bodyClosed,
      stack.at(-1),
    );
    if (html.startsWith('<!--', opening)) {
      const commentEnd = html.indexOf('-->', opening + 4);
      if (commentEnd === -1) {
        snapshotError('managed Vite index.html contains an unterminated comment');
      }
      index = commentEnd + 3;
      continue;
    }

    const tagEnd = htmlTagEnd(html, opening + 1);
    if (tagEnd === -1) {
      snapshotError('managed Vite index.html contains an unterminated tag');
    }
    const content = html.slice(opening + 1, tagEnd);
    const parsed = parseHtmlTag(content);
    if (parsed === null) {
      if (!isSupportedHtmlDeclaration(content, htmlSeen)) {
        snapshotError('managed Vite index.html contains an unsupported declaration');
      }
      index = tagEnd + 1;
      continue;
    }

    if (parsed.closing) {
      if (stack.at(-1) !== parsed.name) {
        snapshotError('managed Vite index.html has invalid element nesting');
      }
      stack.pop();
      if (parsed.name === 'head') {
        headClosed = true;
      } else if (parsed.name === 'body') {
        bodyClosed = true;
      }
      index = tagEnd + 1;
      continue;
    }

    const parent = stack.at(-1);
    if (parsed.name === 'html') {
      if (htmlSeen || stack.length !== 0 || parsed.selfClosing) {
        snapshotError('managed Vite index.html has an invalid html element');
      }
      htmlSeen = true;
    } else if (parsed.name === 'head') {
      if (
        !htmlSeen ||
        parent !== 'html' ||
        headSeen ||
        headClosed ||
        bodySeen ||
        parsed.selfClosing
      ) {
        snapshotError('managed Vite index.html has an invalid head element');
      }
      headSeen = true;
    } else if (parsed.name === 'body') {
      if (
        !htmlSeen ||
        parent !== 'html' ||
        !headSeen ||
        !headClosed ||
        bodySeen ||
        parsed.selfClosing
      ) {
        snapshotError('managed Vite index.html has an invalid body element');
      }
      bodySeen = true;
    } else if (
      !htmlSeen ||
      parent === undefined ||
      bodyClosed ||
      (parent === 'html' && !bodySeen)
    ) {
      snapshotError('managed Vite index.html has content outside the document body');
    }

    if (expectedLoader === undefined) {
      assertNoSceneGlassHtmlAttributes(parsed.attributes);
    } else {
      const hasSceneGlassAttribute = parsed.attributes.some((attribute) =>
        attribute.name.startsWith('data-scg-'),
      );
      if (hasSceneGlassAttribute) {
        if (
          parsed.name !== 'script' ||
          parent !== 'head' ||
          !headSeen ||
          headClosed ||
          parsed.selfClosing ||
          !isCanonicalManagedLoader(parsed.attributes, expectedLoader)
        ) {
          snapshotError('managed Vite index.html has a non-canonical loader');
        }
        canonicalLoaderCount += 1;
      }
    }

    if (!parsed.selfClosing && !isVoidHtmlElement(parsed.name)) {
      stack.push(parsed.name);
    }
    if (isRawTextHtmlElement(parsed.name) && !parsed.selfClosing) {
      const closing = rawTextClosingTag(html, tagEnd + 1, parsed.name);
      if (closing === -1) {
        snapshotError(`managed Vite index.html contains an unterminated ${parsed.name} element`);
      }
      index = closing;
      continue;
    }
    index = tagEnd + 1;
  }

  if (
    stack.length !== 0 ||
    !htmlSeen ||
    !headSeen ||
    !headClosed ||
    !bodySeen ||
    !bodyClosed ||
    (expectedLoader !== undefined && canonicalLoaderCount !== 1)
  ) {
    snapshotError('managed Vite index.html does not have one canonical document head loader');
  }
}

function isCanonicalManagedLoader(
  attributes: readonly ParsedHtmlAttribute[],
  expected: { readonly loaderUrl: string; readonly projectId: string },
): boolean {
  if (attributes.length !== 5) {
    return false;
  }
  const values = new Map(attributes.map((attribute) => [attribute.name, attribute.value]));
  return (
    values.size === 5 &&
    (values.get('async') === null || values.get('async') === '') &&
    values.get('src') === expected.loaderUrl &&
    values.get('data-scg-project') === expected.projectId &&
    values.get('data-scg-navigation') === 'spa' &&
    typeof values.get('data-scg-token') === 'string' &&
    (() => {
      try {
        parseCanonicalOpaqueToken(values.get('data-scg-token') ?? '');
        return true;
      } catch {
        return false;
      }
    })()
  );
}

function assertNoSceneGlassHtmlAttributes(attributes: readonly ParsedHtmlAttribute[]): void {
  if (attributes.some((attribute) => attribute.name.startsWith('data-scg-'))) {
    snapshotError('managed Vite templates must not contain a Scene Glass loader annotation');
  }
}

function isSupportedHtmlDeclaration(content: string, htmlSeen: boolean): boolean {
  return !htmlSeen && /^\s*!doctype\s+html\s*$/i.test(content);
}
function assertManagedHtmlTextContext(
  text: string,
  htmlSeen: boolean,
  bodySeen: boolean,
  bodyClosed: boolean,
  parent: string | undefined,
): void {
  if (text.trim().length !== 0 && (!htmlSeen || bodyClosed || (parent === 'html' && !bodySeen))) {
    snapshotError('managed Vite index.html has content outside the document body');
  }
}

function htmlTagEnd(html: string, start: number): number {
  let quote: '"' | "'" | undefined;
  for (let index = start; index < html.length; index += 1) {
    const character = html[index];
    if (character === '"' || character === "'") {
      if (quote === undefined) {
        quote = character;
      } else if (quote === character) {
        quote = undefined;
      }
      continue;
    }
    if (character === '>' && quote === undefined) {
      return index;
    }
  }
  return -1;
}

function parseHtmlTag(content: string): ParsedHtmlTag | null {
  let index = 0;
  while (index < content.length && isHtmlWhitespace(content[index])) {
    index += 1;
  }
  if (content[index] === '!' || content[index] === '?') {
    return null;
  }

  const closing = content[index] === '/';
  if (closing) {
    index += 1;
    while (index < content.length && isHtmlWhitespace(content[index])) {
      index += 1;
    }
  }
  const nameStart = index;
  while (index < content.length && isHtmlTagNameCharacter(content[index])) {
    index += 1;
  }
  if (nameStart === index) {
    snapshotError('managed Vite index.html contains an invalid tag');
  }
  const name = content.slice(nameStart, index).toLowerCase();
  if (closing) {
    if (
      !content
        .slice(index)
        .split('')
        .every((character) => isHtmlWhitespace(character))
    ) {
      snapshotError('managed Vite index.html contains an invalid closing tag');
    }
    return Object.freeze({
      attributes: Object.freeze([]),
      closing: true,
      name,
      selfClosing: false,
    });
  }

  let tail = content.length;
  while (tail > index && isHtmlWhitespace(content[tail - 1])) {
    tail -= 1;
  }
  const selfClosing = content[tail - 1] === '/';
  const attributes = parseHtmlAttributes(content, index, selfClosing ? tail - 1 : tail);
  return Object.freeze({ attributes, closing: false, name, selfClosing });
}

function parseHtmlAttributes(
  content: string,
  start: number,
  end: number,
): readonly ParsedHtmlAttribute[] {
  const attributes: ParsedHtmlAttribute[] = [];
  const names = new Set<string>();
  let index = start;
  while (index < end) {
    while (index < end && isHtmlWhitespace(content[index])) {
      index += 1;
    }
    if (index === end) {
      break;
    }
    const nameStart = index;
    while (
      index < end &&
      !isHtmlWhitespace(content[index]) &&
      content[index] !== '=' &&
      content[index] !== '>'
    ) {
      index += 1;
    }
    if (nameStart === index) {
      snapshotError('managed Vite index.html contains an invalid attribute');
    }
    const name = content.slice(nameStart, index).toLowerCase();
    if (names.has(name)) {
      snapshotError('managed Vite index.html contains a duplicate attribute');
    }
    names.add(name);
    while (index < end && isHtmlWhitespace(content[index])) {
      index += 1;
    }
    let value: string | null = null;
    if (content[index] === '=') {
      index += 1;
      while (index < end && isHtmlWhitespace(content[index])) {
        index += 1;
      }
      const quote = content[index];
      if (quote === '"' || quote === "'") {
        index += 1;
        const valueStart = index;
        while (index < end && content[index] !== quote) {
          index += 1;
        }
        if (index >= end) {
          snapshotError('managed Vite index.html contains an unterminated attribute');
        }
        value = content.slice(valueStart, index);
        index += 1;
      } else {
        const valueStart = index;
        while (index < end && !isHtmlWhitespace(content[index])) {
          index += 1;
        }
        if (valueStart === index) {
          snapshotError('managed Vite index.html contains an invalid attribute');
        }
        value = content.slice(valueStart, index);
      }
    }
    attributes.push(Object.freeze({ name, value }));
  }
  return Object.freeze(attributes);
}

function isVoidHtmlElement(name: string): boolean {
  return (
    name === 'area' ||
    name === 'base' ||
    name === 'br' ||
    name === 'col' ||
    name === 'embed' ||
    name === 'hr' ||
    name === 'img' ||
    name === 'input' ||
    name === 'link' ||
    name === 'meta' ||
    name === 'param' ||
    name === 'source' ||
    name === 'track' ||
    name === 'wbr'
  );
}

function rawTextClosingTag(html: string, start: number, name: string): number {
  let index = start;
  while (index < html.length) {
    const opening = html.indexOf('<', index);
    if (opening === -1) {
      return -1;
    }
    if (html[opening + 1] !== '/') {
      index = opening + 1;
      continue;
    }
    let candidate = opening + 2;
    while (candidate < html.length && isHtmlWhitespace(html[candidate])) {
      candidate += 1;
    }
    if (
      html.slice(candidate, candidate + name.length).toLowerCase() === name &&
      (candidate + name.length === html.length ||
        isHtmlWhitespace(html[candidate + name.length]) ||
        html[candidate + name.length] === '>')
    ) {
      return opening;
    }
    index = opening + 1;
  }
  return -1;
}

function isRawTextHtmlElement(name: string): boolean {
  return name === 'script' || name === 'style' || name === 'textarea' || name === 'title';
}

function isHtmlWhitespace(character: string | undefined): boolean {
  return (
    character === ' ' ||
    character === '\n' ||
    character === '\r' ||
    character === '\t' ||
    character === '\f'
  );
}

function isHtmlTagNameCharacter(character: string | undefined): boolean {
  return (
    character !== undefined &&
    ((character >= 'a' && character <= 'z') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= '0' && character <= '9') ||
      character === ':' ||
      character === '-')
  );
}

function assertSupportedExtension(relativePath: string, extensions: ReadonlySet<string>): void {
  const name = basename(relativePath);
  if (
    name.startsWith('.env') ||
    name === 'package.json' ||
    name === 'browserslist' ||
    name.startsWith('postcss.') ||
    name.startsWith('vite.config.') ||
    name.endsWith('.map')
  ) {
    snapshotError(`unsupported snapshot input: ${relativePath}`);
  }
  const extension = name.endsWith('.d.ts') ? '.d.ts' : posix.extname(name).toLowerCase();
  if (!extensions.has(extension)) {
    snapshotError(`unsupported snapshot extension: ${relativePath}`);
  }
}
function assertSupportedTsconfig(text: string, relativePath: string): void {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    snapshotError(`tsconfig must be JSON: ${relativePath}`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    snapshotError(`tsconfig must be an object: ${relativePath}`);
  }
  const config = value as Record<string, unknown>;
  if (config.extends !== undefined || config.references !== undefined) {
    snapshotError(`tsconfig inheritance and references are unsupported: ${relativePath}`);
  }
  const compilerOptions = config.compilerOptions;
  if (
    compilerOptions !== undefined &&
    (typeof compilerOptions !== 'object' ||
      compilerOptions === null ||
      Array.isArray(compilerOptions) ||
      (compilerOptions as Record<string, unknown>).paths !== undefined ||
      (compilerOptions as Record<string, unknown>).baseUrl !== undefined ||
      (compilerOptions as Record<string, unknown>).plugins !== undefined ||
      (compilerOptions as Record<string, unknown>).sourceMap === true ||
      (compilerOptions as Record<string, unknown>).inlineSourceMap === true ||
      (compilerOptions as Record<string, unknown>).declarationMap === true)
  ) {
    snapshotError(`tsconfig paths and plugins are unsupported: ${relativePath}`);
  }
}

function assertSafeSegment(segment: string, parent: string): void {
  if (
    segment.length === 0 ||
    segment === '.' ||
    segment === '..' ||
    segment.includes('\u0000') ||
    segment === '.scg' ||
    segment.startsWith('.env') ||
    segment.endsWith('.map')
  ) {
    snapshotError(`unsupported snapshot path: ${parent}/${segment}`);
  }
}

function assertAuthorityCompleteCanaries(
  authorities: readonly CredentialAuthority[],
  canaries: unknown,
): readonly Buffer[] {
  if (!Array.isArray(authorities) || authorities.length === 0 || !Array.isArray(canaries)) {
    snapshotError('snapshot credential canaries must be authority-complete');
  }
  if (canaries.length !== authorities.length) {
    snapshotError('snapshot credential canaries must be authority-complete');
  }

  const authorityIds = new Set(authorities.map((authority) => authority.projectId));
  const canaryIds = new Set<string>();
  const bytes: Buffer[] = [];
  try {
    for (const canary of canaries) {
      if (typeof canary !== 'object' || canary === null) {
        snapshotError('snapshot credential canaries must be authority-complete');
      }
      const projectId = canary.projectId;
      const canaryBytes = canary.bytes;
      if (
        typeof projectId !== 'string' ||
        !authorityIds.has(projectId) ||
        canaryIds.has(projectId) ||
        !(canaryBytes instanceof Uint8Array) ||
        canaryBytes.byteLength === 0 ||
        canaryBytes.byteLength > VITE_SNAPSHOT_CANARY_MAX_BYTES
      ) {
        snapshotError('snapshot credential canaries must be authority-complete');
      }
      const copied = Buffer.from(canaryBytes);
      if (copied.byteLength !== canaryBytes.byteLength) {
        zeroizeBuffer(copied);
        snapshotError('snapshot credential canaries must be authority-complete');
      }
      canaryIds.add(projectId);
      bytes.push(copied);
    }
  } catch (error: unknown) {
    zeroizeSnapshotCanaries(bytes);
    throw error;
  }
  return Object.freeze(bytes);
}
function zeroizeSnapshotCanaries(canaries: readonly Buffer[]): void {
  for (const canary of canaries) {
    zeroizeBuffer(canary);
  }
}

async function assertNoFollowDirectoryIdentity(
  path: string,
  expectedIdentity: FileIdentity,
): Promise<void> {
  const actual = await directoryIdentity(path);
  if (!matchesIdentity(actual, [expectedIdentity])) {
    snapshotError('snapshot authority identity changed');
  }
}
async function assertNoFollowSetupAncestors(projectRoot: string): Promise<void> {
  for (const relativeDirectory of [
    '.scg',
    '.scg/runtime',
    STAGING_DIRECTORY,
    VITE_SNAPSHOT_ROOT_DIRECTORY,
    VITE_SNAPSHOT_COMMITMENT_DIRECTORY,
  ]) {
    try {
      const facts = await lstat(join(projectRoot, ...relativeDirectory.split('/')), {
        bigint: true,
      });
      if (!facts.isDirectory() || facts.isSymbolicLink()) {
        snapshotError('snapshot setup ancestor is unsafe');
      }
    } catch (error: unknown) {
      if (error instanceof SceneGlassContractError) {
        throw error;
      }
      if (!isMissing(error)) {
        snapshotError('snapshot setup ancestor is unavailable');
      }
    }
  }
}
function assertPublicationAuthority(value: unknown): ViteSnapshotPublicationAuthority {
  if (!isRecord(value)) {
    snapshotError('snapshot publication authority is unavailable');
  }
  const createStaging = value.createStaging;
  const publish = value.publish;
  const persistCommitment = value.persistCommitment;
  const discardStaging = value.discardStaging;
  const removePublished = value.removePublished;
  if (
    typeof createStaging !== 'function' ||
    typeof publish !== 'function' ||
    typeof persistCommitment !== 'function' ||
    typeof discardStaging !== 'function' ||
    typeof removePublished !== 'function'
  ) {
    snapshotError('snapshot publication authority is unavailable');
  }
  return Object.freeze<ViteSnapshotPublicationAuthority>({
    async createStaging(input) {
      return Reflect.apply(createStaging, value, [input]) as Promise<ViteSnapshotStagingAuthority>;
    },
    async publish(input) {
      return Reflect.apply(publish, value, [input]) as Promise<ViteSnapshotPublishedAuthority>;
    },
    async persistCommitment(input): Promise<void> {
      await Reflect.apply(persistCommitment, value, [input]);
    },
    async discardStaging(input): Promise<void> {
      await Reflect.apply(discardStaging, value, [input]);
    },
    async removePublished(input): Promise<void> {
      await Reflect.apply(removePublished, value, [input]);
    },
  });
}
function snapshotPublishedAuthority(
  value: unknown,
  expectedSyntheticRoot: string,
): ViteSnapshotPublishedAuthority {
  if (!isRecord(value)) {
    snapshotError('snapshot publication authority returned an invalid published root');
  }
  const syntheticRoot = value.syntheticRoot;
  const rootIdentity = copySnapshotFileIdentity(value.rootIdentity);
  if (syntheticRoot !== expectedSyntheticRoot) {
    snapshotError('snapshot publication authority returned an invalid synthetic root');
  }
  return Object.freeze({ syntheticRoot, rootIdentity });
}

function assertSnapshotAuthority(
  value: unknown,
  expectedSyntheticRoot: string,
): ViteSnapshotAuthority {
  if (!isExactRecord(value, ['syntheticRoot', 'rootIdentity', 'commitmentDigest'])) {
    snapshotError('snapshot external authority is invalid');
  }
  const syntheticRoot = value.syntheticRoot;
  const rootIdentity = copySnapshotFileIdentity(value.rootIdentity);
  const commitmentDigest = value.commitmentDigest;
  if (
    syntheticRoot !== expectedSyntheticRoot ||
    typeof commitmentDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(commitmentDigest)
  ) {
    snapshotError('snapshot external authority is invalid');
  }
  return Object.freeze({ syntheticRoot, rootIdentity, commitmentDigest });
}
function freezeSnapshotAuthorityTransport(value: unknown): ViteSnapshotAuthority {
  if (
    !isExactRecord(value, ['syntheticRoot', 'rootIdentity', 'commitmentDigest']) ||
    !isCanonicalSnapshotAuthorityRoot(value.syntheticRoot) ||
    !isSnapshotAuthorityIdentity(value.rootIdentity) ||
    typeof value.commitmentDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.commitmentDigest)
  ) {
    snapshotAuthorityTransportError();
  }
  return Object.freeze({
    syntheticRoot: value.syntheticRoot,
    rootIdentity: Object.freeze({
      device: value.rootIdentity.device,
      inode: value.rootIdentity.inode,
    }),
    commitmentDigest: value.commitmentDigest,
  });
}

function isCanonicalSnapshotAuthorityRoot(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 1 &&
    !value.includes('\0') &&
    isAbsolute(value) &&
    resolve(value) === value
  );
}

function isSnapshotAuthorityIdentity(value: unknown): value is FileIdentity {
  if (!isExactRecord(value, ['device', 'inode'])) {
    return false;
  }
  return (
    isSnapshotAuthorityIdentityPart(value.device) && isSnapshotAuthorityIdentityPart(value.inode)
  );
}

function isSnapshotAuthorityIdentityPart(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= MAX_SNAPSHOT_AUTHORITY_IDENTITY_DIGITS &&
    DECIMAL_STRING.test(value) &&
    BigInt(value) <= MAX_UNSIGNED_64
  );
}

function snapshotAuthorityTransportError(): never {
  snapshotError('Vite snapshot authority transport is invalid');
}

async function directoryIdentity(path: string): Promise<FileIdentity> {
  try {
    const facts = await lstat(path, { bigint: true });
    if (!facts.isDirectory() || facts.isSymbolicLink()) {
      snapshotError('snapshot authority directory is unsafe');
    }
    return Object.freeze({ device: facts.dev.toString(), inode: facts.ino.toString() });
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      throw error;
    }
    snapshotError('snapshot authority directory is unavailable');
  }
}

function isFileIdentity(value: unknown): value is FileIdentity {
  if (!isExactRecord(value, ['device', 'inode'])) {
    return false;
  }
  const { device, inode } = value;
  return (
    typeof device === 'string' &&
    DECIMAL_STRING.test(device) &&
    typeof inode === 'string' &&
    DECIMAL_STRING.test(inode)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    Object.keys(value).every((key, index) => key === keys[index])
  );
}

/**
 * Production adapter for the native same-FD no-follow reader. Every fact in
 * the returned result is captured from the descriptor that supplied `bytes`.
 */
export function createNativeSameFdSnapshotReader(): SameFdSnapshotReader {
  return Object.freeze({
    async read(request: SameFdSnapshotReadRequest): Promise<SameFdSnapshotReadResult> {
      try {
        const result = secureReadBeneath({
          root: request.root,
          expectedRoot: request.rootIdentity,
          relativePath: request.relativePath,
          deniedIdentities: request.deniedIdentities,
          maxBytes: request.maxBytes,
        });
        if (!isRegularFileMode(result.mode)) {
          zeroizeBuffer(result.bytes);
          return Object.freeze({ status: 'unsafe' });
        }
        return Object.freeze({
          status: 'ok',
          bytes: result.bytes,
          identity: result.identity,
          linkCount: result.linkCount,
          regularFile: true,
        });
      } catch (error: unknown) {
        const status = nativeSnapshotReadStatus(error);
        if (status === undefined) {
          throw error;
        }
        return Object.freeze({ status });
      }
    },
  });
}

function nativeSnapshotReadStatus(
  error: unknown,
): Exclude<SameFdSnapshotReadResult['status'], 'ok'> | undefined {
  if (!(error instanceof OnboardingNativeError)) {
    return undefined;
  }
  switch (error.code) {
    case 'SCG_NATIVE_IDENTITY_MISMATCH':
      return 'replaced';
    case 'SCG_NATIVE_READ_LIMIT':
      return 'too-large';
    case 'SCG_NATIVE_PATH_DENIED':
      return 'unsafe';
    default:
      return undefined;
  }
}

function isRegularFileMode(mode: number): boolean {
  return (mode & 0o170000) === 0o100000;
}
function isTextSnapshotPath(relativePath: string): boolean {
  return /\.(?:css|cts|d\.ts|html|js|json|jsx|mjs|mts|svg|ts|tsx|txt|vue)$/i.test(relativePath);
}

function matchesIdentity(identity: FileIdentity, denied: readonly FileIdentity[]): boolean {
  return denied.some(
    (candidate) => candidate.device === identity.device && candidate.inode === identity.inode,
  );
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength > haystack.byteLength) {
    return false;
  }
  for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    let matched = true;
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return true;
    }
  }
  return false;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
function committedViteSnapshotDigest(value: {
  readonly version: 1;
  readonly syntheticRoot: string;
  readonly rootIdentity: FileIdentity;
  readonly files: readonly CommittedViteSnapshotFile[];
}): string {
  return sha256(Buffer.from(JSON.stringify(value), 'utf8'));
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isMissing(error: unknown): error is NodeJS.ErrnoException {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as NodeJS.ErrnoException).code === 'ENOENT'
  );
}

function isSnapshotError(error: unknown): error is SceneGlassContractError {
  return error instanceof SceneGlassContractError && error.code === 'SCG_VITE_CONFIG_UNSUPPORTED';
}

function snapshotError(message: string): never {
  throw new SceneGlassContractError('SCG_VITE_CONFIG_UNSUPPORTED', message);
}

export function isPathContainedBy(root: string, candidate: string): boolean {
  const relativePath = relative(resolve(root), resolve(candidate));
  return relativePath === '' || (!relativePath.startsWith(`..${sep}`) && relativePath !== '..');
}
