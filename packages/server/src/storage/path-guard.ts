import { lstat, mkdir, opendir, realpath } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { Dir, Stats } from 'node:fs';
import { BUILT_IN_LIMITS, type PageId } from '@scene-glass/contracts';

export const SCG_DIRECTORY_NAME = '.scg';
export const SCG_ANNOTATIONS_DIRECTORY_NAME = 'annotations';

const PAGE_FILE_NAME = /^p_[0-9a-f]{64}\.json$/;
const PAGE_ID = /^p_[0-9a-f]{64}$/;
const EXACT_ENTRY_SCAN_TEMPORARY_ALLOWANCE = BUILT_IN_LIMITS.concurrentRequestsPerProject;
const EXACT_ENTRY_SCAN_LIMIT =
  BUILT_IN_LIMITS.pagesPerProject + EXACT_ENTRY_SCAN_TEMPORARY_ALLOWANCE;

export type ScgStorageErrorCode =
  | 'SCG_ROOT_CHANGED'
  | 'SCG_PAGE_INVALID'
  | 'SCG_PAGE_CORRUPT'
  | 'SCG_PAGE_ID_COLLISION'
  | 'SCG_COMMIT_FAILED'
  | 'SCG_COMMIT_DURABILITY_UNKNOWN'
  | 'SCG_STORAGE_INTEGRITY'
  | 'SCG_LIMIT_FILE';

export class ScgStorageError extends Error {
  public readonly code: ScgStorageErrorCode;

  public constructor(code: ScgStorageErrorCode, message: string) {
    super(message);
    this.name = 'ScgStorageError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface DirectoryIdentity {
  readonly device: number;
  readonly inode: number;
}

export interface GuardedAnnotationPaths {
  readonly root: string;
  readonly scgDirectory: string;
  readonly annotationsDirectory: string;
  assertUnchanged(): Promise<void>;
  pageFile(pageId: PageId): Promise<GuardedPageFile>;
}

export interface GuardedPageFile {
  readonly pageId: PageId;
  readonly path: string;
  readonly directory: string;
  assertUnchanged(): Promise<void>;
  assertExistingFile(signal?: AbortSignal): Promise<boolean>;
}

export async function guardAnnotationPaths(canonicalRoot: string): Promise<GuardedAnnotationPaths> {
  const root = await guardCanonicalRoot(canonicalRoot);
  const rootIdentity = await directoryIdentity(root, 'project root');
  const scgDirectory = await ensureDirectorySegment(root, SCG_DIRECTORY_NAME);
  const scgIdentity = await directoryIdentity(scgDirectory, '.scg directory');
  const annotationsDirectory = await ensureDirectorySegment(
    scgDirectory,
    SCG_ANNOTATIONS_DIRECTORY_NAME,
  );
  const annotationsIdentity = await directoryIdentity(
    annotationsDirectory,
    'annotations directory',
  );

  const assertUnchanged = async (): Promise<void> => {
    await assertCanonicalDirectory(root, rootIdentity, 'project root');
    await assertCanonicalDirectory(scgDirectory, scgIdentity, '.scg directory');
    await assertCanonicalDirectory(
      annotationsDirectory,
      annotationsIdentity,
      'annotations directory',
    );
  };
  await assertUnchanged();

  return Object.freeze({
    root,
    scgDirectory,
    annotationsDirectory,
    assertUnchanged,
    async pageFile(pageId: PageId): Promise<GuardedPageFile> {
      assertSafePageId(pageId);
      await assertUnchanged();
      const filePath = resolve(annotationsDirectory, `${pageId}.json`);
      if (dirname(filePath) !== annotationsDirectory) {
        throw storageError('SCG_PAGE_INVALID', 'page file path is invalid');
      }

      return Object.freeze({
        pageId,
        path: filePath,
        directory: annotationsDirectory,
        assertUnchanged,
        async assertExistingFile(signal?: AbortSignal): Promise<boolean> {
          signal?.throwIfAborted();
          await assertUnchanged();
          signal?.throwIfAborted();
          const stats = await lstatIfPresent(filePath);
          signal?.throwIfAborted();
          if (stats === undefined) {
            return false;
          }
          if (stats.isSymbolicLink() || !stats.isFile()) {
            throw storageError('SCG_ROOT_CHANGED', 'page file is not a regular file');
          }
          if (!(await hasExactRegularFileEntry(annotationsDirectory, `${pageId}.json`, signal))) {
            throw storageError('SCG_PAGE_ID_COLLISION', 'page file name is not canonical');
          }
          signal?.throwIfAborted();
          await assertUnchanged();
          signal?.throwIfAborted();
          return true;
        },
      });
    },
  });
}

export function pageIdFromFileName(fileName: string): PageId {
  if (!PAGE_FILE_NAME.test(fileName)) {
    throw storageError('SCG_PAGE_INVALID', 'page file name is invalid');
  }
  return fileName.slice(0, -'.json'.length) as PageId;
}

export function assertSafePageId(pageId: string): asserts pageId is PageId {
  if (!PAGE_ID.test(pageId)) {
    throw storageError('SCG_PAGE_INVALID', 'page id is invalid');
  }
}

async function guardCanonicalRoot(canonicalRoot: string): Promise<string> {
  if (typeof canonicalRoot !== 'string' || canonicalRoot.length === 0) {
    throw storageError('SCG_ROOT_CHANGED', 'authorized project root is invalid');
  }

  let resolved: string;
  try {
    resolved = await realpath(canonicalRoot);
  } catch {
    throw storageError('SCG_ROOT_CHANGED', 'authorized project root is unavailable');
  }
  if (resolved !== canonicalRoot) {
    throw storageError('SCG_ROOT_CHANGED', 'authorized project root is not canonical');
  }

  await assertDirectory(canonicalRoot, 'project root');
  return canonicalRoot;
}

async function ensureDirectorySegment(parent: string, segment: string): Promise<string> {
  const candidate = resolve(parent, segment);
  if (dirname(candidate) !== parent) {
    throw storageError('SCG_ROOT_CHANGED', 'storage directory path is invalid');
  }

  const existing = await lstatIfPresent(candidate);
  if (existing === undefined) {
    try {
      await mkdir(candidate);
    } catch (error: unknown) {
      if (!hasErrorCode(error, 'EEXIST')) {
        throw storageError('SCG_ROOT_CHANGED', 'storage directory cannot be created');
      }
    }
  }

  await assertDirectory(candidate, 'storage directory');
  let resolved: string;
  try {
    resolved = await realpath(candidate);
  } catch {
    throw storageError('SCG_ROOT_CHANGED', 'storage directory is unavailable');
  }
  if (resolved !== candidate) {
    throw storageError('SCG_ROOT_CHANGED', 'storage directory is not canonical');
  }
  return candidate;
}

async function assertCanonicalDirectory(
  directory: string,
  expected: DirectoryIdentity,
  name: string,
): Promise<void> {
  const stats = await assertDirectory(directory, name);
  if (!sameIdentity(stats, expected)) {
    throw storageError('SCG_ROOT_CHANGED', `${name} changed`);
  }

  let resolved: string;
  try {
    resolved = await realpath(directory);
  } catch {
    throw storageError('SCG_ROOT_CHANGED', `${name} is unavailable`);
  }
  if (resolved !== directory) {
    throw storageError('SCG_ROOT_CHANGED', `${name} is not canonical`);
  }
}

async function directoryIdentity(directory: string, name: string): Promise<DirectoryIdentity> {
  const stats = await assertDirectory(directory, name);
  return Object.freeze({ device: stats.dev, inode: stats.ino });
}

async function assertDirectory(directory: string, name: string): Promise<Stats> {
  let stats: Stats;
  try {
    stats = await lstat(directory);
  } catch {
    throw storageError('SCG_ROOT_CHANGED', `${name} is unavailable`);
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw storageError('SCG_ROOT_CHANGED', `${name} is not a directory`);
  }
  return stats;
}

async function lstatIfPresent(path: string): Promise<Stats | undefined> {
  try {
    return await lstat(path);
  } catch (error: unknown) {
    if (hasErrorCode(error, 'ENOENT')) {
      return undefined;
    }
    throw storageError('SCG_ROOT_CHANGED', 'storage path cannot be inspected');
  }
}

async function hasExactRegularFileEntry(
  directory: string,
  fileName: string,
  signal: AbortSignal | undefined,
): Promise<boolean> {
  let entries: Dir | undefined;
  let result: boolean | undefined;
  let failure: unknown;
  try {
    signal?.throwIfAborted();
    entries = await opendir(directory);
    signal?.throwIfAborted();

    let scannedEntries = 0;
    for (;;) {
      signal?.throwIfAborted();
      const entry = await entries.read();
      signal?.throwIfAborted();
      if (entry === null) {
        result = false;
        break;
      }

      scannedEntries += 1;
      if (scannedEntries > EXACT_ENTRY_SCAN_LIMIT) {
        throw storageError(
          'SCG_LIMIT_FILE',
          'annotation directory exceeds the exact entry scan limit',
        );
      }
      if (entry.name === fileName) {
        result = !entry.isSymbolicLink() && entry.isFile();
        break;
      }
    }
  } catch (error: unknown) {
    failure = error;
  }

  if (entries !== undefined) {
    try {
      await entries.close();
    } catch (error: unknown) {
      failure ??= error;
    }
  }

  signal?.throwIfAborted();
  if (failure !== undefined) {
    if (failure instanceof ScgStorageError) {
      throw failure;
    }
    throw storageError('SCG_ROOT_CHANGED', 'storage directory cannot be listed');
  }
  if (result === undefined) {
    throw storageError('SCG_ROOT_CHANGED', 'storage directory cannot be listed');
  }
  return result;
}
function sameIdentity(stats: Stats, identity: DirectoryIdentity): boolean {
  return stats.dev === identity.device && stats.ino === identity.inode;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function storageError(code: ScgStorageErrorCode, message: string): ScgStorageError {
  return new ScgStorageError(code, message);
}
