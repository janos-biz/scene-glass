import { createHash } from 'node:crypto';
import { constants, type Dir } from 'node:fs';
import { lstat, open, opendir, type FileHandle } from 'node:fs/promises';
import {
  REPLAY_RECORD_COUNT,
  SceneGlassContractError,
  parsePageFileV1,
  parsePageIdentityV1,
  parseReplayRecord,
  serializeCanonicalPageFileV1,
  type PageFileV1,
  type PageFileValidationLimits,
  type PageIdentityV1,
} from '@scene-glass/contracts';
import type { AuthorizedProject } from '../registry/config-project-registry.js';
import { getAuthorizedProjectRoot } from '../registry/memory-project-registry.js';
import { commitAtomically } from './atomic-commit.js';
import type { AtomicCommitFaultPoints } from './fault-points.js';
import {
  type GuardedAnnotationPaths,
  type GuardedPageFile,
  ScgStorageError,
  assertSafePageId,
  guardAnnotationPaths,
  pageIdFromFileName,
} from './path-guard.js';

export interface AuthorizedProjectRootResolver {
  getAuthorizedRoot(project: AuthorizedProject): string | Promise<string>;
}

const DEFAULT_ROOT_RESOLVER: AuthorizedProjectRootResolver = Object.freeze({
  getAuthorizedRoot: getAuthorizedProjectRoot,
});
const PAGE_FILE_NAME = /^p_[0-9a-f]{64}\.json$/;
const CASE_INSENSITIVE_PAGE_FILE_NAME = /^p_[0-9a-f]{64}\.json$/i;
const ATOMIC_TEMPORARY_FILE_NAME =
  /^\.p_[0-9a-f]{64}\.json\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.tmp$/;
const MAX_RECOGNIZED_ANNOTATION_METADATA_ENTRIES = 1;

export interface ScgAnnotationStoreOptions {
  readonly faultPoints?: AtomicCommitFaultPoints;
  readonly limits?: PageFileValidationLimits;
}

export interface AnnotationStore {
  readPage(
    project: AuthorizedProject,
    page: PageIdentityV1,
    signal: AbortSignal,
  ): Promise<PageFileV1 | null>;
  listPages(project: AuthorizedProject, signal: AbortSignal): AsyncIterable<PageFileV1>;
  commitPage(project: AuthorizedProject, page: PageFileV1, signal: AbortSignal): Promise<void>;
}

interface GuardedProject {
  readonly root: string;
  readonly paths: GuardedAnnotationPaths;
}

interface StoredPage {
  readonly bytes: Uint8Array;
  readonly page: PageFileV1;
}
interface BoundedAnnotationDirectory {
  readonly canonicalPageFileNames: readonly string[];
  readonly canonicalPageCount: number;
  readonly nonMetadataEntryCount: number;
}

/**
 * Local-only `.scg` authority. The registry resolves the opaque authorized
 * handle; this adapter never accepts a client-controlled root or file path.
 */
export class ScgAnnotationStore implements AnnotationStore {
  readonly #guards = new Map<string, GuardedProject>();
  readonly #guardInitializations = new Map<string, Promise<GuardedProject>>();
  readonly #commitTails = new Map<string, Promise<void>>();
  readonly #quarantinedProjects = new Set<string>();
  readonly #rootResolver: AuthorizedProjectRootResolver;
  readonly #faultPoints: AtomicCommitFaultPoints | undefined;
  readonly #limits: PageFileValidationLimits | undefined;
  #rootChanged = false;

  public constructor(
    rootResolver: AuthorizedProjectRootResolver = DEFAULT_ROOT_RESOLVER,
    options: ScgAnnotationStoreOptions = {},
  ) {
    this.#rootResolver = rootResolver;
    this.#faultPoints = options.faultPoints;
    this.#limits = options.limits;
  }

  public async readPage(
    project: AuthorizedProject,
    page: PageIdentityV1,
    signal: AbortSignal,
  ): Promise<PageFileV1 | null> {
    this.#assertOperationAllowed(project, signal);
    try {
      const expectedPage = parseRequestedPage(page);
      const limits = this.#limitsFor(project);
      const guarded = await this.#resolveGuard(project, signal);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      const target = await guarded.paths.pageFile(expectedPage.pageId);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      const stored = await this.#readStrict(target, limits, expectedPage, signal);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      return stored?.page ?? null;
    } catch (error: unknown) {
      this.#latchStorageFault(project, error);
      signal.throwIfAborted();
      throw error;
    }
  }

  public listPages(project: AuthorizedProject, signal: AbortSignal): AsyncIterable<PageFileV1> {
    this.#assertOperationAllowed(project, signal);
    return this.#iteratePages(project, signal);
  }

  public async commitPage(
    project: AuthorizedProject,
    page: PageFileV1,
    signal: AbortSignal,
  ): Promise<void> {
    this.#assertOperationAllowed(project, signal);
    await this.#runProjectCommit(project, async (): Promise<void> => {
      let commitStarted = false;
      try {
        this.#assertOperationAllowed(project, signal);
        const limits = this.#limitsFor(project);
        const candidate = parseCommitPage(page, limits);
        const bytes = encodeCanonicalPage(candidate);
        assertCanonicalPageFileLimit(bytes, limits);
        const guarded = await this.#resolveGuard(project, signal);
        this.#assertOperationAllowed(project, signal);
        const target = await guarded.paths.pageFile(candidate.page.pageId);
        this.#assertOperationAllowed(project, signal);
        const existing = await this.#readStrict(target, limits, candidate.page, signal);
        this.#assertOperationAllowed(project, signal);
        assertCommitReplayHistory(candidate, existing, bytes, limits);
        if (existing !== null && !samePageIdentity(existing.page.page, candidate.page)) {
          throw new ScgStorageError(
            'SCG_PAGE_ID_COLLISION',
            'stored annotation page identity does not match the commit',
          );
        }
        const directory = await this.#scanBoundedAnnotationDirectory(project, guarded, signal);
        this.#assertOperationAllowed(project, signal);
        if (
          existing === null &&
          directory.canonicalPageCount >= project.effectiveLimits.pagesPerProject
        ) {
          throw new ScgStorageError(
            'SCG_LIMIT_FILE',
            'annotation project exceeds its effective page limit',
          );
        }
        if (
          existing === null &&
          directory.nonMetadataEntryCount >= project.effectiveLimits.pagesPerProject
        ) {
          throw new ScgStorageError(
            'SCG_LIMIT_FILE',
            'annotation directory exceeds its effective entry limit',
          );
        }

        commitStarted = true;
        await commitAtomically({
          directory: target.directory,
          targetPath: target.path,
          bytes,
          previousBytes: existing?.bytes ?? null,
          signal,
          ...(this.#faultPoints === undefined ? {} : { faultPoints: this.#faultPoints }),
          assertPathUnchanged: async (): Promise<void> => {
            this.#assertStorageAvailable(project);
            await target.assertUnchanged();
            this.#assertStorageAvailable(project);
          },
          strictReadBack: async (): Promise<Uint8Array | null> => {
            this.#assertStorageAvailable(project);
            const visible = await this.#readStrict(target, limits, candidate.page);
            this.#assertStorageAvailable(project);
            return visible?.bytes ?? null;
          },
        });
        this.#assertStorageAvailable(project);
      } catch (error: unknown) {
        this.#latchStorageFault(project, error);
        if (isAbortReason(signal, error)) {
          throw error;
        }
        if (
          !commitStarted ||
          (!isStorageError(error, 'SCG_ROOT_CHANGED') &&
            !isStorageError(error, 'SCG_COMMIT_DURABILITY_UNKNOWN') &&
            !isStorageError(error, 'SCG_STORAGE_INTEGRITY'))
        ) {
          signal.throwIfAborted();
        }
        throw error;
      }
    });
  }

  async *#iteratePages(project: AuthorizedProject, signal: AbortSignal): AsyncIterable<PageFileV1> {
    try {
      this.#assertOperationAllowed(project, signal);
      const guarded = await this.#resolveGuard(project, signal);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      const limits = this.#limitsFor(project);
      const directory = await this.#scanBoundedAnnotationDirectory(project, guarded, signal);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      for (const name of directory.canonicalPageFileNames) {
        this.#assertOperationAllowed(project, signal);
        const pageId = pageIdFromFileName(name);
        const target = await guarded.paths.pageFile(pageId);
        this.#assertStorageAvailable(project);
        signal.throwIfAborted();
        const stored = await this.#readStrict(target, limits, undefined, signal);
        this.#assertStorageAvailable(project);
        signal.throwIfAborted();
        if (stored === null) {
          throw new ScgStorageError(
            'SCG_ROOT_CHANGED',
            'annotation page disappeared during listing',
          );
        }
        yield stored.page;
      }
    } catch (error: unknown) {
      this.#latchStorageFault(project, error);
      signal.throwIfAborted();
      throw error;
    }
  }

  async #resolveGuard(project: AuthorizedProject, signal: AbortSignal): Promise<GuardedProject> {
    this.#assertOperationAllowed(project, signal);
    let root: string;
    try {
      root = await this.#rootResolver.getAuthorizedRoot(project);
    } catch (error: unknown) {
      if (isAbortReason(signal, error)) {
        throw error;
      }
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'authorized project root is unavailable');
    }
    this.#assertStorageAvailable(project);
    signal.throwIfAborted();

    let guarded = this.#guards.get(project.projectId);
    if (guarded === undefined) {
      let initialization = this.#guardInitializations.get(project.projectId);
      if (initialization === undefined) {
        initialization = this.#initializeGuard(project, root);
        this.#guardInitializations.set(project.projectId, initialization);
        void initialization.then(
          () => {
            if (this.#guardInitializations.get(project.projectId) === initialization) {
              this.#guardInitializations.delete(project.projectId);
            }
          },
          () => {
            if (this.#guardInitializations.get(project.projectId) === initialization) {
              this.#guardInitializations.delete(project.projectId);
            }
          },
        );
      }
      guarded = await initialization;
    }

    if (guarded.root !== root) {
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'authorized project root changed');
    }
    try {
      await guarded.paths.assertUnchanged();
    } catch (error: unknown) {
      if (isAbortReason(signal, error) || error instanceof ScgStorageError) {
        throw error;
      }
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'authorized project storage is unavailable');
    }
    this.#assertStorageAvailable(project);
    signal.throwIfAborted();
    return guarded;
  }

  async #initializeGuard(project: AuthorizedProject, root: string): Promise<GuardedProject> {
    try {
      const paths = await guardAnnotationPaths(root);
      this.#assertStorageAvailable(project);
      const guarded = Object.freeze({ root, paths });
      this.#guards.set(project.projectId, guarded);
      return guarded;
    } catch (error: unknown) {
      if (error instanceof ScgStorageError) {
        throw error;
      }
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'authorized project storage is unavailable');
    }
  }

  async #runProjectCommit<T>(project: AuthorizedProject, operation: () => Promise<T>): Promise<T> {
    const previous = this.#commitTails.get(project.projectId);
    let release!: () => void;
    const tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#commitTails.set(project.projectId, tail);

    try {
      if (previous !== undefined) {
        await previous;
      }
      return await operation();
    } finally {
      release();
      if (this.#commitTails.get(project.projectId) === tail) {
        this.#commitTails.delete(project.projectId);
      }
    }
  }

  #assertOperationAllowed(project: AuthorizedProject, signal: AbortSignal): void {
    signal.throwIfAborted();
    this.#assertStorageAvailable(project);
  }

  #assertStorageAvailable(project: AuthorizedProject): void {
    this.#throwIfRootChanged();
    if (this.#quarantinedProjects.has(project.projectId)) {
      throw new ScgStorageError('SCG_STORAGE_INTEGRITY', 'annotation project is quarantined');
    }
  }

  #throwIfRootChanged(): void {
    if (this.#rootChanged) {
      throw new ScgStorageError(
        'SCG_ROOT_CHANGED',
        'annotation storage is stopped after a root change',
      );
    }
  }

  #latchStorageFault(project: AuthorizedProject, error: unknown): void {
    if (isStorageError(error, 'SCG_ROOT_CHANGED')) {
      this.#rootChanged = true;
      return;
    }
    if (
      isStorageError(error, 'SCG_COMMIT_DURABILITY_UNKNOWN') ||
      isStorageError(error, 'SCG_STORAGE_INTEGRITY')
    ) {
      this.#quarantinedProjects.add(project.projectId);
    }
  }

  #limitsFor(project: AuthorizedProject): PageFileValidationLimits {
    const configured = this.#limits;
    if (configured === undefined) {
      return project.effectiveLimits;
    }
    return Object.freeze({
      annotationsPerPage: Math.min(
        configured.annotationsPerPage,
        project.effectiveLimits.annotationsPerPage,
      ),
      pageFileBytes: Math.min(configured.pageFileBytes, project.effectiveLimits.pageFileBytes),
      replayLedgerBytes: Math.min(
        configured.replayLedgerBytes,
        project.effectiveLimits.replayLedgerBytes,
      ),
      replayResultBytes: Math.min(
        configured.replayResultBytes,
        project.effectiveLimits.replayResultBytes,
      ),
    });
  }
  async #scanBoundedAnnotationDirectory(
    project: AuthorizedProject,
    guarded: GuardedProject,
    signal: AbortSignal,
  ): Promise<BoundedAnnotationDirectory> {
    const names: string[] = [];
    let nonMetadataEntries = 0;
    let recognizedMetadataEntries = 0;
    let directory: Dir | undefined;
    let failure: unknown;
    try {
      await guarded.paths.assertUnchanged();
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
      directory = await opendir(guarded.paths.annotationsDirectory);
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();

      for (;;) {
        const entry = await directory.read();
        this.#assertStorageAvailable(project);
        signal.throwIfAborted();
        if (entry === null) {
          break;
        }
        const recognizedMetadata = ATOMIC_TEMPORARY_FILE_NAME.test(entry.name);
        if (recognizedMetadata) {
          recognizedMetadataEntries += 1;
          if (recognizedMetadataEntries > MAX_RECOGNIZED_ANNOTATION_METADATA_ENTRIES) {
            throw new ScgStorageError(
              'SCG_LIMIT_FILE',
              'annotation directory exceeds its recognized metadata allowance',
            );
          }
        } else {
          nonMetadataEntries += 1;
          if (nonMetadataEntries > project.effectiveLimits.pagesPerProject) {
            throw new ScgStorageError(
              'SCG_LIMIT_FILE',
              'annotation directory exceeds its effective entry limit',
            );
          }
        }
        if (!PAGE_FILE_NAME.test(entry.name)) {
          if (CASE_INSENSITIVE_PAGE_FILE_NAME.test(entry.name)) {
            throw new ScgStorageError('SCG_PAGE_ID_COLLISION', 'page file name is not canonical');
          }
          continue;
        }
        if (entry.isSymbolicLink() || !entry.isFile()) {
          throw new ScgStorageError('SCG_ROOT_CHANGED', 'page file is not a regular file');
        }
        names.push(entry.name);
      }
      names.sort();
      await guarded.paths.assertUnchanged();
      this.#assertStorageAvailable(project);
      signal.throwIfAborted();
    } catch (error: unknown) {
      failure = error;
    }

    if (directory !== undefined) {
      try {
        await directory.close();
      } catch (error: unknown) {
        failure ??= error;
      }
    }

    if (failure !== undefined) {
      if (isAbortReason(signal, failure)) {
        throw failure;
      }
      if (failure instanceof ScgStorageError) {
        throw failure;
      }
      throw new ScgStorageError(
        'SCG_ROOT_CHANGED',
        'annotation storage directory cannot be listed',
      );
    }
    return Object.freeze({
      canonicalPageFileNames: Object.freeze(names),
      canonicalPageCount: names.length,
      nonMetadataEntryCount: nonMetadataEntries,
    });
  }

  async #readStrict(
    target: GuardedPageFile,
    limits: PageFileValidationLimits,
    expectedPage?: PageIdentityV1,
    signal?: AbortSignal,
  ): Promise<StoredPage | null> {
    const exists = await target.assertExistingFile(signal);
    signal?.throwIfAborted();
    if (!exists) {
      return null;
    }

    const bytes = await this.#readBoundedPageFile(target, limits, signal);
    signal?.throwIfAborted();
    const page = parseStoredPage(bytes, limits);
    assertStoredPageIdentity(page, target.pageId, expectedPage);
    return Object.freeze({ bytes, page });
  }

  async #readBoundedPageFile(
    target: GuardedPageFile,
    limits: PageFileValidationLimits,
    signal: AbortSignal | undefined,
  ): Promise<Uint8Array> {
    let file: FileHandle | undefined;
    let bytes: Uint8Array | undefined;
    let failure: unknown;
    try {
      file = await open(target.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      signal?.throwIfAborted();
      if (!(await target.assertExistingFile(signal))) {
        throw new ScgStorageError('SCG_ROOT_CHANGED', 'annotation page changed during read');
      }
      signal?.throwIfAborted();

      const buffer = new Uint8Array(limits.pageFileBytes + 1);
      let length = 0;
      while (length < buffer.byteLength) {
        signal?.throwIfAborted();
        const { bytesRead } = await file.read(buffer, length, buffer.byteLength - length, length);
        signal?.throwIfAborted();
        if (bytesRead === 0) {
          break;
        }
        length += bytesRead;
      }
      if (length > limits.pageFileBytes) {
        throw new ScgStorageError(
          'SCG_LIMIT_FILE',
          'annotation page exceeds its effective byte limit',
        );
      }

      const stats = await file.stat();
      signal?.throwIfAborted();
      const pathStats = await lstat(target.path);
      signal?.throwIfAborted();
      if (
        !stats.isFile() ||
        !pathStats.isFile() ||
        pathStats.isSymbolicLink() ||
        pathStats.dev !== stats.dev ||
        pathStats.ino !== stats.ino ||
        stats.size !== length
      ) {
        throw new ScgStorageError('SCG_ROOT_CHANGED', 'annotation page changed during read');
      }
      if (!(await target.assertExistingFile(signal))) {
        throw new ScgStorageError('SCG_ROOT_CHANGED', 'annotation page changed during read');
      }
      signal?.throwIfAborted();
      bytes = buffer.subarray(0, length);
    } catch (error: unknown) {
      failure = error;
    }

    if (file !== undefined) {
      try {
        await file.close();
      } catch (error: unknown) {
        failure ??= error;
      }
    }

    if (failure !== undefined) {
      if (signal !== undefined && isAbortReason(signal, failure)) {
        throw failure;
      }
      if (failure instanceof ScgStorageError) {
        throw failure;
      }
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'annotation page cannot be read');
    }
    if (bytes === undefined) {
      throw new ScgStorageError('SCG_ROOT_CHANGED', 'annotation page cannot be read');
    }
    signal?.throwIfAborted();
    return bytes;
  }
}

function parseRequestedPage(page: PageIdentityV1): PageIdentityV1 {
  try {
    const parsed = parsePageIdentityV1(page);
    assertPageIdentity(parsed);
    return parsed;
  } catch (error: unknown) {
    if (error instanceof ScgStorageError) {
      throw error;
    }
    if (error instanceof SceneGlassContractError) {
      if (error.code === 'SCG_LIMIT_FILE') {
        throw error;
      }
      throw new ScgStorageError('SCG_PAGE_INVALID', 'requested page is invalid');
    }
    throw error;
  }
}

function parseCommitPage(page: PageFileV1, limits: PageFileValidationLimits): PageFileV1 {
  try {
    const parsed = parsePageFileV1(page, limits);
    assertPageIdentity(parsed.page);
    return parsed;
  } catch (error: unknown) {
    if (error instanceof ScgStorageError) {
      throw error;
    }
    if (error instanceof SceneGlassContractError) {
      if (error.code === 'SCG_LIMIT_FILE') {
        throw error;
      }
      throw new ScgStorageError('SCG_PAGE_INVALID', 'annotation page is invalid');
    }
    throw error;
  }
}

function parseStoredPage(bytes: Uint8Array, limits: PageFileValidationLimits): PageFileV1 {
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new ScgStorageError('SCG_PAGE_CORRUPT', 'annotation page is not valid UTF-8');
  }

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (error: unknown) {
    if (error instanceof TypeError) {
      throw new ScgStorageError('SCG_PAGE_CORRUPT', 'annotation page is not valid UTF-8');
    }
    throw error;
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error: unknown) {
    if (error instanceof SyntaxError) {
      throw new ScgStorageError('SCG_PAGE_CORRUPT', 'annotation page is invalid');
    }
    throw error;
  }

  let parsed: PageFileV1;
  try {
    parsed = parsePageFileV1(value, limits);
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      if (error.code === 'SCG_LIMIT_FILE') {
        throw error;
      }
      throw new ScgStorageError('SCG_PAGE_CORRUPT', 'annotation page is invalid');
    }
    throw error;
  }

  const canonical = encodeCanonicalPage(parsed);
  if (!sameBytes(bytes, canonical)) {
    throw new ScgStorageError('SCG_PAGE_CORRUPT', 'annotation page is not canonical JSON');
  }
  return parsed;
}

function assertCommitReplayHistory(
  candidate: PageFileV1,
  existing: StoredPage | null,
  candidateBytes: Uint8Array,
  limits: PageFileValidationLimits,
): void {
  if (existing === null) {
    for (const record of candidate.replayWindow) {
      parseReplayRecord(record, limits);
    }
    return;
  }

  if (sameBytes(candidateBytes, existing.bytes)) {
    return;
  }

  if (candidate.revision !== existing.page.revision + 1) {
    throw new ScgStorageError(
      'SCG_PAGE_INVALID',
      'annotation page revision must append exactly one replay record',
    );
  }

  const latestRecord = candidate.replayWindow.at(-1);
  if (latestRecord === undefined) {
    throw new ScgStorageError(
      'SCG_PAGE_INVALID',
      'annotation page replay history is missing its tail',
    );
  }

  const expectedHistory =
    existing.page.replayWindow.length === REPLAY_RECORD_COUNT
      ? existing.page.replayWindow.slice(1)
      : existing.page.replayWindow;
  const candidateHistory = candidate.replayWindow.slice(0, -1);
  if (
    candidateHistory.length !== expectedHistory.length ||
    candidateHistory.some((record, index) => !sameReplayRecord(record, expectedHistory[index]!))
  ) {
    throw new ScgStorageError(
      'SCG_PAGE_INVALID',
      'annotation page replay history must preserve the persisted tail',
    );
  }

  parseReplayRecord(latestRecord, limits);
}

function sameReplayRecord(
  left: PageFileV1['replayWindow'][number],
  right: PageFileV1['replayWindow'][number],
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertStoredPageIdentity(
  page: PageFileV1,
  pageId: string,
  expectedPage: PageIdentityV1 | undefined,
): void {
  assertSafePageId(pageId);
  assertPageIdentity(page.page);
  if (page.page.pageId !== pageId) {
    throw new ScgStorageError(
      'SCG_PAGE_ID_COLLISION',
      'annotation page identity does not match its file name',
    );
  }
  if (expectedPage !== undefined && !samePageIdentity(page.page, expectedPage)) {
    throw new ScgStorageError(
      'SCG_PAGE_ID_COLLISION',
      'annotation page identity does not match the requested page',
    );
  }
}

function assertPageIdentity(page: PageIdentityV1): void {
  if (
    page.canonicalIdentity.normalize('NFC') !== page.canonicalIdentity ||
    page.route.normalize('NFC') !== page.route
  ) {
    throw new ScgStorageError(
      'SCG_PAGE_ID_COLLISION',
      'annotation page identity is not NFC normalized',
    );
  }
  const pageId = `p_${createHash('sha256').update(page.canonicalIdentity, 'utf8').digest('hex')}`;
  if (page.pageId !== pageId) {
    throw new ScgStorageError(
      'SCG_PAGE_ID_COLLISION',
      'annotation page id does not match its canonical identity',
    );
  }
}

function encodeCanonicalPage(page: PageFileV1): Uint8Array {
  return new TextEncoder().encode(serializeCanonicalPageFileV1(page));
}
function assertCanonicalPageFileLimit(bytes: Uint8Array, limits: PageFileValidationLimits): void {
  if (bytes.byteLength > limits.pageFileBytes) {
    throw new ScgStorageError('SCG_LIMIT_FILE', 'annotation page exceeds its effective byte limit');
  }
}

function samePageIdentity(left: PageIdentityV1, right: PageIdentityV1): boolean {
  return (
    left.policyVersion === right.policyVersion &&
    left.canonicalIdentity === right.canonicalIdentity &&
    left.route === right.route &&
    left.pageId === right.pageId
  );
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function isStorageError(error: unknown, code: ScgStorageError['code']): error is ScgStorageError {
  return error instanceof ScgStorageError && error.code === code;
}

function isAbortReason(signal: AbortSignal, error: unknown): boolean {
  return signal.aborted && error === signal.reason;
}
