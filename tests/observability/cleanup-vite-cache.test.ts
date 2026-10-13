import { describe, expect, it } from 'vitest';

import {
  VITE_CACHE_DIRECTORY_MODE,
  VITE_CACHE_FILE_MODE,
  VITE_CACHE_LIMITS,
  ViteCacheAuthority,
  reopenViteCacheSession,
  type CacheDirectoryReference,
  type CacheMutationFilesystemPort,
  type CacheNativeSession,
  type CacheOpenedSession,
  type CacheRuntimeFilesystemPort,
  type CacheStage,
  type CacheTransactionPort,
  type CacheTransactionalOperation,
  type CacheTreeScan,
  type CacheTerminalReceipt,
  type CacheWatchEvent,
  type CacheTreeWatcher,
  type ViteCacheLimits,
  type ViteCacheProvenance,
  type ViteCacheSession,
} from '../../packages/onboarding/src/vite/cache.js';
import {
  closeManagedViteCacheAuthority,
  createManagedViteCacheAuthority,
  startManagedViteCacheAuthority,
  ViteCacheMonitor,
  type CacheCanaryScannerPort,
  type ViteCacheMonitorScheduler,
  type ViteCacheMonitorTrigger,
  type ViteCacheRecoveryPort,
  type ViteCacheWriterControl,
} from '../../packages/onboarding/src/vite/cache-monitor.js';
import type { FileIdentity } from '../../packages/onboarding/src/types.js';

const OWNER = Object.freeze({ uid: 501, gid: 20 });
const PARENT = Object.freeze({ device: '9', inode: '1' });
const ROOT = Object.freeze({ device: '9', inode: '2' });
const CANARY_LIMITS = Object.freeze({ ...VITE_CACHE_LIMITS });
const CANARY_DIGEST = Object.freeze({
  algorithm: 'sha256' as const,
  digest: 'c'.repeat(64),
});

const PROVENANCE = Object.freeze({
  version: 1,
  installId: 'install-a',
  canonicalParentPath: '/private/tmp/scene-glass',
  root: {
    identity: ROOT,
    canonicalPath: '/private/tmp/scene-glass/vite-install-a',
    device: '9',
    owner: OWNER,
    mode: VITE_CACHE_DIRECTORY_MODE,
  },
  parent: {
    identity: PARENT,
    canonicalPath: '/private/tmp/scene-glass',
    device: '9',
    owner: OWNER,
    mode: VITE_CACHE_DIRECTORY_MODE,
  },
  parentIdentity: PARENT,
  inverse: {
    kind: 'remove-created-vite-cache',
    rootIdentity: ROOT,
    parentIdentity: PARENT,
    canonicalPath: '/private/tmp/scene-glass/vite-install-a',
  },
} satisfies ViteCacheProvenance);

function identity(inode: string): FileIdentity {
  return { device: '9', inode };
}

function safeScan(): CacheTreeScan {
  return {
    rootIdentity: ROOT,
    entries: [
      {
        identity: ROOT,
        parentIdentity: PARENT,
        device: '9',
        owner: OWNER,
        mode: VITE_CACHE_DIRECTORY_MODE,
        kind: 'directory',
        depth: 0,
        sizeBytes: 0,
        linkCount: 1,
        escaped: false,
      },
      {
        identity: identity('3'),
        parentIdentity: ROOT,
        device: '9',
        owner: OWNER,
        mode: VITE_CACHE_FILE_MODE,
        kind: 'regular-file',
        depth: 1,
        sizeBytes: 1,
        linkCount: 1,
        escaped: false,
      },
    ],
  };
}
function reorderedUnsafeScan(): CacheTreeScan {
  const replacement = identity('44');
  const reversedOwner = { gid: OWNER.gid, uid: OWNER.uid };
  return {
    entries: [
      {
        escaped: false,
        linkCount: 1,
        sizeBytes: 0,
        depth: 0,
        kind: 'directory',
        mode: VITE_CACHE_DIRECTORY_MODE,
        owner: reversedOwner,
        device: '9',
        parentIdentity: { inode: PARENT.inode, device: PARENT.device },
        identity: { inode: replacement.inode, device: replacement.device },
      },
      {
        escaped: false,
        linkCount: 1,
        sizeBytes: 1,
        depth: 1,
        kind: 'regular-file',
        mode: VITE_CACHE_FILE_MODE,
        owner: reversedOwner,
        device: '9',
        parentIdentity: { inode: replacement.inode, device: replacement.device },
        identity: { inode: '3', device: '9' },
      },
    ],
    rootIdentity: { inode: replacement.inode, device: replacement.device },
  };
}
function malformedTreeScans(): readonly unknown[] {
  const accessorScan = { rootIdentity: ROOT, entries: safeScan().entries };
  Object.defineProperty(accessorScan, 'entries', {
    enumerable: true,
    get: () => safeScan().entries,
  });
  const prototypeEntry = Object.assign(Object.create({}), safeScan().entries[0]!);
  return [
    accessorScan,
    { rootIdentity: ROOT, entries: [prototypeEntry, safeScan().entries[1]!] },
    { rootIdentity: { ...ROOT, extra: false }, entries: safeScan().entries },
    { ...safeScan(), extra: false },
    { rootIdentity: ROOT, entries: null },
  ];
}

function fakeNativeSession(): CacheNativeSession {
  return Object.freeze({}) as CacheNativeSession;
}

class TransactionLog implements CacheTransactionPort {
  public readonly predecisions: string[] = [];
  public readonly committed: unknown[] = [];

  public async execute<T, R>(operation: CacheTransactionalOperation<T, R>): Promise<R> {
    this.predecisions.push(operation.predecision.action);
    const committed = operation.commit(await operation.execute());
    this.committed.push(committed);
    return committed;
  }
}

class CleanupMutationFilesystem implements CacheMutationFilesystemPort {
  public staged = 0;
  public restored = 0;
  public removed = 0;
  public absentChecked = 0;
  public readonly nativeSessions: CacheNativeSession[] = [];
  public readonly cacheParent: CacheDirectoryReference;
  public readonly cacheRoot: CacheDirectoryReference;

  public constructor(nativeSession: CacheNativeSession) {
    this.cacheParent = {
      identity: { ...PARENT },
      canonicalPath: '/private/tmp/scene-glass',
      device: '9',
      owner: { ...OWNER },
      mode: VITE_CACHE_DIRECTORY_MODE,
      nativeSession,
    };
    this.cacheRoot = {
      identity: { ...ROOT },
      canonicalPath: '/private/tmp/scene-glass/vite-install-a',
      device: '9',
      owner: { ...OWNER },
      mode: VITE_CACHE_DIRECTORY_MODE,
      nativeSession,
    };
  }

  public async openCacheParent(): Promise<CacheDirectoryReference> {
    return this.cacheParent;
  }

  public async createCacheRoot(): Promise<CacheDirectoryReference> {
    return this.cacheRoot;
  }
  public async closeCacheSession(input: { readonly session: CacheNativeSession }): Promise<void> {
    this.nativeSessions.push(input.session);
  }

  public async stageCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
  }): Promise<CacheStage> {
    this.nativeSessions.push(input.session);
    this.staged += 1;
    return {
      originalRootIdentity: input.provenance.root.identity,
      stagedIdentity: input.provenance.root.identity,
      stagingParentIdentity: input.provenance.parentIdentity,
      stagedCanonicalPath: `/private/tmp/scene-glass/.stage-${this.staged}`,
    };
  }

  public async restoreCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly stage: CacheStage;
  }): Promise<void> {
    this.nativeSessions.push(input.session);
    this.restored += 1;
  }

  public async removeStagedCacheRoot(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly stage: CacheStage;
    readonly receipt: CacheTerminalReceipt;
  }): Promise<void> {
    this.nativeSessions.push(input.session);
    this.removed += 1;
  }

  public async assertCacheAbsent(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly receipt: CacheTerminalReceipt;
  }): Promise<void> {
    this.nativeSessions.push(input.session);
    this.absentChecked += 1;
  }
}

class CleanupRuntimeFilesystem implements CacheRuntimeFilesystemPort {
  public readonly nativeSession = fakeNativeSession();
  public opened = 0;
  public nativeSessionClosed = 0;
  public nativeSessionCloseAttempts = 0;
  public watcherClosed = 0;
  public watcherCloseAttempts = 0;
  public failWatcherClose = false;
  public failNativeSessionClose = false;
  public failCacheTreeScan = false;
  public scanOverride: unknown = undefined;
  public readonly scanResults: unknown[] = [];
  public readonly openedProvenances: ViteCacheProvenance[] = [];
  public readonly nativeSessions: CacheNativeSession[] = [];
  public readonly closedNativeSessions: CacheNativeSession[] = [];
  public readonly scanLimits: ViteCacheLimits[] = [];
  public readonly scannedRootIdentities: FileIdentity[] = [];
  public readonly operations: string[] = [];
  #onWatcherFailure: (() => void) | undefined;
  #closedNativeSessions = new Set<CacheNativeSession>();

  public async openCacheSession(input: {
    readonly provenance: ViteCacheProvenance;
  }): Promise<CacheOpenedSession> {
    this.opened += 1;
    this.openedProvenances.push(input.provenance);
    this.operations.push('open-native-session');
    return {
      nativeSession: this.nativeSession,
      root: PROVENANCE.root,
      parent: PROVENANCE.parent,
    };
  }

  public async closeCacheSession(input: { readonly session: CacheNativeSession }): Promise<void> {
    this.nativeSessionCloseAttempts += 1;
    this.closedNativeSessions.push(input.session);
    this.operations.push('close-native-session');
    if (this.failNativeSessionClose) {
      throw new Error('native session close failed');
    }
    this.#closedNativeSessions.add(input.session);
    this.nativeSessionClosed += 1;
  }

  public async scanCacheTree(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly limits: ViteCacheLimits;
  }): Promise<CacheTreeScan> {
    if (this.#closedNativeSessions.has(input.session)) {
      throw new Error('native cache session was already closed');
    }
    this.nativeSessions.push(input.session);
    this.scanLimits.push(input.limits);
    this.operations.push('scan-cache-tree');
    if (this.failCacheTreeScan) {
      throw new Error('cache tree scan failed');
    }
    const scan =
      this.scanResults.shift() ??
      (this.scanOverride === undefined ? safeScan() : this.scanOverride);
    if (typeof scan === 'object' && scan !== null) {
      const rootIdentity = Object.getOwnPropertyDescriptor(scan, 'rootIdentity');
      if (rootIdentity !== undefined && 'value' in rootIdentity) {
        this.scannedRootIdentities.push(rootIdentity.value as FileIdentity);
      }
    }
    return scan as CacheTreeScan;
  }

  public async watchCacheTree(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly onEvent: (event: CacheWatchEvent) => void;
    readonly onFailure: () => void;
  }): Promise<CacheTreeWatcher> {
    this.nativeSessions.push(input.session);
    this.#onWatcherFailure = input.onFailure;
    this.operations.push('watch-cache-tree');
    return {
      close: async () => {
        this.watcherCloseAttempts += 1;
        this.operations.push('close-tree-watcher');
        if (this.failWatcherClose) {
          throw new Error('close failed');
        }
        this.watcherClosed += 1;
      },
    };
  }

  public failWatcher(): void {
    const onFailure = this.#onWatcherFailure;
    if (onFailure === undefined) {
      throw new Error('cache watcher was not opened');
    }
    onFailure();
  }
}

async function session(filesystem: CleanupRuntimeFilesystem): Promise<ViteCacheSession> {
  return reopenViteCacheSession({ filesystem, provenance: PROVENANCE });
}

class Scheduler implements ViteCacheMonitorScheduler {
  public cleared = 0;
  public failClear = false;
  public returnUndefinedHandle = false;

  public constructor(private readonly operations: string[] = []) {}

  public setInterval(): unknown {
    this.operations.push('set-poll-timer');
    return this.returnUndefinedHandle ? undefined : 'cache-monitor-interval';
  }

  public clearInterval(): void {
    this.cleared += 1;
    this.operations.push('clear-poll-timer');
    if (this.failClear) {
      throw new Error('timer cleanup failed');
    }
  }
}

class Scanner implements CacheCanaryScannerPort {
  public readonly triggers: ViteCacheMonitorTrigger[] = [];
  public readonly nativeSessions: CacheNativeSession[] = [];
  public readonly limits: ViteCacheLimits[] = [];
  public readonly tokenHashes: (readonly string[])[] = [];
  public result: unknown = { detected: false };
  public readonly results: unknown[] = [];
  public failCanaryScan = false;

  public constructor(private readonly operations: string[] = []) {}

  public async scanCacheCanaries(input: {
    readonly session: CacheNativeSession;
    readonly provenance: ViteCacheProvenance;
    readonly trigger: ViteCacheMonitorTrigger;
    readonly limits: ViteCacheLimits;
    readonly tokenHashes: readonly string[];
  }): Promise<{ readonly detected: boolean }> {
    this.triggers.push(input.trigger);
    this.nativeSessions.push(input.session);
    this.limits.push(input.limits);
    this.tokenHashes.push(input.tokenHashes);
    this.operations.push(`scan-canaries:${input.trigger}`);
    if (this.failCanaryScan) {
      throw new Error('canary scan failed');
    }
    return (this.results.shift() ?? this.result) as { readonly detected: boolean };
  }
}

class Writer implements ViteCacheWriterControl {
  public readonly operations: string[] = [];
  public failAbort = false;
  public failTerminate = false;

  public constructor(private readonly operationLog: string[] = []) {}

  public abort(): void {
    this.operations.push('abort');
    this.operationLog.push('abort-writer');
    if (this.failAbort) {
      throw new Error('abort failed');
    }
  }

  public terminate(): Promise<void> {
    this.operations.push('terminate');
    this.operationLog.push('terminate-writer');
    return this.failTerminate ? Promise.reject(new Error('terminate failed')) : Promise.resolve();
  }
}

class Recovery implements ViteCacheRecoveryPort {
  public readonly operations: string[] = [];
  public failCompensation = false;
  public failCompensationAttempts = 0;

  public constructor(private readonly operationLog: string[] = []) {}

  public markCompensationRequired(): Promise<void> {
    this.operations.push('compensate');
    this.operationLog.push('mark-compensation-required');
    const shouldFail = this.failCompensation || this.failCompensationAttempts > 0;
    if (this.failCompensationAttempts > 0) {
      this.failCompensationAttempts -= 1;
    }
    return shouldFail ? Promise.reject(new Error('compensation failed')) : Promise.resolve();
  }
}

describe('Vite cache cleanup observability', () => {
  it('stages and restores predecision state, then preserves a receipt across terminal repeated cleanup', async () => {
    const runtime = new CleanupRuntimeFilesystem();
    const filesystem = new CleanupMutationFilesystem(runtime.nativeSession);
    const transactions = new TransactionLog();
    const authority = new ViteCacheAuthority({ filesystem, transactions });
    const activeSession = await session(runtime);
    expect(activeSession.provenance).toEqual(PROVENANCE);
    const receipt = authority.createTerminalReceipt(activeSession);

    const stagedForRecovery = await authority.stageForRemoval(activeSession);
    await authority.restoreStaged(activeSession, stagedForRecovery);
    const stagedForRemoval = await authority.stageForRemoval(activeSession);
    const terminalReceipt = await authority.finalizeTerminalRemoval({
      session: activeSession,
      stage: stagedForRemoval,
      receipt,
    });
    const repeatedReceipt = await authority.finalizeTerminalRemoval({
      session: activeSession,
      receipt,
    });

    expect(filesystem).toMatchObject({ staged: 2, restored: 1, removed: 1, absentChecked: 1 });
    expect(filesystem.nativeSessions).toEqual([
      activeSession.nativeSession,
      activeSession.nativeSession,
      activeSession.nativeSession,
      activeSession.nativeSession,
      activeSession.nativeSession,
    ]);
    expect(terminalReceipt).toEqual(receipt);
    expect(repeatedReceipt).toEqual(receipt);
    expect(transactions.predecisions).toEqual([
      'stage-vite-cache-removal',
      'restore-staged-vite-cache',
      'stage-vite-cache-removal',
      'terminal-remove-vite-cache',
      'terminal-remove-vite-cache',
    ]);
    expect(
      transactions.committed.filter((value) => JSON.stringify(value) === JSON.stringify(receipt)),
    ).toHaveLength(2);
  });

  it('rejects each forged stage boundary before restoring any native state', async () => {
    const runtime = new CleanupRuntimeFilesystem();
    const filesystem = new CleanupMutationFilesystem(runtime.nativeSession);
    const authority = new ViteCacheAuthority({ filesystem, transactions: new TransactionLog() });
    const activeSession = await session(runtime);
    const pathWithinStagingParent = '/private/tmp/scene-glass/.stage-install-a';
    const forgedStages: ReadonlyArray<readonly [string, CacheStage]> = [
      [
        'cross-device staged root',
        {
          originalRootIdentity: ROOT,
          stagedIdentity: { device: '10', inode: ROOT.inode },
          stagingParentIdentity: PARENT,
          stagedCanonicalPath: pathWithinStagingParent,
        },
      ],
      [
        'staging path escape',
        {
          originalRootIdentity: ROOT,
          stagedIdentity: ROOT,
          stagingParentIdentity: PARENT,
          stagedCanonicalPath: '/private/other/.stage-install-a',
        },
      ],
      [
        'original root inode replacement',
        {
          originalRootIdentity: identity('44'),
          stagedIdentity: ROOT,
          stagingParentIdentity: PARENT,
          stagedCanonicalPath: pathWithinStagingParent,
        },
      ],
      [
        'same-device staged-root substitution',
        {
          originalRootIdentity: ROOT,
          stagedIdentity: identity('44'),
          stagingParentIdentity: PARENT,
          stagedCanonicalPath: pathWithinStagingParent,
        },
      ],
      [
        'staging parent inode replacement',
        {
          originalRootIdentity: ROOT,
          stagedIdentity: ROOT,
          stagingParentIdentity: identity('44'),
          stagedCanonicalPath: pathWithinStagingParent,
        },
      ],
    ];

    for (const [, stage] of forgedStages) {
      await expect(authority.restoreStaged(activeSession, stage)).rejects.toThrow(
        'cache stage identity changed',
      );
    }
    expect(filesystem.restored).toBe(0);
    expect(filesystem.nativeSessions).toEqual([]);
  });

  it('scans creation, failure, recovery, and shutdown while closing its watcher and timer', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scheduler = new Scheduler();
    const scanner = new Scanner();
    const activeSession = await session(filesystem);
    const monitor = new ViteCacheMonitor({
      filesystem,
      scanner,
      session: activeSession,
      canary: { tokenHashes: [CANARY_DIGEST.digest] },
      limits: CANARY_LIMITS,
      scheduler,
      writer: new Writer(),
      recovery: new Recovery(),
    });

    await monitor.start();
    await monitor.inspectFailure();
    await monitor.inspectRecovery();
    await monitor.stop();

    expect(scanner.triggers).toEqual(['creation', 'failure', 'recovery', 'shutdown']);
    expect(scanner.tokenHashes).toEqual([
      [CANARY_DIGEST.digest],
      [CANARY_DIGEST.digest],
      [CANARY_DIGEST.digest],
      [CANARY_DIGEST.digest],
    ]);
    expect(scanner.limits).toEqual([CANARY_LIMITS, CANARY_LIMITS, CANARY_LIMITS, CANARY_LIMITS]);
    expect(scanner.limits.every(Object.isFrozen)).toBe(true);
    expect(filesystem.scanLimits).toEqual([
      CANARY_LIMITS,
      CANARY_LIMITS,
      CANARY_LIMITS,
      CANARY_LIMITS,
    ]);
    expect(filesystem.scanLimits.every(Object.isFrozen)).toBe(true);
    expect(filesystem.watcherClosed).toBe(1);
    expect(scheduler.cleared).toBe(1);
    expect(monitor.state).toBe('stopped');
  });
  it('clears a poll timer installed with an undefined scheduler handle', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scheduler = new Scheduler();
    scheduler.returnUndefinedHandle = true;
    const monitor = new ViteCacheMonitor({
      filesystem,
      scanner: new Scanner(),
      session: await session(filesystem),
      canary: { tokenHashes: [CANARY_DIGEST.digest] },
      limits: CANARY_LIMITS,
      scheduler,
      writer: new Writer(),
      recovery: new Recovery(),
    });

    await monitor.start();
    await monitor.stop();

    expect(scheduler.cleared).toBe(1);
  });

  it('defers unsafe infrastructure disposal until writer quiescence is proven', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scheduler = new Scheduler();
    const scanner = new Scanner();
    filesystem.failWatcherClose = true;
    scheduler.failClear = true;
    const writer = new Writer();
    const recovery = new Recovery();
    writer.failAbort = true;
    writer.failTerminate = true;
    recovery.failCompensation = true;
    const activeSession = await session(filesystem);
    const monitor = new ViteCacheMonitor({
      filesystem,
      scanner,
      session: activeSession,
      canary: { tokenHashes: [CANARY_DIGEST.digest] },
      limits: CANARY_LIMITS,
      scheduler,
      writer,
      recovery,
    });

    await monitor.start();
    filesystem.scanOverride = {
      rootIdentity: identity('replacement'),
      entries: [safeScan().entries[0]!],
    };
    const error = await monitor.inspectFailure().catch((cause: unknown) => cause);

    expect(error).toMatchObject({
      reason: 'unsafe-tree',
      cleanupFailures: ['abort-writer', 'terminate-writer', 'mark-compensation-required'],
    });
    expect(writer.operations).toEqual(['abort', 'terminate']);
    expect(recovery.operations).toEqual(['compensate']);
    expect(scheduler.cleared).toBe(0);
    expect(filesystem.watcherCloseAttempts).toBe(0);
    expect(filesystem.watcherClosed).toBe(0);
    expect(monitor.state).toBe('violated');

    writer.failAbort = false;
    writer.failTerminate = false;
    recovery.failCompensation = false;
    scheduler.failClear = false;
    filesystem.failWatcherClose = false;
    await monitor.stop();

    expect(writer.operations).toEqual(['abort', 'terminate', 'abort', 'terminate']);
    expect(recovery.operations).toEqual(['compensate', 'compensate']);
    expect(scheduler.cleared).toBe(1);
    expect(filesystem.watcherCloseAttempts).toBe(1);
    expect(filesystem.watcherClosed).toBe(1);
    expect(monitor.state).toBe('violated');
  });
  it('retries a rejected stop after transient timer and watcher disposal failures', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scheduler = new Scheduler();
    scheduler.failClear = true;
    filesystem.failWatcherClose = true;
    const activeSession = await session(filesystem);
    const monitor = new ViteCacheMonitor({
      filesystem,
      scanner: new Scanner(),
      session: activeSession,
      canary: { tokenHashes: [CANARY_DIGEST.digest] },
      limits: CANARY_LIMITS,
      scheduler,
      writer: new Writer(),
      recovery: new Recovery(),
    });
    await monitor.start();

    await expect(monitor.stop()).rejects.toMatchObject({
      cleanupFailures: ['clear-poll-timer'],
    });
    scheduler.failClear = false;
    filesystem.failWatcherClose = false;
    await expect(monitor.stop()).resolves.toBeUndefined();

    expect(scheduler.cleared).toBe(2);
    expect(filesystem.watcherCloseAttempts).toBe(1);
    expect(filesystem.watcherClosed).toBe(1);
  });

  it('reinspects a managed session before a retried native close', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const writer = new Writer(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    const activeSession = await session(filesystem);
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: activeSession,
      recovery,
      limits: CANARY_LIMITS,
    });
    const observed: unknown[] = [];
    const lease = await startManagedViteCacheAuthority({
      authority,
      writer,
      canary: CANARY_DIGEST,
      onBackgroundError: (error) => {
        observed.push(error);
      },
    });

    filesystem.failWatcher();

    const violation = await lease.violation;
    expect(violation).toMatchObject({
      reason: 'inspection-failed',
      cleanupFailures: [],
      compensationRequired: true,
    });
    expect(observed).toEqual([violation]);
    expect(recovery.operations).toEqual(['compensate']);
    expect(scanner.triggers).toEqual(['creation', 'failure']);
    expect(filesystem.nativeSessions).toEqual([
      activeSession.nativeSession,
      activeSession.nativeSession,
      activeSession.nativeSession,
    ]);
    expect(filesystem.nativeSessionCloseAttempts).toBe(0);
    expect(filesystem.nativeSessionClosed).toBe(0);

    filesystem.failNativeSessionClose = true;
    await expect(lease.close()).rejects.toMatchObject({
      cleanupFailures: ['close-native-session'],
    });
    expect(filesystem.nativeSessionCloseAttempts).toBe(1);
    expect(filesystem.nativeSessionClosed).toBe(0);

    filesystem.failNativeSessionClose = false;
    await lease.close();

    expect(filesystem.nativeSessionCloseAttempts).toBe(2);
    expect(filesystem.nativeSessionClosed).toBe(1);
    expect(recovery.operations).toEqual(['compensate']);
    expect(scanner.triggers).toEqual(['creation', 'failure', 'failure', 'shutdown', 'shutdown']);
    expect(filesystem.operations).toEqual([
      'open-native-session',
      'watch-cache-tree',
      'scan-cache-tree',
      'scan-canaries:creation',
      'abort-writer',
      'terminate-writer',
      'scan-cache-tree',
      'scan-canaries:failure',
      'close-tree-watcher',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:failure',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
    ]);
  });
  it('requires a trusted current release receipt for every lease and failed-start close attempt', async () => {
    const cases = [
      {
        name: 'tree scan failure',
        disrupt: (filesystem: CleanupRuntimeFilesystem): void => {
          filesystem.failCacheTreeScan = true;
        },
        restore: (filesystem: CleanupRuntimeFilesystem): void => {
          filesystem.failCacheTreeScan = false;
        },
      },
      {
        name: 'canary scan failure',
        disrupt: (_filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void => {
          scanner.failCanaryScan = true;
        },
        restore: (_filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void => {
          scanner.failCanaryScan = false;
        },
      },
      {
        name: 'malformed canary result',
        disrupt: (_filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void => {
          scanner.result = { detected: false, extra: false };
        },
        restore: (_filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void => {
          scanner.result = { detected: false };
        },
      },
    ];

    for (const scenario of cases) {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
        limits: CANARY_LIMITS,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      scenario.disrupt(filesystem, scanner);
      await expect(lease.close()).rejects.toMatchObject({ cleanupFailures: [] });
      expect(filesystem.nativeSessionCloseAttempts).toBe(0);
      expect(recovery.operations).toEqual(['compensate']);
      const failedCanaryIndex = filesystem.operations.lastIndexOf('scan-canaries:shutdown');
      expect(filesystem.operations.slice(failedCanaryIndex - 1, failedCanaryIndex + 1)).toEqual([
        'scan-cache-tree',
        'scan-canaries:shutdown',
      ]);

      scenario.restore(filesystem, scanner);
      await expect(lease.close()).resolves.toBeUndefined();
      const operationsAfterClose = [...filesystem.operations];
      await expect(lease.close()).resolves.toBeUndefined();

      const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
      const canaryIndex = filesystem.operations.lastIndexOf('scan-canaries:shutdown');
      expect(filesystem.operations.slice(canaryIndex - 1, canaryIndex + 1)).toEqual([
        'scan-cache-tree',
        'scan-canaries:shutdown',
      ]);
      expect(canaryIndex).toBeLessThan(closeIndex);
      expect(filesystem.operations.indexOf('mark-compensation-required')).toBeLessThan(closeIndex);
      expect(filesystem.operations).toEqual(operationsAfterClose);
    }

    for (const scenario of cases) {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      scenario.disrupt(filesystem, scanner);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
        limits: CANARY_LIMITS,
      });

      await expect(
        startManagedViteCacheAuthority({
          authority,
          writer: new Writer(filesystem.operations),
          canary: CANARY_DIGEST,
          onBackgroundError: () => undefined,
        }),
      ).rejects.toMatchObject({ cleanupFailures: [] });
      expect(filesystem.nativeSessionCloseAttempts).toBe(0);
      expect(recovery.operations).toEqual(['compensate']);
      const failedCanaryIndex = filesystem.operations.lastIndexOf('scan-canaries:shutdown');
      expect(filesystem.operations.slice(failedCanaryIndex - 1, failedCanaryIndex + 1)).toEqual([
        'scan-cache-tree',
        'scan-canaries:shutdown',
      ]);

      scenario.restore(filesystem, scanner);
      await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();
      const operationsAfterClose = [...filesystem.operations];
      await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();

      const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
      const canaryIndex = filesystem.operations.lastIndexOf('scan-canaries:shutdown');
      expect(filesystem.operations.slice(canaryIndex - 1, canaryIndex + 1)).toEqual([
        'scan-cache-tree',
        'scan-canaries:shutdown',
      ]);
      expect(canaryIndex).toBeLessThan(closeIndex);
      expect(filesystem.operations.indexOf('mark-compensation-required')).toBeLessThan(closeIndex);
      expect(filesystem.operations).toEqual(operationsAfterClose);
    }
  });
  it('reinspects never-started authorities before every direct-close retry', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
      limits: CANARY_LIMITS,
    });

    filesystem.failNativeSessionClose = true;
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      cleanupFailures: ['close-native-session'],
    });
    expect(scanner.tokenHashes).toEqual([
      ['0000000000000000000000000000000000000000000000000000000000000000'],
    ]);
    expect(filesystem.nativeSessionCloseAttempts).toBe(1);

    filesystem.failNativeSessionClose = false;
    recovery.failCompensationAttempts = 1;
    filesystem.failCacheTreeScan = true;
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      reason: 'inspection-failed',
      cleanupFailures: ['mark-compensation-required'],
    });
    expect(filesystem.nativeSessionCloseAttempts).toBe(1);
    expect(recovery.operations).toEqual(['compensate']);

    filesystem.failCacheTreeScan = false;
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();
    const operationsAfterClose = [...filesystem.operations];
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();

    const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
    const canaryIndex = filesystem.operations.lastIndexOf('scan-canaries:shutdown');
    expect(filesystem.operations.slice(canaryIndex - 1, canaryIndex + 1)).toEqual([
      'scan-cache-tree',
      'scan-canaries:shutdown',
    ]);
    const markerIndex = filesystem.operations.lastIndexOf('mark-compensation-required');
    expect(canaryIndex).toBeLessThan(markerIndex);
    expect(markerIndex).toBeLessThan(closeIndex);
    expect(filesystem.operations).toEqual(operationsAfterClose);
    expect(recovery.operations).toEqual(['compensate', 'compensate']);
    expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 2, nativeSessionClosed: 1 });
  });
  it('retains a failed startup session until a fresh retry records compensation', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const recovery = new Recovery(filesystem.operations);
    const scanner = new Scanner(filesystem.operations);
    recovery.failCompensationAttempts = 1;
    filesystem.scanOverride = {
      rootIdentity: identity('replacement'),
      entries: [safeScan().entries[0]!],
    };
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
      limits: CANARY_LIMITS,
    });

    const error = await startManagedViteCacheAuthority({
      authority,
      writer: new Writer(filesystem.operations),
      canary: CANARY_DIGEST,
      onBackgroundError: () => undefined,
    }).catch((cause: unknown) => cause);

    expect(error).toMatchObject({
      reason: 'unsafe-tree',
      cleanupFailures: ['mark-compensation-required'],
      compensationRequired: false,
    });
    expect(filesystem.nativeSessionCloseAttempts).toBe(0);
    expect(recovery.operations).toEqual(['compensate']);

    filesystem.scanOverride = safeScan();
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();

    expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
    expect(recovery.operations).toEqual(['compensate', 'compensate']);
    expect(scanner.triggers).toEqual(['creation', 'creation', 'shutdown']);
    expect(filesystem.scanLimits).toHaveLength(4);
    expect(filesystem.operations).toEqual([
      'open-native-session',
      'watch-cache-tree',
      'scan-cache-tree',
      'abort-writer',
      'terminate-writer',
      'scan-cache-tree',
      'scan-canaries:creation',
      'close-tree-watcher',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:creation',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
    ]);
  });
  it('reinspects every failed-start native-close retry after cache mutations', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    const unsafeTree = (inode: string): CacheTreeScan => ({
      rootIdentity: identity(inode),
      entries: [safeScan().entries[0]!],
    });
    filesystem.failNativeSessionClose = true;
    filesystem.scanOverride = unsafeTree('replacement-start');
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
      limits: CANARY_LIMITS,
    });

    await expect(
      startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      }),
    ).rejects.toMatchObject({ cleanupFailures: ['close-native-session'] });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 0,
    });

    filesystem.scanOverride = unsafeTree('replacement-retry-one');
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      cleanupFailures: ['close-native-session'],
    });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 2,
      nativeSessionClosed: 0,
    });

    filesystem.scanOverride = unsafeTree('replacement-retry-two');
    filesystem.failNativeSessionClose = false;
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();

    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 3,
      nativeSessionClosed: 1,
    });
    expect(filesystem.scannedRootIdentities.slice(-2)).toEqual([
      identity('replacement-retry-one'),
      identity('replacement-retry-two'),
    ]);
    expect(scanner.triggers.slice(-2)).toEqual(['shutdown', 'shutdown']);

    const closeAttemptIndices = filesystem.operations.reduce<number[]>(
      (indices, operation, index) =>
        operation === 'close-native-session' ? [...indices, index] : indices,
      [],
    );
    expect(closeAttemptIndices).toHaveLength(3);
    for (const [attempt, closeAttemptIndex] of closeAttemptIndices.entries()) {
      const previousCloseAttemptIndex = closeAttemptIndices[attempt - 1] ?? -1;
      const operationsBeforeClose = filesystem.operations.slice(
        previousCloseAttemptIndex + 1,
        closeAttemptIndex,
      );
      const canaryInspectionIndex = operationsBeforeClose.reduce(
        (lastIndex, operation, index) =>
          operation.startsWith('scan-canaries:') ? index : lastIndex,
        -1,
      );
      expect(canaryInspectionIndex).toBeGreaterThan(0);
      expect(operationsBeforeClose[canaryInspectionIndex - 1]).toBe('scan-cache-tree');
    }
    expect(filesystem.operations.indexOf('close-tree-watcher')).toBeLessThan(
      closeAttemptIndices[0]!,
    );
    expect(filesystem.operations.indexOf('mark-compensation-required')).toBeLessThan(
      closeAttemptIndices[0]!,
    );
  });
  it('retains failed-start authority when retried inspection is untrusted', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    filesystem.failNativeSessionClose = true;
    filesystem.scanOverride = {
      rootIdentity: identity('replacement-start'),
      entries: [safeScan().entries[0]!],
    };
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
      limits: CANARY_LIMITS,
    });

    await expect(
      startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      }),
    ).rejects.toMatchObject({ cleanupFailures: ['close-native-session'] });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 0,
    });
    expect(recovery.operations).toEqual(['compensate']);

    filesystem.scanOverride = safeScan();
    scanner.failCanaryScan = true;
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      reason: 'inspection-failed',
      cleanupFailures: [],
    });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 0,
    });
    scanner.failCanaryScan = false;
    scanner.result = { detected: false, extra: false };
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      reason: 'inspection-failed',
      cleanupFailures: [],
    });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 0,
    });

    scanner.result = { detected: false };

    filesystem.failCacheTreeScan = true;
    await expect(closeManagedViteCacheAuthority(authority)).rejects.toMatchObject({
      reason: 'inspection-failed',
      cleanupFailures: [],
    });
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 0,
    });

    filesystem.failCacheTreeScan = false;
    filesystem.failNativeSessionClose = false;
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();
    const operationsAfterSuccessfulClose = [...filesystem.operations];
    await expect(closeManagedViteCacheAuthority(authority)).resolves.toBeUndefined();

    const compensationIndex = filesystem.operations.indexOf('mark-compensation-required');
    const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
    expect(compensationIndex).toBeGreaterThan(-1);
    expect(compensationIndex).toBeLessThan(closeIndex);
    expect(filesystem.operations.slice(-3)).toEqual([
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
    ]);
    expect(filesystem.operations).toEqual(operationsAfterSuccessfulClose);
    expect(filesystem).toMatchObject({
      nativeSessionCloseAttempts: 2,
      nativeSessionClosed: 1,
    });
  });
  it.each([
    {
      name: 'unsafe tree',
      releaseEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void scanner;
        filesystem.scanOverride = reorderedUnsafeScan();
      },
      reason: 'unsafe-tree',
    },
    {
      name: 'detected canary',
      releaseEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void filesystem;
        scanner.result = { detected: true };
      },
      reason: 'token-canary-detected',
    },
  ])(
    'rejects a safe-stop lease close after release discovers a trusted $name violation',
    async ({ releaseEvidence, reason }) => {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      await expect(lease.stop()).resolves.toBeUndefined();
      releaseEvidence(filesystem, scanner);
      const releaseViolation = await lease.close().catch((cause: unknown) => cause);

      expect(releaseViolation).toMatchObject({
        reason,
        compensationRequired: true,
        nativeSessionReleased: true,
      });
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
      expect(recovery.operations).toEqual(['compensate']);
      const compensationIndex = filesystem.operations.lastIndexOf('mark-compensation-required');
      const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
      expect(compensationIndex).toBeLessThan(closeIndex);

      const operationsAfterRelease = [...filesystem.operations];
      await expect(lease.stop()).rejects.toBe(releaseViolation);
      await expect(lease.close()).rejects.toBe(releaseViolation);
      expect(filesystem.operations).toEqual(operationsAfterRelease);
    },
  );
  it.each([
    {
      name: 'unsafe tree',
      releaseEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void scanner;
        filesystem.scanOverride = reorderedUnsafeScan();
      },
      restoreEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void scanner;
        filesystem.scanOverride = safeScan();
      },
      reason: 'unsafe-tree',
    },
    {
      name: 'detected canary',
      releaseEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void filesystem;
        scanner.result = { detected: true };
      },
      restoreEvidence(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void filesystem;
        scanner.result = { detected: false };
      },
      reason: 'token-canary-detected',
    },
  ])(
    'retains a trusted $name release violation through native-close retry and terminal replay',
    async ({ releaseEvidence, restoreEvidence, reason }) => {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      await expect(lease.stop()).resolves.toBeUndefined();
      releaseEvidence(filesystem, scanner);
      filesystem.failNativeSessionClose = true;
      const failedClose = await lease.close().catch((cause: unknown) => cause);

      expect(failedClose).toMatchObject({
        reason,
        cleanupFailures: ['close-native-session'],
        compensationRequired: true,
        nativeSessionReleased: false,
      });
      expect(recovery.operations).toEqual(['compensate']);
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 0 });

      filesystem.failNativeSessionClose = false;
      restoreEvidence(filesystem, scanner);
      const terminalOutcome = await lease.close().catch((cause: unknown) => cause);

      expect(terminalOutcome).toMatchObject({
        reason,
        compensationRequired: true,
        nativeSessionReleased: true,
      });
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 2, nativeSessionClosed: 1 });
      const compensationIndex = filesystem.operations.lastIndexOf('mark-compensation-required');
      const closeIndex = filesystem.operations.lastIndexOf('close-native-session');
      expect(compensationIndex).toBeLessThan(closeIndex);

      const operationsAfterSettlement = [...filesystem.operations];
      await expect(lease.stop()).rejects.toBe(terminalOutcome);
      await expect(lease.close()).rejects.toBe(terminalOutcome);
      expect(filesystem.operations).toEqual(operationsAfterSettlement);
    },
  );
  it.each([
    {
      name: 'unsafe tree',
      prepareShutdownPrimary(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void scanner;
        filesystem.scanResults.push(reorderedUnsafeScan(), safeScan());
      },
      reason: 'unsafe-tree',
    },
    {
      name: 'detected canary',
      prepareShutdownPrimary(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
        void filesystem;
        scanner.results.push({ detected: true }, { detected: false });
      },
      reason: 'token-canary-detected',
    },
  ])(
    'retains a shutdown $name primary through safe release and native-close retry',
    async ({ prepareShutdownPrimary, reason }) => {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      prepareShutdownPrimary(filesystem, scanner);
      filesystem.failNativeSessionClose = true;
      const failedClose = await lease.close().catch((cause: unknown) => cause);

      expect(failedClose).toMatchObject({
        reason,
        cleanupFailures: ['close-native-session'],
        compensationRequired: true,
        nativeSessionReleased: false,
      });
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 0 });
      expect(recovery.operations).toEqual(['compensate']);

      filesystem.failNativeSessionClose = false;
      const terminalOutcome = await lease.close().catch((cause: unknown) => cause);

      expect(terminalOutcome).toMatchObject({
        reason,
        compensationRequired: true,
        nativeSessionReleased: true,
      });
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 2, nativeSessionClosed: 1 });
      expect(recovery.operations).toEqual(['compensate']);

      const operationsAfterSettlement = [...filesystem.operations];
      await expect(lease.stop()).rejects.toBe(terminalOutcome);
      await expect(lease.close()).rejects.toBe(terminalOutcome);
      expect(filesystem.operations).toEqual(operationsAfterSettlement);
    },
  );
  it('trusts reordered exact tree envelopes as semantic unsafe release evidence', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
    });
    const lease = await startManagedViteCacheAuthority({
      authority,
      writer: new Writer(filesystem.operations),
      canary: CANARY_DIGEST,
      onBackgroundError: () => undefined,
    });

    filesystem.scanOverride = reorderedUnsafeScan();
    await expect(lease.close()).rejects.toMatchObject({
      reason: 'unsafe-tree',
      compensationRequired: true,
      nativeSessionReleased: true,
    });
    expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
    expect(recovery.operations).toEqual(['compensate']);
  });
  it('retains untrusted release admission after a semantic unsafe stop and replays its terminal lease outcome', async () => {
    const cases = [
      {
        name: 'tree',
        prepare(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
          void scanner;
          filesystem.scanResults.push(reorderedUnsafeScan(), malformedTreeScans()[0]!);
        },
      },
      {
        name: 'canary',
        prepare(filesystem: CleanupRuntimeFilesystem, scanner: Scanner): void {
          filesystem.scanResults.push(reorderedUnsafeScan(), reorderedUnsafeScan());
          scanner.results.push({ detected: false }, { detected: false, extra: false });
        },
      },
    ];

    for (const scenario of cases) {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      scenario.prepare(filesystem, scanner);
      const retained = await lease.close().catch((cause: unknown) => cause);
      expect(retained).toMatchObject({
        reason: 'unsafe-tree',
        compensationRequired: true,
        nativeSessionReleased: false,
      });
      expect(filesystem.nativeSessionCloseAttempts).toBe(0);

      filesystem.scanResults.push(safeScan(), safeScan());
      scanner.results.push({ detected: false }, { detected: false });
      const terminal = await lease.close().catch((cause: unknown) => cause);
      expect(terminal).toMatchObject({
        reason: 'unsafe-tree',
        compensationRequired: true,
        nativeSessionReleased: true,
      });
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
      expect(recovery.operations).toEqual(['compensate']);

      const operationsAfterTerminalOutcome = [...filesystem.operations];
      await expect(lease.stop()).rejects.toBe(terminal);
      await expect(lease.close()).rejects.toBe(terminal);
      expect(filesystem.operations).toEqual(operationsAfterTerminalOutcome);
    }
  });
  it('requires exact fresh release receipts after malformed managed tree scans', async () => {
    for (const malformedScan of malformedTreeScans()) {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner(filesystem.operations);
      const recovery = new Recovery(filesystem.operations);
      const authority = createManagedViteCacheAuthority({
        filesystem,
        scanner,
        session: await session(filesystem),
        recovery,
      });
      const lease = await startManagedViteCacheAuthority({
        authority,
        writer: new Writer(filesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      });

      filesystem.scanOverride = malformedScan;
      await expect(lease.close()).rejects.toMatchObject({
        reason: 'inspection-failed',
        compensationRequired: true,
      });
      expect(filesystem.nativeSessionCloseAttempts).toBe(0);
      expect(recovery.operations).toEqual(['compensate']);

      filesystem.scanOverride = safeScan();
      await expect(lease.close()).resolves.toBeUndefined();
      expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
      expect(scanner.triggers[scanner.triggers.length - 1]).toBe('shutdown');
    }

    const failedStartFilesystem = new CleanupRuntimeFilesystem();
    const failedStartScanner = new Scanner(failedStartFilesystem.operations);
    const failedStartAuthority = createManagedViteCacheAuthority({
      filesystem: failedStartFilesystem,
      scanner: failedStartScanner,
      session: await session(failedStartFilesystem),
      recovery: new Recovery(failedStartFilesystem.operations),
    });
    failedStartFilesystem.scanOverride = malformedTreeScans()[0];
    await expect(
      startManagedViteCacheAuthority({
        authority: failedStartAuthority,
        writer: new Writer(failedStartFilesystem.operations),
        canary: CANARY_DIGEST,
        onBackgroundError: () => undefined,
      }),
    ).rejects.toMatchObject({ reason: 'unsafe-tree' });
    expect(failedStartFilesystem.nativeSessionCloseAttempts).toBe(0);

    failedStartFilesystem.scanOverride = safeScan();
    await expect(closeManagedViteCacheAuthority(failedStartAuthority)).resolves.toBeUndefined();
    expect(failedStartFilesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 1,
    });
    expect(failedStartScanner.triggers[failedStartScanner.triggers.length - 1]).toBe('shutdown');

    const neverStartedFilesystem = new CleanupRuntimeFilesystem();
    const neverStartedScanner = new Scanner(neverStartedFilesystem.operations);
    const neverStartedRecovery = new Recovery(neverStartedFilesystem.operations);
    const neverStartedAuthority = createManagedViteCacheAuthority({
      filesystem: neverStartedFilesystem,
      scanner: neverStartedScanner,
      session: await session(neverStartedFilesystem),
      recovery: neverStartedRecovery,
    });
    neverStartedFilesystem.scanOverride = malformedTreeScans()[1];
    await expect(closeManagedViteCacheAuthority(neverStartedAuthority)).rejects.toMatchObject({
      reason: 'inspection-failed',
      compensationRequired: true,
    });
    expect(neverStartedFilesystem.nativeSessionCloseAttempts).toBe(0);

    neverStartedFilesystem.scanOverride = safeScan();
    neverStartedScanner.failCanaryScan = true;
    await expect(closeManagedViteCacheAuthority(neverStartedAuthority)).rejects.toMatchObject({
      reason: 'inspection-failed',
    });
    expect(neverStartedFilesystem.nativeSessionCloseAttempts).toBe(0);

    neverStartedScanner.failCanaryScan = false;
    await expect(closeManagedViteCacheAuthority(neverStartedAuthority)).resolves.toBeUndefined();
    const closeIndex = neverStartedFilesystem.operations.lastIndexOf('close-native-session');
    expect(neverStartedFilesystem.operations.slice(closeIndex - 2, closeIndex)).toEqual([
      'scan-cache-tree',
      'scan-canaries:shutdown',
    ]);
    expect(neverStartedFilesystem).toMatchObject({
      nativeSessionCloseAttempts: 1,
      nativeSessionClosed: 1,
    });
  });
  it('requires compensation persistence before a managed lease releases its native session', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    recovery.failCompensationAttempts = 1;
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: await session(filesystem),
      recovery,
      limits: CANARY_LIMITS,
    });
    const lease = await startManagedViteCacheAuthority({
      authority,
      writer: new Writer(filesystem.operations),
      canary: CANARY_DIGEST,
      onBackgroundError: () => undefined,
    });
    filesystem.scanOverride = {
      rootIdentity: identity('replacement'),
      entries: [safeScan().entries[0]!],
    };

    await expect(lease.close()).rejects.toMatchObject({
      cleanupFailures: ['mark-compensation-required'],
      compensationRequired: false,
    });
    expect(filesystem.nativeSessionCloseAttempts).toBe(0);
    expect(recovery.operations).toEqual(['compensate']);

    filesystem.scanOverride = safeScan();
    await lease.close();
    await lease.close();

    expect(filesystem).toMatchObject({ nativeSessionCloseAttempts: 1, nativeSessionClosed: 1 });
    expect(recovery.operations).toEqual(['compensate', 'compensate']);
    expect(scanner.triggers).toEqual(['creation', 'shutdown', 'shutdown', 'shutdown']);
    expect(filesystem.scanLimits).toHaveLength(4);
    expect(filesystem.operations).toEqual([
      'open-native-session',
      'watch-cache-tree',
      'scan-cache-tree',
      'scan-canaries:creation',
      'abort-writer',
      'terminate-writer',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-tree-watcher',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
    ]);
  });
  it('retains a primary shutdown violation after native close and recovery cleanup complete', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scanner = new Scanner(filesystem.operations);
    const writer = new Writer(filesystem.operations);
    const recovery = new Recovery(filesystem.operations);
    const activeSession = await session(filesystem);
    const authority = createManagedViteCacheAuthority({
      filesystem,
      scanner,
      session: activeSession,
      recovery,
      limits: CANARY_LIMITS,
    });
    const lease = await startManagedViteCacheAuthority({
      authority,
      writer,
      canary: CANARY_DIGEST,
      onBackgroundError: () => undefined,
    });

    filesystem.scanOverride = {
      rootIdentity: identity('replacement'),
      entries: [safeScan().entries[0]!],
    };
    const error = await lease.close().catch((cause: unknown) => cause);

    expect(error).toMatchObject({
      reason: 'unsafe-tree',
      cleanupFailures: [],
      compensationRequired: true,
    });
    expect(filesystem).toMatchObject({ watcherClosed: 1, nativeSessionClosed: 1 });
    expect(filesystem.operations).toEqual([
      'open-native-session',
      'watch-cache-tree',
      'scan-cache-tree',
      'scan-canaries:creation',
      'abort-writer',
      'terminate-writer',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-tree-watcher',
      'mark-compensation-required',
      'scan-cache-tree',
      'scan-canaries:shutdown',
      'close-native-session',
    ]);
    expect(recovery.operations).toEqual(['compensate']);
  });
  it('records external inspection compensation before returning the violation', async () => {
    const filesystem = new CleanupRuntimeFilesystem();
    const scheduler = new Scheduler();
    const writer = new Writer();
    const activeSession = await session(filesystem);
    let compensationRecorded = false;
    let beginCompensation!: () => void;
    const compensationStarted = new Promise<void>((resolve) => {
      beginCompensation = resolve;
    });
    let releaseCompensation!: () => void;
    const compensationReleased = new Promise<void>((resolve) => {
      releaseCompensation = resolve;
    });
    const monitor = new ViteCacheMonitor({
      filesystem,
      scanner: new Scanner(),
      session: activeSession,
      canary: { tokenHashes: [CANARY_DIGEST.digest] },
      limits: CANARY_LIMITS,
      scheduler,
      writer,
      recovery: {
        markCompensationRequired: async () => {
          beginCompensation();
          await compensationReleased;
          compensationRecorded = true;
        },
      },
    });

    await monitor.start();
    filesystem.scanOverride = {
      rootIdentity: identity('replacement'),
      entries: [safeScan().entries[0]!],
    };
    const inspection = monitor.inspectFailure().catch((cause: unknown) => cause);

    await compensationStarted;
    expect(compensationRecorded).toBe(false);
    expect(writer.operations).toEqual(['abort', 'terminate']);
    expect(filesystem.watcherClosed).toBe(1);
    expect(filesystem.nativeSessionCloseAttempts).toBe(0);
    expect(filesystem.nativeSessionClosed).toBe(0);
    releaseCompensation();

    const error = await inspection;
    expect(error).toMatchObject({
      reason: 'unsafe-tree',
      compensationRequired: true,
    });
    expect(compensationRecorded).toBe(true);
    expect(writer.operations).toEqual(['abort', 'terminate']);
    expect(filesystem.nativeSessionCloseAttempts).toBe(1);
    expect(filesystem.nativeSessionClosed).toBe(1);

    await monitor.stop();
    expect(filesystem.watcherClosed).toBe(1);
    expect(scheduler.cleared).toBe(1);
  });
  it('rejects canary scanner payloads that are not exact boolean records', async () => {
    const accessorResult = {};
    Object.defineProperty(accessorResult, 'detected', {
      enumerable: true,
      get: () => false,
    });
    const symbolResult = Object.defineProperty({ detected: false }, Symbol('extra'), {
      enumerable: true,
      value: false,
    });
    const invalidResults: readonly unknown[] = [
      { detected: false, extra: false },
      Object.create({ detected: false }),
      accessorResult,
      symbolResult,
    ];

    for (const result of invalidResults) {
      const filesystem = new CleanupRuntimeFilesystem();
      const scanner = new Scanner();
      scanner.result = result;
      const writer = new Writer();
      const recovery = new Recovery();
      const activeSession = await session(filesystem);
      const monitor = new ViteCacheMonitor({
        filesystem,
        scanner,
        session: activeSession,
        canary: { tokenHashes: [CANARY_DIGEST.digest] },
        limits: CANARY_LIMITS,
        writer,
        recovery,
      });

      await expect(monitor.start()).rejects.toMatchObject({ reason: 'inspection-failed' });
      expect(writer.operations).toEqual(['abort', 'terminate']);
      expect(recovery.operations).toEqual(['compensate']);
    }
  });
});
