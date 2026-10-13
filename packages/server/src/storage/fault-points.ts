export const ATOMIC_COMMIT_FAULT_POINTS = [
  'open',
  'write',
  'fsync',
  'close',
  'rename',
  'dir-sync',
] as const;

export type AtomicCommitFaultPoint = (typeof ATOMIC_COMMIT_FAULT_POINTS)[number];

export interface AtomicCommitFaultContext {
  readonly point: AtomicCommitFaultPoint;
  readonly temporaryPath: string;
  readonly targetPath: string;
}

export type AtomicCommitFaultHook = (context: AtomicCommitFaultContext) => void | Promise<void>;

/**
 * Test-only hooks around the durability protocol. A hook runs immediately
 * before the corresponding filesystem operation and may throw to simulate a
 * failure without weakening the production write path.
 */
export type AtomicCommitFaultPoints = Readonly<
  Partial<Record<AtomicCommitFaultPoint, AtomicCommitFaultHook>>
>;

export async function invokeAtomicCommitFaultPoint(
  faultPoints: AtomicCommitFaultPoints | undefined,
  point: AtomicCommitFaultPoint,
  temporaryPath: string,
  targetPath: string,
): Promise<void> {
  const hook = faultPoints?.[point];
  if (hook === undefined) {
    return;
  }
  await hook(
    Object.freeze({
      point,
      temporaryPath,
      targetPath,
    }),
  );
}
