import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { createSceneGlassAppForTest } from '../../packages/server/src/app.js';
import { rootSupportedResult } from '../../packages/server/src/platform/probe.js';

const token = requiredEnvironment('SCENE_GLASS_TEST_TOKEN');
const projectId = requiredEnvironment('SCENE_GLASS_TEST_PROJECT_ID');
const workspace = await mkdtemp(join(tmpdir(), 'scene-glass-e2e-authority-'));
let app: Awaited<ReturnType<typeof createSceneGlassAppForTest>> | undefined;
let closePromise: Promise<void> | undefined;

const close = (): Promise<void> => {
  closePromise ??= closeResources();
  return closePromise;
};

async function closeResources(): Promise<void> {
  const failures: unknown[] = [];

  if (app !== undefined) {
    try {
      await closeWithinShutdownTimeout(app.close(), 'app close');
    } catch (error) {
      failures.push(error);
    }
  }

  try {
    await closeWithinShutdownTimeout(
      rm(workspace, { force: true, recursive: true }),
      'workspace removal',
    );
  } catch (error) {
    failures.push(error);
  }

  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      'SCENE_GLASS_E2E_AUTHORITY_CLEANUP_FAILED: authority server or workspace cleanup failed.',
    );
  }
}

const cleanupFailureMessage =
  'SCENE_GLASS_E2E_AUTHORITY_CLEANUP_FAILED: authority server or workspace cleanup failed.';
const shutdownCleanupTimeoutMilliseconds = 10_000;

type RedactedShutdownCause = Readonly<{
  readonly source: 'runtime' | 'startup';
  readonly type: 'array' | 'error' | 'null' | 'object' | 'primitive';
}>;

let shutdownExitCode = 0;
let shutdownPromise: Promise<void> | undefined;
let exitCalled = false;
const primaryCauses: RedactedShutdownCause[] = [];

function aggregateErrors(error: unknown): readonly unknown[] {
  return error instanceof AggregateError ? [...error.errors] : [error];
}

function redactShutdownCause(
  source: RedactedShutdownCause['source'],
  error: unknown,
): RedactedShutdownCause {
  return {
    source,
    type:
      error === null
        ? 'null'
        : Array.isArray(error)
          ? 'array'
          : error instanceof Error
            ? 'error'
            : typeof error === 'object'
              ? 'object'
              : 'primitive',
  };
}

async function closeWithinShutdownTimeout(operation: Promise<void>, phase: string): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(
            new Error(
              `SCENE_GLASS_E2E_AUTHORITY_CLEANUP_TIMEOUT: ${phase} exceeded ${shutdownCleanupTimeoutMilliseconds}ms.`,
            ),
          );
        }, shutdownCleanupTimeoutMilliseconds);
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

function exitOnce(exitCode: number): void {
  if (exitCalled) {
    return;
  }

  exitCalled = true;
  process.exit(exitCode);
}

async function finishShutdown(): Promise<void> {
  let cleanupFailures: readonly unknown[] = [];

  try {
    await close();
  } catch (error) {
    cleanupFailures = aggregateErrors(error);
  }

  if (primaryCauses.some((cause) => cause.source === 'runtime')) {
    console.error(
      `SCENE_GLASS_E2E_AUTHORITY_RUNTIME_FAILED: owned authority terminated unexpectedly; causes=${JSON.stringify(primaryCauses)}.`,
    );
  }
  if (primaryCauses.some((cause) => cause.source === 'startup')) {
    console.error(
      `SCENE_GLASS_E2E_AUTHORITY_STARTUP_FAILED: unable to start owned authority; causes=${JSON.stringify(primaryCauses)}.`,
    );
  }
  if (cleanupFailures.length > 0) {
    console.error(`${cleanupFailureMessage} failures=${cleanupFailures.length}.`);
  }

  const exitCode =
    shutdownExitCode === 0 && primaryCauses.length === 0 && cleanupFailures.length === 0 ? 0 : 1;
  exitOnce(exitCode);
}

function requestShutdown(exitCode: number, cause?: RedactedShutdownCause): void {
  shutdownExitCode = Math.max(shutdownExitCode, exitCode);
  if (cause !== undefined) {
    primaryCauses.push(cause);
  }
  shutdownPromise ??= finishShutdown();
}

const fail = (reason: unknown): void => {
  requestShutdown(1, redactShutdownCause('runtime', reason));
};

process.once('SIGINT', () => requestShutdown(0));
process.once('SIGTERM', () => requestShutdown(0));
process.once('uncaughtException', fail);
process.once('unhandledRejection', fail);

try {
  const projectRoot = join(workspace, 'project');
  const configPath = join(workspace, 'scene-glass.config.json');

  await mkdir(projectRoot);
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      projects: [
        {
          projectId,
          root: projectRoot,
          allowedOrigins: ['http://127.0.0.1:4173', 'http://127.0.0.1:4174'],
          tokenEnv: 'SCENE_GLASS_TEST_TOKEN',
        },
      ],
    }),
  );

  const loaderSource = await readFile(
    resolve(process.cwd(), 'packages/browser-client/dist/scene-glass-loader.js'),
    'utf8',
  );
  app = await createSceneGlassAppForTest({
    configPath,
    environment: { SCENE_GLASS_TEST_TOKEN: token },
    projectRootProbe: async (root) =>
      rootSupportedResult('darwin', 'macos-authoritative', {
        realPath: root,
        device: 1,
        inode: 1,
        fileSystemType: 26,
        identityStableAtProbe: true,
      }),
  });
  app.get('/scene-glass-loader.js', (_request, reply) =>
    reply.type('application/javascript; charset=utf-8').send(loaderSource),
  );

  await app.listen({ host: '127.0.0.1', port: 4175 });
  console.log('SCENE_GLASS_E2E_READY http://127.0.0.1:4175/scene-glass-loader.js');
} catch (error) {
  requestShutdown(1, redactShutdownCause('startup', error));
}

await new Promise<void>(() => undefined);

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}
