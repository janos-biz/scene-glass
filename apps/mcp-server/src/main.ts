import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { createSceneGlassApp, registerSceneGlassLoader } from '@scene-glass/server';
import {
  ConfigPathInputError,
  resolveSceneGlassConfigPath,
} from '../../../packages/server/src/startup/config-path.js';

export const LOOPBACK_HOST = '127.0.0.1';

export interface StartupOptions {
  readonly configPath: string;
  readonly port: number;
}

export interface MainOptions {
  readonly argv?: readonly string[];
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

export class StartupInputError extends Error {
  public constructor() {
    super('Scene Glass startup options are invalid');
    this.name = 'StartupInputError';
  }
}

/**
 * Parses the only supported startup settings. Values supplied on the command
 * line take precedence over their explicit environment counterparts.
 */
export function parseStartupOptions(
  argv: readonly string[] = process.argv.slice(2),
  environment: Readonly<Record<string, string | undefined>> = process.env,
): StartupOptions {
  const values = readArguments(argv);
  assertLoopbackOnly(values.host ?? environment.SCENE_GLASS_HOST);

  let configPath: string;
  try {
    configPath = resolveSceneGlassConfigPath({
      ...(values.configPath === undefined ? {} : { configPath: values.configPath }),
      environment,
      homeDirectory: homedir,
    });
  } catch (error: unknown) {
    if (error instanceof ConfigPathInputError) {
      throw new StartupInputError();
    }
    throw error;
  }

  const port = parsePort(values.port ?? environment.SCENE_GLASS_PORT);
  return Object.freeze({ configPath, port });
}

/**
 * Creates and binds the server only after factory startup validation succeeds.
 * The listener host is deliberately not configurable.
 */
export async function main(
  options: MainOptions = {},
): Promise<Awaited<ReturnType<typeof createSceneGlassApp>>> {
  const environment = options.environment ?? process.env;
  const startup = parseStartupOptions(options.argv, environment);
  const app = await createSceneGlassApp({
    configPath: startup.configPath,
    environment,
  });
  try {
    const loaderSource = await readSceneGlassLoader();
    registerSceneGlassLoader(app, loaderSource);
  } catch (error: unknown) {
    await app.close();
    throw error;
  }

  let closing: Promise<void> | undefined;
  let receivedShutdownSignal = false;
  const close = (): Promise<void> => {
    closing ??= app.close().then((): void => undefined);
    return closing;
  };
  const onSignal = (): void => {
    receivedShutdownSignal = true;
    void close();
  };

  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  app.addHook('onClose', () => {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  });
  try {
    await app.listen({ host: '127.0.0.1', port: startup.port });
  } catch (error: unknown) {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    await close();
    if (!receivedShutdownSignal) {
      throw error;
    }
  }

  return app;
}

interface ArgumentValues {
  readonly configPath?: string;
  readonly port?: string;
  readonly host?: string;
}

function readArguments(argv: readonly string[]): ArgumentValues {
  let configPath: string | undefined;
  let port: string | undefined;
  let host: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) {
      throw new StartupInputError();
    }

    if (argument.startsWith('--config=')) {
      configPath = assignOnce(configPath, argument.slice('--config='.length));
      continue;
    }
    if (argument.startsWith('--port=')) {
      port = assignOnce(port, argument.slice('--port='.length));
      continue;
    }
    if (argument.startsWith('--host=')) {
      host = assignOnce(host, argument.slice('--host='.length));
      continue;
    }

    if (argument === '--config' || argument === '--port' || argument === '--host') {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new StartupInputError();
      }
      index += 1;
      switch (argument) {
        case '--config':
          configPath = assignOnce(configPath, value);
          break;
        case '--port':
          port = assignOnce(port, value);
          break;
        case '--host':
          host = assignOnce(host, value);
          break;
      }
      continue;
    }

    throw new StartupInputError();
  }

  return Object.freeze({
    ...(configPath === undefined ? {} : { configPath }),
    ...(port === undefined ? {} : { port }),
    ...(host === undefined ? {} : { host }),
  });
}

function assignOnce(existing: string | undefined, value: string): string {
  if (existing !== undefined) {
    throw new StartupInputError();
  }
  return value;
}

function parsePort(value: string | undefined): number {
  if (value === undefined || !/^(?:0|[1-9][0-9]{0,4})$/.test(value)) {
    throw new StartupInputError();
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port > 65_535) {
    throw new StartupInputError();
  }
  return port;
}

function assertLoopbackOnly(value: string | undefined): void {
  if (value !== undefined && value !== LOOPBACK_HOST) {
    throw new StartupInputError();
  }
}

async function readSceneGlassLoader(): Promise<Buffer> {
  const loaderUrl = import.meta.resolve('@scene-glass/browser-client/scene-glass-loader.js');
  return readFile(new URL(loaderUrl));
}

function isDirectExecution(): boolean {
  const entryPoint = process.argv[1];
  return entryPoint !== undefined && import.meta.url === pathToFileURL(resolve(entryPoint)).href;
}

function startupErrorCode(error: unknown): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string' &&
    /^SCG_[A-Z_]+$/.test(error.code)
  ) {
    return error.code;
  }
  return 'SCG_STARTUP_FAILED';
}

if (isDirectExecution()) {
  void main().catch((error: unknown) => {
    process.exitCode = 1;
    process.stderr.write(`${startupErrorCode(error)}\n`);
  });
}
