import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import {
  assertLowercaseUuidV4,
  isProjectId,
  SceneGlassContractError,
  type LimitName,
  type ProjectFramework,
} from '@scene-glass/contracts';
import Fastify, { type FastifyInstance } from 'fastify';

import type { EnvironmentSnapshot } from './config/validator.js';
import { LocalTokenVerifier } from './auth/local-token-verifier.js';
import { createDiagnosticsLifecycle } from './diagnostics/index.js';
import { diagnosticRoute } from './http/diagnostic-route.js';
import {
  mcpRoute,
  type McpDispatcher as McpTransportDispatcher,
  type McpDispatcherInput,
} from './http/mcp-route.js';
import { createAnnotationTools, type ProjectLock } from './mcp/annotation-tools.js';
import {
  createMcpDispatcher,
  McpRpcError,
  type McpDispatcher as JsonRpcDispatcher,
} from './mcp/dispatcher.js';
import { createPromptExportTool } from './mcp/export-tool.js';
import { SessionManager } from './mcp/session-manager.js';
import { SceneGlassLogger } from './observability/logger.js';
import { MemoryProjectRegistry } from './registry/memory-project-registry.js';
import { ScgAnnotationStore } from './storage/scg-annotation-store.js';
import {
  buildSceneGlassStartupSnapshot,
  buildSceneGlassStartupSnapshotForTest,
  PlatformStartupError,
  type LifecycleSemanticConfigBinding,
  type ProjectRootProbe,
} from './startup/snapshot.js';

const MCP_PROJECT_ROUTE_PREFIX = '/mcp/v1/projects/';
type SceneGlassStartupSnapshot = Awaited<ReturnType<typeof buildSceneGlassStartupSnapshot>>;

export { PlatformStartupError };
export type { ProjectRootProbe };
declare const lifecycleOriginAuthorityBrand: unique symbol;
export interface LifecycleOriginAuthority {
  readonly [lifecycleOriginAuthorityBrand]: 'scene-glass-lifecycle-origin-authority';
}
interface LifecycleOriginAuthorityState {
  readonly binding: LifecycleSemanticConfigBinding;
  readonly replacements: readonly Readonly<{
    readonly projectId: string;
    readonly baseline: readonly string[];
    readonly origins: readonly string[];
  }>[];
  used: boolean;
}
const lifecycleOriginAuthorities = new WeakMap<
  LifecycleOriginAuthority,
  LifecycleOriginAuthorityState
>();

/** Lifecycle-only handoff; normal application options deliberately have no Origin override. */
export function createLifecycleOriginAuthority(
  input: Readonly<{
    readonly binding: LifecycleSemanticConfigBinding;
    readonly replacements: readonly Readonly<{
      readonly projectId: string;
      readonly baseline: readonly string[];
      readonly origins: readonly string[];
    }>[];
  }>,
): LifecycleOriginAuthority {
  const authority = Object.freeze({}) as LifecycleOriginAuthority;
  lifecycleOriginAuthorities.set(authority, {
    binding: snapshotLifecycleSemanticConfigBinding(input.binding),
    replacements: Object.freeze(
      input.replacements.map((replacement) =>
        Object.freeze({
          projectId: replacement.projectId,
          baseline: Object.freeze([...replacement.baseline]),
          origins: Object.freeze([...replacement.origins]),
        }),
      ),
    ),
    used: false,
  });
  return authority;
}

export async function createSceneGlassLifecycleApp(
  options: CreateSceneGlassAppOptions & {
    readonly lifecycleOriginAuthority: LifecycleOriginAuthority;
  },
): Promise<FastifyInstance> {
  if (options.diagnosticAdditionalAllowedOrigin !== undefined) {
    throw new TypeError('lifecycle app cannot widen diagnostic Origin policy');
  }
  const state = lifecycleOriginAuthorities.get(options.lifecycleOriginAuthority);
  if (state === undefined || state.used)
    throw new TypeError('lifecycle Origin authority is invalid');
  state.used = true;
  const logger = options.logger ?? new SceneGlassLogger();
  const startup = await buildSceneGlassStartupSnapshot({
    configPath: options.configPath,
    ...(options.environment === undefined ? {} : { environment: options.environment }),
    logger,
  });
  if (JSON.stringify(startup.lifecycleBinding) !== JSON.stringify(state.binding)) {
    throw new TypeError('lifecycle Origin authority binding is invalid');
  }
  const replacements = new Map(
    state.replacements.map((replacement) => [replacement.projectId, replacement]),
  );
  if (replacements.size !== state.replacements.length) {
    throw new TypeError('lifecycle Origin authority is invalid');
  }
  const seen = new Set<string>();
  let matchedReplacements = 0;
  const projects = startup.validated.projects.map((project) => {
    const replacement = replacements.get(project.projectId);
    if (project.framework === 'html') {
      if (replacement !== undefined) {
        throw new TypeError('lifecycle Origin authority baseline is invalid');
      }
      for (const origin of project.allowedOrigins) {
        if (seen.has(origin)) throw new TypeError('lifecycle Origin authority conflicts');
        seen.add(origin);
      }
      return project;
    }
    if (
      replacement === undefined ||
      JSON.stringify(project.allowedOrigins) !== JSON.stringify(replacement.baseline) ||
      !isExactLifecycleOriginPair(replacement.baseline) ||
      !isExactLifecycleOriginPair(replacement.origins)
    ) {
      throw new TypeError('lifecycle Origin authority baseline is invalid');
    }
    matchedReplacements += 1;
    for (const origin of replacement.origins) {
      if (seen.has(origin)) throw new TypeError('lifecycle Origin authority conflicts');
      seen.add(origin);
    }
    return Object.freeze({ ...project, allowedOrigins: Object.freeze([...replacement.origins]) });
  });
  if (matchedReplacements !== replacements.size) {
    throw new TypeError('lifecycle Origin authority is invalid');
  }
  const transformed = Object.freeze({
    ...startup,
    validated: Object.freeze({ ...startup.validated, projects: Object.freeze(projects) }),
  });
  for (const replacement of state.replacements) {
    logger.emit('origin.applied', {
      count: replacement.origins.length,
      projectId: replacement.projectId,
      stage: 'lifecycle-origin-application',
    });
  }
  return createSceneGlassAppFromStartup(
    options,
    logger,
    withDiagnosticAdditionalAllowedOrigin(transformed, options.diagnosticAdditionalAllowedOrigin),
  );
}

function isExactLifecycleOriginPair(origins: readonly string[]): boolean {
  if (origins.length !== 2) return false;
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/u.exec(origins[0] ?? '');
  if (match === null) return false;
  const port = Number(match[1]);
  return (
    Number.isSafeInteger(port) &&
    port <= 65_535 &&
    port !== 80 &&
    port !== 4_175 &&
    String(port) === match[1] &&
    origins[1] === `http://localhost:${port}`
  );
}
function snapshotLifecycleSemanticConfigBinding(
  value: LifecycleSemanticConfigBinding,
): LifecycleSemanticConfigBinding {
  if (value.schemaVersion !== 1 || !Array.isArray(value.projects)) {
    throw new TypeError('lifecycle Origin authority binding is invalid');
  }
  const globalLimits = snapshotLifecycleNumberRecord(value.globalLimits);
  const projectIds = new Set<string>();
  const projects = value.projects.map((project) => {
    if (
      !isProjectId(project.projectId) ||
      projectIds.has(project.projectId) ||
      typeof project.root !== 'string' ||
      project.root.length === 0 ||
      (project.framework !== 'html' &&
        project.framework !== 'vue3' &&
        project.framework !== 'react') ||
      typeof project.tokenEnv !== 'string' ||
      project.tokenEnv.length === 0 ||
      !Array.isArray(project.allowedOrigins) ||
      project.allowedOrigins.length === 0 ||
      project.allowedOrigins.some((origin: unknown) => typeof origin !== 'string')
    ) {
      throw new TypeError('lifecycle Origin authority binding is invalid');
    }
    projectIds.add(project.projectId);
    const limits = snapshotLifecycleNumberRecord(project.limits);
    return Object.freeze({
      projectId: project.projectId,
      root: project.root,
      framework: project.framework,
      tokenEnv: project.tokenEnv,
      allowedOrigins: Object.freeze([...project.allowedOrigins]),
      ...(limits === undefined ? {} : { limits }),
    });
  });
  return Object.freeze({
    schemaVersion: 1,
    ...(globalLimits === undefined ? {} : { globalLimits }),
    projects: Object.freeze(projects),
  });
}

function snapshotLifecycleNumberRecord(
  value: Readonly<Record<string, number>> | undefined,
): Readonly<Record<string, number>> | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('lifecycle Origin authority binding is invalid');
  }
  const snapshot: Record<string, number> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (!Number.isSafeInteger(entry) || entry < 1) {
      throw new TypeError('lifecycle Origin authority binding is invalid');
    }
    snapshot[key] = entry;
  }
  return Object.freeze(snapshot);
}
export function registerSceneGlassLoader(app: FastifyInstance, loaderSource: Buffer): void {
  if (!Buffer.isBuffer(loaderSource) || loaderSource.byteLength === 0) {
    throw new TypeError('Scene Glass loader source is invalid');
  }
  app.get('/scene-glass-loader.js', (_request, reply) =>
    reply
      .header('cache-control', 'no-store')
      .type('application/javascript; charset=utf-8')
      .send(loaderSource),
  );
}

export interface CreateSceneGlassAppOptions {
  /** Required explicit startup path; configuration is never inferred. */
  readonly configPath: string;
  readonly environment?: EnvironmentSnapshot;
  /**
   * Diagnostic-only origin admitted for one configured project in this app instance.
   * It is never written to the server configuration.
   */
  readonly diagnosticAdditionalAllowedOrigin?: Readonly<{
    readonly origin: string;
    readonly projectId: string;
  }>;
  /** Injectable only for structured-log assertions and host-owned sinks. */
  readonly logger?: SceneGlassLogger;
  /** Injectable only for deterministic timestamps in tests. */
  readonly now?: () => number;
  /** Injectable only for deterministic annotation IDs in tests. */
  readonly randomUuid?: () => string;
}

/** @internal Test-only composition seams. */
export interface CreateSceneGlassAppForTestOptions extends CreateSceneGlassAppOptions {
  readonly projectRootProbe: ProjectRootProbe;
  /** @internal Test-only Fastify factory for composition-failure assertions. */
  readonly fastifyFactory?: () => FastifyInstance;
}

export interface PreflightSceneGlassStartupOptions {
  /** Required explicit startup path; configuration is never inferred. */
  readonly configPath: string;
  readonly environment?: EnvironmentSnapshot;
}

export interface SceneGlassStartupPreflightProject {
  readonly allowedOrigins: readonly string[];
  readonly canonicalRoot: string;
  readonly framework: ProjectFramework;
  readonly limits: Readonly<Record<LimitName, number>>;
  readonly projectId: string;
}

/**
 * The secretless, immutable result of validating startup configuration before
 * creating request, socket, or storage state.
 */
export interface SceneGlassStartupPreflight {
  readonly globalLimits: Readonly<Record<LimitName, number>>;
  readonly projects: readonly SceneGlassStartupPreflightProject[];
}

/**
 * Validates all configuration, credentials, and project roots without creating
 * the local authority. Failures deliberately retain no internal cause.
 */
export async function preflightSceneGlassStartup(
  options: PreflightSceneGlassStartupOptions,
): Promise<SceneGlassStartupPreflight> {
  try {
    return createStartupPreflight(await buildSceneGlassStartupSnapshot(options));
  } catch {
    throw new SceneGlassContractError(
      'SCG_STARTUP_PREFLIGHT_FAILED',
      'Scene Glass startup preflight failed',
    );
  }
}

/**
 * Creates the complete local authority without binding a socket. Startup
 * validates all configuration and configured roots before Fastify is created.
 */
export async function createSceneGlassApp(
  options: CreateSceneGlassAppOptions,
): Promise<FastifyInstance> {
  const logger = options.logger ?? new SceneGlassLogger();
  const startup = withDiagnosticAdditionalAllowedOrigin(
    await buildSceneGlassStartupSnapshot({
      configPath: options.configPath,
      ...(options.environment === undefined ? {} : { environment: options.environment }),
      logger,
    }),
    options.diagnosticAdditionalAllowedOrigin,
  );
  return createSceneGlassAppFromStartup(options, logger, startup);
}

/** @internal Test-only app factory; production uses native root probing and Fastify. */
export async function createSceneGlassAppForTest(
  options: CreateSceneGlassAppForTestOptions,
): Promise<FastifyInstance> {
  const logger = options.logger ?? new SceneGlassLogger();
  const startup = await buildSceneGlassStartupSnapshotForTest({
    configPath: options.configPath,
    ...(options.environment === undefined ? {} : { environment: options.environment }),
    logger,
    projectRootProbe: options.projectRootProbe,
  });
  return createSceneGlassAppFromStartup(options, logger, startup, options.fastifyFactory);
}
function withDiagnosticAdditionalAllowedOrigin(
  startup: SceneGlassStartupSnapshot,
  additional: CreateSceneGlassAppOptions['diagnosticAdditionalAllowedOrigin'],
): SceneGlassStartupSnapshot {
  if (additional === undefined) {
    return startup;
  }
  if (!/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/u.test(additional.origin)) {
    throw new TypeError('diagnostic additional origin must be an exact loopback HTTP origin');
  }

  let found = false;
  const projects = startup.validated.projects.map((project) => {
    if (project.projectId !== additional.projectId) {
      return project;
    }
    found = true;
    if (project.allowedOrigins.includes(additional.origin)) {
      return project;
    }
    return Object.freeze({
      ...project,
      allowedOrigins: Object.freeze([...project.allowedOrigins, additional.origin]),
    });
  });
  if (!found) {
    throw new TypeError('diagnostic additional origin project is not configured');
  }
  return Object.freeze({
    ...startup,
    validated: Object.freeze({
      ...startup.validated,
      projects: Object.freeze(projects),
    }),
  });
}

async function createSceneGlassAppFromStartup(
  options: CreateSceneGlassAppOptions,
  logger: SceneGlassLogger,
  startup: SceneGlassStartupSnapshot,
  fastifyFactory?: () => FastifyInstance,
): Promise<FastifyInstance> {
  const { effectiveLimits, validated } = startup;
  const registry = new MemoryProjectRegistry(validated, effectiveLimits);
  const verifier = new LocalTokenVerifier(
    validated.projects.map((project) => project.normalCredential),
    {
      onRevocationCheckFailed: (evidence) => {
        logger.emit('auth.rejected', { ...evidence });
      },
    },
  );
  logger.emit('config.accepted');

  const sessions = new SessionManager(options.now === undefined ? {} : { now: options.now });
  const diagnostics = createDiagnosticsLifecycle({
    logger,
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  const store = new ScgAnnotationStore();
  const dispatcher = new SessionBoundMcpDispatcher({
    store,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.randomUuid === undefined ? {} : { randomUuid: options.randomUuid }),
  });
  const app = fastifyFactory?.() ?? Fastify({ logger: false });

  app.addHook('onClose', () => {
    sessions.shutdown();
    diagnostics.shutdown();
  });

  try {
    await app.register(mcpRoute, {
      dispatcher,
      logger,
      diagnosticRunStore: diagnostics.runStore,
      maxBodyBytes: effectiveLimits.global.httpBodyBytes,
      requestTimeoutMs: effectiveLimits.global.requestTimeoutMs,
      ...(options.now === undefined ? {} : { now: options.now }),
      registry,
      sessions,
      verifier,
    });
    await app.register(diagnosticRoute, {
      endpointForProject: (project) => diagnosticMcpEndpoint(app, project.projectId),
      issuer: diagnostics.issuer,
      maxBodyBytes: effectiveLimits.global.httpBodyBytes,
      registry,
      verifier,
    });
  } catch (registrationError) {
    try {
      await app.close();
    } catch (cleanupError) {
      throw new AggregateError(
        [registrationError, cleanupError],
        'Scene Glass app registration failed and cleanup failed',
        { cause: registrationError },
      );
    }
    throw registrationError;
  }

  return app;
}

function createStartupPreflight(startup: {
  readonly effectiveLimits: {
    readonly global: Readonly<Record<LimitName, number>>;
    getProject(projectId: string): Readonly<Record<LimitName, number>> | undefined;
  };
  readonly validated: {
    readonly projects: readonly {
      readonly allowedOrigins: readonly string[];
      readonly canonicalRoot: string;
      readonly framework: ProjectFramework;
      readonly projectId: string;
    }[];
  };
}): SceneGlassStartupPreflight {
  const projects = startup.validated.projects.map((project) => {
    const limits = startup.effectiveLimits.getProject(project.projectId);
    if (limits === undefined) {
      throw new TypeError('startup project limits are unavailable');
    }

    return Object.freeze({
      allowedOrigins: Object.freeze([...project.allowedOrigins]),
      canonicalRoot: project.canonicalRoot,
      framework: project.framework,
      limits: freezeLimitValues(limits),
      projectId: project.projectId,
    });
  });

  return Object.freeze({
    globalLimits: freezeLimitValues(startup.effectiveLimits.global),
    projects: Object.freeze(projects),
  });
}

function freezeLimitValues(
  limits: Readonly<Record<LimitName, number>>,
): Readonly<Record<LimitName, number>> {
  return Object.freeze({ ...limits });
}

class SessionBoundMcpDispatcher implements McpTransportDispatcher {
  readonly #dispatchers = new Map<string, JsonRpcDispatcher>();
  readonly #locks = new Map<string, SerialProjectLock>();
  readonly #now: () => number;
  readonly #randomUuid: () => string;
  readonly #store: ScgAnnotationStore;

  public constructor(options: {
    readonly now?: () => number;
    readonly randomUuid?: () => string;
    readonly store: ScgAnnotationStore;
  }) {
    this.#now = options.now ?? Date.now;
    this.#randomUuid = options.randomUuid ?? randomUUID;
    this.#store = options.store;
  }

  public async dispatch(input: McpDispatcherInput): Promise<unknown | undefined> {
    const composedSignal = composeAbortSignals(input.signal, input.session.signal);
    try {
      composedSignal.signal.throwIfAborted();
      const dispatcher = this.dispatcherFor(input);
      composedSignal.signal.throwIfAborted();
      const response = await dispatcher.dispatch(input.message, { signal: composedSignal.signal });
      composedSignal.signal.throwIfAborted();
      return response;
    } finally {
      composedSignal.dispose();
    }
  }

  private dispatcherFor(input: McpDispatcherInput): JsonRpcDispatcher {
    const existing = this.#dispatchers.get(input.session.id);
    if (existing !== undefined) {
      return existing;
    }

    const projectLock = this.lockFor(input.project.projectId);
    const timestamp = (): string => new Date(readEpochMillis(this.#now)).toISOString();
    const dispatcher = createMcpDispatcher({
      scope: 'normal',
      tools: [
        ...createAnnotationTools({
          project: input.project,
          store: this.#store,
          projectLock,
          createServerValues: () => {
            const createdAt = timestamp();
            return Object.freeze({
              id: assertLowercaseUuidV4(this.#randomUuid()),
              createdAt,
              updatedAt: createdAt,
            });
          },
          updateServerValues: () =>
            Object.freeze({
              updatedAt: timestamp(),
            }),
        }),
        createPromptExportTool({
          project: input.project,
          store: this.#store,
          projectLock,
          exportTimeoutMs: input.project.effectiveLimits.exportTimeoutMs,
        }),
      ],
    });

    if (
      !input.session.addResource({
        dispose: () => {
          this.#dispatchers.delete(input.session.id);
        },
      })
    ) {
      throw new McpRpcError('SCG_SESSION_CLOSED');
    }
    this.#dispatchers.set(input.session.id, dispatcher);
    return dispatcher;
  }

  private lockFor(projectId: string): ProjectLock {
    let lock = this.#locks.get(projectId);
    if (lock === undefined) {
      lock = new SerialProjectLock();
      this.#locks.set(projectId, lock);
    }
    return lock;
  }
}
interface ComposedAbortSignal {
  readonly signal: AbortSignal;
  dispose(): void;
}

function composeAbortSignals(...signals: AbortSignal[]): ComposedAbortSignal {
  const controller = new AbortController();
  const listeners: Array<readonly [AbortSignal, () => void]> = [];
  let disposed = false;
  const dispose = (): void => {
    if (disposed) {
      return;
    }
    disposed = true;
    for (const [signal, listener] of listeners) {
      signal.removeEventListener('abort', listener);
    }
    listeners.length = 0;
  };
  const abortFrom = (signal: AbortSignal): void => {
    if (!controller.signal.aborted) {
      controller.abort(signal.reason);
    }
    dispose();
  };

  for (const signal of signals) {
    if (signal.aborted) {
      abortFrom(signal);
      break;
    }
    const listener = (): void => {
      abortFrom(signal);
    };
    listeners.push([signal, listener]);
    signal.addEventListener('abort', listener, { once: true });
  }

  return Object.freeze({ signal: controller.signal, dispose });
}

export class SerialProjectLock implements ProjectLock {
  #active = false;
  readonly #waiters: ProjectLockWaiter[] = [];

  public async runExclusive<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> {
    signal.throwIfAborted();
    await this.acquire(signal);
    try {
      signal.throwIfAborted();
      return await operation();
    } finally {
      this.release();
    }
  }

  private acquire(signal: AbortSignal): Promise<void> {
    if (!this.#active) {
      this.#active = true;
      return Promise.resolve();
    }

    return new Promise<void>((resolve, reject) => {
      const onAbort = (): void => {
        const index = this.#waiters.indexOf(waiter);
        if (index !== -1) {
          this.#waiters.splice(index, 1);
        }
        signal.removeEventListener('abort', onAbort);
        reject(signal.reason);
      };
      const waiter: ProjectLockWaiter = { signal, resolve, reject, onAbort };
      this.#waiters.push(waiter);
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
      }
    });
  }

  private release(): void {
    for (;;) {
      const waiter = this.#waiters.shift();
      if (waiter === undefined) {
        this.#active = false;
        return;
      }

      waiter.signal.removeEventListener('abort', waiter.onAbort);
      if (waiter.signal.aborted) {
        waiter.reject(waiter.signal.reason);
        continue;
      }
      waiter.resolve();
      return;
    }
  }
}

interface ProjectLockWaiter {
  readonly signal: AbortSignal;
  readonly resolve: () => void;
  readonly reject: (reason: unknown) => void;
  readonly onAbort: () => void;
}

function diagnosticMcpEndpoint(app: FastifyInstance, projectId: string): string {
  const address = app.server.address();
  if (!isLoopbackAddress(address)) {
    throw new Error('diagnostic MCP endpoint is unavailable');
  }
  return `http://127.0.0.1:${address.port}${MCP_PROJECT_ROUTE_PREFIX}${encodeURIComponent(projectId)}`;
}

function isLoopbackAddress(address: string | AddressInfo | null): address is AddressInfo {
  return (
    address !== null &&
    typeof address === 'object' &&
    address.address === '127.0.0.1' &&
    Number.isSafeInteger(address.port) &&
    address.port > 0 &&
    address.port <= 65_535
  );
}

function readEpochMillis(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError('server clock must return a non-negative safe integer');
  }
  return value;
}
