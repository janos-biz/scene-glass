import type { DiagnosticsPanelOpener, SceneGlassApi } from './client.js';
import type { McpClientDependencies } from './mcp-client.js';
import type { PageIdentityAuthority } from './identity/resolver.js';
import { createSceneGlassRuntime } from './runtime.js';

const PROJECT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const LITERAL_LOOPBACK_PATTERN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})(?:\/|$)/;

export interface SceneGlassLoaderOptions extends McpClientDependencies {
  readonly window?: Window;
  readonly document?: Document;
  readonly script?: HTMLScriptElement | null;
  readonly openDiagnosticsPanel?: DiagnosticsPanelOpener;
  readonly pageIdentity?: PageIdentityAuthority;
}

export function installSceneGlass(
  options: SceneGlassLoaderOptions = {},
): SceneGlassApi | undefined {
  let browserWindow: Window | undefined;
  let document: Document | undefined;
  try {
    browserWindow = options.window ?? browserWindowOrUndefined();
    document = options.document ?? browserDocumentOrUndefined();
  } catch {
    return undefined;
  }
  if (browserWindow === undefined || document === undefined) {
    return undefined;
  }
  const activeWindow = browserWindow;
  const activeDocument = document;

  let token: string | null = null;
  try {
    const script = options.script ?? currentScript(activeDocument);
    if (script === null) {
      return publishUnavailable(activeWindow);
    }

    const endpointAttribute = script.getAttribute('data-scg-endpoint');
    const project = script.getAttribute('data-scg-project');
    token = script.getAttribute('data-scg-token');
    script.removeAttribute('data-scg-token');
    const navigation = script.getAttribute('data-scg-navigation');
    const pageIdentity =
      options.pageIdentity === undefined
        ? parsePageIdentityAttributes(script)
        : options.pageIdentity;

    if (hasSceneGlass(activeWindow)) {
      token = null;
      return undefined;
    }

    const endpoints = resolveEndpoints(endpointAttribute, script.getAttribute('src'), project);
    if (
      endpoints === null ||
      pageIdentity === null ||
      !isProjectId(project) ||
      !isToken(token) ||
      (navigation !== 'document' && navigation !== 'spa')
    ) {
      token = null;
      return publishUnavailable(activeWindow);
    }

    const runtime = createSceneGlassRuntime({
      endpoint: endpoints.mcp,
      diagnosticEndpoint: endpoints.diagnostic,
      token,
      projectId: project,
      navigation,
      window: activeWindow,
      document: activeDocument,
      ...(pageIdentity === undefined ? {} : { pageIdentity }),
      ...(options.openDiagnosticsPanel === undefined
        ? {}
        : { openDiagnosticsPanel: options.openDiagnosticsPanel }),
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.crypto === undefined ? {} : { crypto: options.crypto }),
    });
    token = null;

    const api = runtime.getApi();
    if (!publish(activeWindow, api)) {
      runtime.destroy();
      return undefined;
    }

    void runtime.start();
    return api;
  } catch {
    token = null;
    return publishUnavailable(activeWindow);
  }
}

function parsePageIdentityAttributes(
  script: HTMLScriptElement,
): PageIdentityAuthority | null | undefined {
  const override = script.getAttribute('data-scg-page-identity');
  if (override === '') {
    return null;
  }

  const includeQuery = parseOptionalBooleanAttribute(script.getAttribute('data-scg-include-query'));
  const includeHash = parseOptionalBooleanAttribute(script.getAttribute('data-scg-include-hash'));
  if (includeQuery === null || includeHash === null) {
    return null;
  }

  if (override === null && includeQuery === undefined && includeHash === undefined) {
    return undefined;
  }

  return Object.freeze({
    ...(override === null ? {} : { override }),
    ...(includeQuery === undefined && includeHash === undefined
      ? {}
      : {
          policy: Object.freeze({
            includeQuery: includeQuery ?? false,
            includeHash: includeHash ?? false,
          }),
        }),
  });
}

function parseOptionalBooleanAttribute(value: string | null): boolean | null | undefined {
  if (value === null) {
    return undefined;
  }
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  return null;
}
function resolveEndpoints(
  endpointAttribute: string | null,
  sourceAttribute: string | null,
  project: string | null,
): { readonly mcp: string; readonly diagnostic: string } | null {
  if (!isProjectId(project)) {
    return null;
  }

  const candidate = endpointAttribute ?? sourceAttribute;
  if (candidate === null) {
    return null;
  }
  const loopback = parseLiteralLoopbackUrl(candidate);
  if (loopback === null) {
    return null;
  }
  if (endpointAttribute !== null && loopback.url.pathname !== '/') {
    return null;
  }

  const projectPath = encodeURIComponent(project);
  return Object.freeze({
    mcp: `${loopback.origin}/mcp/v1/projects/${projectPath}`,
    diagnostic: `${loopback.origin}/mcp/v1/projects/${projectPath}/diagnostic-runs`,
  });
}

function parseLiteralLoopbackUrl(
  value: string,
): { readonly origin: string; readonly url: URL } | null {
  const match = LITERAL_LOOPBACK_PATTERN.exec(value);
  if (match === null) {
    return null;
  }
  const portValue = match[1];
  if (portValue === undefined || Number(portValue) > 65535) {
    return null;
  }

  try {
    const url = new URL(value);
    if (
      url.protocol !== 'http:' ||
      url.hostname !== '127.0.0.1' ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.search.length > 0 ||
      url.hash.length > 0
    ) {
      return null;
    }
    return Object.freeze({
      origin: `http://127.0.0.1:${portValue}`,
      url,
    });
  } catch {
    return null;
  }
}

function isProjectId(value: string | null): value is string {
  return value !== null && PROJECT_ID_PATTERN.test(value);
}

function isToken(value: string | null): value is string {
  return value !== null && value.trim().length > 0 && !containsAsciiControlCharacter(value);
}

function containsAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) {
      return true;
    }
  }
  return false;
}

function currentScript(document: Document): HTMLScriptElement | null {
  const script = document.currentScript;
  if (
    script === null ||
    typeof script.getAttribute !== 'function' ||
    typeof script.removeAttribute !== 'function'
  ) {
    return null;
  }
  return script as HTMLScriptElement;
}

function hasSceneGlass(browserWindow: Window): boolean {
  try {
    return 'SceneGlass' in (browserWindow as Window & { readonly SceneGlass?: unknown });
  } catch {
    return true;
  }
}

function publishUnavailable(browserWindow: Window): SceneGlassApi | undefined {
  if (hasSceneGlass(browserWindow)) {
    return undefined;
  }
  const api = createUnavailableApi();
  return publish(browserWindow, api) ? api : undefined;
}

function publish(browserWindow: Window, api: SceneGlassApi): boolean {
  if (hasSceneGlass(browserWindow)) {
    return false;
  }
  try {
    Object.defineProperty(browserWindow, 'SceneGlass', {
      configurable: false,
      enumerable: false,
      writable: false,
      value: api,
    });
    return true;
  } catch {
    return false;
  }
}

function createUnavailableApi(): SceneGlassApi {
  let state: 'unavailable' | 'destroyed' = 'unavailable';
  return Object.freeze({
    get state(): 'unavailable' | 'destroyed' {
      return state;
    },
    notifyReady(): void {},
    retry(): Promise<void> {
      return Promise.resolve();
    },
    openDiagnostics(): Promise<void> {
      return Promise.reject(new Error('Scene Glass is unavailable'));
    },
    destroy(): Promise<void> {
      state = 'destroyed';
      return Promise.resolve();
    },
  });
}

function browserWindowOrUndefined(): Window | undefined {
  return typeof window === 'undefined' ? undefined : window;
}

function browserDocumentOrUndefined(): Document | undefined {
  return typeof document === 'undefined' ? undefined : document;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  installSceneGlass();
}
