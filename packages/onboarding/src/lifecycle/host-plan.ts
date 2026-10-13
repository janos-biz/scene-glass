import { createHash } from 'node:crypto';

import { isProjectId } from '@scene-glass/contracts';

import type {
  CredentialAuthority,
  FileIdentity,
  StaticHostDescriptorV1,
  ViteHostDescriptorV1,
} from '../types.js';
import type {
  AdoptedCredentialArtifact,
  OwnedFileArtifact,
  OwnedHunk,
  SetupCreatedCredentialArtifact,
} from './types.js';

export const HOST_PLAN_SCHEMA_VERSION = 1 as const;
export const MANAGED_VITE_CONTRACT = 'g001-managed-vite-v1' as const;
export const STATIC_LOADER_MARKER = '<!-- scene-glass:static-loader:v1 -->' as const;

export const MAX_HOST_CANDIDATES = 8;
export const MAX_HOST_SOURCE_FACTS = 4_096;
export const MAX_HOST_SOURCE_BYTES = 64 * 1024 * 1024;
export const MAX_HOST_SOURCE_FILE_BYTES = 1024 * 1024;
export const MAX_HOST_PACKAGE_FACTS = 64;
export const MAX_HOST_CREDENTIAL_AUTHORITIES = 32;
export const MAX_HOST_PATH_BYTES = 4096;

const VITE_VERSION = '7.3.6' as const;
const VUE_VERSION = '3.5.40' as const;
const VUE_PLUGIN_VERSION = '6.0.8' as const;
const REACT_VERSION = '19.1.1' as const;
const REACT_PLUGIN_VERSION = '5.0.4' as const;
const LOADER_URL = 'http://127.0.0.1:4175/scene-glass-loader.js' as const;
const READINESS_PATH = '/__scene-glass/ready' as const;
const CREDENTIAL_KEY = 'SCENE_GLASS_HOST_TOKEN' as const;
const DECIMAL_IDENTITY = /^(?:0|[1-9][0-9]*)$/;
const INSTALL_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const VITE_CONFIG_PATH = 'vite.config.ts';
const VITE_CONFIG_PATH_PATTERN = /(?:^|\/)vite\.config\.[^/]+$/i;
const MAX_PLANNED_RELATIVE_PATH_BYTES = '.scg/runtime/host-integration-helper.mjs'.length;
const VUE_PLUGIN_SPECIFIER = /(["'])@vitejs\/plugin-vue\1/u;
const PWA_PLUGIN_SPECIFIER = /(["'])vite-plugin-pwa\1/u;
const REACT_PLUGIN_SPECIFIER = /(["'])@vitejs\/plugin-react\1/u;
const MAX_VITE_SERVER_BLOCK_BYTES = 64 * 1024;

export type HostKind = 'vue3' | 'react' | 'html';
export type HostOverride = HostKind;

/**
 * All source text is supplied by the caller. This module neither discovers nor
 * reads files; a false completion bit is deliberately insufficient evidence.
 */
export interface HostSourceScanFact {
  readonly complete: boolean;
  readonly sources: readonly HostSourceFact[];
}

export interface HostSourceFact {
  readonly path: string;
  readonly source: string;
}

/** Resolved package facts, not package-manager range syntax. */
export interface HostPackageFact {
  readonly name: string;
  readonly resolvedDependencies: readonly HostPackageDependencyFact[];
}

export interface HostPackageDependencyFact {
  readonly name: string;
  readonly version: string;
}

/** The only Vite topology this planner accepts from the completed G001 layer. */
export interface ManagedViteConfigFact {
  readonly path: 'vite.config.ts';
  readonly contract: typeof MANAGED_VITE_CONTRACT;
  readonly plugin: '@vitejs/plugin-vue' | '@vitejs/plugin-react';
  readonly aliases: readonly [];
}
/**
 * Detects the supported Vite plugin from an arbitrary host config. The live-dev
 * contract no longer requires a canonical config: the host runs its own dev
 * server, so additional plugins and options are the host's own business. Only
 * ambiguity is rejected (both supported plugins, or neither).
 */
export function managedVitePluginFromConfig(
  source: string,
): ManagedViteConfigFact['plugin'] | undefined {
  if (PWA_PLUGIN_SPECIFIER.test(source)) return undefined;
  if (viteServerFactsFromConfig(source) === undefined) return undefined;
  const vue = VUE_PLUGIN_SPECIFIER.test(source);
  const react = REACT_PLUGIN_SPECIFIER.test(source);
  if (vue === react) return undefined;
  return vue ? '@vitejs/plugin-vue' : '@vitejs/plugin-react';
}

/**
 * Statically resolves the host dev-server origin facts from an arbitrary Vite
 * config. Only the top level of the single `server: { ... }` block is read;
 * nested blocks (fs, proxy, hmr, ...) and unrelated options are ignored.
 * Returns undefined when the origin cannot be determined statically: multiple
 * server blocks, an unterminated block, a non-literal port, a duplicate
 * host/port key, or a non-loopback host.
 */
export function viteServerFactsFromConfig(
  source: string,
):
  | Readonly<{ readonly host?: string; readonly port?: number; readonly strictPort?: boolean }>
  | undefined {
  const openings = [...source.matchAll(/\bserver\s*:\s*\{/gu)];
  if (openings.length === 0) {
    return /\bserver\s*:/u.test(source) ? undefined : Object.freeze({});
  }
  if (openings.length !== 1 || openings[0]?.index === undefined) return undefined;

  const start = openings[0].index + openings[0][0].length;
  const limit = Math.min(source.length, start + MAX_VITE_SERVER_BLOCK_BYTES);
  let depth = 1;
  let quote: string | null = null;
  let topLevel = '';
  let closed = false;
  for (let index = start; index < limit; index += 1) {
    const character = source[index] as string;
    if (quote !== null) {
      if (character === '\\') {
        index += 1;
      } else if (character === quote) {
        quote = null;
      }
      if (depth === 1) topLevel += character;
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      if (depth === 1) topLevel += character;
      continue;
    }
    if (character === '{' || character === '[' || character === '(') {
      depth += 1;
      continue;
    }
    if (character === '}' || character === ']' || character === ')') {
      depth -= 1;
      if (depth === 0) {
        closed = character === '}';
        break;
      }
      continue;
    }
    if (depth === 1) topLevel += character;
  }
  if (!closed) return undefined;

  const hosts = [...topLevel.matchAll(/\bhost\s*:/gu)];
  const ports = [...topLevel.matchAll(/\bport\s*:/gu)];
  if (hosts.length > 1 || ports.length > 1) return undefined;

  let host: string | undefined;
  if (hosts.length === 1 && hosts[0]?.index !== undefined) {
    const rest = topLevel.slice(hosts[0].index + hosts[0][0].length);
    const match = /^\s*(['"])([^'"]*)\1\s*(?:,|$)/u.exec(rest);
    if (match === null || (match[2] !== '127.0.0.1' && match[2] !== 'localhost')) return undefined;
    host = match[2];
  }
  let port: number | undefined;
  if (ports.length === 1 && ports[0]?.index !== undefined) {
    const rest = topLevel.slice(ports[0].index + ports[0][0].length);
    const match = /^\s*([1-9][0-9]{0,4})\s*(?:,|$)/u.exec(rest);
    if (match === null) return undefined;
    const value = Number(match[1]);
    if (!Number.isSafeInteger(value) || value > 65_535) return undefined;
    port = value;
  }
  // HTTPS 로 뜨는 dev 서버는 허가 origin(http) 과 맞지 않는다. 무시하지 말고 닫는다.
  const https = [...topLevel.matchAll(/\bhttps\s*:/gu)];
  if (https.length > 1) return undefined;
  if (https.length === 1 && https[0]?.index !== undefined) {
    if (!/^\s*false\s*(?:,|$)/u.test(topLevel.slice(https[0].index + https[0][0].length))) {
      return undefined;
    }
  }

  const stricts = [...topLevel.matchAll(/\bstrictPort\s*:/gu)];
  if (stricts.length > 1) return undefined;
  let strictPort: boolean | undefined;
  if (stricts.length === 1 && stricts[0]?.index !== undefined) {
    const rest = topLevel.slice(stricts[0].index + stricts[0][0].length);
    const match = /^\s*(true|false)\s*(?:,|$)/u.exec(rest);
    if (match === null) return undefined;
    strictPort = match[1] === 'true';
  }

  return Object.freeze({
    ...(host === undefined ? {} : { host }),
    ...(port === undefined ? {} : { port }),
    ...(strictPort === undefined ? {} : { strictPort }),
  });
}
/**
 * Closed declared-start authority. This parses only the source declarations; it
 * neither loads Vite nor asserts an effective configuration or live listener.
 */
export type DeclaredViteFramework = 'vue3' | 'react';

export type DeclaredViteOriginReason =
  | 'SCG_START_VITE_DECLARATION_INVALID'
  | 'SCG_START_VITE_PORT_DISALLOWED'
  | 'SCG_START_VITE_PERSISTED_BASELINE_INVALID';

export interface DeclaredViteOriginPolicy {
  readonly framework: DeclaredViteFramework;
  readonly projectId: string;
  readonly port: number;
  readonly origins: readonly [string, string];
}

export interface DeclaredViteStartInput {
  readonly framework: DeclaredViteFramework;
  readonly projectId: string;
  readonly packageJson: string;
  readonly viteConfig: string;
  readonly allowedOrigins?: readonly string[];
}

export type DeclaredViteOriginResolution =
  | Readonly<{ readonly ok: true; readonly policy: DeclaredViteOriginPolicy }>
  | Readonly<{ readonly ok: false; readonly reason: DeclaredViteOriginReason }>;

/** Formats the sole accepted Vite Origin representation, in canonical order. */
export function canonicalDeclaredViteOrigins(port: number): readonly [string, string] | undefined {
  if (!isDeclaredVitePort(port)) return undefined;
  return Object.freeze([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
}

/** Validates the immutable historical Vite baseline without accepting reordering. */
export function isHistoricalDeclaredViteOriginPair(origins: readonly string[]): boolean {
  if (origins.length !== 2) return false;
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]*)$/u.exec(origins[0] ?? '');
  if (match === null) return false;
  const port = Number(match[1]);
  const expected = canonicalDeclaredViteOrigins(port);
  return expected !== undefined && origins[1] === expected[1];
}

/** Replaces, never appends to, an already validated historical Vite baseline. */
export function replaceHistoricalDeclaredViteOriginPair(
  baseline: readonly string[],
  port: number,
): readonly [string, string] | undefined {
  if (!isHistoricalDeclaredViteOriginPair(baseline)) return undefined;
  return canonicalDeclaredViteOrigins(port);
}

export function resolveDeclaredViteOriginPolicy(
  input: DeclaredViteStartInput,
): DeclaredViteOriginResolution {
  const invalid = (): DeclaredViteOriginResolution =>
    Object.freeze({ ok: false, reason: 'SCG_START_VITE_DECLARATION_INVALID' as const });
  const baselineInvalid = (): DeclaredViteOriginResolution =>
    Object.freeze({ ok: false, reason: 'SCG_START_VITE_PERSISTED_BASELINE_INVALID' as const });
  const portDisallowed = (): DeclaredViteOriginResolution =>
    Object.freeze({ ok: false, reason: 'SCG_START_VITE_PORT_DISALLOWED' as const });

  if (
    (input.framework !== 'vue3' && input.framework !== 'react') ||
    !isProjectId(input.projectId) ||
    typeof input.packageJson !== 'string' ||
    typeof input.viteConfig !== 'string'
  ) {
    return invalid();
  }
  if (
    input.allowedOrigins !== undefined &&
    !isHistoricalDeclaredViteOriginPair(input.allowedOrigins)
  ) {
    return baselineInvalid();
  }

  const packageRecord = parseDeclaredPackage(input.packageJson);
  if (packageRecord === undefined || packageRecord.name !== input.projectId) return invalid();
  const script = packageRecord.scripts?.dev;
  if (typeof script !== 'string') return invalid();
  const command = parseDeclaredViteScript(script);
  if (command === undefined) return invalid();

  // The host's plugins, imports, aliases and options are its own business. Only
  // three facts decide the origin — the framework plugin, `server.port` and
  // `server.strictPort` — so read exactly those, from the same lenient extractor
  // host discovery already trusts. Requiring the whole file to match a canonical
  // shape made an ordinary extra plugin fail setup and every later start, which
  // pushed hosts into rewriting their own `dev` script to work around it.
  //
  // Lenient is not lax: the extractor still refuses a config whose origin cannot
  // be read statically — more than one `server` block, an unterminated block, a
  // duplicate or non-literal `port`/`strictPort`, a non-loopback host, or an
  // `https` option that is not literally `false`.
  const expectedPlugin = input.framework === 'vue3' ? '@vitejs/plugin-vue' : '@vitejs/plugin-react';
  if (managedVitePluginFromConfig(input.viteConfig) !== expectedPlugin) return invalid();
  const declaration = viteServerFactsFromConfig(input.viteConfig);
  if (declaration === undefined) return invalid();

  // `strictPort` 는 요구하지 않는다. 없으면 Vite 가 점유된 포트를 피해 다음 번호로 올라가고,
  // 그때 브라우저의 Origin 이 허가 목록과 어긋나 **로더가 붙지 않을 뿐**이다. 페이지는 그대로
  // 돌고 권한이 새지도 않는다(토큰은 프로젝트별이라 다른 포트의 페이지가 갖고 있지 않다).
  // 그 정도 결과를 근거로 기동 전체를 막던 것이 호스트에 `--strictPort` 를 강요한 원인이었다.
  // 어긋나면 기동 배너에 찍힌 허가 origin 과 주소창을 대조해 바로 알 수 있다.
  const port = command.port ?? declaration.port ?? 5173;
  const origins = canonicalDeclaredViteOrigins(port);
  if (origins === undefined) return portDisallowed();

  return Object.freeze({
    ok: true,
    policy: Object.freeze({
      framework: input.framework,
      projectId: input.projectId,
      port,
      origins,
    }),
  });
}

function isDeclaredVitePort(port: number): boolean {
  return Number.isSafeInteger(port) && port >= 1 && port <= 65_535 && port !== 80 && port !== 4175;
}

function parseDeclaredPackage(
  value: string,
): { readonly name: string; readonly scripts?: Record<string, unknown> } | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    const record = parsed as Record<string, unknown>;
    if (typeof record.name !== 'string') return undefined;
    if (
      record.scripts !== undefined &&
      (record.scripts === null ||
        typeof record.scripts !== 'object' ||
        Array.isArray(record.scripts))
    ) {
      return undefined;
    }
    return {
      name: record.name,
      ...(record.scripts === undefined
        ? {}
        : { scripts: record.scripts as Record<string, unknown> }),
    };
  } catch {
    return undefined;
  }
}

function parseDeclaredViteScript(script: string):
  | Readonly<{
      readonly host?: '127.0.0.1' | 'localhost';
      readonly port?: number;
      readonly strictPort: boolean;
    }>
  | undefined {
  if (script.trim() !== script || script.length === 0) return undefined;
  const tokens = script.split(/\s+/u);
  if (tokens[0] !== 'vite') return undefined;
  let host: '127.0.0.1' | 'localhost' | undefined;
  let port: number | undefined;
  let strictPort = false;
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === '--strictPort') {
      if (strictPort) return undefined;
      strictPort = true;
      continue;
    }
    const hostValue =
      token === '--host'
        ? tokens[++index]
        : token?.startsWith('--host=')
          ? token.slice(7)
          : undefined;
    if (hostValue !== undefined) {
      if (host !== undefined || (hostValue !== '127.0.0.1' && hostValue !== 'localhost'))
        return undefined;
      host = hostValue;
      continue;
    }
    const portValue =
      token === '--port'
        ? tokens[++index]
        : token?.startsWith('--port=')
          ? token.slice(7)
          : undefined;
    if (portValue !== undefined) {
      if (port !== undefined || !isDecimalPort(portValue)) return undefined;
      port = Number(portValue);
      continue;
    }
    return undefined;
  }
  return Object.freeze({
    ...(host === undefined ? {} : { host }),
    ...(port === undefined ? {} : { port }),
    strictPort,
  });
}

function isDecimalPort(value: string): boolean {
  return /^(?:0|[1-9][0-9]*)$/u.test(value);
}

export interface HostDescriptorFact {
  readonly projectId: string;
  readonly port: number;
  readonly installId: string;
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
}

export interface HostCandidateFact {
  readonly rootPath: string;
  readonly descriptor: HostDescriptorFact;
  readonly package: HostPackageFact | undefined;
  readonly viteConfig: ManagedViteConfigFact | undefined;
  readonly sourceScan: HostSourceScanFact;
}

export interface AdoptCredentialAuthorityFact {
  readonly kind: 'adopt';
  readonly authority: CredentialAuthority;
}

/** This requests entropy and a post-write identity from the transaction layer. */
export interface CreateCredentialCandidateFact {
  readonly kind: 'create';
  readonly requestId: string;
  readonly bits: 256;
  readonly projectId: string;
  readonly path: string;
}

export type HostCredentialFact = AdoptCredentialAuthorityFact | CreateCredentialCandidateFact;

export interface HostPlanInput {
  readonly schemaVersion: 1;
  readonly candidates: readonly HostCandidateFact[];
  readonly credential: HostCredentialFact;
  readonly override?: HostOverride;
}

export interface PendingCredentialAuthority {
  readonly projectId: string;
  readonly path: string;
}

export type HostDescriptorBlueprintAuthority = CredentialAuthority | PendingCredentialAuthority;

/**
 * A preapproval descriptor cannot be passed to a G001 runtime parser. The
 * discriminator and, for a created credential, identity-free placeholder make
 * it structurally distinct from a runtime descriptor.
 */
export type StaticHostDescriptorBlueprint = Omit<
  StaticHostDescriptorV1,
  'credentialAuthorities'
> & {
  readonly kind: 'host-descriptor-blueprint-v1';
  readonly credentialAuthorities: readonly HostDescriptorBlueprintAuthority[];
};

export type ViteHostDescriptorBlueprint = Omit<ViteHostDescriptorV1, 'credentialAuthorities'> & {
  readonly kind: 'host-descriptor-blueprint-v1';
  readonly credentialAuthorities: readonly HostDescriptorBlueprintAuthority[];
};

export type HostDescriptorBlueprint = StaticHostDescriptorBlueprint | ViteHostDescriptorBlueprint;

export interface PlannedHostArtifact {
  readonly role: 'loader' | 'descriptor' | 'helper';
  readonly artifact: OwnedFileArtifact;
}

export interface PlannedAdoptedCredential {
  readonly kind: 'adopted-authority';
  readonly authority: CredentialAuthority;
  readonly artifact: AdoptedCredentialArtifact;
}

export interface PlannedCreatedCredential {
  readonly kind: 'setup-created-candidate';
  readonly requestId: string;
  readonly bits: 256;
  readonly projectId: string;
  readonly path: string;
  readonly artifact: SetupCreatedCredentialArtifact;
}

export type PlannedCredential = PlannedAdoptedCredential | PlannedCreatedCredential;

/**
 * The plan is a secretless structural image. It contains no source content,
 * credentials, token digests, mutation callbacks, generated entropy, or a
 * runtime-valid descriptor.
 */
export interface HostIntegrationPlan {
  readonly schemaVersion: 1;
  readonly host: HostKind;
  readonly rootPath: string;
  readonly installId: string;
  readonly descriptor: HostDescriptorBlueprint;
  readonly loader: Readonly<{
    readonly async: true;
    readonly navigation: 'spa' | 'document';
    readonly dataScgNavigation: 'spa' | 'document';
    readonly sourceMarker: boolean;
    readonly sourceMarkerPlacement: 'immediately-before-unique-head';
    readonly targetPath: 'public/index.html' | 'index.html';
    readonly insertionStrategy: 'immediately-before-unique-head';
  }>;
  readonly credential: PlannedCredential;
  readonly artifacts: readonly PlannedHostArtifact[];
}

export interface FinalizedHostIntegrationPlan {
  readonly schemaVersion: 1;
  readonly host: HostKind;
  readonly rootPath: string;
  readonly installId: string;
  readonly descriptor: StaticHostDescriptorV1 | ViteHostDescriptorV1;
  readonly loader: HostIntegrationPlan['loader'];
  readonly credential: PlannedCredential;
  readonly artifacts: readonly PlannedHostArtifact[];
}

export type HostPlanErrorCode =
  | 'invalid-facts'
  | 'source-scan-indeterminate'
  | 'source-scan-over-budget'
  | 'service-worker-evidence'
  | 'nextjs-unsupported'
  | 'vite-contract-unsupported'
  | 'host-unsupported'
  | 'host-ambiguous'
  | 'override-unsupported'
  | 'static-template-ambiguous'
  | 'loader-already-present'
  | 'credential-unsupported';

export class HostPlanError extends Error {
  public readonly code: HostPlanErrorCode;

  public constructor(code: HostPlanErrorCode, message: string) {
    super(message);
    this.name = 'HostPlanError';
    this.code = code;
  }
}

interface SourceSnapshot {
  readonly path: string;
  readonly source: string;
}

interface PackageSnapshot {
  readonly name: string;
  readonly dependencies: ReadonlyMap<string, string>;
}

interface ViteConfigSnapshot {
  readonly path: 'vite.config.ts';
  readonly plugin: '@vitejs/plugin-vue' | '@vitejs/plugin-react';
}

interface DescriptorSnapshot {
  readonly projectId: string;
  readonly port: number;
  readonly installId: string;
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
}

interface CandidateSnapshot {
  readonly rootPath: string;
  readonly descriptor: DescriptorSnapshot;
  readonly package: PackageSnapshot | undefined;
  readonly viteConfig: ViteConfigSnapshot | undefined;
  readonly sources: readonly SourceSnapshot[];
}

type CredentialSnapshot =
  | {
      readonly kind: 'adopt';
      readonly authority: CredentialAuthority;
    }
  | {
      readonly kind: 'create';
      readonly requestId: string;
      readonly bits: 256;
      readonly projectId: string;
      readonly path: string;
    };

interface InputSnapshot {
  readonly candidates: readonly CandidateSnapshot[];
  readonly credential: CredentialSnapshot;
  readonly override: HostOverride | undefined;
}

/**
 * Builds a bounded, deterministic integration plan from caller-supplied facts.
 * Invalid or unsupported input throws before any plan or mutation intent exists.
 */
export function planHostIntegration(input: HostPlanInput): HostIntegrationPlan {
  const facts = snapshotInput(input);
  if (facts.candidates.length !== 1) {
    fail('host-ambiguous', 'exactly one host candidate is required');
  }
  const candidate = facts.candidates[0];
  if (candidate === undefined) {
    fail('host-ambiguous', 'host candidate is missing');
  }

  const detected = detectHost(candidate);
  if (detected !== 'html' && !isDeclaredVitePort(candidate.descriptor.port)) {
    fail('invalid-facts', 'Vite descriptor port is outside the declared-start contract');
  }
  assertReservedTargetsAbsent(candidate.sources);
  if (facts.override !== undefined && facts.override !== detected) {
    fail('override-unsupported', 'host override is not supported by the detected topology');
  }

  const credential = planCredential(facts.credential, candidate.descriptor);
  const descriptor = createDescriptorBlueprint(detected, candidate.descriptor, credential);
  const loader = createLoader(detected);
  const artifacts = planArtifacts(detected, candidate.rootPath, descriptor, loader.targetPath);

  return Object.freeze({
    schemaVersion: HOST_PLAN_SCHEMA_VERSION,
    host: detected,
    rootPath: candidate.rootPath,
    installId: candidate.descriptor.installId,
    descriptor,
    loader,
    credential,
    artifacts,
  });
}

function snapshotInput(input: unknown): InputSnapshot {
  const root = exactRecord(
    input,
    ['schemaVersion', 'candidates', 'credential'],
    ['override'],
    'host plan input',
  );
  if (root.schemaVersion !== HOST_PLAN_SCHEMA_VERSION) {
    fail('invalid-facts', 'host plan input must use schema version 1');
  }

  const candidates = denseArray(root.candidates, 'host candidates', MAX_HOST_CANDIDATES).map(
    (value) => snapshotCandidate(value),
  );
  const override = root.override === undefined ? undefined : parseHostOverride(root.override);
  const credential = snapshotCredential(root.credential);
  return Object.freeze({ candidates: Object.freeze(candidates), credential, override });
}

function snapshotCandidate(value: unknown): CandidateSnapshot {
  const record = exactRecord(
    value,
    ['rootPath', 'descriptor', 'package', 'viteConfig', 'sourceScan'],
    [],
    'host candidate',
  );
  const rootPath = parseAbsolutePath(record.rootPath, 'host root path');
  if (utf8Bytes(rootPath) + 1 + MAX_PLANNED_RELATIVE_PATH_BYTES > MAX_HOST_PATH_BYTES) {
    fail('invalid-facts', 'host root path leaves no room for planned artifact paths');
  }
  const descriptor = snapshotDescriptor(record.descriptor);
  const packageFact = record.package === undefined ? undefined : snapshotPackage(record.package);
  const viteConfig =
    record.viteConfig === undefined ? undefined : snapshotViteConfig(record.viteConfig);
  const sources = snapshotSourceScan(record.sourceScan);
  return Object.freeze({ rootPath, descriptor, package: packageFact, viteConfig, sources });
}

function snapshotDescriptor(value: unknown): DescriptorSnapshot {
  const record = exactRecord(
    value,
    ['projectId', 'port', 'installId', 'approvedRootIdentity', 'credentialAuthorities'],
    [],
    'host descriptor facts',
  );
  const projectId = parseProjectId(record.projectId, 'descriptor projectId');
  const port = parsePort(record.port);
  const installId = parseIdentifier(record.installId, 'descriptor installId');
  const approvedRootIdentity = snapshotIdentity(
    record.approvedRootIdentity,
    'approved root identity',
  );
  const authorities = denseArray(
    record.credentialAuthorities,
    'credential authorities',
    MAX_HOST_CREDENTIAL_AUTHORITIES,
  ).map((entry) => snapshotAuthority(entry, 'credential authority'));
  if (
    authorities.length > 1 ||
    (authorities[0] !== undefined && authorities[0].projectId !== projectId)
  ) {
    fail('invalid-facts', 'credential authorities must contain only the selected authority');
  }
  return Object.freeze({
    projectId,
    port,
    installId,
    approvedRootIdentity,
    credentialAuthorities: Object.freeze(authorities),
  });
}

function snapshotPackage(value: unknown): PackageSnapshot {
  const record = exactRecord(value, ['name', 'resolvedDependencies'], [], 'package facts');
  const name = parseIdentifier(record.name, 'package name');
  const dependencies = denseArray(
    record.resolvedDependencies,
    'resolved package dependencies',
    MAX_HOST_PACKAGE_FACTS,
  );
  const values = new Map<string, string>();
  for (const dependencyValue of dependencies) {
    const dependency = exactRecord(
      dependencyValue,
      ['name', 'version'],
      [],
      'resolved package dependency',
    );
    const dependencyName = parsePackageName(dependency.name);
    const version = parseVersion(dependency.version);
    if (values.has(dependencyName)) {
      fail('invalid-facts', 'resolved package dependencies must be unique');
    }
    values.set(dependencyName, version);
  }
  return Object.freeze({ name, dependencies: values });
}

function snapshotViteConfig(value: unknown): ViteConfigSnapshot {
  const record = exactRecord(
    value,
    ['path', 'contract', 'plugin', 'aliases'],
    [],
    'Vite config facts',
  );
  if (
    record.path !== VITE_CONFIG_PATH ||
    record.contract !== MANAGED_VITE_CONTRACT ||
    (record.plugin !== '@vitejs/plugin-vue' && record.plugin !== '@vitejs/plugin-react')
  ) {
    fail('vite-contract-unsupported', 'Vite config is outside the managed G001 contract');
  }
  if (denseArray(record.aliases, 'Vite aliases', MAX_HOST_PACKAGE_FACTS).length !== 0) {
    fail('vite-contract-unsupported', 'Vite aliases are outside the managed G001 contract');
  }
  return Object.freeze({ path: VITE_CONFIG_PATH, plugin: record.plugin });
}

function snapshotSourceScan(value: unknown): readonly SourceSnapshot[] {
  const record = exactRecord(value, ['complete', 'sources'], [], 'source scan facts');
  if (record.complete !== true) {
    fail('source-scan-indeterminate', 'source scan must be complete');
  }

  const sourceFacts = denseArray(record.sources, 'source facts', MAX_HOST_SOURCE_FACTS);
  const sources: SourceSnapshot[] = [];
  const paths = new Set<string>();
  let totalBytes = 0;
  for (const sourceFact of sourceFacts) {
    const source = exactRecord(sourceFact, ['path', 'source'], [], 'source fact');
    const path = parseRelativePath(source.path, 'source path');
    const text = parseSource(source.source);
    const size = utf8Bytes(text);
    if (size > MAX_HOST_SOURCE_FILE_BYTES || totalBytes + size > MAX_HOST_SOURCE_BYTES) {
      fail('source-scan-over-budget', 'source scan exceeds its byte budget');
    }
    if (paths.has(path)) {
      fail('invalid-facts', 'source scan paths must be unique');
    }
    paths.add(path);
    totalBytes += size;
    sources.push(Object.freeze({ path, source: text }));
  }
  return Object.freeze(sources);
}
function assertReservedTargetsAbsent(sources: readonly SourceSnapshot[]): void {
  if (
    sources.some(
      (source) =>
        source.path === '.scg/runtime/host-descriptor.v1.json' ||
        source.path === '.scg/runtime/host-integration-helper.mjs',
    )
  ) {
    fail('invalid-facts', 'reserved .scg runtime targets must be absent before approval');
  }
}

function snapshotCredential(value: unknown): CredentialSnapshot {
  const discriminator = recordValues(value, 'credential facts');
  const kind = discriminator.kind;
  if (kind === 'adopt') {
    const record = exactRecord(value, ['kind', 'authority'], [], 'adopted credential facts');
    return Object.freeze({
      kind,
      authority: snapshotAuthority(record.authority, 'adopted credential authority'),
    });
  }
  if (kind === 'create') {
    const record = exactRecord(
      value,
      ['kind', 'requestId', 'bits', 'projectId', 'path'],
      [],
      'created credential facts',
    );
    if (record.bits !== 256) {
      fail('credential-unsupported', 'credential candidate requests must be 256 bits');
    }
    return Object.freeze({
      kind,
      requestId: parseIdentifier(record.requestId, 'credential candidate requestId'),
      bits: 256,
      projectId: parseProjectId(record.projectId, 'created credential projectId'),
      path: parseAbsolutePath(record.path, 'created credential path'),
    });
  }
  fail(
    'credential-unsupported',
    'credential facts must select adoption or a 256-bit candidate request',
  );
}

function snapshotAuthority(value: unknown, name: string): CredentialAuthority {
  const record = exactRecord(value, ['projectId', 'path', 'device', 'inode'], [], name);
  return Object.freeze({
    projectId: parseProjectId(record.projectId, `${name} projectId`),
    path: parseAbsolutePath(record.path, `${name} path`),
    device: parseIdentityPart(record.device, `${name} device`),
    inode: parseIdentityPart(record.inode, `${name} inode`),
  });
}

function snapshotIdentity(value: unknown, name: string): FileIdentity {
  const record = exactRecord(value, ['device', 'inode'], [], name);
  return Object.freeze({
    device: parseIdentityPart(record.device, `${name} device`),
    inode: parseIdentityPart(record.inode, `${name} inode`),
  });
}

function detectHost(candidate: CandidateSnapshot): HostKind {
  if (candidate.viteConfig !== undefined && hasSource(candidate.sources, 'public/index.html')) {
    fail('host-ambiguous', 'Vite and static HTML topology evidence conflict');
  }
  rejectServiceWorkerEvidence(candidate.sources);
  rejectNextEvidence(candidate);
  assertNoExistingLoader(candidate.sources);

  const viteConfigPaths = candidate.sources.filter((source) =>
    VITE_CONFIG_PATH_PATTERN.test(source.path),
  );
  if (candidate.viteConfig === undefined) {
    if (viteConfigPaths.length > 0 || hasViteDependency(candidate.package)) {
      fail('vite-contract-unsupported', 'Vite evidence lacks the managed G001 contract');
    }
    return detectStaticHost(candidate.sources);
  }

  if (
    viteConfigPaths.length !== 1 ||
    viteConfigPaths[0]?.path !== candidate.viteConfig.path ||
    !hasSource(candidate.sources, 'index.html')
  ) {
    fail(
      'vite-contract-unsupported',
      'Vite config and root template facts must match the managed contract',
    );
  }

  const rootTemplate = sourceFor(candidate.sources, 'index.html');
  if (rootTemplate === undefined || countOccurrences(rootTemplate.source, '</head>') !== 1) {
    fail('vite-contract-unsupported', 'Vite root template requires one closing head tag');
  }
  const packageFact = candidate.package;
  if (candidate.viteConfig.plugin === '@vitejs/plugin-vue') {
    if (
      !hasVueEvidence(candidate.sources) ||
      (hasFrameworkDependency(packageFact, ['vite', 'vue', '@vitejs/plugin-vue']) &&
        (!hasCompatibleDependency(packageFact, 'vue', 3) ||
          !hasViteDependency(packageFact) ||
          !hasDependency(packageFact, '@vitejs/plugin-vue')))
    ) {
      fail('host-unsupported', 'Vue Vite evidence is incomplete');
    }
    return 'vue3';
  }

  if (
    !hasReactDiscriminator(candidate.sources) ||
    (hasFrameworkDependency(packageFact, ['vite', 'react', 'react-dom', '@vitejs/plugin-react']) &&
      (!hasCompatibleDependency(packageFact, 'react', 18, 19) ||
        !hasCompatibleDependency(packageFact, 'react-dom', 18, 19) ||
        !hasDependency(packageFact, '@vitejs/plugin-react')))
  ) {
    fail('host-unsupported', 'React Vite evidence is incomplete');
  }
  return 'react';
}

function detectStaticHost(sources: readonly SourceSnapshot[]): 'html' {
  const template = sourceFor(sources, 'public/index.html');
  if (template === undefined) {
    fail('host-unsupported', 'static HTML requires public/index.html source facts');
  }
  const closeCount = countCaseInsensitive(template.source, '</head>');
  const markerCount = countOccurrences(template.source, STATIC_LOADER_MARKER);
  if (closeCount !== 1 || markerCount !== 0) {
    fail('static-template-ambiguous', 'static HTML requires one unmarked closing head tag');
  }
  return 'html';
}

function decodeBoundedJsEscapes(value: string): string {
  return value.replace(
    /\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})/g,
    (match, hex: string | undefined, braced: string | undefined, unicode: string | undefined) => {
      const code = Number.parseInt(hex ?? braced ?? unicode ?? '', 16);
      if (!Number.isSafeInteger(code) || code > 0x10_ff_ff) {
        return match;
      }
      try {
        return String.fromCodePoint(code);
      } catch {
        return match;
      }
    },
  );
}

function rejectServiceWorkerEvidence(sources: readonly SourceSnapshot[]): void {
  for (const source of sources) {
    const path = source.path.toLowerCase();
    const decoded = decodeBoundedJsEscapes(source.source);
    for (const candidate of source.source === decoded
      ? [source.source]
      : [source.source, decoded]) {
      const text = candidate.toLowerCase();
      const compact = text.replace(/[^a-z0-9]/g, '');
      // Adjacent forms only: independent occurrences of the ordinary words
      // 'service' and 'worker' (e.g. ESG copy about workers) are not PWA
      // evidence. Compact/dashed forms are covered separately below.
      const splitServiceWorker = /\bservice[\s._-]{1,3}worker\b/iu.test(candidate);
      if (
        path.endsWith('.webmanifest') ||
        path.endsWith('/sw.js') ||
        path === 'sw.js' ||
        path.includes('service-worker') ||
        text.includes('serviceworker') ||
        text.includes('service-worker') ||
        text.includes('workbox') ||
        text.includes('registersw') ||
        text.includes('rel="manifest"') ||
        text.includes("rel='manifest'") ||
        compact.includes('navigatorserviceworker') ||
        splitServiceWorker
      ) {
        fail('service-worker-evidence', 'service-worker or PWA evidence is unsupported');
      }
    }
  }
}

function rejectNextEvidence(candidate: CandidateSnapshot): void {
  if (candidate.package?.dependencies.has('next') === true) {
    fail('nextjs-unsupported', 'Next.js is unsupported');
  }
  for (const source of candidate.sources) {
    const path = source.path.toLowerCase();
    const text = source.source.toLowerCase();
    if (
      path.startsWith('pages/') ||
      path.startsWith('app/') ||
      path.includes('next.config.') ||
      text.includes("from 'next") ||
      text.includes('from "next') ||
      text.includes('next/navigation') ||
      text.includes('next/router')
    ) {
      fail('nextjs-unsupported', 'Next.js evidence is unsupported');
    }
  }
}

function assertNoExistingLoader(sources: readonly SourceSnapshot[]): void {
  for (const source of sources) {
    if (
      source.source.includes('data-scg-token') ||
      source.source.includes('data-scg-navigation') ||
      source.source.includes(STATIC_LOADER_MARKER)
    ) {
      fail('loader-already-present', 'existing Scene Glass loader evidence is ambiguous');
    }
  }
}

function createLoader(host: HostKind): HostIntegrationPlan['loader'] {
  const targetPath = host === 'html' ? ('public/index.html' as const) : ('index.html' as const);
  return Object.freeze({
    async: true as const,
    navigation: host === 'html' ? ('document' as const) : ('spa' as const),
    dataScgNavigation: host === 'html' ? ('document' as const) : ('spa' as const),
    sourceMarker: host === 'html',
    sourceMarkerPlacement: 'immediately-before-unique-head' as const,
    targetPath,
    insertionStrategy: 'immediately-before-unique-head' as const,
  });
}
function createLoaderFromTarget(
  host: HostKind,
  targetPath: HostIntegrationPlan['loader']['targetPath'],
): HostIntegrationPlan['loader'] {
  if (
    (host === 'html' && targetPath !== 'public/index.html') ||
    (host !== 'html' && targetPath !== 'index.html')
  ) {
    fail('invalid-facts', 'host integration loader target is not canonical');
  }
  return Object.freeze({
    async: true as const,
    navigation: host === 'html' ? ('document' as const) : ('spa' as const),
    dataScgNavigation: host === 'html' ? ('document' as const) : ('spa' as const),
    sourceMarker: host === 'html',
    sourceMarkerPlacement: 'immediately-before-unique-head' as const,
    targetPath,
    insertionStrategy: 'immediately-before-unique-head' as const,
  });
}

function createDescriptorBlueprint(
  host: HostKind,
  facts: DescriptorSnapshot,
  credential: PlannedCredential,
): HostDescriptorBlueprint {
  const credentialAuthorities = freezeBlueprintAuthorities(
    credential.kind === 'adopted-authority'
      ? [credential.authority]
      : [Object.freeze({ projectId: credential.projectId, path: credential.path })],
  );

  if (host === 'html') {
    return Object.freeze<StaticHostDescriptorBlueprint>({
      kind: 'host-descriptor-blueprint-v1',
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port: facts.port,
      projectId: facts.projectId,
      loaderUrl: LOADER_URL,
      credentialProjectId: facts.projectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'document',
      readinessPath: READINESS_PATH,
      approvedRootIdentity: facts.approvedRootIdentity,
      credentialAuthorities,
    });
  }

  if (host === 'vue3') {
    return Object.freeze<ViteHostDescriptorBlueprint>({
      kind: 'host-descriptor-blueprint-v1',
      schemaVersion: 1,
      viteVersion: VITE_VERSION,
      framework: 'vue3',
      frameworkVersion: VUE_VERSION,
      frameworkPluginVersion: VUE_PLUGIN_VERSION,
      projectId: facts.projectId,
      rootTemplate: 'index.html',
      loaderUrl: LOADER_URL,
      host: '127.0.0.1',
      port: facts.port,
      credentialProjectId: facts.projectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'spa',
      readinessPath: READINESS_PATH,
      approvedRootIdentity: facts.approvedRootIdentity,
      credentialAuthorities,
      installId: facts.installId,
    });
  }

  return Object.freeze<ViteHostDescriptorBlueprint>({
    kind: 'host-descriptor-blueprint-v1',
    schemaVersion: 1,
    viteVersion: VITE_VERSION,
    framework: 'react',
    frameworkVersion: REACT_VERSION,
    frameworkPluginVersion: REACT_PLUGIN_VERSION,
    projectId: facts.projectId,
    rootTemplate: 'index.html',
    loaderUrl: LOADER_URL,
    host: '127.0.0.1',
    port: facts.port,
    credentialProjectId: facts.projectId,
    credentialKey: CREDENTIAL_KEY,
    navigation: 'spa',
    readinessPath: READINESS_PATH,
    approvedRootIdentity: facts.approvedRootIdentity,
    credentialAuthorities,
    installId: facts.installId,
  });
}

function createRuntimeDescriptor(
  host: HostKind,
  facts: Readonly<{
    projectId: string;
    port: number;
    installId: string;
    approvedRootIdentity: FileIdentity;
  }>,
  credentialAuthorities: readonly CredentialAuthority[],
): StaticHostDescriptorV1 | ViteHostDescriptorV1 {
  if (host === 'html') {
    return Object.freeze<StaticHostDescriptorV1>({
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port: facts.port,
      projectId: facts.projectId,
      loaderUrl: LOADER_URL,
      credentialProjectId: facts.projectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'document',
      readinessPath: READINESS_PATH,
      approvedRootIdentity: facts.approvedRootIdentity,
      credentialAuthorities,
    });
  }

  if (host === 'vue3') {
    return Object.freeze<ViteHostDescriptorV1>({
      schemaVersion: 1,
      viteVersion: VITE_VERSION,
      framework: 'vue3',
      frameworkVersion: VUE_VERSION,
      frameworkPluginVersion: VUE_PLUGIN_VERSION,
      projectId: facts.projectId,
      rootTemplate: 'index.html',
      loaderUrl: LOADER_URL,
      host: '127.0.0.1',
      port: facts.port,
      credentialProjectId: facts.projectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'spa',
      readinessPath: READINESS_PATH,
      approvedRootIdentity: facts.approvedRootIdentity,
      credentialAuthorities,
      installId: facts.installId,
    });
  }

  return Object.freeze<ViteHostDescriptorV1>({
    schemaVersion: 1,
    viteVersion: VITE_VERSION,
    framework: 'react',
    frameworkVersion: REACT_VERSION,
    frameworkPluginVersion: REACT_PLUGIN_VERSION,
    projectId: facts.projectId,
    rootTemplate: 'index.html',
    loaderUrl: LOADER_URL,
    host: '127.0.0.1',
    port: facts.port,
    credentialProjectId: facts.projectId,
    credentialKey: CREDENTIAL_KEY,
    navigation: 'spa',
    readinessPath: READINESS_PATH,
    approvedRootIdentity: facts.approvedRootIdentity,
    credentialAuthorities,
    installId: facts.installId,
  });
}

function planCredential(
  input: CredentialSnapshot,
  descriptor: DescriptorSnapshot,
): PlannedCredential {
  if (input.kind === 'adopt') {
    const selected = descriptor.credentialAuthorities[0];
    if (
      descriptor.credentialAuthorities.length !== 1 ||
      selected === undefined ||
      selected.projectId !== descriptor.projectId ||
      !sameAuthority(input.authority, selected)
    ) {
      fail(
        'credential-unsupported',
        'credential authority must be the selected descriptor authority',
      );
    }
    return createPlannedAdoptedCredential(input.authority);
  }

  if (input.projectId !== descriptor.projectId || descriptor.credentialAuthorities.length !== 0) {
    fail(
      'credential-unsupported',
      'created credential must reserve the selected project and a new path',
    );
  }
  return createPlannedCreatedCredential(input.requestId, input.projectId, input.path);
}

function createPlannedAdoptedCredential(authority: CredentialAuthority): PlannedAdoptedCredential {
  const artifact: AdoptedCredentialArtifact = Object.freeze({
    path: authority.path,
    kind: 'credential',
    ownership: 'adopted',
    inverse: Object.freeze({ kind: 'none' }),
  });
  return Object.freeze({ kind: 'adopted-authority', authority, artifact });
}

function createPlannedCreatedCredential(
  requestId: string,
  projectId: string,
  path: string,
): PlannedCreatedCredential {
  const artifact: SetupCreatedCredentialArtifact = Object.freeze({
    path,
    kind: 'credential',
    ownership: 'setup-created',
    inverse: Object.freeze({ kind: 'delete-created-credential', path }),
  });
  return Object.freeze({
    kind: 'setup-created-candidate',
    requestId,
    bits: 256,
    projectId,
    path,
    artifact,
  });
}
export function finalizeHostIntegrationPlan(
  plan: HostIntegrationPlan,
  createdAuthority?: CredentialAuthority,
): FinalizedHostIntegrationPlan {
  const snapshot = snapshotFinalizationPlan(plan);
  const descriptorAuthorities = snapshot.descriptor.credentialAuthorities;
  let authorities: readonly CredentialAuthority[];
  let credential: PlannedCredential;

  if (snapshot.credential.kind === 'adopted-authority') {
    if (createdAuthority !== undefined) {
      fail('credential-unsupported', 'adopted credentials cannot accept a post-write authority');
    }
    if (
      descriptorAuthorities.length !== 1 ||
      descriptorAuthorities.some((authority) => !isCredentialAuthority(authority))
    ) {
      fail(
        'credential-unsupported',
        'adopted descriptor blueprint must contain exactly one selected authority',
      );
    }
    const selected = descriptorAuthorities[0];
    if (
      selected === undefined ||
      !isCredentialAuthority(selected) ||
      selected.projectId !== snapshot.descriptor.projectId ||
      !sameAuthority(selected, snapshot.credential.authority)
    ) {
      fail(
        'credential-unsupported',
        'adopted credential must match the selected descriptor authority',
      );
    }
    authorities = freezeCredentialAuthorities([selected]);
    credential = createPlannedAdoptedCredential(snapshot.credential.authority);
  } else {
    const pendingAuthorities = descriptorAuthorities.filter(
      (authority): authority is PendingCredentialAuthority => !isCredentialAuthority(authority),
    );
    if (
      descriptorAuthorities.length !== 1 ||
      pendingAuthorities.length !== 1 ||
      !samePendingAuthority(pendingAuthorities[0], snapshot.credential)
    ) {
      fail('credential-unsupported', 'created credential requires one matching pending authority');
    }
    if (createdAuthority === undefined) {
      fail('credential-unsupported', 'created credential requires one post-write authority');
    }
    const created = snapshotAuthority(createdAuthority, 'created credential post-write authority');
    if (
      created.projectId !== snapshot.credential.projectId ||
      created.path !== snapshot.credential.path
    ) {
      fail('credential-unsupported', 'post-write authority must match the pending credential path');
    }
    authorities = freezeCredentialAuthorities([created]);
    credential = createPlannedCreatedCredential(
      snapshot.credential.requestId,
      snapshot.credential.projectId,
      snapshot.credential.path,
    );
  }

  const descriptor = createRuntimeDescriptor(
    snapshot.host,
    {
      projectId: snapshot.descriptor.projectId,
      port: snapshot.descriptor.port,
      installId: snapshot.installId,
      approvedRootIdentity: snapshot.descriptor.approvedRootIdentity,
    },
    authorities,
  );
  const loader = snapshot.loader;
  const artifacts = planArtifacts(snapshot.host, snapshot.rootPath, descriptor, loader.targetPath);
  return Object.freeze({
    schemaVersion: HOST_PLAN_SCHEMA_VERSION,
    host: snapshot.host,
    rootPath: snapshot.rootPath,
    installId: snapshot.installId,
    descriptor,
    loader,
    credential,
    artifacts,
  });
}

interface FinalizationSnapshot {
  readonly host: HostKind;
  readonly rootPath: string;
  readonly installId: string;
  readonly descriptor: HostDescriptorBlueprint;
  readonly credential: PlannedCredential;
  readonly loader: HostIntegrationPlan['loader'];
}

function snapshotFinalizationPlan(value: unknown): FinalizationSnapshot {
  const record = exactRecord(
    value,
    [
      'schemaVersion',
      'host',
      'rootPath',
      'installId',
      'descriptor',
      'loader',
      'credential',
      'artifacts',
    ],
    [],
    'host integration plan',
  );
  if (record.schemaVersion !== HOST_PLAN_SCHEMA_VERSION) {
    fail('invalid-facts', 'host integration plan must use schema version 1');
  }
  const host = parseHostOverride(record.host);
  const rootPath = parseAbsolutePath(record.rootPath, 'host integration root path');
  const installId = parseIdentifier(record.installId, 'host integration installId');
  const descriptor = snapshotDescriptorBlueprint(record.descriptor, host);
  if (
    descriptor.projectId !== descriptor.credentialProjectId ||
    (host !== 'html' && (!('installId' in descriptor) || descriptor.installId !== installId))
  ) {
    fail('invalid-facts', 'host integration descriptor blueprint does not match its plan');
  }
  const loader = snapshotLoader(record.loader, host);
  denseArray(record.artifacts, 'host integration artifacts', 4);
  const credential = snapshotPlannedCredential(record.credential);
  return Object.freeze({ host, rootPath, installId, descriptor, loader, credential });
}

function snapshotLoader(value: unknown, host: HostKind): HostIntegrationPlan['loader'] {
  const record = exactRecord(
    value,
    [
      'async',
      'navigation',
      'dataScgNavigation',
      'sourceMarker',
      'sourceMarkerPlacement',
      'targetPath',
      'insertionStrategy',
    ],
    [],
    'host integration loader',
  );
  const targetPath =
    host === 'html'
      ? ('public/index.html' as const)
      : record.targetPath === 'index.html'
        ? ('index.html' as const)
        : fail('invalid-facts', 'host integration loader target is not canonical');
  const expected = createLoaderFromTarget(host, targetPath);
  if (
    record.async !== expected.async ||
    record.navigation !== expected.navigation ||
    record.dataScgNavigation !== expected.dataScgNavigation ||
    record.sourceMarker !== expected.sourceMarker ||
    record.sourceMarkerPlacement !== expected.sourceMarkerPlacement ||
    record.targetPath !== expected.targetPath ||
    record.insertionStrategy !== expected.insertionStrategy
  ) {
    fail('invalid-facts', 'host integration loader is not canonical');
  }
  return expected;
}

function snapshotDescriptorBlueprint(value: unknown, host: HostKind): HostDescriptorBlueprint {
  if (host === 'html') {
    const record = exactRecord(
      value,
      [
        'kind',
        'schemaVersion',
        'template',
        'publicRoot',
        'host',
        'port',
        'projectId',
        'loaderUrl',
        'credentialProjectId',
        'credentialKey',
        'navigation',
        'readinessPath',
        'approvedRootIdentity',
        'credentialAuthorities',
      ],
      [],
      'static descriptor blueprint',
    );
    const common = snapshotBlueprintCommon(record, 'document');
    if (
      record.template !== 'public/index.html' ||
      record.publicRoot !== 'public' ||
      record.host !== '127.0.0.1'
    ) {
      fail('invalid-facts', 'static descriptor blueprint is not canonical');
    }
    return Object.freeze<StaticHostDescriptorBlueprint>({
      kind: 'host-descriptor-blueprint-v1',
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: '127.0.0.1',
      port: common.port,
      projectId: common.projectId,
      loaderUrl: LOADER_URL,
      credentialProjectId: common.projectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'document',
      readinessPath: READINESS_PATH,
      approvedRootIdentity: common.approvedRootIdentity,
      credentialAuthorities: common.credentialAuthorities,
    });
  }

  const record = exactRecord(
    value,
    [
      'kind',
      'schemaVersion',
      'viteVersion',
      'framework',
      'frameworkVersion',
      'frameworkPluginVersion',
      'projectId',
      'rootTemplate',
      'loaderUrl',
      'host',
      'port',
      'credentialProjectId',
      'credentialKey',
      'navigation',
      'readinessPath',
      'approvedRootIdentity',
      'credentialAuthorities',
      'installId',
    ],
    [],
    'Vite descriptor blueprint',
  );
  const common = snapshotBlueprintCommon(record, 'spa');
  const expected =
    host === 'vue3'
      ? {
          framework: 'vue3' as const,
          frameworkVersion: VUE_VERSION,
          frameworkPluginVersion: VUE_PLUGIN_VERSION,
        }
      : {
          framework: 'react' as const,
          frameworkVersion: REACT_VERSION,
          frameworkPluginVersion: REACT_PLUGIN_VERSION,
        };
  if (
    record.viteVersion !== VITE_VERSION ||
    record.framework !== expected.framework ||
    record.frameworkVersion !== expected.frameworkVersion ||
    record.frameworkPluginVersion !== expected.frameworkPluginVersion ||
    record.rootTemplate !== 'index.html' ||
    record.host !== '127.0.0.1'
  ) {
    fail('invalid-facts', 'Vite descriptor blueprint is not canonical');
  }
  return Object.freeze<ViteHostDescriptorBlueprint>({
    kind: 'host-descriptor-blueprint-v1',
    schemaVersion: 1,
    viteVersion: VITE_VERSION,
    framework: expected.framework,
    frameworkVersion: expected.frameworkVersion,
    frameworkPluginVersion: expected.frameworkPluginVersion,
    projectId: common.projectId,
    rootTemplate: 'index.html',
    loaderUrl: LOADER_URL,
    host: '127.0.0.1',
    port: common.port,
    credentialProjectId: common.projectId,
    credentialKey: CREDENTIAL_KEY,
    navigation: 'spa',
    readinessPath: READINESS_PATH,
    approvedRootIdentity: common.approvedRootIdentity,
    credentialAuthorities: common.credentialAuthorities,
    installId: parseIdentifier(record.installId, 'Vite descriptor blueprint installId'),
  });
}

function snapshotBlueprintCommon(
  record: Record<string, unknown>,
  navigation: 'spa' | 'document',
): Readonly<{
  projectId: string;
  port: number;
  approvedRootIdentity: FileIdentity;
  credentialAuthorities: readonly HostDescriptorBlueprintAuthority[];
}> {
  if (
    record.kind !== 'host-descriptor-blueprint-v1' ||
    record.schemaVersion !== 1 ||
    record.loaderUrl !== LOADER_URL ||
    record.credentialKey !== CREDENTIAL_KEY ||
    record.navigation !== navigation ||
    record.readinessPath !== READINESS_PATH
  ) {
    fail('invalid-facts', 'descriptor blueprint is not canonical');
  }
  const projectId = parseProjectId(record.projectId, 'descriptor blueprint projectId');
  if (record.credentialProjectId !== projectId) {
    fail('invalid-facts', 'descriptor blueprint selected credential project is not canonical');
  }
  return Object.freeze({
    projectId,
    port: parsePort(record.port),
    approvedRootIdentity: snapshotIdentity(
      record.approvedRootIdentity,
      'descriptor blueprint root identity',
    ),
    credentialAuthorities: snapshotBlueprintAuthorities(record.credentialAuthorities, projectId),
  });
}

function snapshotBlueprintAuthorities(
  value: unknown,
  selectedProjectId: string,
): readonly HostDescriptorBlueprintAuthority[] {
  const values = denseArray(
    value,
    'descriptor blueprint credential authorities',
    MAX_HOST_CREDENTIAL_AUTHORITIES,
  );
  if (values.length !== 1) {
    fail('invalid-facts', 'descriptor blueprint must contain exactly one selected authority');
  }
  const authority = snapshotBlueprintAuthority(
    values[0],
    'descriptor blueprint credential authority',
  );
  if (authority.projectId !== selectedProjectId) {
    fail('invalid-facts', 'descriptor blueprint authority must match selected project');
  }
  return freezeBlueprintAuthorities([authority]);
}

function snapshotBlueprintAuthority(
  value: unknown,
  name: string,
): HostDescriptorBlueprintAuthority {
  const record = recordValues(value, name);
  if (Object.hasOwn(record, 'device') || Object.hasOwn(record, 'inode')) {
    return snapshotAuthority(value, name);
  }
  const pending = exactRecord(value, ['projectId', 'path'], [], name);
  return Object.freeze({
    projectId: parseProjectId(pending.projectId, `${name} projectId`),
    path: parseAbsolutePath(pending.path, `${name} path`),
  });
}

function freezeBlueprintAuthorities(
  authorities: readonly HostDescriptorBlueprintAuthority[],
): readonly HostDescriptorBlueprintAuthority[] {
  assertNoAuthorityAliases(authorities);
  return Object.freeze(
    authorities.slice().sort((left, right) => compareAscii(left.projectId, right.projectId)),
  );
}

function freezeCredentialAuthorities(
  authorities: readonly CredentialAuthority[],
): readonly CredentialAuthority[] {
  assertNoAuthorityAliases(authorities);
  return Object.freeze(
    authorities.slice().sort((left, right) => compareAscii(left.projectId, right.projectId)),
  );
}

function assertNoAuthorityAliases(authorities: readonly HostDescriptorBlueprintAuthority[]): void {
  const projectIds = new Set<string>();
  const paths = new Set<string>();
  const identities = new Set<string>();
  for (const authority of authorities) {
    if (
      projectIds.has(authority.projectId) ||
      paths.has(authority.path) ||
      (isCredentialAuthority(authority) && identities.has(`${authority.device}:${authority.inode}`))
    ) {
      fail('credential-unsupported', 'credential authorities must not contain duplicate facts');
    }
    projectIds.add(authority.projectId);
    paths.add(authority.path);
    if (isCredentialAuthority(authority)) {
      identities.add(`${authority.device}:${authority.inode}`);
    }
  }
}

function isCredentialAuthority(
  authority: HostDescriptorBlueprintAuthority,
): authority is CredentialAuthority {
  return Object.hasOwn(authority, 'device') && Object.hasOwn(authority, 'inode');
}

function samePendingAuthority(
  authority: PendingCredentialAuthority | undefined,
  credential: PlannedCreatedCredential,
): boolean {
  return (
    authority !== undefined &&
    authority.projectId === credential.projectId &&
    authority.path === credential.path
  );
}

function snapshotPlannedCredential(value: unknown): PlannedCredential {
  const discriminator = recordValues(value, 'planned credential');
  if (discriminator.kind === 'adopted-authority') {
    const record = exactRecord(
      value,
      ['kind', 'authority', 'artifact'],
      [],
      'adopted planned credential',
    );
    const authority = snapshotAuthority(record.authority, 'adopted planned credential authority');
    assertPlannedCredentialArtifact(record.artifact, authority.path, 'adopted');
    return createPlannedAdoptedCredential(authority);
  }
  if (discriminator.kind === 'setup-created-candidate') {
    const record = exactRecord(
      value,
      ['kind', 'requestId', 'bits', 'projectId', 'path', 'artifact'],
      [],
      'created planned credential',
    );
    if (record.bits !== 256) {
      fail('credential-unsupported', 'created planned credential must request 256 bits');
    }
    const requestId = parseIdentifier(record.requestId, 'created planned credential requestId');
    const projectId = parseProjectId(record.projectId, 'created planned credential projectId');
    const path = parseAbsolutePath(record.path, 'created planned credential path');
    assertPlannedCredentialArtifact(record.artifact, path, 'setup-created');
    return createPlannedCreatedCredential(requestId, projectId, path);
  }
  fail('credential-unsupported', 'planned credential must be adopted or setup-created');
}

function assertPlannedCredentialArtifact(
  value: unknown,
  path: string,
  ownership: 'adopted' | 'setup-created',
): void {
  const record = exactRecord(
    value,
    ['path', 'kind', 'ownership', 'inverse'],
    [],
    'planned credential artifact',
  );
  if (record.path !== path || record.kind !== 'credential' || record.ownership !== ownership) {
    fail('invalid-facts', 'planned credential artifact is not canonical');
  }
  const inverse =
    ownership === 'adopted'
      ? exactRecord(record.inverse, ['kind'], [], 'adopted credential inverse')
      : exactRecord(record.inverse, ['kind', 'path'], [], 'created credential inverse');
  if (
    (ownership === 'adopted' && inverse.kind !== 'none') ||
    (ownership === 'setup-created' &&
      (inverse.kind !== 'delete-created-credential' || inverse.path !== path))
  ) {
    fail('invalid-facts', 'planned credential inverse is not canonical');
  }
}

function planArtifacts(
  host: HostKind,
  rootPath: string,
  descriptor: HostDescriptorBlueprint | StaticHostDescriptorV1 | ViteHostDescriptorV1,
  loaderTargetPath: HostIntegrationPlan['loader']['targetPath'],
): readonly PlannedHostArtifact[] {
  const artifacts: PlannedHostArtifact[] = [];
  artifacts.push(
    plannedArtifact(
      'loader',
      joinPath(rootPath, loaderTargetPath),
      host,
      descriptor,
      'insert',
      false,
    ),
  );
  artifacts.push(
    plannedArtifact(
      'descriptor',
      joinPath(rootPath, '.scg/runtime/host-descriptor.v1.json'),
      host,
      descriptor,
      'insert',
      true,
    ),
  );
  artifacts.push(
    plannedArtifact(
      'helper',
      joinPath(rootPath, '.scg/runtime/host-integration-helper.mjs'),
      host,
      descriptor,
      'insert',
      true,
    ),
  );
  return Object.freeze(artifacts);
}

function plannedArtifact(
  role: PlannedHostArtifact['role'],
  path: string,
  host: HostKind,
  descriptor: HostDescriptorBlueprint | StaticHostDescriptorV1 | ViteHostDescriptorV1,
  operation: OwnedHunk['operation'],
  created: boolean,
): PlannedHostArtifact {
  const id = `scg-${host}-${role}-${fingerprint(`id:${descriptor.projectId}:${host}:${role}`).slice(7, 23)}`;
  const subject = `scg-${host}-${role}`;
  /*
   * These are preapproval correlation values only. The transaction replaces
   * them with fingerprints of the materialized postimage before any manifest
   * is staged; a plan is never deletion authority.
   */
  const hunkFingerprint = fingerprint(`planned-hunk:${id}:${operation}`);
  const hunk: OwnedHunk = Object.freeze({ id, fingerprint: hunkFingerprint, operation, subject });
  const artifactFingerprint = fingerprint(`planned-artifact:${role}:${path}`);
  const artifact: OwnedFileArtifact = Object.freeze({
    path,
    kind: 'file',
    fingerprint: artifactFingerprint,
    hunks: Object.freeze([hunk]),
    inverse: created
      ? Object.freeze({
          kind: 'delete-created-file' as const,
          path,
          expectedFingerprint: artifactFingerprint,
        })
      : Object.freeze({ kind: 'none' as const }),
  });
  return Object.freeze({ role, artifact });
}

function hasViteDependency(packageFact: PackageSnapshot | undefined): boolean {
  return hasDependency(packageFact, 'vite');
}

function hasDependency(packageFact: PackageSnapshot | undefined, name: string): boolean {
  return packageFact?.dependencies.has(name) === true;
}

function hasFrameworkDependency(
  packageFact: PackageSnapshot | undefined,
  names: readonly string[],
): boolean {
  return names.some((name) => hasDependency(packageFact, name));
}

function hasCompatibleDependency(
  packageFact: PackageSnapshot | undefined,
  name: string,
  ...compatibleMajors: readonly number[]
): boolean {
  const version = packageFact?.dependencies.get(name);
  const major = version === undefined ? undefined : declaredDependencyMajor(version);
  return major !== undefined && compatibleMajors.includes(major);
}

/** Extracts a bounded dependency major only when its range stays within that major. */
function declaredDependencyMajor(version: string): number | undefined {
  const direct = /^(?:[~^]\s*)?v?(\d+)(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?$/u.exec(version);
  if (direct !== null) {
    return parseDependencyMajor(direct[1]);
  }

  const bounded = /^>=\s*v?(\d+)(?:\.\d+){0,2}\s+<\s*v?(\d+)(?:\.\d+){0,2}$/u.exec(version);
  if (bounded === null) return undefined;

  const lowerMajor = parseDependencyMajor(bounded[1]);
  const upperMajor = parseDependencyMajor(bounded[2]);
  return lowerMajor !== undefined && upperMajor === lowerMajor + 1 ? lowerMajor : undefined;
}

function parseDependencyMajor(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const major = Number(value);
  return Number.isSafeInteger(major) && major >= 0 ? major : undefined;
}

function hasVueEvidence(sources: readonly SourceSnapshot[]): boolean {
  return sources.some(
    (source) =>
      source.path.endsWith('.vue') ||
      /from\s*['"]vue['"]/.test(source.source) ||
      /\bcreateApp\s*\(/.test(source.source),
  );
}

/** Avoid classifying arbitrary JSX or a React dependency as a React SPA. */
function hasReactDiscriminator(sources: readonly SourceSnapshot[]): boolean {
  return sources.some(
    (source) =>
      source.source.includes('react-dom/client') && /\bcreateRoot\s*\(/.test(source.source),
  );
}

function sourceFor(sources: readonly SourceSnapshot[], path: string): SourceSnapshot | undefined {
  return sources.find((source) => source.path === path);
}

function hasSource(sources: readonly SourceSnapshot[], path: string): boolean {
  return sourceFor(sources, path) !== undefined;
}

function countOccurrences(value: string, needle: string): number {
  let count = 0;
  let index = value.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = value.indexOf(needle, index + needle.length);
  }
  return count;
}

function countCaseInsensitive(value: string, needle: string): number {
  return countOccurrences(value.toLowerCase(), needle.toLowerCase());
}

function sameAuthority(left: CredentialAuthority, right: CredentialAuthority): boolean {
  return (
    left.projectId === right.projectId &&
    left.path === right.path &&
    left.device === right.device &&
    left.inode === right.inode
  );
}

function parseHostOverride(value: unknown): HostOverride {
  if (value === 'vue3' || value === 'react' || value === 'html') {
    return value;
  }
  fail('override-unsupported', 'host override must be vue3, react, or html');
}

function parseProjectId(value: unknown, name: string): string {
  if (!isProjectId(value)) {
    fail('invalid-facts', `${name} must be a canonical project id`);
  }
  return value;
}

function parsePort(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 65535) {
    fail('invalid-facts', 'descriptor port must be a TCP port');
  }
  return value;
}

function parseIdentifier(value: unknown, name: string): string {
  if (typeof value !== 'string' || !INSTALL_ID.test(value)) {
    fail('invalid-facts', `${name} must be a bounded canonical identifier`);
  }
  return value;
}

function parsePackageName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    utf8Bytes(value) > 256 ||
    value.includes('\u0000') ||
    hasUnpairedSurrogate(value)
  ) {
    fail('invalid-facts', 'package dependency name must be bounded text');
  }
  return value;
}

function parseVersion(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    utf8Bytes(value) > 128 ||
    value.includes('\u0000') ||
    hasUnpairedSurrogate(value)
  ) {
    fail('invalid-facts', 'package dependency version must be bounded text');
  }
  return value;
}

function parseSource(value: unknown): string {
  if (typeof value !== 'string' || value.includes('\u0000') || hasUnpairedSurrogate(value)) {
    fail('invalid-facts', 'source text must be bounded Unicode text');
  }
  return value;
}

function parseIdentityPart(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 20 ||
    !DECIMAL_IDENTITY.test(value) ||
    BigInt(value) > 18_446_744_073_709_551_615n
  ) {
    fail('invalid-facts', `${name} must be an unsigned decimal identity`);
  }
  return value;
}

function parseAbsolutePath(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    utf8Bytes(value) > MAX_HOST_PATH_BYTES ||
    value.length < 2 ||
    !value.startsWith('/') ||
    value.includes('\u0000') ||
    hasUnpairedSurrogate(value)
  ) {
    fail('invalid-facts', `${name} must be a bounded canonical absolute path`);
  }
  const segments = value.slice(1).split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    fail('invalid-facts', `${name} must be a bounded canonical absolute path`);
  }
  return value;
}

function parseRelativePath(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    utf8Bytes(value) > MAX_HOST_PATH_BYTES ||
    value.startsWith('/') ||
    value.includes('\\') ||
    value.includes('\u0000') ||
    hasUnpairedSurrogate(value)
  ) {
    fail('invalid-facts', `${name} must be a bounded canonical relative path`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    fail('invalid-facts', `${name} must be a bounded canonical relative path`);
  }
  return value;
}

function joinPath(root: string, relative: string): string {
  return `${root}/${relative}`;
}

function fingerprint(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  name: string,
): Record<string, unknown> {
  const values = recordValues(value, name);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(values)) {
    if (!allowed.has(key)) {
      fail('invalid-facts', `${name} must use exact plain-record keys`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(values, key)) {
      fail('invalid-facts', `${name} is missing ${key}`);
    }
  }
  return values;
}

/** Snapshots data descriptors only; inherited, accessor, symbol, and exotic records fail. */
function recordValues(value: unknown, name: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('invalid-facts', `${name} must be an exact plain record`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('invalid-facts', `${name} must not contain symbol keys`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      descriptor.enumerable !== true
    ) {
      fail('invalid-facts', `${name} must contain enumerable data properties only`);
    }
    values[key] = descriptor.value;
  }
  return values;
}

function denseArray(value: unknown, name: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail('invalid-facts', `${name} must be a dense plain array`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('invalid-facts', `${name} must not contain symbol keys`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  const lengthValue: unknown = lengthDescriptor?.value;
  if (
    lengthDescriptor === undefined ||
    !Object.hasOwn(lengthDescriptor, 'value') ||
    typeof lengthValue !== 'number' ||
    !Number.isSafeInteger(lengthValue) ||
    lengthValue < 0 ||
    lengthValue > maximum
  ) {
    fail('invalid-facts', `${name} exceeds its count budget`);
  }
  const length = lengthValue;
  if (Object.keys(descriptors).length !== length + 1) {
    fail('invalid-facts', `${name} must be a dense plain array`);
  }
  const values: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      descriptor.enumerable !== true
    ) {
      fail('invalid-facts', `${name} must be a dense plain array`);
    }
    values.push(descriptor.value);
  }
  return values;
}

function fail(code: HostPlanErrorCode, message: string): never {
  throw new HostPlanError(code, message);
}
