import { SceneGlassContractError, isRecord, parseProjectId } from '@scene-glass/contracts';
import type {
  ConfiguredProject,
  CredentialAuthority,
  DecimalString,
  DescriptorProjectSet,
  FileIdentity,
  StaticHostDescriptorV1,
  ViteFrameworkVersionTuple,
  ViteHostDescriptorV1,
} from './types.js';

const MAX_UNSIGNED_64 = 18_446_744_073_709_551_615n;
const MAX_DECIMAL_IDENTITY_DIGITS = 20;
const MAX_DESCRIPTOR_JSON_BYTES = 1024 * 1024;
const DECIMAL_STRING = /^(?:0|[1-9][0-9]*)$/;

export const STATIC_HOST_DESCRIPTOR_V1_KEYS = Object.freeze([
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
] as const);

export const VITE_HOST_DESCRIPTOR_V1_KEYS = Object.freeze([
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
] as const);

const FILE_IDENTITY_KEYS = Object.freeze(['device', 'inode'] as const);
const CREDENTIAL_AUTHORITY_KEYS = Object.freeze(['projectId', 'path', 'device', 'inode'] as const);
const LOADER_URL = 'http://127.0.0.1:4175/scene-glass-loader.js';
const READINESS_PATH = '/__scene-glass/ready';
const CREDENTIAL_KEY = 'SCENE_GLASS_HOST_TOKEN';
const LOOPBACK_HOST = '127.0.0.1';
const VITE_VERSION = '7.3.6';

type DescriptorKind = 'static' | 'vite';
type DescriptorValidationProvenance = {
  readonly errors: WeakSet<SceneGlassContractError>;
};
export interface TrustedDescriptorProject extends ConfiguredProject {
  readonly canonicalRoot: string;
  readonly publicRootIdentity: FileIdentity;
  readonly tokenEnv: string;
  readonly credentialAuthority: CredentialAuthority;
}

export interface TrustedDescriptorProjectSet {
  readonly projects: readonly TrustedDescriptorProject[];
}

interface ParsedConfiguredProjects {
  readonly projectIds: readonly string[];
  readonly trustedProjects: ReadonlyMap<string, TrustedDescriptorProject> | undefined;
}
export interface StaticRuntimeAuthoritySnapshot {
  readonly descriptor: StaticHostDescriptorV1;
  readonly canonicalRoot: string;
  readonly publicRootIdentity: FileIdentity;
  readonly deniedCredentialIdentities: readonly FileIdentity[];
}

interface ParsedStaticHostDescriptor {
  readonly descriptor: StaticHostDescriptorV1;
  readonly selectedTrustedProject: TrustedDescriptorProject | undefined;
  readonly trustedProjects: ReadonlyMap<string, TrustedDescriptorProject> | undefined;
}

export function isDecimalString(value: unknown): value is DecimalString {
  if (
    typeof value !== 'string' ||
    value.length > MAX_DECIMAL_IDENTITY_DIGITS ||
    !DECIMAL_STRING.test(value)
  ) {
    return false;
  }
  return BigInt(value) <= MAX_UNSIGNED_64;
}

export function isFileIdentity(value: unknown): value is FileIdentity {
  return (
    isOrdinaryRecord(value) &&
    hasExactKeyOrder(value, FILE_IDENTITY_KEYS) &&
    isDecimalString(value.device) &&
    isDecimalString(value.inode)
  );
}

export function parseStaticHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): StaticHostDescriptorV1 {
  return parseStaticHostDescriptorV1Internal(value, configuredProjects).descriptor;
}

export function snapshotTrustedStaticRuntimeAuthority(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): StaticRuntimeAuthoritySnapshot {
  const parsed = parseStaticHostDescriptorV1Internal(value, configuredProjects, undefined, true);
  const selectedTrustedProject = parsed.selectedTrustedProject;
  if (selectedTrustedProject === undefined) {
    descriptorError('static', 'configured project authority facts must be complete');
  }
  return Object.freeze({
    descriptor: parsed.descriptor,
    canonicalRoot: selectedTrustedProject.canonicalRoot,
    publicRootIdentity: selectedTrustedProject.publicRootIdentity,
    deniedCredentialIdentities: snapshotDeniedCredentialIdentities(parsed.trustedProjects),
  });
}

function parseStaticHostDescriptorV1Internal(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
  provenance?: DescriptorValidationProvenance,
  requireTrustedFacts = false,
): ParsedStaticHostDescriptor {
  const record = descriptorRecord(value, 'static', provenance);
  assertExactKeyOrder(record, STATIC_HOST_DESCRIPTOR_V1_KEYS, 'static', provenance);
  const configured = parseConfiguredProjects(
    configuredProjects,
    'static',
    provenance,
    requireTrustedFacts,
  );

  const projectId = parseDescriptorProjectId(record.projectId, 'static', provenance);
  const credentialProjectId = parseDescriptorProjectId(
    record.credentialProjectId,
    'static',
    provenance,
  );
  assertFixedStaticFields(record, provenance);
  assertDescriptorProject(
    projectId,
    credentialProjectId,
    configured.projectIds,
    'static',
    provenance,
  );
  const approvedRootIdentity = parseFileIdentity(record.approvedRootIdentity, 'static', provenance);
  const credentialAuthorities = parseCredentialAuthorities(
    record.credentialAuthorities,
    projectId,
    'static',
    provenance,
  );
  assertTrustedConfiguredDescriptor(
    projectId,
    credentialProjectId,
    CREDENTIAL_KEY,
    approvedRootIdentity,
    credentialAuthorities,
    configured.trustedProjects,
    'static',
    provenance,
  );

  const selectedTrustedProject = configured.trustedProjects?.get(projectId);
  if (requireTrustedFacts && selectedTrustedProject === undefined) {
    descriptorError('static', 'configured project authority facts must be complete', provenance);
  }
  return Object.freeze({
    descriptor: Object.freeze<StaticHostDescriptorV1>({
      schemaVersion: 1,
      template: 'public/index.html',
      publicRoot: 'public',
      host: LOOPBACK_HOST,
      port: parsePort(record.port, 'static', provenance),
      projectId,
      loaderUrl: LOADER_URL,
      credentialProjectId,
      credentialKey: CREDENTIAL_KEY,
      navigation: 'document',
      readinessPath: READINESS_PATH,
      approvedRootIdentity,
      credentialAuthorities,
    }),
    selectedTrustedProject,
    trustedProjects: configured.trustedProjects,
  });
}

export function parseViteHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): ViteHostDescriptorV1 {
  return parseViteHostDescriptorV1Internal(value, configuredProjects);
}

function parseViteHostDescriptorV1Internal(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
  provenance?: DescriptorValidationProvenance,
): ViteHostDescriptorV1 {
  const record = descriptorRecord(value, 'vite', provenance);
  assertExactKeyOrder(record, VITE_HOST_DESCRIPTOR_V1_KEYS, 'vite', provenance);
  const configured = parseConfiguredProjects(configuredProjects, 'vite', provenance);

  const projectId = parseDescriptorProjectId(record.projectId, 'vite', provenance);
  const credentialProjectId = parseDescriptorProjectId(
    record.credentialProjectId,
    'vite',
    provenance,
  );
  assertFixedViteFields(record, provenance);
  const frameworkVersionTuple = parseViteFrameworkVersionTuple(record, provenance);
  assertDescriptorProject(
    projectId,
    credentialProjectId,
    configured.projectIds,
    'vite',
    provenance,
  );
  const approvedRootIdentity = parseFileIdentity(record.approvedRootIdentity, 'vite', provenance);
  const credentialAuthorities = parseCredentialAuthorities(
    record.credentialAuthorities,
    projectId,
    'vite',
    provenance,
  );
  assertTrustedConfiguredDescriptor(
    projectId,
    credentialProjectId,
    CREDENTIAL_KEY,
    approvedRootIdentity,
    credentialAuthorities,
    configured.trustedProjects,
    'vite',
    provenance,
  );

  const descriptorFields = {
    projectId,
    rootTemplate: 'index.html',
    loaderUrl: LOADER_URL,
    host: LOOPBACK_HOST,
    port: parsePort(record.port, 'vite', provenance),
    credentialProjectId,
    credentialKey: CREDENTIAL_KEY,
    navigation: 'spa',
    readinessPath: READINESS_PATH,
    approvedRootIdentity,
    credentialAuthorities,
    installId: parseInstallId(record.installId, 'vite', provenance),
  } as const;

  if (frameworkVersionTuple.framework === 'vue3') {
    return Object.freeze({
      schemaVersion: 1,
      viteVersion: VITE_VERSION,
      framework: 'vue3',
      frameworkVersion: frameworkVersionTuple.frameworkVersion,
      frameworkPluginVersion: frameworkVersionTuple.frameworkPluginVersion,
      ...descriptorFields,
    });
  }

  return Object.freeze({
    schemaVersion: 1,
    viteVersion: VITE_VERSION,
    framework: 'react',
    frameworkVersion: frameworkVersionTuple.frameworkVersion,
    frameworkPluginVersion: frameworkVersionTuple.frameworkPluginVersion,
    ...descriptorFields,
  });
}

export function isStaticHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): value is StaticHostDescriptorV1 {
  const provenance: DescriptorValidationProvenance = { errors: new WeakSet() };
  try {
    parseStaticHostDescriptorV1Internal(value, configuredProjects, provenance);
    return true;
  } catch (error: unknown) {
    if (isDescriptorValidationError(error, provenance)) {
      return false;
    }
    throw error;
  }
}

export function isViteHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): value is ViteHostDescriptorV1 {
  const provenance: DescriptorValidationProvenance = { errors: new WeakSet() };
  try {
    parseViteHostDescriptorV1Internal(value, configuredProjects, provenance);
    return true;
  } catch (error: unknown) {
    if (isDescriptorValidationError(error, provenance)) {
      return false;
    }
    throw error;
  }
}

export function serializeStaticHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): string {
  return serializeCanonicalDescriptor(parseStaticHostDescriptorV1(value, configuredProjects));
}

export function serializeViteHostDescriptorV1(
  value: unknown,
  configuredProjects: DescriptorProjectSet,
): string {
  return serializeCanonicalDescriptor(parseViteHostDescriptorV1(value, configuredProjects));
}

export function parseStaticHostDescriptorJsonV1(
  serialized: unknown,
  configuredProjects: DescriptorProjectSet,
): StaticHostDescriptorV1 {
  return parseCanonicalDescriptorJson(
    serialized,
    configuredProjects,
    'static',
    parseStaticHostDescriptorV1,
  );
}

export function parseViteHostDescriptorJsonV1(
  serialized: unknown,
  configuredProjects: DescriptorProjectSet,
): ViteHostDescriptorV1 {
  return parseCanonicalDescriptorJson(
    serialized,
    configuredProjects,
    'vite',
    parseViteHostDescriptorV1,
  );
}

function serializeCanonicalDescriptor(value: object): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function parseCanonicalDescriptorJson<T extends object>(
  serialized: unknown,
  configuredProjects: DescriptorProjectSet,
  kind: DescriptorKind,
  parse: (value: unknown, projects: DescriptorProjectSet) => T,
): T {
  if (typeof serialized !== 'string') {
    descriptorError(kind, 'descriptor JSON must be a string');
  }
  if (exceedsUtf8ByteLimit(serialized, MAX_DESCRIPTOR_JSON_BYTES)) {
    descriptorError(kind, 'descriptor JSON exceeds its UTF-8 byte limit');
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    descriptorError(kind, 'descriptor JSON must be valid JSON');
  }

  const descriptor = parse(value, configuredProjects);
  if (serializeCanonicalDescriptor(descriptor) !== serialized) {
    descriptorError(kind, 'descriptor JSON must use canonical two-space LF serialization');
  }
  return descriptor;
}

function isOrdinaryRecord(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function descriptorRecord(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): Record<string, unknown> {
  if (!isOrdinaryRecord(value)) {
    descriptorError(kind, 'descriptor must be an object', provenance);
  }

  return snapshotExternalRecord(value);
}

function snapshotExternalRecord(value: Record<string, unknown>): Record<string, unknown> {
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      continue;
    }
    const propertyValue = Reflect.get(value, key);
    Object.defineProperty(snapshot, key, {
      value: propertyValue,
      enumerable: descriptor.enumerable ?? false,
      configurable: false,
      writable: false,
    });
  }
  return snapshot;
}

function assertFixedStaticFields(
  record: Record<string, unknown>,
  provenance?: DescriptorValidationProvenance,
): void {
  if (
    record.schemaVersion !== 1 ||
    record.template !== 'public/index.html' ||
    record.publicRoot !== 'public' ||
    record.host !== LOOPBACK_HOST ||
    record.loaderUrl !== LOADER_URL ||
    record.credentialKey !== CREDENTIAL_KEY ||
    record.navigation !== 'document' ||
    record.readinessPath !== READINESS_PATH
  ) {
    descriptorError('static', 'descriptor contains an unsupported fixed field value', provenance);
  }
}

function assertFixedViteFields(
  record: Record<string, unknown>,
  provenance?: DescriptorValidationProvenance,
): void {
  if (
    record.schemaVersion !== 1 ||
    record.viteVersion !== VITE_VERSION ||
    record.rootTemplate !== 'index.html' ||
    record.host !== LOOPBACK_HOST ||
    record.loaderUrl !== LOADER_URL ||
    record.credentialKey !== CREDENTIAL_KEY ||
    record.navigation !== 'spa' ||
    record.readinessPath !== READINESS_PATH
  ) {
    descriptorError('vite', 'descriptor contains an unsupported fixed field value', provenance);
  }
}

function parseViteFrameworkVersionTuple(
  record: Record<string, unknown>,
  provenance?: DescriptorValidationProvenance,
): ViteFrameworkVersionTuple {
  if (
    record.framework === 'vue3' &&
    record.frameworkVersion === '3.5.40' &&
    record.frameworkPluginVersion === '6.0.8'
  ) {
    return {
      framework: 'vue3',
      frameworkVersion: '3.5.40',
      frameworkPluginVersion: '6.0.8',
    };
  }

  if (
    record.framework === 'react' &&
    record.frameworkVersion === '19.1.1' &&
    record.frameworkPluginVersion === '5.0.4'
  ) {
    return {
      framework: 'react',
      frameworkVersion: '19.1.1',
      frameworkPluginVersion: '5.0.4',
    };
  }

  descriptorError('vite', 'descriptor contains an unsupported framework version tuple', provenance);
}

function parseConfiguredProjects(
  configuredProjects: DescriptorProjectSet,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
  requireTrustedFacts = false,
): ParsedConfiguredProjects {
  const projects = hasConfiguredProjectsProperty(configuredProjects)
    ? configuredProjects.projects
    : configuredProjects;
  if (!Array.isArray(projects) || projects.length === 0) {
    descriptorError(kind, 'configured projects must be a non-empty array', provenance);
  }

  const projectIds: string[] = [];
  const trustedProjects = new Map<string, TrustedDescriptorProject>();
  let requiresTrustedFacts = false;
  for (let index = 0; index < projects.length; index += 1) {
    if (!Object.hasOwn(projects, index)) {
      descriptorError(kind, 'configured projects must be a dense array', provenance);
    }

    const sourceProject = projects[index];
    if (!isRecord(sourceProject) || !Object.hasOwn(sourceProject, 'projectId')) {
      descriptorError(kind, 'configured project is invalid', provenance);
    }
    const project = snapshotExternalRecord(sourceProject);

    const projectId = parseDescriptorProjectId(project.projectId, kind, provenance);
    if (projectIds.includes(projectId)) {
      descriptorError(kind, 'configured projectIds must be unique', provenance);
    }
    projectIds.push(projectId);

    const hasTrustedFact =
      Object.hasOwn(project, 'canonicalRoot') ||
      Object.hasOwn(project, 'publicRootIdentity') ||
      Object.hasOwn(project, 'tokenEnv') ||
      Object.hasOwn(project, 'credentialAuthority');
    if (hasTrustedFact) {
      requiresTrustedFacts = true;
      trustedProjects.set(
        projectId,
        parseTrustedDescriptorProject(project, projectId, kind, provenance),
      );
    }
  }

  if ((requiresTrustedFacts || requireTrustedFacts) && trustedProjects.size !== projectIds.length) {
    descriptorError(kind, 'configured project authority facts must be complete', provenance);
  }
  return Object.freeze({
    projectIds: Object.freeze(projectIds),
    trustedProjects: requiresTrustedFacts || requireTrustedFacts ? trustedProjects : undefined,
  });
}

function hasConfiguredProjectsProperty(
  value: DescriptorProjectSet,
): value is { readonly projects: readonly ConfiguredProject[] } {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.hasOwn(value, 'projects')
  );
}
function parseTrustedDescriptorProject(
  value: Record<string, unknown>,
  expectedProjectId: string,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): TrustedDescriptorProject {
  if (
    !hasExactKeyOrder(value, [
      'projectId',
      'canonicalRoot',
      'publicRootIdentity',
      'tokenEnv',
      'credentialAuthority',
    ] as const)
  ) {
    descriptorError(kind, 'configured project authority facts are invalid', provenance);
  }
  const projectId = parseDescriptorProjectId(value.projectId, kind, provenance);
  if (
    projectId !== expectedProjectId ||
    !isCanonicalAbsolutePath(value.canonicalRoot) ||
    !isTokenEnvironmentName(value.tokenEnv)
  ) {
    descriptorError(kind, 'configured project authority facts are invalid', provenance);
  }
  const publicRootIdentity = parseFileIdentity(value.publicRootIdentity, kind, provenance);
  const credentialAuthority = parseCredentialAuthority(value.credentialAuthority, kind, provenance);
  if (credentialAuthority.projectId !== projectId) {
    descriptorError(kind, 'configured credential authority project is invalid', provenance);
  }
  return Object.freeze({
    projectId,
    canonicalRoot: value.canonicalRoot,
    publicRootIdentity,
    tokenEnv: value.tokenEnv,
    credentialAuthority,
  });
}
function snapshotDeniedCredentialIdentities(
  trustedProjects: ReadonlyMap<string, TrustedDescriptorProject> | undefined,
): readonly FileIdentity[] {
  if (trustedProjects === undefined) {
    descriptorError('static', 'configured project authority facts must be complete');
  }
  const projects = [...trustedProjects.values()].sort((left, right) =>
    left.projectId < right.projectId ? -1 : left.projectId > right.projectId ? 1 : 0,
  );
  return Object.freeze(
    projects.map(({ credentialAuthority }) =>
      Object.freeze<FileIdentity>({
        device: credentialAuthority.device,
        inode: credentialAuthority.inode,
      }),
    ),
  );
}

function assertTrustedConfiguredDescriptor(
  projectId: string,
  credentialProjectId: string,
  credentialKey: string,
  approvedRootIdentity: FileIdentity,
  credentialAuthorities: readonly CredentialAuthority[],
  trustedProjects: ReadonlyMap<string, TrustedDescriptorProject> | undefined,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): void {
  if (trustedProjects === undefined) {
    return;
  }
  const selectedProject = trustedProjects.get(projectId);
  if (
    selectedProject === undefined ||
    selectedProject.projectId !== credentialProjectId ||
    credentialAuthorities.length !== 1
  ) {
    descriptorError(kind, 'descriptor does not match configured project authority', provenance);
  }
  if (!sameFileIdentity(approvedRootIdentity, selectedProject.publicRootIdentity)) {
    descriptorError(kind, 'descriptor approved root identity is not configured', provenance);
  }
  const authority = credentialAuthorities[0];
  if (
    authority === undefined ||
    authority.projectId !== projectId ||
    !sameCredentialAuthority(authority, selectedProject.credentialAuthority)
  ) {
    descriptorError(kind, 'descriptor credential authority is not configured', provenance);
  }
}

function sameCredentialAuthority(left: CredentialAuthority, right: CredentialAuthority): boolean {
  return (
    left.projectId === right.projectId &&
    left.path === right.path &&
    left.device === right.device &&
    left.inode === right.inode
  );
}
function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function isTokenEnvironmentName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length <= 1 ||
    !value.startsWith('/') ||
    value.includes('\u0000') ||
    hasUnpairedSurrogate(value)
  ) {
    return false;
  }
  const segments = value.slice(1).split('/');
  return !segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..');
}

function assertDescriptorProject(
  projectId: string,
  credentialProjectId: string,
  configuredProjectIds: readonly string[],
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): void {
  if (
    projectId !== credentialProjectId ||
    !configuredProjectIds.includes(projectId) ||
    !configuredProjectIds.includes(credentialProjectId)
  ) {
    descriptorError(kind, 'descriptor project must be a configured credential project', provenance);
  }
}

function parseCredentialAuthorities(
  value: unknown,
  selectedProjectId: string,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): readonly CredentialAuthority[] {
  if (!Array.isArray(value) || value.length !== 1 || !Object.hasOwn(value, 0)) {
    descriptorError(
      kind,
      'credentialAuthorities must contain exactly one selected authority',
      provenance,
    );
  }

  const authority = parseCredentialAuthority(value[0], kind, provenance);
  if (authority.projectId !== selectedProjectId) {
    descriptorError(kind, 'credentialAuthorities must match the selected project', provenance);
  }
  return Object.freeze([authority]);
}

function parseCredentialAuthority(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): CredentialAuthority {
  const record = descriptorRecord(value, kind, provenance);
  assertExactKeyOrder(record, CREDENTIAL_AUTHORITY_KEYS, kind, provenance);

  return Object.freeze<CredentialAuthority>({
    projectId: parseDescriptorProjectId(record.projectId, kind, provenance),
    path: parseCanonicalAbsolutePath(record.path, kind, provenance),
    device: parseDecimalIdentity(record.device, kind, provenance),
    inode: parseDecimalIdentity(record.inode, kind, provenance),
  });
}

function parseFileIdentity(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): FileIdentity {
  const record = descriptorRecord(value, kind, provenance);
  assertExactKeyOrder(record, FILE_IDENTITY_KEYS, kind, provenance);

  return Object.freeze<FileIdentity>({
    device: parseDecimalIdentity(record.device, kind, provenance),
    inode: parseDecimalIdentity(record.inode, kind, provenance),
  });
}

function parseDecimalIdentity(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): DecimalString {
  if (!isDecimalString(value)) {
    descriptorError(kind, 'file identity must use canonical unsigned decimal strings', provenance);
  }
  return value;
}

function parseCanonicalAbsolutePath(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): string {
  if (!isCanonicalAbsolutePath(value)) {
    descriptorError(
      kind,
      'credential authority path must be a well-formed canonical absolute path',
      provenance,
    );
  }
  return value;
}

function parsePort(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): number {
  const minimumPort = kind === 'static' ? 0 : 1;
  if (
    typeof value !== 'number' ||
    Object.is(value, -0) ||
    !Number.isSafeInteger(value) ||
    value < minimumPort ||
    value > 65_535
  ) {
    descriptorError(
      kind,
      kind === 'static' ? 'port must be a TCP port' : 'port must be a non-zero TCP port',
      provenance,
    );
  }
  return value;
}

function parseInstallId(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 128 ||
    /[^a-zA-Z0-9_-]/.test(value)
  ) {
    descriptorError(kind, 'installId must be a non-blank ASCII identifier', provenance);
  }
  return value;
}

function parseDescriptorProjectId(
  value: unknown,
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): string {
  try {
    return parseProjectId(value);
  } catch (error: unknown) {
    if (error instanceof SceneGlassContractError) {
      descriptorError(kind, 'projectId is invalid', provenance);
    }
    throw error;
  }
}

function assertExactKeyOrder(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
  kind: DescriptorKind,
  provenance?: DescriptorValidationProvenance,
): void {
  if (!hasExactKeyOrder(record, expectedKeys)) {
    descriptorError(kind, 'descriptor contains missing, unknown, or reordered fields', provenance);
  }
}

function hasExactKeyOrder(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
): boolean {
  const actualKeys = Reflect.ownKeys(record);
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every(
      (key, index) =>
        key === expectedKeys[index] && Object.prototype.propertyIsEnumerable.call(record, key),
    )
  );
}

function exceedsUtf8ByteLimit(value: string, maximum: number): boolean {
  let byteLength = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x7f) {
      byteLength += 1;
    } else if (codeUnit <= 0x7ff) {
      byteLength += 2;
    } else if (
      codeUnit >= 0xd800 &&
      codeUnit <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      byteLength += 4;
      index += 1;
    } else {
      byteLength += 3;
    }
    if (byteLength > maximum) {
      return true;
    }
  }
  return false;
}
function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function isDescriptorValidationError(
  error: unknown,
  provenance: DescriptorValidationProvenance,
): error is SceneGlassContractError {
  return error instanceof SceneGlassContractError && provenance.errors.has(error);
}

function descriptorError(
  kind: DescriptorKind,
  message: string,
  provenance?: DescriptorValidationProvenance,
): never {
  const error = new SceneGlassContractError(
    kind === 'static' ? 'SCG_STATIC_DESCRIPTOR_INVALID' : 'SCG_VITE_CONFIG_UNSUPPORTED',
    message,
  );
  provenance?.errors.add(error);
  throw error;
}
