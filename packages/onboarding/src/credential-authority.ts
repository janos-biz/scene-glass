import { resolve } from 'node:path';
import {
  MAX_CREDENTIAL_AUTHORITIES,
  MAX_NATIVE_READ_BYTES,
  OnboardingNativeError,
  secureReadCredential,
  verifyCredentialAuthoritySet,
  zeroizeBuffer,
  type CredentialReadCapability,
  type CredentialReadOptions,
} from './native.js';
import type { CredentialAuthority, FileIdentity } from './types.js';

const DECIMAL_IDENTITY_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_CREDENTIAL_PATH_BYTES = 4 * 1024;
const MAX_CREDENTIAL_PATH_COMPONENTS = 256;
const MAX_CREDENTIAL_PATH_COMPONENT_BYTES = 255;
const MAX_CREDENTIAL_PROJECT_ID_BYTES = 128;
const MAX_CREDENTIAL_IDENTITY_DECIMAL_DIGITS = 20;
const MAX_CREDENTIAL_IDENTITY_DECIMAL_VALUE = '18446744073709551615';
export const CREDENTIAL_AUTHORITY_REGISTRY_FILENAME = 'credential-authorities.v1.json';
const CREDENTIAL_AUTHORITY_REGISTRY_MAX_BYTES = 64 * 1024;
const MAX_CREDENTIAL_TOKEN_ENV_BYTES = 255;
const REGISTRY_PROJECT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,127}$/;
const TOKEN_ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CREDENTIAL_AUTHORITY_REGISTRY_KEYS = Object.freeze(['schemaVersion', 'projects'] as const);
const CREDENTIAL_AUTHORITY_REGISTRY_ENTRY_KEYS = Object.freeze([
  'projectId',
  'tokenEnv',
  'canonicalRoot',
  'credentialPath',
  'device',
  'inode',
] as const);

export interface CredentialAuthorityRegistryEntry {
  readonly projectId: string;
  readonly tokenEnv: string;
  readonly canonicalRoot: string;
  readonly credentialPath: string;
  readonly device: string;
  readonly inode: string;
}

export interface CredentialAuthorityRegistrySelectionV1 {
  readonly schemaVersion: 1;
  readonly projects: readonly CredentialAuthorityRegistryEntry[];
}

/** Empty `projects` is the canonical retained shared registry state. */
export type CredentialAuthorityRegistryV1 = CredentialAuthorityRegistrySelectionV1;

export class CredentialAuthorityRegistryError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'CredentialAuthorityRegistryError';
  }
}

export const MAX_CREDENTIAL_AUTHORITY_REGISTRY_BYTES = CREDENTIAL_AUTHORITY_REGISTRY_MAX_BYTES;

const verifiedSelections = new WeakMap<VerifiedCredentialAuthorities, VerifiedSelectionState>();

export interface VerifyCredentialAuthoritiesOptions extends CredentialReadOptions {
  readonly authorities: readonly CredentialAuthority[];
  readonly selectedProjectId: string;
}

export interface VerifiedCredentialAuthorities {
  readonly selectedAuthority: CredentialAuthority;
  readonly capability: CredentialReadCapability;
  readonly deniedIdentities: readonly FileIdentity[];
  readonly expectedOwnerUid: number;
  readonly maxBytes: number;
}
interface ValidatedAuthority {
  readonly authority: CredentialAuthority;
}
interface VerifiedSelectionState {
  capability: CredentialReadCapability | undefined;
  authority: CredentialAuthority | undefined;
}

export function verifyCredentialAuthorities(
  options: VerifyCredentialAuthoritiesOptions,
): VerifiedCredentialAuthorities {
  const canonicalOptions = credentialAuthorityOptionsSnapshot(options);
  const projectIds = new Set<string>();
  const paths = new Set<string>();
  const identities = new Set<string>();
  const candidates: ValidatedAuthority[] = [];
  let selected: ValidatedAuthority | undefined;

  for (const source of canonicalOptions.authorities) {
    const snapshot = credentialAuthoritySnapshot(source);
    if (projectIds.has(snapshot.projectId) || paths.has(snapshot.path)) {
      throw credentialAuthorityInvalid();
    }
    const identityKey = `${snapshot.device}:${snapshot.inode}`;
    if (identities.has(identityKey)) {
      throw credentialAuthorityInvalid();
    }
    projectIds.add(snapshot.projectId);
    paths.add(snapshot.path);
    identities.add(identityKey);

    const candidate: ValidatedAuthority = {
      authority: snapshot,
    };
    candidates.push(candidate);
    if (snapshot.projectId === canonicalOptions.selectedProjectId) {
      selected = candidate;
    }
  }

  if (selected === undefined) {
    throw credentialAuthorityInvalid();
  }

  const deniedIdentities = Object.freeze(
    candidates.map(({ authority }) =>
      Object.freeze({ device: authority.device, inode: authority.inode }),
    ),
  );
  const authoritySnapshots = Object.freeze(candidates.map((candidate) => candidate.authority));
  const capability = verifyCredentialAuthoritySet(
    authoritySnapshots,
    canonicalOptions.selectedProjectId,
    Object.freeze({
      expectedOwnerUid: canonicalOptions.expectedOwnerUid,
      maxBytes: canonicalOptions.maxBytes,
    }),
  );
  const verified = Object.freeze({
    selectedAuthority: selected.authority,
    capability,
    deniedIdentities,
    expectedOwnerUid: canonicalOptions.expectedOwnerUid,
    maxBytes: canonicalOptions.maxBytes,
  });
  verifiedSelections.set(verified, {
    capability,
    authority: selected.authority,
  });
  return verified;
}

export async function withSelectedCredential<T>(
  verified: VerifiedCredentialAuthorities,
  callback: (credential: Buffer) => T | Promise<T>,
): Promise<T> {
  const selection = verifiedSelections.get(verified);
  const capability = selection?.capability;
  const authority = selection?.authority;
  if (
    selection === undefined ||
    capability === undefined ||
    authority === undefined ||
    typeof callback !== 'function'
  ) {
    throw credentialAuthorityInvalid();
  }

  let credential: Buffer;
  try {
    credential = secureReadCredential(capability, {
      expectedOwnerUid: verified.expectedOwnerUid,
      maxBytes: verified.maxBytes,
    });
  } catch (error: unknown) {
    if (
      error instanceof OnboardingNativeError &&
      error.code === 'SCG_CREDENTIAL_AUTHORITY_INVALID'
    ) {
      clearVerifiedSelection(selection);
    }
    throw error;
  }
  let callbackFailed = false;
  let callbackFailure: unknown;
  let result!: T;
  try {
    result = await callback(credential);
  } catch (error: unknown) {
    callbackFailed = true;
    callbackFailure = error;
  }

  let cleanupFailed = false;
  let cleanupFailure: unknown;
  try {
    zeroizeBuffer(credential);
  } catch (error: unknown) {
    cleanupFailed = true;
    cleanupFailure = error;
  }

  if (callbackFailed) {
    if (cleanupFailed) {
      throw new AggregateError(
        [callbackFailure, cleanupFailure],
        'Credential callback and buffer cleanup failed.',
        { cause: callbackFailure },
      );
    }
    throw callbackFailure;
  }
  if (cleanupFailed) {
    throw cleanupFailure;
  }
  return result;
}
function clearVerifiedSelection(selection: VerifiedSelectionState): void {
  selection.capability = undefined;
  selection.authority = undefined;
}

function credentialAuthorityOptionsSnapshot(options: unknown): VerifyCredentialAuthoritiesOptions {
  if (!isRecord(options)) {
    throw credentialAuthorityInvalid();
  }
  const selectedProjectId = options.selectedProjectId;
  if (!isCanonicalCredentialProjectId(selectedProjectId)) {
    throw credentialAuthorityInvalid();
  }
  const rawAuthorities = options.authorities;
  const expectedOwnerUid = options.expectedOwnerUid;
  const maxBytes = options.maxBytes;
  if (!Array.isArray(rawAuthorities)) {
    throw credentialAuthorityInvalid();
  }
  const authorityCount = rawAuthorities.length;
  if (
    authorityCount === 0 ||
    authorityCount > MAX_CREDENTIAL_AUTHORITIES ||
    typeof expectedOwnerUid !== 'number' ||
    !Number.isSafeInteger(expectedOwnerUid) ||
    expectedOwnerUid < 0 ||
    expectedOwnerUid > 0xffff_ffff ||
    typeof process.geteuid !== 'function' ||
    expectedOwnerUid !== process.geteuid() ||
    typeof maxBytes !== 'number' ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0 ||
    maxBytes > MAX_NATIVE_READ_BYTES
  ) {
    throw credentialAuthorityInvalid();
  }

  const authorities: CredentialAuthority[] = [];
  for (let index = 0; index < authorityCount; index += 1) {
    const authority = rawAuthorities[index];
    if (authority === undefined) {
      throw credentialAuthorityInvalid();
    }
    authorities.push(authority);
  }
  return Object.freeze({
    authorities: Object.freeze(authorities),
    selectedProjectId,
    expectedOwnerUid,
    maxBytes,
  });
}
function isCanonicalCredentialProjectId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= MAX_CREDENTIAL_PROJECT_ID_BYTES &&
    !value.includes('\0')
  );
}

function isCanonicalCredentialIdentityPart(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_CREDENTIAL_IDENTITY_DECIMAL_DIGITS &&
    (value.length < MAX_CREDENTIAL_IDENTITY_DECIMAL_DIGITS ||
      value <= MAX_CREDENTIAL_IDENTITY_DECIMAL_VALUE) &&
    DECIMAL_IDENTITY_PATTERN.test(value)
  );
}

function assertCanonicalCredentialAuthority(
  authority: unknown,
): asserts authority is CredentialAuthority {
  if (!isRecord(authority) || !isCanonicalCredentialProjectId(authority.projectId)) {
    throw credentialAuthorityInvalid();
  }
  if (
    typeof authority.path !== 'string' ||
    authority.path.length === 0 ||
    Buffer.byteLength(authority.path, 'utf8') > MAX_CREDENTIAL_PATH_BYTES ||
    authority.path.includes('\0') ||
    !authority.path.startsWith('/') ||
    authority.path === '/' ||
    resolve(authority.path) !== authority.path ||
    !isCanonicalCredentialIdentityPart(authority.device) ||
    !isCanonicalCredentialIdentityPart(authority.inode)
  ) {
    throw credentialAuthorityInvalid();
  }
  const components = authority.path.slice(1).split('/');
  if (
    components.length > MAX_CREDENTIAL_PATH_COMPONENTS ||
    components.some(
      (component) =>
        component.length === 0 ||
        component === '.' ||
        component === '..' ||
        Buffer.byteLength(component, 'utf8') > MAX_CREDENTIAL_PATH_COMPONENT_BYTES,
    )
  ) {
    throw credentialAuthorityInvalid();
  }
}
function credentialAuthoritySnapshot(authority: unknown): CredentialAuthority {
  if (!isRecord(authority)) {
    throw credentialAuthorityInvalid();
  }
  const snapshot = Object.freeze({
    projectId: authority.projectId,
    path: authority.path,
    device: authority.device,
    inode: authority.inode,
  });
  assertCanonicalCredentialAuthority(snapshot);
  return snapshot;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function credentialAuthorityInvalid(): OnboardingNativeError {
  return new OnboardingNativeError(
    'SCG_CREDENTIAL_AUTHORITY_INVALID',
    'Credential authority is invalid.',
  );
}
export function parseCredentialAuthorityRegistryEntryV1(
  value: unknown,
): CredentialAuthorityRegistryEntry {
  const record = credentialAuthorityRegistryExactRecord(
    value,
    CREDENTIAL_AUTHORITY_REGISTRY_ENTRY_KEYS,
    'credential authority registry entry',
  );
  if (
    !isRegistryProjectId(record.projectId) ||
    !isRegistryTokenEnv(record.tokenEnv) ||
    !isCanonicalRegistryPath(record.canonicalRoot) ||
    !isCanonicalRegistryPath(record.credentialPath) ||
    !record.credentialPath.startsWith(`${record.canonicalRoot}/`) ||
    !isCanonicalCredentialIdentityPart(record.device) ||
    !isCanonicalCredentialIdentityPart(record.inode)
  ) {
    throw credentialAuthorityRegistryInvalid('credential authority registry entry is invalid');
  }
  return Object.freeze({
    projectId: record.projectId,
    tokenEnv: record.tokenEnv,
    canonicalRoot: record.canonicalRoot,
    credentialPath: record.credentialPath,
    device: record.device,
    inode: record.inode,
  });
}

export function parseCredentialAuthorityRegistrySelectionV1(
  value: unknown,
): CredentialAuthorityRegistrySelectionV1 {
  const record = credentialAuthorityRegistryExactRecord(
    value,
    CREDENTIAL_AUTHORITY_REGISTRY_KEYS,
    'credential authority registry selection',
  );
  if (record.schemaVersion !== 1 || !Array.isArray(record.projects) || record.projects.length > 1) {
    throw credentialAuthorityRegistryInvalid('credential authority registry selection is invalid');
  }
  const projects: CredentialAuthorityRegistryEntry[] = [];
  for (let index = 0; index < record.projects.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(record.projects, index)) {
      throw credentialAuthorityRegistryInvalid(
        'credential authority registry selection is invalid',
      );
    }
    projects.push(parseCredentialAuthorityRegistryEntryV1(record.projects[index]));
  }
  return Object.freeze({ schemaVersion: 1, projects: Object.freeze(projects) });
}

export function parseCredentialAuthorityRegistryV1(value: unknown): CredentialAuthorityRegistryV1 {
  const record = credentialAuthorityRegistryExactRecord(
    value,
    CREDENTIAL_AUTHORITY_REGISTRY_KEYS,
    'credential authority registry',
  );
  if (
    record.schemaVersion !== 1 ||
    !Array.isArray(record.projects) ||
    record.projects.length > MAX_CREDENTIAL_AUTHORITIES
  ) {
    throw credentialAuthorityRegistryInvalid('credential authority registry is invalid');
  }

  const projects: CredentialAuthorityRegistryEntry[] = [];
  const projectIds = new Set<string>();
  const paths = new Set<string>();
  const identities = new Set<string>();
  let priorProjectId: string | undefined;
  for (let index = 0; index < record.projects.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(record.projects, index)) {
      throw credentialAuthorityRegistryInvalid('credential authority registry is invalid');
    }
    const entry = parseCredentialAuthorityRegistryEntryV1(record.projects[index]);
    const identity = `${entry.device}:${entry.inode}`;
    if (
      (priorProjectId !== undefined && priorProjectId >= entry.projectId) ||
      projectIds.has(entry.projectId) ||
      paths.has(entry.credentialPath) ||
      identities.has(identity)
    ) {
      throw credentialAuthorityRegistryInvalid('credential authority registry is invalid');
    }
    priorProjectId = entry.projectId;
    projectIds.add(entry.projectId);
    paths.add(entry.credentialPath);
    identities.add(identity);
    projects.push(entry);
  }

  return Object.freeze({ schemaVersion: 1, projects: Object.freeze(projects) });
}

export function serializeCredentialAuthorityRegistryV1(value: unknown): string {
  const registry = parseCredentialAuthorityRegistryV1(value);
  const serialized = `${JSON.stringify(registry, null, 2)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > CREDENTIAL_AUTHORITY_REGISTRY_MAX_BYTES) {
    throw credentialAuthorityRegistryInvalid(
      'credential authority registry JSON exceeds its byte limit',
    );
  }
  return serialized;
}

export function parseCredentialAuthorityRegistryJsonV1(
  value: unknown,
): CredentialAuthorityRegistryV1 {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') > CREDENTIAL_AUTHORITY_REGISTRY_MAX_BYTES
  ) {
    throw credentialAuthorityRegistryInvalid('credential authority registry JSON is invalid');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw credentialAuthorityRegistryInvalid('credential authority registry JSON is invalid');
  }
  const registry = parseCredentialAuthorityRegistryV1(parsed);
  if (serializeCredentialAuthorityRegistryV1(registry) !== value) {
    throw credentialAuthorityRegistryInvalid(
      'credential authority registry JSON must use canonical two-space LF serialization',
    );
  }
  return registry;
}

function credentialAuthorityRegistryExactRecord(
  value: unknown,
  keys: readonly string[],
  name: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw credentialAuthorityRegistryInvalid(`${name} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw credentialAuthorityRegistryInvalid(`${name} must be an ordinary object`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key, index) => key !== keys[index])) {
    throw credentialAuthorityRegistryInvalid(`${name} must have exact canonical own keys`);
  }
  return value;
}

function isRegistryProjectId(value: unknown): value is string {
  return typeof value === 'string' && REGISTRY_PROJECT_ID_PATTERN.test(value);
}

function isRegistryTokenEnv(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= MAX_CREDENTIAL_TOKEN_ENV_BYTES &&
    TOKEN_ENV_PATTERN.test(value)
  );
}

function isCanonicalRegistryPath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length <= 1 ||
    Buffer.byteLength(value, 'utf8') > MAX_CREDENTIAL_PATH_BYTES ||
    value.includes('\0') ||
    hasUnpairedSurrogate(value) ||
    !value.startsWith('/') ||
    resolve(value) !== value
  ) {
    return false;
  }
  const components = value.slice(1).split('/');
  return (
    components.length <= MAX_CREDENTIAL_PATH_COMPONENTS &&
    components.every(
      (component) =>
        component.length > 0 &&
        component !== '.' &&
        component !== '..' &&
        Buffer.byteLength(component, 'utf8') <= MAX_CREDENTIAL_PATH_COMPONENT_BYTES,
    )
  );
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
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function credentialAuthorityRegistryInvalid(message: string): CredentialAuthorityRegistryError {
  return new CredentialAuthorityRegistryError(message);
}
