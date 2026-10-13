import { createHash } from 'node:crypto';

export type RedactedLogArray = ReadonlyArray<RedactedLogValue>;

export interface RedactedLogRecord {
  readonly [key: string]: RedactedLogValue;
}

export type RedactedLogValue =
  null | boolean | number | string | RedactedLogArray | RedactedLogRecord;

const REDACTED = '[REDACTED]';
const CIRCULAR = '[CIRCULAR]';
const TRUNCATED = '[TRUNCATED]';
const BINARY = '[BINARY]';
const ERROR = '[ERROR]';
const ACCESSOR = '[ACCESSOR]';
const MAX_DEPTH = 16;

/**
 * Removes values that can carry capabilities, filesystem authority, annotation
 * text, or exception detail. Project identifiers remain correlatable only as
 * a stable opaque hash. The returned value contains only JSON-safe data.
 */
export function redactLogValue(value: unknown): RedactedLogValue {
  return redactValue(value, new WeakSet<object>(), 0);
}

export function redactLogRecord(
  value: Readonly<Record<string, unknown>>,
): Readonly<Record<string, RedactedLogValue>> {
  const redacted = redactLogValue(value);
  return isRedactedRecord(redacted) ? redacted : Object.freeze(Object.create(null));
}

/** Produces an opaque, namespace-separated identifier for log correlation. */
export function hashProjectId(projectId: string): string {
  const digest = createHash('sha256')
    .update('scene-glass:project-id:v1\u0000', 'utf8')
    .update(projectId, 'utf8')
    .digest('hex');
  return `project_${digest.slice(0, 24)}`;
}

export function isSensitiveLogField(key: string): boolean {
  const normalized = normalizeKey(key);
  return (
    normalized.includes('token') ||
    normalized.includes('authorization') ||
    normalized.includes('authorisation') ||
    normalized.includes('credential') ||
    normalized.includes('secret') ||
    normalized.includes('password') ||
    normalized.includes('passphrase') ||
    normalized.includes('apikey') ||
    normalized.includes('privatekey') ||
    normalized.includes('accesskey') ||
    normalized.includes('bearer') ||
    normalized === 'key' ||
    normalized.endsWith('key') ||
    normalized.includes('keymaterial') ||
    normalized.includes('sensitive') ||
    normalized === 'auth' ||
    normalized.includes('cookie') ||
    normalized.includes('session') ||
    normalized.includes('capability') ||
    normalized.includes('root') ||
    normalized.includes('realpath') ||
    normalized.includes('filepath') ||
    normalized.includes('directory') ||
    normalized.includes('memo') ||
    normalized.includes('surrounding') ||
    normalized.includes('stack') ||
    normalized.includes('text') ||
    normalized.includes('configuration') ||
    normalized === 'config' ||
    normalized.includes('origin') ||
    normalized.includes('digest') ||
    normalized === 'source' ||
    normalized === 'path' ||
    normalized === 'body' ||
    normalized.includes('payload') ||
    normalized.includes('content') ||
    normalized.includes('annotation') ||
    normalized.includes('header') ||
    normalized.includes('query') ||
    normalized.includes('message') ||
    normalized.includes('detail') ||
    normalized === 'error' ||
    normalized === 'env' ||
    normalized.startsWith('env')
  );
}

function redactValue(value: unknown, ancestors: WeakSet<object>, depth: number): RedactedLogValue {
  if (depth > MAX_DEPTH) {
    return TRUNCATED;
  }
  if (value === null) {
    return null;
  }

  switch (typeof value) {
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : null;
    case 'string':
      return redactUnsafeString(value);
    case 'bigint':
      return value.toString();
    case 'undefined':
    case 'function':
    case 'symbol':
      return null;
    case 'object':
      break;
    default:
      return null;
  }

  if (value instanceof Error) {
    return ERROR;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (value instanceof RegExp) {
    return value.toString();
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return BINARY;
  }
  if (value instanceof Map || value instanceof Set) {
    return TRUNCATED;
  }
  if (ancestors.has(value)) {
    return CIRCULAR;
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return Object.freeze(value.map((entry) => redactValue(entry, ancestors, depth + 1)));
    }

    const result: Record<string, RedactedLogValue> = Object.create(null);
    for (const key of Object.keys(value)) {
      if (isSensitiveLogField(key)) {
        continue;
      }

      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined) {
        continue;
      }

      if (isProjectIdField(key)) {
        const opaqueProjectId = redactProjectIdentifier(descriptor);
        if (opaqueProjectId !== null) {
          result[`${key}Hash`] = opaqueProjectId;
        }
        continue;
      }

      result[key] =
        'value' in descriptor ? redactValue(descriptor.value, ancestors, depth + 1) : ACCESSOR;
    }
    return Object.freeze(result);
  } finally {
    ancestors.delete(value);
  }
}
function isRedactedRecord(value: RedactedLogValue): value is RedactedLogRecord {
  return value !== null && !Array.isArray(value) && typeof value === 'object';
}

function redactProjectIdentifier(descriptor: PropertyDescriptor): RedactedLogValue | null {
  if (!('value' in descriptor)) {
    return ACCESSOR;
  }
  if (typeof descriptor.value === 'string') {
    return hashProjectId(descriptor.value);
  }
  if (Array.isArray(descriptor.value)) {
    return Object.freeze(
      descriptor.value.map((value) =>
        typeof value === 'string' ? hashProjectId(value) : REDACTED,
      ),
    );
  }
  return REDACTED;
}

function isProjectIdField(key: string): boolean {
  const normalized = normalizeKey(key);
  return normalized.endsWith('projectid') || normalized.endsWith('projectids');
}

function normalizeKey(key: string): string {
  return key.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function redactUnsafeString(value: string): string {
  return looksLikeCapability(value) ? REDACTED : value;
}

function looksLikeCapability(value: string): boolean {
  return (
    /\b(?:bearer|basic)\s+[\w~+/=.-]+/i.test(value) ||
    /\b(?:token|authorization|secret|password)\s*[:=]/i.test(value) ||
    /^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(value) ||
    /^[A-Za-z0-9_-]{48,}$/.test(value)
  );
}
