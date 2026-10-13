import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';

const PACKAGE_MANAGER = 'pnpm@10.34.5';
const NODE_ENGINE = '>=24 <25';
const ONBOARDING_IMPORTER = 'packages/onboarding';
const REVIEWED_LOCK_SHA256 = '2d34dc7cef878b09368af7ae21960e0a85500339b84b1ae99db62d94cbdb3ea8';
const REVIEWED_WORKSPACE_SOURCE =
  "packages:\n  - 'apps/*'\n  - 'packages/*'\n  - 'fixtures/*'\nallowBuilds:\n  esbuild: true\n  fs-ext: true\nstrictDepBuilds: true\n";
const CANONICAL_NODE_GYP_VERSION = '11.2.0';
const CANONICAL_NODE_GYP_STORE_ENTRY = `node-gyp@${CANONICAL_NODE_GYP_VERSION}`;
const CANONICAL_NODE_GYP_BIN = './bin/node-gyp.js';
const CANONICAL_NODE_GYP_ENTRY = join(
  'node_modules',
  '.pnpm',
  CANONICAL_NODE_GYP_STORE_ENTRY,
  'node_modules',
  'node-gyp',
  'bin',
  'node-gyp.js',
);
const CANONICAL_NATIVE_BUILD_SCRIPT =
  'node ../../node_modules/.pnpm/node-gyp@11.2.0/node_modules/node-gyp/bin/node-gyp.js rebuild --directory .';
const CANONICAL_NODE_GYP_REBUILD_SHIM = join(
  'node_modules',
  '.pnpm',
  'node_modules',
  '.bin',
  'node-gyp',
);
const CANONICAL_NODE_GYP_REBUILD_SHIM_MAX_BYTES = 8 * 1024;
const PNPM_VIRTUAL_STORE_DIR_MAX_LENGTH = 120;
const LIFECYCLE_KEYS = Object.freeze([
  'preinstall',
  'install',
  'postinstall',
  'prebuild:native',
  'postbuild:native',
]);
const REVIEWED_BUILD_PACKAGES = Object.freeze({
  'esbuild@0.25.5': Object.freeze({
    integrity:
      'sha512-P8OtKZRv/5J5hhz0cUAdu/cLuPIKXpQl1R9pZtvmHWQvrAUVd0UNIPT4IB4W3rNOqVO0rlqHmCIbSwxh/c9yUQ==',
    scripts: Object.freeze({ postinstall: 'node install.js' }),
  }),
  'esbuild@0.28.1': Object.freeze({
    integrity:
      'sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==',
    scripts: Object.freeze({ postinstall: 'node install.js' }),
  }),
  'fs-ext@2.1.1': Object.freeze({
    integrity:
      'sha512-/TrISPOFhCkbgIRWK9lzscRzwPCu0PqtCcvMc9jsHKBgZGoqA0VzhspVht5Zu8lxaXjIYIBWILHpRotYkCCcQA==',
    scripts: Object.freeze({ install: 'node-gyp configure build' }),
  }),
});
const REVIEWED_ESBUILD_VERSIONS = Object.freeze(['0.25.5', '0.28.1']);
const REVIEWED_ONBOARDING_DEPENDENCIES = Object.freeze({
  ajv: '8.20.0',
  esbuild: '0.25.5',
  fastify: '5.10.0',
  'fs-ext': '2.1.1',
  'node-addon-api': '8.5.0',
  'node-gyp': '11.2.0',
});
const REVIEWED_ONBOARDING_WORKSPACE_DEPENDENCIES = Object.freeze({
  '@scene-glass/contracts': Object.freeze({
    specifier: 'workspace:*',
    resolution: 'link:../contracts',
  }),
  '@scene-glass/core': Object.freeze({
    specifier: 'workspace:*',
    resolution: 'link:../core',
  }),
  '@scene-glass/server': Object.freeze({
    specifier: 'workspace:*',
    resolution: 'link:../server',
  }),
});
const REVIEWED_WORKSPACE_PACKAGE_PATHS = Object.freeze({
  '@scene-glass/browser-client': 'packages/browser-client',
  '@scene-glass/contracts': 'packages/contracts',
  '@scene-glass/core': 'packages/core',
  '@scene-glass/fixture-static-html': 'fixtures/static-html',
  '@scene-glass/fixture-vue3-spa': 'fixtures/vue3-spa',
  '@scene-glass/mcp-server': 'apps/mcp-server',
  '@scene-glass/onboarding': 'packages/onboarding',
  '@scene-glass/server': 'packages/server',
  'react-ordinary': 'fixtures/react-ordinary',
  'vue3-ordinary': 'fixtures/vue3-ordinary',
});
const REVIEWED_PNPM_PACKAGE_ALIASES = Object.freeze({
  'string-width-cjs': 'string-width',
  'strip-ansi-cjs': 'strip-ansi',
  'wrap-ansi-cjs': 'wrap-ansi',
});
const MAX_VIRTUAL_STORE_ENTRIES = 4_096;
const MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES = 1_024;
const MAX_YAML_DOCUMENT_CHARACTERS = 2 * 1024 * 1024;
const MAX_YAML_DOCUMENT_LINES = 16_384;
const MAX_YAML_DOCUMENT_BYTES = MAX_YAML_DOCUMENT_CHARACTERS;
const MAX_JSON_DOCUMENT_BYTES = 512 * 1024;
const MAX_DIRECTORY_DEPTH = 8;
const MAX_DIRECTORY_READ_CONCURRENCY = 16;
const BOOTSTRAP_READ_CHUNK_BYTES = 64 * 1024;
let activeDirectoryReads = 0;
const FORBIDDEN_BUILD_POLICY_KEYS = new Set([
  'onlybuiltdependencies',
  'ignoredbuiltdependencies',
  'neverbuiltdependencies',
]);

export const BOOTSTRAP_TIMELINE = Object.freeze([
  'corepack pnpm install --frozen-lockfile --ignore-scripts',
  'node scripts/verify-bootstrap.mjs',
  'corepack pnpm rebuild fs-ext esbuild',
  'corepack pnpm --filter @scene-glass/onboarding run build:native',
  'node packages/onboarding/scripts/build-runtime.mjs',
  'node packages/onboarding/scripts/verify-artifacts.mjs',
]);

export class BootstrapVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BootstrapVerificationError';
  }
}

function fail(message) {
  throw new BootstrapVerificationError(message);
}
function assertYamlDocumentBounds(source, label) {
  if (source.length > MAX_YAML_DOCUMENT_CHARACTERS) {
    fail(`${label} exceeds the document size limit`);
  }

  let lines = 1;
  for (const character of source) {
    if (character === '\n') {
      lines += 1;
      if (lines > MAX_YAML_DOCUMENT_LINES) {
        fail(`${label} exceeds the line limit`);
      }
    }
  }
}
function assertNoYamlAliasesOrMergeKeys(source, label) {
  for (const line of source.split('\n')) {
    if (line.includes('<<')) {
      fail(`${label} must not use YAML merge keys`);
    }
    let quote = null;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (quote === "'") {
        if (character === "'" && line[index + 1] === "'") {
          index += 1;
        } else if (character === "'") {
          quote = null;
        }
        continue;
      }
      if (quote === '"') {
        if (character === '\\') {
          index += 1;
        } else if (character === '"') {
          quote = null;
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }

      const previous = line[index - 1];
      const startsYamlToken =
        previous === undefined ||
        previous === ' ' ||
        previous === '\t' ||
        previous === '[' ||
        previous === '{' ||
        previous === ',';
      if (startsYamlToken && (character === '&' || character === '*')) {
        fail(`${label} must not use YAML aliases or anchors`);
      }
      if (startsYamlToken && character === '!') {
        fail(`${label} must not use YAML tags`);
      }
    }
  }
}

function assertExact(actual, expected, label) {
  if (actual !== expected) {
    fail(
      `${label} must be exactly ${JSON.stringify(expected)}; received ${JSON.stringify(actual)}`,
    );
  }
}
function assertPnpmPeerVersion(actual, expected, label) {
  if (typeof actual !== 'string' || !actual.startsWith(expected)) {
    fail(
      `${label} must be ${JSON.stringify(expected)} with only pnpm peer suffixes; received ${JSON.stringify(actual)}`,
    );
  }

  function consumePeerSuffix(index) {
    if (actual[index] !== '(') {
      fail(
        `${label} must be ${JSON.stringify(expected)} with only pnpm peer suffixes; received ${JSON.stringify(actual)}`,
      );
    }

    const referenceStart = ++index;
    while (index < actual.length && actual[index] !== '(' && actual[index] !== ')') {
      if (
        actual[index] === '\n' ||
        actual[index] === '\r' ||
        actual[index] === ' ' ||
        actual[index] === '\t'
      ) {
        fail(`${label} has an invalid pnpm peer suffix: ${JSON.stringify(actual)}`);
      }
      index += 1;
    }

    const reference = actual.slice(referenceStart, index);
    if (!/^(?:@[^/()\s@]+\/)?[^/()\s@][^()\s@]*@[^()\s@]+$/.test(reference)) {
      fail(`${label} has an invalid pnpm peer suffix: ${JSON.stringify(actual)}`);
    }

    while (actual[index] === '(') {
      index = consumePeerSuffix(index);
    }
    if (actual[index] !== ')') {
      fail(`${label} has an invalid pnpm peer suffix: ${JSON.stringify(actual)}`);
    }
    return index + 1;
  }

  let index = expected.length;
  while (index < actual.length) {
    index = consumePeerSuffix(index);
  }
}

function parseJson(text, path) {
  try {
    return JSON.parse(text);
  } catch (error) {
    fail(`${path} is not valid JSON: ${error.message}`);
  }
}

async function readBoundedUtf8(path, label, maxBytes) {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0 ||
    typeof constants.O_NOFOLLOW !== 'number' ||
    typeof constants.O_NONBLOCK !== 'number'
  ) {
    fail('bootstrap verifier requires bounded no-follow file reads');
  }

  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ELOOP') {
      fail(`${label} must be a regular non-symlink file`);
    }
    throw error;
  }

  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(maxBytes)) {
      fail(`${label} exceeds the document size limit`);
    }

    const chunks = [];
    const chunk = Buffer.allocUnsafe(Math.min(BOOTSTRAP_READ_CHUNK_BYTES, maxBytes));
    let size = 0;
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, size);
      if (bytesRead === 0) {
        break;
      }
      if (size + bytesRead > maxBytes) {
        fail(`${label} exceeds the document size limit`);
      }
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
      size += bytesRead;
    }

    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.mode !== after.mode ||
      before.nlink !== after.nlink ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      size !== Number(before.size)
    ) {
      fail(`${label} changed while it was being read`);
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size));
    } catch {
      fail(`${label} is not valid UTF-8`);
    }
  } finally {
    await handle.close();
  }
}

async function readJson(path) {
  return parseJson(await readBoundedUtf8(path, path, MAX_JSON_DOCUMENT_BYTES), path);
}

function packageKey(name, version) {
  return `${name}@${version}`;
}

function lifecycleScripts(manifest, bindingGypPresent) {
  const scripts = manifest.scripts ?? {};
  if (scripts === null || Array.isArray(scripts) || typeof scripts !== 'object') {
    fail(`${manifest.name ?? 'unknown package'} has a non-object scripts field`);
  }

  const result = {};
  for (const key of LIFECYCLE_KEYS) {
    if (Object.hasOwn(scripts, key)) {
      if (typeof scripts[key] !== 'string' || scripts[key].length === 0) {
        fail(`${manifest.name ?? 'unknown package'} has an invalid ${key} lifecycle script`);
      }
      result[key] = scripts[key];
    }
  }
  if (
    bindingGypPresent &&
    !Object.hasOwn(scripts, 'preinstall') &&
    !Object.hasOwn(scripts, 'install')
  ) {
    result.install = 'node-gyp rebuild';
  }
  return result;
}

async function hasBindingGyp(manifestPath) {
  const path = join(dirname(manifestPath), 'binding.gyp');
  let status;
  try {
    status = await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
  if (!status.isFile() || status.isSymbolicLink()) {
    fail(`${path} must be a regular non-symlink file`);
  }
  return true;
}

function sameObject(left, right) {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && left[key] === right[key])
  );
}

function section(source, name) {
  const entry = yamlMappingEntries(source, 0, 'pnpm-lock.yaml').get(name);
  if (entry === undefined) {
    fail(`pnpm-lock.yaml is missing the ${name} section`);
  }
  return entry.body;
}

function yamlScalar(value, label) {
  const scalar = value.trim();
  if (scalar.length === 0) {
    fail(`${label} must not be empty`);
  }

  if (scalar.startsWith("'")) {
    if (!scalar.endsWith("'") || scalar.length < 2) {
      fail(`${label} has an invalid single-quoted scalar`);
    }
    const unquoted = scalar.slice(1, -1).replace(/''/g, "'");
    if (unquoted.length === 0) {
      fail(`${label} must not be empty`);
    }
    return unquoted;
  }

  if (scalar.startsWith('"')) {
    try {
      const unquoted = JSON.parse(scalar);
      if (typeof unquoted !== 'string' || unquoted.length === 0) {
        fail(`${label} must be a non-empty string`);
      }
      return unquoted;
    } catch {
      fail(`${label} has an invalid double-quoted scalar`);
    }
  }

  if (
    scalar.includes('#') ||
    scalar.includes('{') ||
    scalar.includes('}') ||
    scalar.includes('[') ||
    scalar.includes(']')
  ) {
    fail(`${label} has an unsupported scalar`);
  }
  return scalar;
}

function yamlMappingEntry(line, indentation, label, allowCompactValue = false) {
  const prefix = ' '.repeat(indentation);
  if (!line.startsWith(prefix)) {
    return null;
  }

  const source = line.slice(indentation);
  if (source.length === 0 || /^[ \t]/.test(source)) {
    return null;
  }

  let colon = -1;
  let quote = null;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (quote === "'") {
      if (character === "'" && source[index + 1] === "'") {
        index += 1;
      } else if (character === "'") {
        quote = null;
      }
      continue;
    }
    if (quote === '"') {
      if (character === '\\') {
        index += 1;
      } else if (character === '"') {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
    } else if (character === ':') {
      colon = index;
      break;
    }
  }

  if (colon === -1 || quote !== null) {
    return null;
  }
  const rawKey = source.slice(0, colon).trimEnd();
  const rawValue = source.slice(colon + 1);
  if (
    rawKey.length === 0 ||
    (rawValue.length > 0 && !allowCompactValue && !/^[ \t]/.test(rawValue))
  ) {
    return null;
  }
  return { key: yamlScalar(rawKey, `${label} key`), value: rawValue.trim() };
}

function addYamlMapEntry(map, key, value, label) {
  if (map.has(key)) {
    fail(`${label} repeats ${key}`);
  }
  map.set(key, value);
}
function yamlMappingEntries(source, indentation, label, duplicateError) {
  const lines = source.split('\n');
  const entries = new Map();
  const prefix = ' '.repeat(indentation);

  for (let index = 0; index < lines.length;) {
    const line = lines[index];
    const entry = yamlMappingEntry(line, indentation, label);
    if (entry === null) {
      if (line.trim().length > 0 && line.startsWith(prefix) && !line.startsWith(`${prefix} `)) {
        fail(`${label} has an invalid mapping entry`);
      }
      index += 1;
      continue;
    }

    let end = index + 1;
    while (end < lines.length && yamlMappingEntry(lines[end], indentation, label) === null) {
      end += 1;
    }
    if (entries.has(entry.key)) {
      fail(duplicateError?.(entry.key) ?? `${label} repeats ${entry.key}`);
    }
    entries.set(entry.key, {
      body: lines.slice(index + 1, end).join('\n'),
      value: entry.value,
    });
    index = end;
  }

  return entries;
}

function yamlFlowRecord(value, label) {
  if (!value.startsWith('{') || !value.endsWith('}')) {
    fail(`${label} must be a flow mapping`);
  }

  let body = value.slice(1, -1).trim();
  if (body.length === 0) {
    fail(`${label} must not be empty`);
  }
  if (body.endsWith(',')) {
    body = body.slice(0, -1).trimEnd();
  }

  const fields = new Map();
  let start = 0;
  let quote = null;
  for (let index = 0; index <= body.length; index += 1) {
    const character = body[index];
    if (index === body.length || (character === ',' && quote === null)) {
      const field = yamlMappingEntry(body.slice(start, index).trim(), 0, label, true);
      if (field === null || field.value.length === 0) {
        fail(`${label} has an invalid flow field`);
      }
      addYamlMapEntry(fields, field.key, yamlScalar(field.value, `${label} ${field.key}`), label);
      start = index + 1;
      continue;
    }
    if (quote === "'") {
      if (character === "'" && body[index + 1] === "'") {
        index += 1;
      } else if (character === "'") {
        quote = null;
      }
    } else if (quote === '"') {
      if (character === '\\') {
        index += 1;
      } else if (character === '"') {
        quote = null;
      }
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (character === '{' || character === '}' || character === '[' || character === ']') {
      fail(`${label} has an unsupported flow value`);
    }
  }

  if (quote !== null) {
    fail(`${label} has an unterminated quoted scalar`);
  }
  return fields;
}
function yamlFlowMappingValue(entry, indentation, label) {
  if (entry.value.length > 0) {
    if (entry.body.trim().length > 0) {
      fail(`${label} has content after its inline flow mapping`);
    }
    return entry.value;
  }

  const prefix = ' '.repeat(indentation);
  const lines = entry.body.split('\n').filter((line) => line.trim().length > 0);
  if (lines.length === 0 || lines.some((line) => !line.startsWith(prefix))) {
    fail(`${label} must be a flow mapping`);
  }
  return lines.map((line) => line.trim()).join(' ');
}

function importerDependencyRecord(lines, start, end, name) {
  const entry = yamlMappingEntry(
    lines[start],
    6,
    `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer dependency`,
  );
  if (entry === null) {
    fail(`pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer has an invalid dependency record`);
  }

  const label = `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer ${name}`;
  let fields;
  if (entry.value.startsWith('{')) {
    fields = yamlFlowRecord(entry.value, label);
    for (let index = start + 1; index < end; index += 1) {
      if (lines[index].trim().length !== 0) {
        fail(`${label} has an invalid inline record`);
      }
    }
  } else {
    if (entry.value.length !== 0) {
      fail(`${label} must use a block or flow mapping`);
    }

    fields = new Map();
    for (let index = start + 1; index < end; index += 1) {
      if (lines[index].trim().length === 0) {
        continue;
      }
      const field = yamlMappingEntry(lines[index], 8, label);
      if (field === null || field.value.length === 0) {
        fail(`${label} has an invalid block field`);
      }
      addYamlMapEntry(fields, field.key, yamlScalar(field.value, `${label} ${field.key}`), label);
    }
  }

  if (fields.size !== 2 || !fields.has('specifier') || !fields.has('version')) {
    fail(`${label} must contain exactly specifier and version`);
  }
  return { specifier: fields.get('specifier'), version: fields.get('version') };
}

function parseOnboardingImporter(importers) {
  const lines = importers.split('\n');
  let importerStart = -1;
  let importerEnd = lines.length;
  const seenImporters = new Set();

  for (let index = 0; index < lines.length; index += 1) {
    const importer = yamlMappingEntry(lines[index], 2, 'pnpm-lock.yaml importer');
    if (importer === null) {
      continue;
    }
    if (seenImporters.has(importer.key)) {
      fail('pnpm-lock.yaml repeats an importer key');
    }
    seenImporters.add(importer.key);
    if (importer.key === ONBOARDING_IMPORTER) {
      if (importerStart !== -1) {
        fail(`pnpm-lock.yaml repeats the ${ONBOARDING_IMPORTER} importer`);
      }
      if (importer.value.length !== 0) {
        fail(`pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer must be a block mapping`);
      }
      importerStart = index;
      continue;
    }
    if (importerStart !== -1 && importerEnd === lines.length) {
      importerEnd = index;
    }
  }

  if (importerStart === -1) {
    fail(`pnpm-lock.yaml is missing the ${ONBOARDING_IMPORTER} importer`);
  }

  const sections = [];
  const seenSections = new Set();
  for (let index = importerStart + 1; index < importerEnd; index += 1) {
    const sectionEntry = yamlMappingEntry(
      lines[index],
      4,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer`,
    );
    if (sectionEntry === null) {
      continue;
    }
    if (seenSections.has(sectionEntry.key)) {
      fail(`pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer repeats ${sectionEntry.key}`);
    }
    seenSections.add(sectionEntry.key);
    if (sectionEntry.value.length !== 0) {
      fail(
        `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer section ${sectionEntry.key} must be a block mapping`,
      );
    }
    sections.push({ index, name: sectionEntry.key });
  }

  if (sections.length !== 1 || sections[0].name !== 'dependencies') {
    fail(
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer must use exactly one dependencies section`,
    );
  }

  const dependencyEnd = importerEnd;
  const dependencies = new Map();
  for (let index = sections[0].index + 1; index < dependencyEnd;) {
    if (lines[index].trim().length === 0) {
      index += 1;
      continue;
    }
    const dependency = yamlMappingEntry(
      lines[index],
      6,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer dependency`,
    );
    if (dependency === null) {
      fail(`pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer has an invalid dependency record`);
    }

    let recordEnd = index + 1;
    while (recordEnd < dependencyEnd) {
      if (yamlMappingEntry(lines[recordEnd], 6, 'pnpm-lock.yaml importer dependency') !== null) {
        break;
      }
      recordEnd += 1;
    }
    addYamlMapEntry(
      dependencies,
      dependency.key,
      importerDependencyRecord(lines, index, recordEnd, dependency.key),
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer dependencies`,
    );
    index = recordEnd;
  }

  return dependencies;
}

function recordsForPackage(sectionSource, name, label) {
  const records = [];
  for (const [key, record] of yamlMappingEntries(sectionSource, 2, label)) {
    const prefix = `${name}@`;
    if (key.startsWith(prefix)) {
      records.push({ body: record.body, version: key.slice(prefix.length) });
    }
  }
  return records;
}

function lockIntegrity(record, name, version) {
  const label = `pnpm-lock.yaml ${name}@${version} record`;
  const resolution = yamlMappingEntries(record.body, 4, label).get('resolution');
  if (resolution === undefined) {
    fail(`${label} must contain exactly one inline resolution.integrity`);
  }
  const fields = yamlFlowRecord(
    yamlFlowMappingValue(resolution, 6, `${label} resolution`),
    `${label} resolution`,
  );
  if (fields.size !== 1 || !fields.has('integrity')) {
    fail(`${label} must contain exactly one inline resolution.integrity`);
  }
  return fields.get('integrity');
}

function verifyReviewedLockRecords(packagesSection, name, versions) {
  const records = recordsForPackage(packagesSection, name, 'pnpm-lock.yaml packages');
  for (const version of versions) {
    const matchingRecords = records.filter((record) => record.version === version);
    if (records.length !== versions.length || matchingRecords.length !== 1) {
      const found = records.map((record) => record.version).join(', ') || 'none';
      fail(`pnpm-lock.yaml must contain exactly ${name}@${version}; found ${found}`);
    }

    const reviewed = REVIEWED_BUILD_PACKAGES[packageKey(name, version)];
    assertExact(
      lockIntegrity(matchingRecords[0], name, version),
      reviewed.integrity,
      `pnpm-lock.yaml ${name}@${version} integrity`,
    );
  }
}

function dependencyVersion(snapshot, packageName, consumer) {
  const label = `pnpm-lock.yaml ${consumer} snapshot`;
  const dependencies = yamlMappingEntries(snapshot.body, 4, label).get('dependencies');
  if (dependencies === undefined || dependencies.value.length !== 0) {
    fail(`pnpm-lock.yaml ${consumer} snapshot is missing ${packageName}`);
  }
  const dependency = yamlMappingEntries(dependencies.body, 6, `${label} dependencies`).get(
    packageName,
  );
  if (dependency === undefined || dependency.value.length === 0) {
    fail(`pnpm-lock.yaml ${consumer} snapshot is missing ${packageName}`);
  }
  return yamlScalar(dependency.value, `${label} ${packageName}`);
}

function verifyEsbuildConsumers(snapshotsSection) {
  for (const [name, expectedVersion] of [['tsx', '4.23.1']]) {
    const records = recordsForPackage(snapshotsSection, name, 'pnpm-lock.yaml snapshots');
    if (records.length !== 1) {
      const found = records.map((record) => record.version).join(', ') || 'none';
      fail(
        `pnpm-lock.yaml must contain exactly one ${name}@${expectedVersion} snapshot; found ${found}`,
      );
    }

    const [record] = records;
    assertPnpmPeerVersion(record.version, expectedVersion, `pnpm-lock.yaml ${name} snapshot`);
    assertExact(
      dependencyVersion(record, 'esbuild', `pnpm-lock.yaml ${name}@${record.version}`),
      '0.28.1',
      `pnpm-lock.yaml ${name}@${record.version} esbuild`,
    );
  }
}

function verifyNoOtherEsbuildVersions(lockSource) {
  let records = 0;
  for (const line of lockSource.split('\n')) {
    const indentation = line.length - line.trimStart().length;
    const entry = yamlMappingEntry(line, indentation, 'pnpm-lock.yaml');
    if (entry === null || entry.key !== 'esbuild' || entry.value.length === 0) {
      continue;
    }

    records += 1;
    const label = 'pnpm-lock.yaml esbuild dependency record';
    let version;
    if (entry.value.startsWith('{')) {
      const fields = yamlFlowRecord(entry.value, label);
      if (fields.size !== 2 || !fields.has('specifier') || !fields.has('version')) {
        fail(`${label} must contain exactly specifier and version`);
      }
      assertExact(fields.get('specifier'), fields.get('version'), `${label} specifier`);
      version = fields.get('version');
    } else {
      version = yamlScalar(entry.value, label);
    }
    if (!REVIEWED_ESBUILD_VERSIONS.includes(version)) {
      fail(`pnpm-lock.yaml esbuild dependency version must be reviewed; received ${version}`);
    }
  }
  if (records === 0) {
    fail('pnpm-lock.yaml has no esbuild dependency records');
  }
}
function snapshotIdentity(key) {
  const versionSeparator = key.startsWith('@')
    ? key.indexOf('@', key.indexOf('/') + 1)
    : key.indexOf('@');
  if (versionSeparator <= 0 || versionSeparator === key.length - 1) {
    fail(`pnpm-lock.yaml has an invalid snapshot key ${JSON.stringify(key)}`);
  }
  const name = key.slice(0, versionSeparator);
  packageNamePathSegments(name);
  const resolution = key.slice(versionSeparator + 1);
  const peerContext = resolution.indexOf('(');
  const version = peerContext === -1 ? resolution : resolution.slice(0, peerContext);
  if (version.length === 0) {
    fail(`pnpm-lock.yaml has an invalid snapshot key ${JSON.stringify(key)}`);
  }
  return { name, version };
}

function snapshotStoreEntryName(key) {
  let filename = key.replace(/[\\/:*?"<>|#]/g, '+');
  if (filename.includes('(')) {
    filename = filename.replace(/\)$/, '').replace(/\)\(|\(|\)/g, '_');
  }
  if (
    filename.length > PNPM_VIRTUAL_STORE_DIR_MAX_LENGTH ||
    (filename !== filename.toLowerCase() && !filename.startsWith('file+'))
  ) {
    return `${filename.substring(0, PNPM_VIRTUAL_STORE_DIR_MAX_LENGTH - 33)}_${createHash('sha256')
      .update(filename)
      .digest('hex')
      .slice(0, 32)}`;
  }
  return filename;
}

function snapshotDependencies(snapshot, key) {
  const label = `pnpm-lock.yaml ${key} snapshot`;
  const sections = yamlMappingEntries(snapshot.body, 4, label);
  const dependencies = new Map();
  const requiredDependencies = new Map();
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const section = sections.get(field);
    if (section === undefined) {
      continue;
    }
    if (section.value.length !== 0) {
      fail(`${label} ${field} must be a block mapping`);
    }
    for (const [name, dependency] of yamlMappingEntries(section.body, 6, `${label} ${field}`)) {
      if (dependency.value.length === 0 || dependency.body.trim().length !== 0) {
        fail(`${label} ${field} ${name} must be a scalar`);
      }
      const resolution = yamlScalar(dependency.value, `${label} ${field} ${name}`);
      const previous = dependencies.get(name);
      if (previous !== undefined && previous !== resolution) {
        fail(`${label} repeats dependency ${name}`);
      }
      dependencies.set(name, resolution);
      if (field === 'dependencies') {
        requiredDependencies.set(name, resolution);
      }
    }
  }
  return { dependencies, requiredDependencies };
}

function snapshotGraph(snapshotsSource) {
  const byKey = new Map();
  const byStoreEntry = new Map();
  for (const [key, snapshot] of yamlMappingEntries(
    snapshotsSource,
    2,
    'pnpm-lock.yaml snapshots',
  )) {
    const identity = snapshotIdentity(key);
    const dependencySets = snapshotDependencies(snapshot, key);
    const record = {
      key,
      name: identity.name,
      version: identity.version,
      dependencies: dependencySets.dependencies,
      requiredDependencies: dependencySets.requiredDependencies,
    };
    const storeEntry = snapshotStoreEntryName(key);
    if (byStoreEntry.has(storeEntry)) {
      fail(`pnpm-lock.yaml snapshots collide at virtual-store entry ${storeEntry}`);
    }
    byKey.set(key, record);
    byStoreEntry.set(storeEntry, record);
  }
  return { byKey, byStoreEntry };
}

function lockSha256(lockSource) {
  return createHash('sha256').update(lockSource).digest('hex');
}

function verifyLock(lockSource, expectedLockHash) {
  assertExact(lockSha256(lockSource), expectedLockHash, 'pnpm-lock.yaml SHA-256');
  assertYamlDocumentBounds(lockSource, 'pnpm-lock.yaml');
  assertNoYamlAliasesOrMergeKeys(lockSource, 'pnpm-lock.yaml');
  assertExact(
    lockSource.match(/^lockfileVersion: ['"]?([^'"\n]+)['"]?$/m)?.[1],
    '9.0',
    'pnpm-lock.yaml lockfileVersion',
  );

  const importers = section(lockSource, 'importers');
  const dependencies = parseOnboardingImporter(importers);
  const expectedNames = [
    ...Object.keys(REVIEWED_ONBOARDING_WORKSPACE_DEPENDENCIES),
    ...Object.keys(REVIEWED_ONBOARDING_DEPENDENCIES),
  ].sort();
  const actualNames = [...dependencies.keys()].sort();

  for (const name of actualNames) {
    if (
      name.startsWith('@scene-glass/') &&
      !Object.hasOwn(REVIEWED_ONBOARDING_WORKSPACE_DEPENDENCIES, name)
    ) {
      fail('pnpm-lock.yaml onboarding importer references an unknown workspace package');
    }
  }
  if (
    actualNames.length !== expectedNames.length ||
    actualNames.some((name, index) => name !== expectedNames[index])
  ) {
    fail(
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer dependencies do not match the reviewed map`,
    );
  }

  for (const [name, expected] of Object.entries(REVIEWED_ONBOARDING_WORKSPACE_DEPENDENCIES)) {
    const dependency = dependencies.get(name);
    assertExact(
      dependency.specifier,
      expected.specifier,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} ${name} specifier`,
    );
    assertExact(
      dependency.version,
      expected.resolution,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} ${name} version`,
    );
  }
  for (const [name, version] of Object.entries(REVIEWED_ONBOARDING_DEPENDENCIES)) {
    const dependency = dependencies.get(name);
    assertExact(
      dependency.specifier,
      version,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} ${name} specifier`,
    );
    assertPnpmPeerVersion(
      dependency.version,
      version,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} ${name} version`,
    );
  }

  const packages = section(lockSource, 'packages');
  const snapshots = section(lockSource, 'snapshots');
  verifyReviewedLockRecords(packages, 'esbuild', REVIEWED_ESBUILD_VERSIONS);
  verifyReviewedLockRecords(packages, 'fs-ext', ['2.1.1']);
  verifyEsbuildConsumers(snapshots);
  verifyNoOtherEsbuildVersions(lockSource);
  return {
    importerDependencies: dependencies,
    snapshots: snapshotGraph(snapshots),
  };
}

function yamlAllowBuilds(allowBuilds) {
  if (allowBuilds === undefined) {
    fail('pnpm-workspace.yaml is missing allowBuilds');
  }
  if (allowBuilds.value.length !== 0) {
    fail('pnpm-workspace.yaml allowBuilds must be a block mapping');
  }

  const values = new Map();
  const entries = yamlMappingEntries(
    allowBuilds.body,
    2,
    'pnpm-workspace.yaml',
    (key) => `pnpm-workspace.yaml repeats allowBuilds entry ${key}`,
  );
  for (const [key, entry] of entries) {
    if (entry.value !== 'true' && entry.value !== 'false') {
      fail(`pnpm-workspace.yaml has an invalid allowBuilds entry:   ${key}: ${entry.value}`);
    }
    if (entry.body.trim().length !== 0) {
      fail(`pnpm-workspace.yaml has an invalid allowBuilds entry:   ${key}: ${entry.value}`);
    }
    values.set(key, entry.value === 'true');
  }
  return values;
}

function normalizedBuildPolicyKey(key) {
  return key.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

function isBuildPolicyKey(key) {
  const normalized = normalizedBuildPolicyKey(key);
  return FORBIDDEN_BUILD_POLICY_KEYS.has(normalized) || normalized.includes('build');
}

function verifyWorkspacePolicy(workspaceSource) {
  assertYamlDocumentBounds(workspaceSource, 'pnpm-workspace.yaml');
  assertNoYamlAliasesOrMergeKeys(workspaceSource, 'pnpm-workspace.yaml');
  const declarations = yamlMappingEntries(workspaceSource, 0, 'pnpm-workspace.yaml', (key) => {
    if (key === 'allowBuilds') {
      return 'pnpm-workspace.yaml must declare exactly one allowBuilds policy';
    }
    if (key === 'strictDepBuilds') {
      return 'pnpm-workspace.yaml must declare exactly one strictDepBuilds policy';
    }
    return `pnpm-workspace.yaml repeats ${key}`;
  });

  for (const key of declarations.keys()) {
    if (key !== 'allowBuilds' && key !== 'strictDepBuilds' && isBuildPolicyKey(key)) {
      fail(`pnpm-workspace.yaml must not declare alternate build policy ${key}`);
    }
  }

  const strictDepBuilds = declarations.get('strictDepBuilds');
  if (strictDepBuilds === undefined) {
    fail('pnpm-workspace.yaml must declare exactly one strictDepBuilds policy');
  }
  if (strictDepBuilds.body.trim().length !== 0) {
    fail('pnpm-workspace.yaml strictDepBuilds must be exactly "true"; received a block mapping');
  }
  assertExact(strictDepBuilds.value, 'true', 'pnpm-workspace.yaml strictDepBuilds');

  const allowed = yamlAllowBuilds(declarations.get('allowBuilds'));
  const expected = ['esbuild', 'fs-ext'];
  if (allowed.size !== expected.length || expected.some((name) => allowed.get(name) !== true)) {
    fail('pnpm-workspace.yaml allowBuilds must allow exactly esbuild and fs-ext');
  }
  assertExact(workspaceSource, REVIEWED_WORKSPACE_SOURCE, 'pnpm-workspace.yaml source');
}

function verifyRootManifestPolicy(rootPackage) {
  const rootBuildPolicyKeys = Object.keys(rootPackage).filter(isBuildPolicyKey);
  if (rootBuildPolicyKeys.length > 0) {
    fail(`package.json must not declare build policy ${rootBuildPolicyKeys[0]}`);
  }

  if (Object.hasOwn(rootPackage, 'pnpm')) {
    fail('package.json must not declare a pnpm policy object');
  }
}

async function requiredDirectory(path, label, maxEntries) {
  if (activeDirectoryReads >= MAX_DIRECTORY_READ_CONCURRENCY) {
    fail(`${label} exceeds the directory inspection concurrency limit`);
  }

  activeDirectoryReads += 1;
  let handle;
  try {
    handle = await opendir(path, { bufferSize: 32 });
    const entries = [];
    for (;;) {
      const entry = await handle.read();
      if (entry === null) {
        break;
      }
      if (entries.length >= maxEntries) {
        fail(`${label} exceeds the entry limit`);
      }
      entries.push(entry);
    }
    return entries.sort((left, right) => {
      if (left.name < right.name) {
        return -1;
      }
      if (left.name > right.name) {
        return 1;
      }
      return 0;
    });
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail(`missing ${label} at ${path}`);
    }
    throw error;
  } finally {
    activeDirectoryReads -= 1;
    if (handle !== undefined) {
      await handle.close();
    }
  }
}

function isPathInside(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return (
    pathFromRoot === '' ||
    (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..' && !isAbsolute(pathFromRoot))
  );
}
function assertDirectoryDepth(path, canonicalRoot, label) {
  const pathFromRoot = relative(canonicalRoot, path);
  const depth = pathFromRoot === '' ? 0 : pathFromRoot.split(sep).length;
  if (depth > MAX_DIRECTORY_DEPTH) {
    fail(`${label} exceeds the directory depth limit`);
  }
}
async function requiredCanonicalDirectoryPath(path, label, canonicalRoot) {
  let status;
  try {
    status = await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail(`missing ${label} at ${path}`);
    }
    throw error;
  }
  if (!status.isDirectory() || status.isSymbolicLink()) {
    fail(`${label} must be a real directory`);
  }

  const canonicalPath = await realpath(path);
  if (!isPathInside(canonicalRoot, canonicalPath)) {
    fail(`${label} must be contained under the canonical workspace`);
  }
  assertDirectoryDepth(canonicalPath, canonicalRoot, label);
  return canonicalPath;
}

async function requiredCanonicalDirectory(path, label, maxEntries, canonicalRoot) {
  const canonicalPath = await requiredCanonicalDirectoryPath(path, label, canonicalRoot);
  return {
    canonicalPath,
    entries: await requiredDirectory(canonicalPath, label, maxEntries),
  };
}

function virtualStoreManifestMatches(entryName, manifest) {
  const encodedName = manifest.name.replace('/', '+');
  const baseName = `${encodedName}@${manifest.version}`;
  return entryName === baseName || entryName.startsWith(`${baseName}_`);
}

function dependencyTargetName(name, specifier, path) {
  packageNamePathSegments(name);
  if (!specifier.startsWith('npm:')) {
    return name;
  }

  const alias = specifier.slice('npm:'.length);
  const scopeSeparator = alias.indexOf('/');
  const versionSeparator = alias.startsWith('@')
    ? alias.indexOf('@', scopeSeparator + 1)
    : alias.indexOf('@');
  if (
    versionSeparator <= 0 ||
    versionSeparator === alias.length - 1 ||
    (alias.startsWith('@') && scopeSeparator <= 1)
  ) {
    fail(`${path} has an invalid npm dependency alias`);
  }
  const targetName = alias.slice(0, versionSeparator);
  packageNamePathSegments(targetName);
  return targetName;
}

function dependencyTargets(manifest, path) {
  const targets = new Map();
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[field];
    if (dependencies === undefined) {
      continue;
    }
    if (dependencies === null || Array.isArray(dependencies) || typeof dependencies !== 'object') {
      fail(`${path} has a non-object ${field} field`);
    }
    for (const [name, specifier] of Object.entries(dependencies)) {
      if (typeof specifier !== 'string' || specifier.length === 0) {
        fail(`${path} has an invalid ${field} entry`);
      }
      const targetName = dependencyTargetName(name, specifier, path);
      const previousTarget = targets.get(name);
      if (previousTarget !== undefined && previousTarget.targetName !== targetName) {
        fail(`${path} has conflicting dependency targets`);
      }
      targets.set(name, { targetName });
    }
  }
  return targets;
}

function packageNamePathSegments(name) {
  const segments = name.split('/');
  if (
    (segments.length === 1 && segments[0].length > 0 && !segments[0].startsWith('@')) ||
    (segments.length === 2 && /^@[^/]+$/.test(segments[0]) && segments[1].length > 0)
  ) {
    return segments;
  }
  fail('pnpm virtual store has an invalid dependency name');
}

function expectedSnapshotTarget(snapshot, dependencyName, targetName, snapshots) {
  const resolution = snapshot.dependencies.get(dependencyName);
  if (resolution === undefined) {
    fail(`pnpm virtual store ${snapshot.key} snapshot is missing dependency ${dependencyName}`);
  }
  if (resolution.startsWith('link:')) {
    return null;
  }

  const key = resolution.startsWith(`${targetName}@`) ? resolution : `${targetName}@${resolution}`;
  const target = snapshots.byKey.get(key);
  if (target === undefined || target.name !== targetName) {
    fail(
      `pnpm virtual store ${snapshot.key} dependency ${dependencyName} does not resolve to a reviewed lock snapshot`,
    );
  }
  return target;
}

async function verifyDependencySymlink(
  path,
  expectedTargetName,
  expectedSnapshot,
  virtualStore,
  workspaceRoot,
  snapshots,
) {
  let target;
  try {
    target = await realpath(path);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail('pnpm virtual store has a broken dependency symlink');
    }
    throw error;
  }

  const storePackage = isPathInside(virtualStore, target);
  if (!storePackage) {
    const workspacePackagePath = REVIEWED_WORKSPACE_PACKAGE_PATHS[expectedTargetName];
    if (workspacePackagePath === undefined) {
      fail('pnpm virtual store dependency symlink resolves outside the virtual store');
    }
    if (expectedSnapshot !== null) {
      fail(
        'pnpm virtual store dependency symlink does not resolve to its reviewed snapshot target',
      );
    }
    const expectedWorkspaceTarget = await requiredCanonicalDirectoryPath(
      join(workspaceRoot, workspacePackagePath),
      'reviewed workspace package root',
      workspaceRoot,
    );
    if (target !== expectedWorkspaceTarget) {
      fail('pnpm virtual store dependency symlink does not resolve to its reviewed workspace root');
    }
  }
  let manifest;
  try {
    const targetStatus = await lstat(target);
    const manifestPath = join(target, 'package.json');
    const manifestStatus = await lstat(manifestPath);
    if (
      !targetStatus.isDirectory() ||
      targetStatus.isSymbolicLink() ||
      !manifestStatus.isFile() ||
      manifestStatus.isSymbolicLink()
    ) {
      fail('pnpm virtual store dependency symlink must resolve to a package directory');
    }
    manifest = await readJson(manifestPath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail('pnpm virtual store has a broken dependency symlink');
    }
    throw error;
  }

  if (
    manifest === null ||
    Array.isArray(manifest) ||
    typeof manifest !== 'object' ||
    typeof manifest.name !== 'string' ||
    typeof manifest.version !== 'string' ||
    manifest.name.length === 0 ||
    manifest.version.length === 0
  ) {
    fail('pnpm virtual store dependency symlink target manifest is invalid');
  }
  if (manifest.name !== expectedTargetName) {
    fail(
      'pnpm virtual store dependency symlink target manifest name does not match the dependency name',
    );
  }

  if (!storePackage) {
    return;
  }

  const expectedSegments = packageNamePathSegments(expectedTargetName);
  const targetSegments = relative(virtualStore, target).split(sep);
  if (
    targetSegments.length !== expectedSegments.length + 2 ||
    targetSegments[1] !== 'node_modules' ||
    !expectedSegments.every((segment, index) => targetSegments[index + 2] === segment)
  ) {
    fail('pnpm virtual store dependency symlink must resolve to a canonical store package entry');
  }

  const actualSnapshot = snapshots.byStoreEntry.get(targetSegments[0]);
  if (
    actualSnapshot === undefined ||
    actualSnapshot.name !== manifest.name ||
    actualSnapshot.version !== manifest.version
  ) {
    fail(
      `pnpm virtual store dependency symlink does not resolve to a reviewed lock snapshot: ${JSON.stringify(
        {
          entry: targetSegments[0],
          manifest: `${manifest.name}@${manifest.version}`,
        },
      )}`,
    );
  }
  if (expectedSnapshot !== null && actualSnapshot.key !== expectedSnapshot.key) {
    fail('pnpm virtual store dependency symlink does not match its reviewed snapshot target');
  }
}
function importerSnapshotTarget(dependency, targetName, snapshots) {
  if (dependency.version.startsWith('link:')) {
    return null;
  }
  const key = dependency.version.startsWith(`${targetName}@`)
    ? dependency.version
    : `${targetName}@${dependency.version}`;
  const snapshot = snapshots.byKey.get(key);
  if (snapshot === undefined || snapshot.name !== targetName) {
    fail(
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer dependency does not resolve to a reviewed lock snapshot`,
    );
  }
  return snapshot;
}

async function verifyOnboardingImporterLinks(root, dependencies, snapshots) {
  const canonicalRoot = await realpath(root);
  const { canonicalPath: virtualStore } = await requiredCanonicalDirectory(
    join(canonicalRoot, 'node_modules', '.pnpm'),
    'pnpm virtual store',
    MAX_VIRTUAL_STORE_ENTRIES,
    canonicalRoot,
  );
  const { canonicalPath: importerNodeModules, entries } = await requiredCanonicalDirectory(
    join(canonicalRoot, ONBOARDING_IMPORTER, 'node_modules'),
    'onboarding importer node_modules directory',
    MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
    canonicalRoot,
  );
  const realized = new Map();

  for (const entry of entries) {
    const path = join(importerNodeModules, entry.name);
    if (entry.name === '.bin') {
      await requiredCanonicalDirectoryPath(
        path,
        'onboarding importer .bin directory',
        importerNodeModules,
      );
      continue;
    }
    if (entry.isSymbolicLink()) {
      realized.set(entry.name, path);
      continue;
    }
    if (!entry.isDirectory() || !entry.name.startsWith('@')) {
      fail('onboarding importer has an invalid dependency link entry');
    }
    const { canonicalPath: scopeDirectory, entries: scopedEntries } =
      await requiredCanonicalDirectory(
        path,
        'onboarding importer scoped dependency directory',
        MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
        importerNodeModules,
      );
    for (const scopedEntry of scopedEntries) {
      if (!scopedEntry.isSymbolicLink()) {
        fail('onboarding importer has an invalid scoped dependency link entry');
      }
      realized.set(`${entry.name}/${scopedEntry.name}`, join(scopeDirectory, scopedEntry.name));
    }
  }

  const expectedNames = [...dependencies.keys()].sort();
  const actualNames = [...realized.keys()].sort();
  if (
    expectedNames.length !== actualNames.length ||
    expectedNames.some((name, index) => name !== actualNames[index])
  ) {
    fail(
      `onboarding importer realized dependency links do not exactly match the reviewed lock importer; expected ${JSON.stringify(expectedNames)}, received ${JSON.stringify(actualNames)}`,
    );
  }

  for (const [name, dependency] of dependencies) {
    const path = realized.get(name);
    if (path === undefined) {
      fail('onboarding importer is missing a reviewed dependency link');
    }
    const targetName = dependencyTargetName(
      name,
      dependency.specifier,
      `pnpm-lock.yaml ${ONBOARDING_IMPORTER} importer ${name}`,
    );
    await verifyDependencySymlink(
      path,
      targetName,
      importerSnapshotTarget(dependency, targetName, snapshots),
      virtualStore,
      canonicalRoot,
      snapshots,
    );
  }
}
async function verifyStructuralDependencySymlinks(virtualStore, workspaceRoot, snapshots) {
  const { canonicalPath: structuralDirectory, entries } = await requiredCanonicalDirectory(
    join(virtualStore, 'node_modules'),
    'pnpm virtual store structural node_modules directory',
    MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
    virtualStore,
  );

  for (const entry of entries) {
    const path = join(structuralDirectory, entry.name);
    if (entry.name === '.bin') {
      await requiredCanonicalDirectoryPath(
        path,
        'pnpm virtual store structural .bin entry',
        virtualStore,
      );
      continue;
    }
    if (entry.isSymbolicLink()) {
      const targetName = REVIEWED_PNPM_PACKAGE_ALIASES[entry.name] ?? entry.name;
      await verifyDependencySymlink(path, targetName, null, virtualStore, workspaceRoot, snapshots);
      continue;
    }
    if (!entry.isDirectory() || !entry.name.startsWith('@')) {
      fail('pnpm virtual store has an invalid structural dependency entry');
    }

    const { canonicalPath: scopedDirectory, entries: scopedEntries } =
      await requiredCanonicalDirectory(
        path,
        'pnpm virtual store structural scoped dependency directory',
        MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
        virtualStore,
      );
    for (const scopedEntry of scopedEntries) {
      if (!scopedEntry.isSymbolicLink()) {
        fail('pnpm virtual store has an invalid structural scoped dependency entry');
      }
      const dependencyName = `${entry.name}/${scopedEntry.name}`;
      const targetName = REVIEWED_PNPM_PACKAGE_ALIASES[dependencyName] ?? dependencyName;
      await verifyDependencySymlink(
        join(scopedDirectory, scopedEntry.name),
        targetName,
        null,
        virtualStore,
        workspaceRoot,
        snapshots,
      );
    }
  }
}

async function packageManifestsIn(virtualStore, entryName) {
  const { canonicalPath: directory, entries } = await requiredCanonicalDirectory(
    join(virtualStore, entryName, 'node_modules'),
    'package node_modules directory',
    MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
    virtualStore,
  );
  const ownManifests = [];
  const dependencyEdges = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.name === '.bin') {
      await requiredCanonicalDirectoryPath(path, 'pnpm virtual store .bin entry', virtualStore);
      continue;
    }
    if (entry.isSymbolicLink()) {
      dependencyEdges.push({ name: entry.name, path });
      continue;
    }
    if (!entry.isDirectory()) {
      fail('pnpm virtual store has an unexpected non-directory package entry');
    }

    if (!entry.name.startsWith('@')) {
      const ownPackageDirectory = await requiredCanonicalDirectoryPath(
        path,
        'pnpm virtual store own package directory',
        virtualStore,
      );
      ownManifests.push(join(ownPackageDirectory, 'package.json'));
      continue;
    }

    const { canonicalPath: scopedDirectory, entries: scopedEntries } =
      await requiredCanonicalDirectory(
        path,
        'scoped package directory',
        MAX_VIRTUAL_STORE_NODE_MODULES_ENTRIES,
        virtualStore,
      );
    if (scopedEntries.length === 0) {
      fail('pnpm virtual store has an empty scoped package directory');
    }
    for (const scopedEntry of scopedEntries) {
      const scopedPath = join(scopedDirectory, scopedEntry.name);
      if (scopedEntry.isSymbolicLink()) {
        dependencyEdges.push({ name: `${entry.name}/${scopedEntry.name}`, path: scopedPath });
      } else if (scopedEntry.isDirectory()) {
        const ownPackageDirectory = await requiredCanonicalDirectoryPath(
          scopedPath,
          'pnpm virtual store scoped own package directory',
          virtualStore,
        );
        ownManifests.push(join(ownPackageDirectory, 'package.json'));
      } else {
        fail('pnpm virtual store has an unexpected scoped package entry');
      }
    }
  }

  if (ownManifests.length !== 1) {
    fail('pnpm virtual store package entry must contain exactly one own package manifest');
  }
  return { entryName, manifestPath: ownManifests[0], dependencyEdges };
}

async function extractedPackageManifests(root, snapshots) {
  const canonicalRoot = await realpath(root);
  const virtualStore = join(canonicalRoot, 'node_modules', '.pnpm');
  const { canonicalPath: resolvedVirtualStore, entries } = await requiredCanonicalDirectory(
    virtualStore,
    'pnpm virtual store',
    MAX_VIRTUAL_STORE_ENTRIES,
    canonicalRoot,
  );

  const records = [];
  for (const entry of entries) {
    if (entry.name === 'lock.yaml') {
      if (!entry.isFile()) {
        fail('pnpm virtual store lock.yaml must be a file');
      }
      continue;
    }
    if (entry.name === 'node_modules') {
      if (!entry.isDirectory() || entry.isSymbolicLink()) {
        fail('pnpm virtual store structural entry must be a real directory');
      }
      await verifyStructuralDependencySymlinks(resolvedVirtualStore, canonicalRoot, snapshots);
      continue;
    }
    if (entry.name === '.bin') {
      await requiredCanonicalDirectoryPath(
        join(resolvedVirtualStore, entry.name),
        'pnpm virtual store structural entry',
        resolvedVirtualStore,
      );
      continue;
    }
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      fail('pnpm virtual store has an unexpected non-directory entry');
    }
    await requiredCanonicalDirectoryPath(
      join(resolvedVirtualStore, entry.name),
      'pnpm virtual store package entry',
      resolvedVirtualStore,
    );
    records.push(await packageManifestsIn(resolvedVirtualStore, entry.name));
  }

  const manifests = [];
  for (const record of records) {
    try {
      const manifestStatus = await lstat(record.manifestPath);
      if (!manifestStatus.isFile()) {
        fail('pnpm virtual store own package manifest must be a regular file');
      }
      const manifest = await readJson(record.manifestPath);
      if (
        typeof manifest.name !== 'string' ||
        manifest.name.length === 0 ||
        typeof manifest.version !== 'string' ||
        manifest.version.length === 0
      ) {
        fail('pnpm virtual store own package manifest has no string name and version');
      }
      if (manifest.name === 'esbuild' && !REVIEWED_ESBUILD_VERSIONS.includes(manifest.version)) {
        fail(`${record.manifestPath} has unreviewed esbuild version ${manifest.version}`);
      }
      if (manifest.name === 'fs-ext' && manifest.version !== '2.1.1') {
        fail(`${record.manifestPath} has unreviewed fs-ext version ${manifest.version}`);
      }
      if (!virtualStoreManifestMatches(record.entryName, manifest)) {
        fail('pnpm virtual store package entry does not match its own package manifest');
      }

      const expectedDependencyTargets = dependencyTargets(manifest, record.manifestPath);
      const sourceSnapshot = snapshots.byStoreEntry.get(record.entryName);
      if (sourceSnapshot === undefined) {
        fail('pnpm virtual store package entry does not resolve to a reviewed lock snapshot');
      }
      if (sourceSnapshot.name !== manifest.name || sourceSnapshot.version !== manifest.version) {
        fail('pnpm virtual store package entry does not match its reviewed lock snapshot');
      }
      const realizedEdgeNames = new Set(record.dependencyEdges.map((edge) => edge.name));
      const requiredEdgeNames = [...sourceSnapshot.requiredDependencies.keys()].sort();
      if (requiredEdgeNames.some((name) => !realizedEdgeNames.has(name))) {
        fail(
          `pnpm virtual store realized dependency links do not exactly match its reviewed snapshot edges: ${JSON.stringify(
            {
              entry: record.entryName,
              expected: requiredEdgeNames,
              realized: [...realizedEdgeNames].sort(),
            },
          )}`,
        );
      }
      for (const edge of record.dependencyEdges) {
        const target = expectedDependencyTargets.get(edge.name);
        if (target === undefined) {
          fail('pnpm virtual store has an unexpected dependency symlink');
        }
        const expectedSnapshot = expectedSnapshotTarget(
          sourceSnapshot,
          edge.name,
          target.targetName,
          snapshots,
        );
        await verifyDependencySymlink(
          edge.path,
          target.targetName,
          expectedSnapshot,
          resolvedVirtualStore,
          canonicalRoot,
          snapshots,
        );
      }
      manifests.push({ path: record.manifestPath, manifest });
    } catch (error) {
      if (error.code === 'ENOENT') {
        fail('pnpm virtual store is missing an own package manifest');
      }
      throw error;
    }
  }
  return manifests;
}

async function verifyExtractedManifests(root, snapshots) {
  const manifests = await extractedPackageManifests(root, snapshots);
  const reviewedSeen = new Set();
  const reviewedLifecycleCounts = new Map();
  const manifestLifecyclePackages = new Set();
  const manifestUnreviewedLifecyclePackages = new Set();
  const violations = [];

  for (const { path, manifest } of manifests) {
    if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') {
      fail(`${path} has no string name and version`);
    }
    const scripts = lifecycleScripts(manifest, await hasBindingGyp(path));
    const key = packageKey(manifest.name, manifest.version);
    const reviewed = REVIEWED_BUILD_PACKAGES[key];

    if (reviewed !== undefined && !sameObject(scripts, reviewed.scripts)) {
      violations.push(`${path} lifecycle scripts for ${key} do not match the reviewed scripts`);
      continue;
    }
    if (Object.keys(scripts).length === 0) {
      continue;
    }
    manifestLifecyclePackages.add(key);
    if (reviewed === undefined) {
      manifestUnreviewedLifecyclePackages.add(key);
      violations.push(`${path} declares unreviewed lifecycle scripts for ${key}`);
      continue;
    }
    reviewedSeen.add(key);
    reviewedLifecycleCounts.set(key, (reviewedLifecycleCounts.get(key) ?? 0) + 1);
  }

  for (const key of Object.keys(REVIEWED_BUILD_PACKAGES)) {
    if (reviewedLifecycleCounts.get(key) !== 1) {
      violations.push(
        `extracted manifests must contain exactly one reviewed lifecycle package for ${key}`,
      );
    }
  }

  if (violations.length > 0) {
    fail(violations.join('; '));
  }
  return {
    manifestLifecyclePackages: [...manifestLifecyclePackages].sort(),
    manifestUnreviewedLifecyclePackages: [...manifestUnreviewedLifecyclePackages].sort(),
    reviewedPackages: [...reviewedSeen].sort(),
  };
}
async function requireRegularFile(path, label) {
  let status;
  try {
    status = await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail(`missing ${label} at ${path}`);
    }
    throw error;
  }
  if (!status.isFile() || status.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file`);
  }
  return status;
}
async function assertPathAbsent(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return;
    }
    throw error;
  }
  fail(`unexpected ${label} at ${path}`);
}

function normalizeCanonicalNodeGypShimSource(source, root, canonicalRoot) {
  const normalizedRoot = '/__scene_glass_bootstrap_root__';
  let normalized = source;
  for (const candidateRoot of new Set([resolve(root), canonicalRoot])) {
    const prefix = `${candidateRoot}${sep}node_modules${sep}.pnpm${sep}`;
    const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    normalized = normalized.replace(
      new RegExp(`(^|["'=:])${escapedPrefix}`, 'g'),
      `$1${normalizedRoot}/node_modules/.pnpm/`,
    );
  }
  return normalized;
}

async function verifyCanonicalNativeRebuildShim(root, canonicalNodeGypEntry) {
  const canonicalRoot = await realpath(root);
  const shimPath = join(canonicalRoot, CANONICAL_NODE_GYP_REBUILD_SHIM);
  await assertPathAbsent(
    join(dirname(shimPath), 'node'),
    'canonical node-gyp rebuild shim $basedir/node',
  );
  const shimStatus = await requireRegularFile(shimPath, 'canonical node-gyp rebuild shim');
  if (shimStatus.size > CANONICAL_NODE_GYP_REBUILD_SHIM_MAX_BYTES) {
    fail('canonical node-gyp rebuild shim exceeds the size limit');
  }
  if ((shimStatus.mode & 0o111) === 0) {
    fail('canonical node-gyp rebuild shim must be executable');
  }
  const canonicalEntry = await realpath(canonicalNodeGypEntry);
  const shimTarget = join(dirname(shimPath), '..', 'node-gyp', 'bin', 'node-gyp.js');
  let canonicalShimTarget;
  try {
    canonicalShimTarget = await realpath(shimTarget);
  } catch (error) {
    if (error.code === 'ENOENT') {
      fail('canonical node-gyp rebuild shim target is missing');
    }
    throw error;
  }
  if (canonicalShimTarget !== canonicalEntry) {
    fail('canonical node-gyp rebuild shim must resolve to the canonical node-gyp entry');
  }
  const expectedShim = [
    '#!/bin/sh',
    'basedir=$(dirname "$(echo "$0" | sed -e \'s,\\\\,/,g\')")',
    '',
    'case `uname` in',
    '    *CYGWIN*|*MINGW*|*MSYS*)',
    '        if command -v cygpath > /dev/null 2>&1; then',
    '            basedir=`cygpath -w "$basedir"`',
    '        fi',
    '    ;;',
    'esac',
    '',
    'if [ -x "$basedir/node" ]; then',
    '  exec "$basedir/node"  "$basedir/../node-gyp/bin/node-gyp.js" "$@"',
    'else',
    '  exec node  "$basedir/../node-gyp/bin/node-gyp.js" "$@"',
    'fi',
    '',
  ].join('\n');
  const source = await readBoundedUtf8(
    shimPath,
    'canonical node-gyp rebuild shim',
    CANONICAL_NODE_GYP_REBUILD_SHIM_MAX_BYTES,
  );
  assertExact(
    normalizeCanonicalNodeGypShimSource(source, root, canonicalRoot),
    normalizeCanonicalNodeGypShimSource(expectedShim, root, canonicalRoot),
    'canonical node-gyp rebuild shim source',
  );
}

async function verifyCanonicalNativeBuild(root) {
  const onboardingManifestPath = join(root, 'packages', 'onboarding', 'package.json');
  await requireRegularFile(onboardingManifestPath, 'onboarding package manifest');
  const onboardingManifest = await readJson(onboardingManifestPath);
  assertExact(
    onboardingManifest.scripts?.['build:native'],
    CANONICAL_NATIVE_BUILD_SCRIPT,
    'packages/onboarding/package.json scripts.build:native',
  );
  for (const hook of ['prebuild:native', 'postbuild:native']) {
    assertExact(
      onboardingManifest.scripts?.[hook],
      undefined,
      `packages/onboarding/package.json scripts.${hook}`,
    );
  }

  const nodeGypManifestPath = join(
    root,
    'node_modules',
    '.pnpm',
    CANONICAL_NODE_GYP_STORE_ENTRY,
    'node_modules',
    'node-gyp',
    'package.json',
  );
  await requireRegularFile(nodeGypManifestPath, 'canonical node-gyp manifest');
  const nodeGypManifest = await readJson(nodeGypManifestPath);
  assertExact(nodeGypManifest.name, 'node-gyp', 'canonical node-gyp manifest name');
  assertExact(
    nodeGypManifest.version,
    CANONICAL_NODE_GYP_VERSION,
    'canonical node-gyp manifest version',
  );
  assertExact(nodeGypManifest.bin, CANONICAL_NODE_GYP_BIN, 'canonical node-gyp manifest bin');
  await assertPathAbsent(
    join(
      root,
      'node_modules',
      '.pnpm',
      'fs-ext@2.1.1',
      'node_modules',
      'fs-ext',
      'node_modules',
      '.bin',
      'node-gyp',
    ),
    'package-local node-gyp rebuild shim',
  );

  const canonicalNodeGypEntry = join(root, CANONICAL_NODE_GYP_ENTRY);
  await requireRegularFile(canonicalNodeGypEntry, 'canonical node-gyp entry');
  await verifyCanonicalNativeRebuildShim(root, canonicalNodeGypEntry);
}

async function verifyBootstrapAt(root, expectedLockHash) {
  const absoluteRoot = resolve(root);
  const [rootPackage, lockSource, workspaceSource] = await Promise.all([
    readJson(join(absoluteRoot, 'package.json')),
    readBoundedUtf8(
      join(absoluteRoot, 'pnpm-lock.yaml'),
      'pnpm-lock.yaml',
      MAX_YAML_DOCUMENT_BYTES,
    ),
    readBoundedUtf8(
      join(absoluteRoot, 'pnpm-workspace.yaml'),
      'pnpm-workspace.yaml',
      MAX_YAML_DOCUMENT_BYTES,
    ),
  ]);

  assertExact(rootPackage.packageManager, PACKAGE_MANAGER, 'package.json packageManager');
  assertExact(rootPackage.engines?.node, NODE_ENGINE, 'package.json engines.node');
  verifyRootManifestPolicy(rootPackage);
  verifyWorkspacePolicy(workspaceSource);
  const lock = verifyLock(lockSource, expectedLockHash);
  const extracted = await verifyExtractedManifests(absoluteRoot, lock.snapshots);
  await verifyOnboardingImporterLinks(absoluteRoot, lock.importerDependencies, lock.snapshots);
  await verifyCanonicalNativeBuild(absoluteRoot);

  return {
    manifestLifecyclePackages: extracted.manifestLifecyclePackages,
    manifestUnreviewedLifecyclePackages: extracted.manifestUnreviewedLifecyclePackages,
    reviewedPackages: extracted.reviewedPackages,
    timeline: BOOTSTRAP_TIMELINE,
  };
}

export async function verifyBootstrap({ root = process.cwd() } = {}) {
  return verifyBootstrapAt(root, REVIEWED_LOCK_SHA256);
}

const TEST_FIXTURE_RUNTIME_ENV = 'VITEST';

/** Test-only helper for semantic lock mutations. It is unavailable to production callers. */
export async function verifyBootstrapFixture({ root = process.cwd(), expectedLockHash } = {}) {
  if (process.env[TEST_FIXTURE_RUNTIME_ENV] !== 'true') {
    fail('verifyBootstrapFixture is available only in the test runtime');
  }
  if (typeof expectedLockHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedLockHash)) {
    fail('verifyBootstrapFixture requires a lowercase SHA-256 expectedLockHash');
  }
  return verifyBootstrapAt(root, expectedLockHash);
}

function parseCliArguments(args) {
  for (const option of ['--root', '--print-timeline']) {
    if (args.filter((argument) => argument === option).length > 1) {
      fail(`duplicate option: ${option}`);
    }
  }

  if (args.includes('--print-timeline')) {
    if (args.length !== 1) {
      fail('--print-timeline cannot be combined with other arguments');
    }
    return { printTimeline: true, root: null };
  }
  if (args.length === 0) {
    return { printTimeline: false, root: process.cwd() };
  }
  if (args[0] === '--root') {
    if (args.length !== 2) {
      fail(`unexpected argument: ${args[2] ?? ''}`.trim());
    }
    if (args[1].length === 0 || args[1].startsWith('--')) {
      fail('--root requires a directory');
    }
    return { printTimeline: false, root: args[1] };
  }
  if (args[0].startsWith('--')) {
    fail(`unknown argument: ${args[0]}`);
  }
  fail(`unexpected positional argument: ${args[0]}`);
}

async function main() {
  const command = parseCliArguments(process.argv.slice(2));
  if (command.printTimeline) {
    process.stdout.write(`${BOOTSTRAP_TIMELINE.join('\n')}\n`);
    return;
  }

  await verifyBootstrap({ root: command.root });
  process.stdout.write('bootstrap manifest review passed\n');
}

const invokedPath = process.argv[1] === undefined ? null : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.name}: ${error.message}\n`);
    process.exitCode = 1;
  });
}
