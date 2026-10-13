import { builtinModules } from 'node:module';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  opendir,
  realpath,
  rename,
  rmdir,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const ESBUILD_VERSION = '0.25.5';
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cliEntryPoint = join(packageRoot, 'src', 'cli.ts');
const distDirectory = join(packageRoot, 'dist');
const cliOutput = join(distDirectory, 'cli.js');
const buildManifest = join(distDirectory, 'build-manifest.json');
const repositoryRoot = resolve(packageRoot, '..', '..');
const approvedWorkspaceSourceRoots = Object.freeze([
  join(packageRoot, 'src'),
  join(repositoryRoot, 'packages', 'contracts', 'src'),
  join(repositoryRoot, 'packages', 'core', 'src'),
  join(repositoryRoot, 'packages', 'server', 'src'),
]);
const approvedCredentialSourceInputs = new Set([
  join(packageRoot, 'src', 'credential-authority.ts'),
  join(repositoryRoot, 'packages', 'server', 'src', 'auth', 'credential-subject.ts'),
]);
const nodeBuiltins = new Set([
  ...builtinModules,
  ...builtinModules.map((name) => (name.startsWith('node:') ? name : `node:${name}`)),
]);
const externalBuiltins = [...nodeBuiltins, 'node:*'];
const runtimeExternalPackages = ['fs-ext', 'fastify', 'ajv'];
const runtimeExternalRootOnlyPackages = new Set(['fastify', 'ajv']);
const MAX_DIST_DIRECTORY_ENTRIES = 1_024;
const MAX_DIST_DIRECTORY_DEPTH = 8;
const MAX_DIST_TRAVERSAL_OPERATIONS = 4_096;
const DIST_TRAVERSAL_DEADLINE_MS = 5_000;
const AUDITED_CLI_READ_CHUNK_BYTES = 64 * 1024;
const auditedCliPublicationAuthorities = new WeakMap();

export class RuntimeBuildError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RuntimeBuildError';
  }
}

function fail(message) {
  throw new RuntimeBuildError(message);
}
export function resolveAuditedCliPublication(authority) {
  if ((typeof authority !== 'object' && typeof authority !== 'function') || authority === null) {
    return undefined;
  }
  return auditedCliPublicationAuthorities.get(authority);
}

function isBuiltin(specifier) {
  return nodeBuiltins.has(specifier);
}

function isApprovedRuntimeExternal(specifier) {
  return runtimeExternalPackages.some(
    (packageRoot) =>
      specifier === packageRoot ||
      (!runtimeExternalRootOnlyPackages.has(packageRoot) &&
        specifier.startsWith(`${packageRoot}/`)),
  );
}

function disallowedInput(path) {
  const normalized = path.replaceAll('\\', '/');
  if (/(^|\/)\.gjc(?:\/|$)/i.test(normalized)) {
    return '.gjc';
  }
  if (/(^|\/)(?:test|tests|__tests__)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(normalized)) {
    return 'test';
  }
  if (
    /(^|\/)(?:credential|credentials|secret|secrets)(?:[._/-]|$)/i.test(normalized) &&
    !approvedCredentialSourceInputs.has(resolve(packageRoot, path))
  ) {
    return 'credential';
  }
  if (/\.map(?:$|[?#])/i.test(normalized) || /source-?map/i.test(normalized)) {
    return 'source-map';
  }
  return null;
}

function assertSafePath(path, label) {
  const reason = disallowedInput(path);
  if (reason !== null) {
    fail(`${label} imports forbidden ${reason} input`);
  }
}

function assertWorkspaceInput(path) {
  const resolved = resolve(packageRoot, path);
  const approved = approvedWorkspaceSourceRoots.some((root) => {
    const fromRoot = relative(root, resolved);
    return (
      fromRoot === '' ||
      (!fromRoot.startsWith(`..${sep}`) && fromRoot !== '..' && !isAbsolute(fromRoot))
    );
  });
  if (!approved) {
    fail('runtime metafile input is outside the approved onboarding runtime roots');
  }
}

export function auditMetafile(metafile) {
  if (
    metafile === null ||
    typeof metafile !== 'object' ||
    metafile.inputs === undefined ||
    metafile.outputs === undefined
  ) {
    fail('esbuild did not return a complete metafile');
  }

  for (const [input, metadata] of Object.entries(metafile.inputs)) {
    assertSafePath(input, 'runtime metafile');
    assertWorkspaceInput(input);
    for (const imported of metadata.imports ?? []) {
      assertSafePath(imported.path, 'runtime metafile');
      if (
        imported.external &&
        !isBuiltin(imported.path) &&
        !isApprovedRuntimeExternal(imported.path)
      ) {
        fail(`runtime bundle leaves unapproved import external: ${imported.path}`);
      }
    }
  }

  for (const [output, metadata] of Object.entries(metafile.outputs)) {
    if (/\.map$/i.test(output)) {
      fail('runtime build emitted a source map');
    }
    for (const imported of metadata.imports ?? []) {
      assertSafePath(imported.path, 'runtime output metafile');
      if (
        imported.external &&
        !isBuiltin(imported.path) &&
        !isApprovedRuntimeExternal(imported.path)
      ) {
        fail(`runtime bundle leaves unapproved import external: ${imported.path}`);
      }
    }
  }
}

function assertOutputIsSecretless(contents) {
  const source = Buffer.from(contents.buffer, contents.byteOffset, contents.byteLength).toString(
    'utf8',
  );
  if (/sourceMappingURL|sourceURL=/i.test(source)) {
    fail('runtime CLI contains a source-map reference');
  }
  if (
    /synthetic-token-canary|authorization\s*:\s*bearer\s+[^\s"'`]+|(?:access[_-]?token|secret|password)\s*[:=]\s*["'`][^"'`]+/i.test(
      source,
    )
  ) {
    fail('runtime CLI contains a credential-like literal');
  }
}

function isPathInside(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return (
    pathFromRoot === '' ||
    (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..' && !isAbsolute(pathFromRoot))
  );
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function createDistTraversalBudget() {
  return {
    deadline: Date.now() + DIST_TRAVERSAL_DEADLINE_MS,
    operations: 0,
  };
}

function consumeDistTraversalBudget(budget) {
  budget.operations += 1;
  if (budget.operations > MAX_DIST_TRAVERSAL_OPERATIONS || Date.now() > budget.deadline) {
    fail('runtime dist traversal exceeded its global operation or deadline bound');
  }
}

async function pinDistDirectory() {
  await mkdir(distDirectory, { recursive: true, mode: 0o700 });
  const [facts, canonicalPath, canonicalPackageRoot] = await Promise.all([
    lstat(distDirectory, { bigint: true }),
    realpath(distDirectory),
    realpath(packageRoot),
  ]);
  if (
    !facts.isDirectory() ||
    facts.isSymbolicLink() ||
    !isPathInside(canonicalPackageRoot, canonicalPath)
  ) {
    fail('runtime dist root must be a real directory contained by the onboarding package');
  }
  return Object.freeze({
    canonicalPath,
    identity: Object.freeze({ dev: facts.dev, ino: facts.ino }),
    path: distDirectory,
  });
}

async function assertPinnedDistDirectory(authority) {
  const [facts, canonicalPath] = await Promise.all([
    lstat(authority.path, { bigint: true }),
    realpath(authority.path),
  ]);
  if (
    !facts.isDirectory() ||
    facts.isSymbolicLink() ||
    !sameDirectoryIdentity(authority.identity, facts) ||
    canonicalPath !== authority.canonicalPath
  ) {
    fail('runtime dist root changed after it was pinned');
  }
}

function assertContainedDistPath(authority, path) {
  if (!isPathInside(authority.canonicalPath, resolve(path))) {
    fail('runtime dist traversal escaped its pinned root');
  }
}

async function boundedDistDirectoryEntries(authority, directory, depth, budget) {
  if (depth > MAX_DIST_DIRECTORY_DEPTH) {
    fail('runtime dist directory exceeds the nesting-depth limit');
  }
  consumeDistTraversalBudget(budget);
  await assertPinnedDistDirectory(authority);
  assertContainedDistPath(authority, directory);

  const before = await lstat(directory, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    fail('runtime dist traversal encountered an unsafe directory');
  }
  const canonicalDirectory = await realpath(directory);
  if (!isPathInside(authority.canonicalPath, canonicalDirectory)) {
    fail('runtime dist traversal escaped its pinned root');
  }

  let handle;
  try {
    handle = await opendir(directory, { bufferSize: 32 });
    const entries = [];
    for (;;) {
      consumeDistTraversalBudget(budget);
      const entry = await handle.read();
      if (entry === null) {
        break;
      }
      if (entries.length >= MAX_DIST_DIRECTORY_ENTRIES) {
        fail('runtime dist directory exceeds the entry limit');
      }
      if (
        entry.name.length === 0 ||
        entry.name === '.' ||
        entry.name === '..' ||
        entry.name.includes(sep)
      ) {
        fail('runtime dist directory has an invalid entry name');
      }
      entries.push(entry);
    }
    const after = await lstat(directory, { bigint: true });
    if (!sameDirectoryIdentity(before, after) || after.isSymbolicLink()) {
      fail('runtime dist directory changed while it was traversed');
    }
    return entries.sort((left, right) => left.name.localeCompare(right.name));
  } finally {
    await handle?.close();
  }
}

async function removeBoundedDistPath(authority, path, depth, budget) {
  consumeDistTraversalBudget(budget);
  await assertPinnedDistDirectory(authority);
  assertContainedDistPath(authority, path);
  const facts = await lstat(path, { bigint: true });
  if (!facts.isDirectory() || facts.isSymbolicLink()) {
    await unlink(path);
    return;
  }

  for (const entry of await boundedDistDirectoryEntries(authority, path, depth, budget)) {
    await removeBoundedDistPath(authority, join(path, entry.name), depth + 1, budget);
  }
  const after = await lstat(path, { bigint: true });
  if (!sameDirectoryIdentity(facts, after) || after.isSymbolicLink()) {
    fail('runtime dist directory changed before cleanup');
  }
  await rmdir(path);
}

async function removeDistPathIfPresent(authority, path, budget) {
  try {
    await removeBoundedDistPath(authority, path, 1, budget);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return;
    }
    throw error;
  }
}

async function removeStaleRuntimeBuildDirectories(
  authority,
  directory,
  removeSourceMaps,
  depth,
  budget,
) {
  for (const entry of await boundedDistDirectoryEntries(authority, directory, depth, budget)) {
    const path = join(directory, entry.name);
    if (entry.name.startsWith('.runtime-build-')) {
      await removeBoundedDistPath(authority, path, depth + 1, budget);
      continue;
    }
    if (entry.name.toLowerCase().endsWith('.map')) {
      if (removeSourceMaps) {
        await removeBoundedDistPath(authority, path, depth + 1, budget);
      }
      continue;
    }
    if (entry.isDirectory()) {
      await removeStaleRuntimeBuildDirectories(
        authority,
        path,
        removeSourceMaps,
        depth + 1,
        budget,
      );
    }
  }
}

async function removeRejectedBuildArtifacts({ removeSourceMaps = false, authority, budget } = {}) {
  const pinnedAuthority = authority ?? (await pinDistDirectory());
  const traversalBudget = budget ?? createDistTraversalBudget();
  await assertPinnedDistDirectory(pinnedAuthority);
  await removeDistPathIfPresent(pinnedAuthority, cliOutput, traversalBudget);
  await removeDistPathIfPresent(pinnedAuthority, buildManifest, traversalBudget);
  await removeStaleRuntimeBuildDirectories(
    pinnedAuthority,
    pinnedAuthority.path,
    removeSourceMaps,
    0,
    traversalBudget,
  );
}

async function assertDistDirectoryHasNoSourceMaps(authority, directory, depth, budget) {
  for (const entry of await boundedDistDirectoryEntries(authority, directory, depth, budget)) {
    if (entry.name.toLowerCase().endsWith('.map')) {
      fail('runtime dist directory contains a source map');
    }
    if (entry.isDirectory()) {
      await assertDistDirectoryHasNoSourceMaps(
        authority,
        join(directory, entry.name),
        depth + 1,
        budget,
      );
    }
  }
}

function cliOutputFromBuild(result) {
  if (!Array.isArray(result.outputFiles) || result.outputFiles.length !== 1) {
    fail('esbuild did not return exactly one in-memory CLI output');
  }
  const [output] = result.outputFiles;
  if (
    output === undefined ||
    resolve(output.path) !== cliOutput ||
    !Number.isSafeInteger(output.contents.byteLength) ||
    output.contents.byteLength <= 0 ||
    output.contents.byteLength > 16 * 1024 * 1024
  ) {
    fail('esbuild returned an unexpected or oversized CLI output');
  }
  return output.contents;
}

async function pinAuditedPublishedCli(contents, authority) {
  if (
    typeof constants.O_NOFOLLOW !== 'number' ||
    typeof constants.O_NONBLOCK !== 'number' ||
    !Number.isSafeInteger(contents.byteLength) ||
    contents.byteLength <= 0 ||
    contents.byteLength > 16 * 1024 * 1024
  ) {
    fail('audited runtime CLI has invalid publication bounds');
  }

  await assertPinnedDistDirectory(authority);
  const auditedContents = Buffer.from(contents.buffer, contents.byteOffset, contents.byteLength);
  const hash = createHash('sha256').update(auditedContents).digest('hex');
  let handle;
  try {
    handle = await open(
      cliOutput,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const facts = await handle.stat({ bigint: true });
    if (
      !facts.isFile() ||
      facts.nlink !== 1n ||
      (facts.mode & 0o7777n) !== 0o600n ||
      facts.size !== BigInt(auditedContents.byteLength)
    ) {
      fail('published runtime CLI has invalid identity or bounds');
    }

    const digest = createHash('sha256');
    const chunk = Buffer.allocUnsafe(AUDITED_CLI_READ_CHUNK_BYTES);
    let offset = 0;
    while (offset < auditedContents.byteLength) {
      const { bytesRead } = await handle.read(
        chunk,
        0,
        Math.min(chunk.byteLength, auditedContents.byteLength - offset),
        offset,
      );
      if (
        bytesRead === 0 ||
        !chunk.subarray(0, bytesRead).equals(auditedContents.subarray(offset, offset + bytesRead))
      ) {
        fail('published runtime CLI does not match audited esbuild bytes');
      }
      digest.update(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== facts.dev ||
      after.ino !== facts.ino ||
      after.mode !== facts.mode ||
      after.nlink !== facts.nlink ||
      after.size !== facts.size ||
      after.mtimeNs !== facts.mtimeNs ||
      after.ctimeNs !== facts.ctimeNs ||
      digest.digest('hex') !== hash
    ) {
      fail('published runtime CLI changed while its audited bytes were pinned');
    }
    await assertPinnedDistDirectory(authority);
    const publicationAuthority = Object.freeze({});
    auditedCliPublicationAuthorities.set(
      publicationAuthority,
      Object.freeze({ contents: auditedContents, facts, handle, hash, path: cliOutput }),
    );
    return publicationAuthority;
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function publishAuditedCli(contents, authority) {
  await assertPinnedDistDirectory(authority);
  const temporaryDirectory = await mkdtemp(join(authority.path, '.runtime-build-'));
  const temporaryOutput = join(temporaryDirectory, 'cli.js');
  let publication;
  let buildFailure;
  try {
    await writeFile(temporaryOutput, contents, { mode: 0o600 });
    await assertPinnedDistDirectory(authority);
    await rename(temporaryOutput, cliOutput);
    publication = await pinAuditedPublishedCli(contents, authority);
  } catch (error) {
    buildFailure = error;
  }

  let cleanupFailure;
  try {
    await removeBoundedDistPath(authority, temporaryDirectory, 1, createDistTraversalBudget());
  } catch (error) {
    cleanupFailure = error;
  }
  if (cleanupFailure !== undefined) {
    const failures = [...(buildFailure === undefined ? [] : [buildFailure]), cleanupFailure];
    const pinnedPublication = resolveAuditedCliPublication(publication);
    try {
      await pinnedPublication?.handle.close();
    } catch (error) {
      failures.push(error);
    }
    throw new AggregateError(
      failures,
      'runtime build publication and temporary-output cleanup failed',
    );
  }
  if (buildFailure !== undefined) {
    throw buildFailure;
  }
  if (publication === undefined) {
    fail('audited runtime CLI publication did not produce authority');
  }
  return publication;
}

async function discardRejectedBuild(error, { authority } = {}) {
  try {
    await removeRejectedBuildArtifacts({
      removeSourceMaps: true,
      authority,
      budget: createDistTraversalBudget(),
    });
  } catch (cleanupError) {
    throw new AggregateError(
      [error, cleanupError],
      'runtime build failed and rejected-artifact cleanup also failed',
    );
  }
}

export async function buildRuntime() {
  let authority;
  try {
    if (esbuild.version !== ESBUILD_VERSION) {
      fail(`expected esbuild ${ESBUILD_VERSION}; resolved ${esbuild.version}`);
    }
    authority = await pinDistDirectory();
    const setupBudget = createDistTraversalBudget();
    await removeRejectedBuildArtifacts({ authority, budget: setupBudget });
    await assertDistDirectoryHasNoSourceMaps(authority, authority.path, 0, setupBudget);
    const result = await esbuild.build({
      absWorkingDir: packageRoot,
      bundle: true,
      entryPoints: [cliEntryPoint],
      external: [...externalBuiltins, ...runtimeExternalPackages],
      format: 'esm',
      legalComments: 'none',
      metafile: true,
      outfile: cliOutput,
      packages: 'bundle',
      platform: 'node',
      sourcemap: false,
      target: 'node24',
      write: false,
    });

    auditMetafile(result.metafile);
    const contents = cliOutputFromBuild(result);
    assertOutputIsSecretless(contents);
    const auditedCli = await publishAuditedCli(contents, authority);
    try {
      await assertPinnedDistDirectory(authority);
      const { publishRuntimeBuildManifest } = await import('./verify-artifacts.mjs');
      await publishRuntimeBuildManifest(auditedCli);
      await assertPinnedDistDirectory(authority);
    } finally {
      const publication = resolveAuditedCliPublication(auditedCli);
      await publication?.handle.close();
    }
    return { cliOutput, metafile: result.metafile };
  } catch (error) {
    await discardRejectedBuild(error, { authority });
    throw error;
  }
}

async function main() {
  if (process.argv.length !== 2) {
    fail('build-runtime.mjs accepts no arguments');
  }
  const result = await buildRuntime();
  process.stdout.write(
    `bundled ${relative(packageRoot, result.cliOutput)} with esbuild ${ESBUILD_VERSION}\n`,
  );
}

const invokedPath = process.argv[1] === undefined ? null : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.name}: ${error.message}\n`);
    process.exitCode = 1;
  });
}
