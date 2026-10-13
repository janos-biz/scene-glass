import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ONBOARDING_ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../packages/onboarding');
const SOURCE_ROOT = join(ONBOARDING_ROOT, 'src');
const DIST_ROOT = join(ONBOARDING_ROOT, 'dist');
const LEGACY_READ_ONLY_SYMBOLS = new Set([
  'parseViteSnapshotAuthorityJson',
  'serializeViteSnapshotAuthorityJson',
]);
const FORBIDDEN_PATTERNS = [
  /data-scg-root/u,
  /preparing-vite|vite-ready/u,
  /\bstartManagedViteDev\s*\(/u,
  /\bhmr\s*:\s*false\b/u,
  /\bwatch\s*:\s*null\b/u,
  /\b(?:createNativeViteSnapshotPublicationAuthority|parseViteSnapshotAuthorityJson|serializeViteSnapshotAuthorityJson)\b/u,
  /managed-vite-child|managed-vite-dev/u,
  /:\s*4174\b/u,
];

async function files(
  directory: string,
  extension: string,
  relativeDirectory = '',
): Promise<readonly string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry): Promise<readonly string[]> => {
      const relativePath = join(relativeDirectory, entry.name);
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        return files(path, extension, relativePath);
      }
      return entry.isFile() && entry.name.endsWith(extension) ? [relativePath] : [];
    }),
  );
  return nested.flat();
}

function matchingForbiddenPatterns(source: string): readonly RegExp[] {
  return FORBIDDEN_PATTERNS.filter((pattern) =>
    [...source.matchAll(new RegExp(pattern.source, `${pattern.flags}g`))].some(
      (match) => !LEGACY_READ_ONLY_SYMBOLS.has(match[0]),
    ),
  );
}

describe('managed Vite forbidden behavior', () => {
  it('does not reintroduce managed Vite production behavior', async () => {
    const violations: string[] = [];
    for (const [label, root, extension] of [
      ['src', SOURCE_ROOT, '.ts'],
      ['dist', DIST_ROOT, '.js'],
    ] as const) {
      for (const relativePath of await files(root, extension)) {
        const source = await readFile(join(root, relativePath), 'utf8');
        for (const pattern of matchingForbiddenPatterns(source)) {
          violations.push(`${label}/${relativePath}: ${pattern}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
