import {
  BUILT_IN_LIMITS,
  SceneGlassContractError,
  parsePageFileV1,
  serializeCanonicalPageFileV1,
  type ElementAnnotation,
  type LimitValues,
  type PageFileV1,
  type PageFileValidationLimits,
  type PageId,
} from '@scene-glass/contracts';
import { canonicalizeJson } from './operation-replay.js';

export type PromptExportMode = 'page' | 'project';

export type PromptExportLimits = PageFileValidationLimits &
  Pick<LimitValues, 'exportRenderBytes' | 'exportScanBytes'>;

export type PromptExportCheckpoint = () => void;

export type PromptExportOptions =
  | {
      readonly mode: 'page';
      readonly pageId: PageId;
      readonly limits?: PromptExportLimits;
      readonly checkpoint?: PromptExportCheckpoint;
    }
  | {
      readonly mode: 'project';
      readonly limits?: PromptExportLimits;
      readonly checkpoint?: PromptExportCheckpoint;
    };

type PromptExportInvocationOptions = {
  readonly mode: PromptExportMode;
  readonly pageId?: PageId;
  readonly limits?: PromptExportLimits;
  readonly checkpoint?: PromptExportCheckpoint;
};

const LOCATOR_JSON_STRING_MAX_LENGTH = 65_536;
const LOCATOR_RENDER_MAX_DEPTH = 32;
const LOCATOR_RENDER_MAX_NODES = 10_000;

const DEFAULT_EXPORT_LIMITS: PromptExportLimits = BUILT_IN_LIMITS;

export function exportReviewMarkdown(
  pageFiles: readonly PageFileV1[],
  options: PromptExportOptions,
): string;
export function exportReviewMarkdown(
  pageFiles: readonly PageFileV1[],
  options: PromptExportInvocationOptions,
): string {
  const limits = options.limits ?? DEFAULT_EXPORT_LIMITS;
  assertExportOptions(options);
  const checkpoint = options.checkpoint;
  checkpoint?.();
  const parsedPageFiles: PageFileV1[] = [];
  for (const pageFile of pageFiles) {
    checkpoint?.();
    parsedPageFiles.push(parsePageFileV1(pageFile, limits));
    checkpoint?.();
  }
  const selected = selectPages(parsedPageFiles, options, checkpoint);
  let scanBytes = 0;

  for (const pageFile of selected) {
    checkpoint?.();
    scanBytes += utf8Bytes(serializeCanonicalPageFileV1(pageFile));
    checkpoint?.();
    if (scanBytes > limits.exportScanBytes) {
      throw exportLimitError('export scan exceeds its effective byte limit');
    }
  }

  const sections = ['# Scene Glass Review'];
  for (const pageFile of selected) {
    checkpoint?.();
    sections.push(renderPage(pageFile, checkpoint));
  }
  const markdown = `${sections.join('\n\n')}\n`;

  checkpoint?.();
  if (utf8Bytes(markdown) > limits.exportRenderBytes) {
    throw exportLimitError('export output exceeds its effective byte limit');
  }
  return markdown;
}

export function exportProjectReviewMarkdown(
  pageFiles: readonly PageFileV1[],
  limits?: PromptExportLimits,
): string {
  return exportReviewMarkdown(pageFiles, {
    mode: 'project',
    ...(limits === undefined ? {} : { limits }),
  });
}

export function exportCurrentPageReviewMarkdown(
  pageFiles: readonly PageFileV1[],
  pageId: PageId,
  limits?: PromptExportLimits,
): string {
  return exportReviewMarkdown(pageFiles, {
    mode: 'page',
    pageId,
    ...(limits === undefined ? {} : { limits }),
  });
}

function selectPages(
  pageFiles: readonly PageFileV1[],
  options: PromptExportInvocationOptions,
  checkpoint: PromptExportCheckpoint | undefined,
): readonly PageFileV1[] {
  switch (options.mode) {
    case 'page': {
      if (options.pageId === undefined) {
        throw exportError('current-page export requires a pageId');
      }
      const pages: PageFileV1[] = [];
      for (const pageFile of pageFiles) {
        checkpoint?.();
        if (pageFile.page.pageId === options.pageId) {
          pages.push(pageFile);
        }
      }
      if (pages.length !== 1) {
        throw exportError('current-page export requires exactly one matching page');
      }
      return Object.freeze(pages);
    }
    case 'project': {
      const pageIds = new Set<string>();
      for (const pageFile of pageFiles) {
        checkpoint?.();
        if (pageIds.has(pageFile.page.pageId)) {
          throw exportError('project export contains duplicate pageIds');
        }
        pageIds.add(pageFile.page.pageId);
      }
      const pages = [...pageFiles].sort(comparePages);
      checkpoint?.();
      return Object.freeze(pages);
    }
    default:
      throw exportError('prompt export mode is invalid');
  }
}

function renderPage(pageFile: PageFileV1, checkpoint: PromptExportCheckpoint | undefined): string {
  const annotations = [...pageFile.annotations].sort(compareAnnotations);
  checkpoint?.();
  const sections = [`## Page Feedback: ${escapeMarkdownLiteral(pageFile.page.route)}`];
  for (const [index, annotation] of annotations.entries()) {
    checkpoint?.();
    sections.push(renderAnnotation(annotation, index + 1));
  }
  return sections.join('\n\n');
}

function assertExportMode(mode: unknown): asserts mode is PromptExportMode {
  if (mode !== 'page' && mode !== 'project') {
    throw exportError('prompt export mode is invalid');
  }
}

function assertExportOptions(options: PromptExportInvocationOptions): void {
  assertExportMode(options.mode);
  if (options.mode === 'project' && Object.prototype.hasOwnProperty.call(options, 'pageId')) {
    throw exportError('project export does not accept a pageId');
  }
}
function renderAnnotation(annotation: ElementAnnotation, index: number): string {
  if (annotation.context === undefined) {
    return renderLegacyAnnotation(annotation, index);
  }

  const { context } = annotation;
  const headingSelector = `${context.tag}${
    context.classes.length === 0 ? '' : `.${context.classes.join('.')}`
  }`;
  const lines = [`### ${index}. ${escapeMarkdownLiteral(headingSelector)}`];

  if (annotation.resolution.status !== 'resolved') {
    lines.push(`> WARNING: unresolved (${annotation.resolution.status})`);
  }
  lines.push(`**Location:** ${renderInlineCode(context.cssPath)}`);
  if (context.sourceFile !== undefined && context.sourceFile !== '') {
    lines.push(`**Source:** ${escapeMarkdownLiteral(context.sourceFile)}`);
  }
  if (context.classes.length > 0) {
    lines.push(`**Classes:** ${renderInlineCode(context.classes.join(' '))}`);
  }
  if (context.componentTrail !== undefined && context.componentTrail.length > 0) {
    lines.push(
      `**Component:** ${context.componentTrail
        .map((component) => `<${escapeMarkdownLiteral(component)}>`)
        .join(' ')}`,
    );
  }
  lines.push(
    `**Position:** ${context.rect[0]}, ${context.rect[1]} (${context.rect[2]}x${context.rect[3]})`,
  );
  lines.push(`**Viewport:** ${context.viewport[0]}x${context.viewport[1]}`);
  if (context.selectedText.trim() !== '') {
    lines.push(`**Selected:** "${escapeMarkdownLiteral(context.selectedText)}"`);
  }
  lines.push(`**Memo:** ${escapeMarkdownLiteral(annotation.memo)}`);
  return lines.join('\n');
}

function renderLegacyAnnotation(annotation: ElementAnnotation, index: number): string {
  const surroundingText = normalizeMarkdownText(annotation.surroundingText);
  const fence = '`'.repeat(Math.max(3, longestBacktickRun(surroundingText) + 1));
  const locatorJson = canonicalizeJson(expandEmbeddedLocatorJson(annotation.locator));
  const normalizedLocator = normalizeMarkdownText(locatorJson);
  const locatorFence = '`'.repeat(Math.max(3, longestBacktickRun(normalizedLocator) + 1));
  const lines = [`### Annotation ${index}`];

  if (annotation.resolution.status !== 'resolved') {
    lines.push(`> WARNING: unresolved (${annotation.resolution.status})`);
  }
  lines.push('Locator:', locatorFence, normalizedLocator, locatorFence);
  lines.push(`Memo: ${escapeMarkdownLiteral(annotation.memo)}`);
  lines.push('Surrounding text:', fence, surroundingText, fence);
  return lines.join('\n');
}

function renderInlineCode(value: string): string {
  const escaped = escapeMarkdownLiteral(value);
  const fence = '`'.repeat(Math.max(1, longestBacktickRun(escaped) + 1));
  return `${fence}${escaped}${fence}`;
}

function expandEmbeddedLocatorJson(locator: unknown): unknown {
  let remainingNodes = LOCATOR_RENDER_MAX_NODES;
  return visit(locator, 0);

  function visit(value: unknown, depth: number): unknown {
    if (remainingNodes === 0 || depth >= LOCATOR_RENDER_MAX_DEPTH) {
      return value;
    }
    remainingNodes -= 1;

    if (typeof value === 'string') {
      return expandJsonString(value, depth);
    }
    if (Array.isArray(value)) {
      return value.map((entry) => visit(entry, depth + 1));
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [key, visit(entry, depth + 1)]),
      );
    }
    return value;
  }

  function expandJsonString(value: string, depth: number): unknown {
    if (value.length > LOCATOR_JSON_STRING_MAX_LENGTH || (value[0] !== '[' && value[0] !== '{')) {
      return value;
    }
    try {
      const parsed: unknown = JSON.parse(value);
      return Array.isArray(parsed) || (parsed !== null && typeof parsed === 'object')
        ? visit(parsed, depth + 1)
        : value;
    } catch {
      return value;
    }
  }
}

function comparePages(left: PageFileV1, right: PageFileV1): number {
  return (
    compareCodePoints(left.page.route, right.page.route) ||
    compareCodePoints(left.page.canonicalIdentity, right.page.canonicalIdentity) ||
    compareCodePoints(left.page.pageId, right.page.pageId)
  );
}

function compareAnnotations(left: ElementAnnotation, right: ElementAnnotation): number {
  return left.domOrder - right.domOrder || compareCodePoints(left.id, right.id);
}

function compareCodePoints(left: string, right: string): number {
  const leftIterator = left[Symbol.iterator]();
  const rightIterator = right[Symbol.iterator]();
  while (true) {
    const leftPart = leftIterator.next();
    const rightPart = rightIterator.next();
    if (leftPart.done || rightPart.done) {
      if (leftPart.done && rightPart.done) {
        return 0;
      }
      return leftPart.done ? -1 : 1;
    }
    const difference =
      (leftPart.value as string).codePointAt(0)! - (rightPart.value as string).codePointAt(0)!;
    if (difference !== 0) {
      return difference;
    }
  }
}

function escapeMarkdownLiteral(value: string): string {
  const normalized = normalizeMarkdownText(value);
  const characters = Array.from(normalized);
  let escaped = '';
  let atLineStart = true;

  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index]!;
    if (character === '\n') {
      escaped += character;
      atLineStart = true;
      continue;
    }
    if (atLineStart && character === ' ') {
      escaped += '&#32;';
      continue;
    }
    if (atLineStart && isAsciiDigit(character)) {
      let end = index;
      while (end < characters.length && isAsciiDigit(characters[end]!)) {
        end += 1;
      }
      if (characters[end] === '.' || characters[end] === ')') {
        escaped += `${characters.slice(index, end).join('')}\\${characters[end]!}`;
        index = end;
        atLineStart = false;
        continue;
      }
    }

    const escapesInline =
      character === '\\' ||
      character === '`' ||
      character === '*' ||
      character === '_' ||
      character === '[' ||
      character === ']' ||
      (character === '!' && characters[index + 1] === '[') ||
      (character === '~' && characters[index + 1] === '~');
    const escapesLineStart =
      atLineStart &&
      ('#>-+*=|'.includes(character) || (character === '~' && characters[index + 1] === '~'));

    atLineStart = false;
    if (character === '&') {
      escaped += '&amp;';
    } else if (character === '<') {
      escaped += '&lt;';
    } else if (escapesInline || escapesLineStart) {
      escaped += `\\${character}`;
    } else {
      escaped += character;
    }
  }
  return escaped;
}

function isAsciiDigit(value: string): boolean {
  return value >= '0' && value <= '9';
}

function normalizeMarkdownText(value: string): string {
  assertWellFormedUnicode(value);
  return defendControls(value.normalize('NFC').replace(/\r\n?/g, '\n'));
}

function defendControls(value: string): string {
  let escaped = '';
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (!isEscapableControl(codeUnit)) {
      continue;
    }
    escaped += value.slice(start, index);
    escaped += `\\u${codeUnit.toString(16).padStart(4, '0')}`;
    start = index + 1;
  }
  return start === 0 ? value : escaped + value.slice(start);
}

function isEscapableControl(codeUnit: number): boolean {
  return (codeUnit <= 0x1f && codeUnit !== 0x0a) || (codeUnit >= 0x7f && codeUnit <= 0x9f);
}

function longestBacktickRun(value: string): number {
  let longest = 0;
  let current = 0;
  for (const character of value) {
    if (character === '`') {
      current += 1;
      longest = Math.max(longest, current);
    } else {
      current = 0;
    }
  }
  return longest;
}

function assertWellFormedUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw exportError('export content contains an unpaired surrogate');
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw exportError('export content contains an unpaired surrogate');
    }
  }
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function exportError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_PAGE_FILE_INVALID', message);
}

function exportLimitError(message: string): SceneGlassContractError {
  return new SceneGlassContractError('SCG_LIMIT_FILE', message);
}
