import { parseAnnotationContext, type AnnotationContext } from '@scene-glass/contracts';

const MAX_BYTES = 512;
const MAX_CSS_PATH_BYTES = 4_096;
const MAX_SELECTED_TEXT_CODE_POINTS = 500;
const MAX_SELECTED_TEXT_BYTES = 4_096;
const MAX_LEVELS = 8;
const MAX_ITEMS = 64;

type VueComponent = {
  readonly type?: {
    readonly __file?: unknown;
    readonly __name?: unknown;
    readonly name?: unknown;
  };
  readonly parent?: VueComponent | null;
};

type ReactFiber = {
  readonly return?: ReactFiber | null;
  readonly type?: unknown;
  readonly _debugSource?: {
    readonly fileName?: unknown;
  };
};

/** Captures best-effort, contract-safe context for a selected element. */
export function captureAnnotationContext(element: Element): AnnotationContext {
  const viewport = viewportFor(element);
  const rect = rectFor(element);
  const tag = tagFor(element);
  const classes = classesFor(element);
  const cssPath = cssPathFor(element);
  const selectedText = selectedTextFor(element);
  const required = { viewport, rect, tag, classes, cssPath, selectedText };
  const minimal = { viewport, rect, tag, classes: [], cssPath: '', selectedText: '' };

  try {
    const vue = vueContextFor(element);
    const frameworkContext = vue ?? reactContextFor(element);
    return parseAnnotationContext({ ...required, ...frameworkContext });
  } catch {
    return parseAnnotationContext(minimal);
  }
}

function viewportFor(element: Element): readonly [number, number] {
  try {
    const view = element.ownerDocument.defaultView;
    return [nonNegativeSafeInteger(view?.innerWidth), nonNegativeSafeInteger(view?.innerHeight)];
  } catch {
    return [0, 0];
  }
}

function rectFor(element: Element): readonly [number, number, number, number] {
  try {
    const rect = element.getBoundingClientRect();
    return [
      safeInteger(rect.x),
      safeInteger(rect.y),
      nonNegativeSafeInteger(rect.width),
      nonNegativeSafeInteger(rect.height),
    ];
  } catch {
    return [0, 0, 0, 0];
  }
}

function tagFor(element: Element): string {
  try {
    const tag = element.localName.toLowerCase();
    return /^[a-z][a-z0-9:-]*$/.test(tag) ? tag : 'div';
  } catch {
    return 'div';
  }
}

function classesFor(element: Element): readonly string[] {
  try {
    return Array.from(element.classList)
      .filter((className) => isSafeText(className, MAX_BYTES) && className.trim().length > 0)
      .slice(0, MAX_ITEMS);
  } catch {
    return [];
  }
}

function cssPathFor(element: Element): string {
  try {
    const segments: string[] = [];
    let current: Element | null = element;
    for (let level = 0; current !== null && level < MAX_LEVELS; level += 1) {
      const tag = tagFor(current);
      const id = stripControlCharacters(current.id);
      const classes = classesFor(current);
      segments.unshift(
        `${tag}${id.length === 0 ? '' : `#${id}`}${classes.map((name) => `.${name}`).join('')}`,
      );
      if (
        current === current.ownerDocument.body ||
        current === current.ownerDocument.documentElement
      ) {
        break;
      }
      current = current.parentElement;
    }
    return truncateBytes(stripControlCharacters(segments.join(' > ')), MAX_CSS_PATH_BYTES);
  } catch {
    return '';
  }
}

function selectedTextFor(element: Element): string {
  try {
    const normalized = (element.textContent ?? '').replace(/\s+/g, ' ').trim();
    return truncateBytes(
      Array.from(normalized).slice(0, MAX_SELECTED_TEXT_CODE_POINTS).join(''),
      MAX_SELECTED_TEXT_BYTES,
    );
  } catch {
    return '';
  }
}

function vueContextFor(element: Element): Partial<AnnotationContext> | undefined {
  try {
    let component = (element as Element & { __vueParentComponent?: VueComponent })
      .__vueParentComponent;
    if (component === undefined) {
      return undefined;
    }

    let sourceFile: string | undefined;
    const trail: string[] = [];
    const seen = new Set<VueComponent>();
    while (component !== null && component !== undefined && !seen.has(component)) {
      seen.add(component);
      const file = component.type?.__file;
      if (sourceFile === undefined && typeof file === 'string') {
        const relative = projectRelativeFile(file);
        if (relative !== undefined && isSafeText(relative, MAX_BYTES)) {
          sourceFile = relative;
        }
      }
      const name = vueDisplayName(component);
      if (name !== undefined) {
        trail.unshift(name);
      }
      component = component.parent ?? undefined;
    }

    return {
      ...(sourceFile === undefined ? {} : { sourceFile }),
      ...(trail.length === 0 ? {} : { componentTrail: trail.slice(0, MAX_ITEMS) }),
    };
  } catch {
    return undefined;
  }
}

function vueDisplayName(component: VueComponent): string | undefined {
  const type = component.type;
  const named = type?.__name ?? type?.name;
  if (typeof named === 'string' && isSafeText(named, MAX_BYTES) && named.trim().length > 0) {
    return named;
  }
  if (typeof type?.__file !== 'string') {
    return undefined;
  }
  const basename = type.__file
    .split(/[\\/]/)
    .pop()
    ?.replace(/\.[^.]*$/, '');
  return basename !== undefined && isSafeText(basename, MAX_BYTES) && basename.trim().length > 0
    ? basename
    : undefined;
}

function reactContextFor(element: Element): Partial<AnnotationContext> | undefined {
  try {
    const key = Object.getOwnPropertyNames(element).find(
      (name) => name.startsWith('__reactFiber$') || name.startsWith('__reactInternalInstance$'),
    );
    if (key === undefined) {
      return undefined;
    }
    let fiber = (element as unknown as Record<string, unknown>)[key] as ReactFiber | undefined;
    let sourceFile: string | undefined;
    const trail: string[] = [];
    const seen = new Set<ReactFiber>();
    while (fiber !== null && fiber !== undefined && !seen.has(fiber)) {
      seen.add(fiber);
      const fileName = fiber._debugSource?.fileName;
      if (sourceFile === undefined && typeof fileName === 'string') {
        const relative = projectRelativeFile(fileName);
        if (relative !== undefined && isSafeText(relative, MAX_BYTES)) {
          sourceFile = relative;
        }
      }
      const type = fiber.type;
      if (typeof type === 'function') {
        const name =
          (type as { readonly displayName?: unknown; readonly name?: unknown }).displayName ??
          (type as { readonly name?: unknown }).name;
        if (typeof name === 'string' && isSafeText(name, MAX_BYTES) && name.trim().length > 0) {
          trail.unshift(name);
        }
      }
      fiber = fiber.return ?? undefined;
    }

    return {
      ...(sourceFile === undefined ? {} : { sourceFile }),
      ...(trail.length === 0 ? {} : { componentTrail: trail.slice(0, MAX_ITEMS) }),
    };
  } catch {
    return undefined;
  }
}

function safeInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 0;
  }
  const rounded = Math.round(value);
  return Number.isSafeInteger(rounded) ? rounded : 0;
}

function nonNegativeSafeInteger(value: unknown): number {
  const rounded = safeInteger(value);
  return rounded < 0 ? 0 : rounded;
}

function isControlCharCode(codeUnit: number): boolean {
  return codeUnit <= 0x1f || codeUnit === 0x7f;
}

function isSafeText(value: string, maximumBytes: number): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (isControlCharCode(value.charCodeAt(index))) {
      return false;
    }
  }
  return utf8ByteLength(value) <= maximumBytes;
}

function stripControlCharacters(value: string): string {
  let result = '';
  for (const character of value) {
    if (!isControlCharCode(character.charCodeAt(0))) {
      result += character;
    }
  }
  return result;
}

function projectRelativeFile(file: string): string | undefined {
  const normalized = stripControlCharacters(file).replace(/\\/g, '/').trim();
  if (normalized.length === 0) {
    return undefined;
  }
  const srcIndex = normalized.lastIndexOf('/src/');
  if (srcIndex !== -1) {
    return normalized.slice(srcIndex + 1);
  }
  const slashIndex = normalized.lastIndexOf('/');
  return slashIndex === -1 ? normalized : normalized.slice(slashIndex + 1);
}

function truncateBytes(value: string, maximumBytes: number): string {
  let result = '';
  let bytes = 0;
  for (const character of value) {
    const characterBytes = utf8ByteLength(character);
    if (bytes + characterBytes > maximumBytes) {
      break;
    }
    result += character;
    bytes += characterBytes;
  }
  return result;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}
