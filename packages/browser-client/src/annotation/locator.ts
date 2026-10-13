import type {
  LocatorFingerprint,
  LocatorInput,
  LocatorStableAttribute,
} from '@scene-glass/contracts';

export type ElementLocator = LocatorInput;

export const MAX_LOCATOR_ANCESTORS = 4;
export const MAX_LOCATOR_ATTRIBUTES = 12;
export const MAX_LOCATOR_ATTRIBUTE_VALUE_CODE_POINTS = 128;
export const MAX_LOCATOR_TEXT_CODE_POINTS = 512;
export const MAX_LOCATOR_ATTRIBUTE_NAME_CODE_POINTS = 64;

const STABLE_ATTRIBUTE_NAMES = new Set([
  'alt',
  'for',
  'href',
  'id',
  'name',
  'rel',
  'role',
  'title',
  'type',
]);

/**
 * Captures the local browser capability for a mounted light-DOM element.
 * `data-scg-id` is used only when it is unique in this document; otherwise a
 * bounded fingerprint is produced so a later duplicate cannot bind blindly.
 */
export async function captureElementLocator(element: Element): Promise<ElementLocator> {
  assertMountedLightDomElement(element);

  const dataScgId = uniqueDataScgId(element);
  if (dataScgId !== undefined) {
    return Object.freeze({ dataScgId });
  }

  return Object.freeze({
    fingerprint: await captureElementFingerprint(element),
  });
}

export async function captureElementFingerprint(element: Element): Promise<LocatorFingerprint> {
  assertMountedLightDomElement(element);

  const fingerprint = {
    tag: tagNameFor(element),
    stableAttributes: stableAttributesFor(element),
    ancestorSignatures: ancestorSignaturesFor(element),
    textDigest: await digestVisibleText(visibleTextFor(element)),
  } satisfies LocatorFingerprint;

  return freezeFingerprint(fingerprint);
}

export function isMountedLightDomElement(element: Element): boolean {
  const document = element.ownerDocument;
  return (
    document.documentElement !== null &&
    document.documentElement.contains(element) &&
    element.getRootNode() === document
  );
}

function assertMountedLightDomElement(element: Element): void {
  if (!isMountedLightDomElement(element)) {
    throw new Error('Scene Glass can capture locators only for mounted light-DOM elements');
  }
}

function uniqueDataScgId(element: Element): string | undefined {
  const value = element.getAttribute('data-scg-id');
  if (value === null || !isSafeLocatorField(value)) {
    return undefined;
  }

  let count = 0;
  for (const candidate of element.ownerDocument.querySelectorAll('[data-scg-id]')) {
    if (candidate.getAttribute('data-scg-id') === value && isMountedLightDomElement(candidate)) {
      count += 1;
      if (count > 1) {
        return undefined;
      }
    }
  }
  return count === 1 ? value : undefined;
}

function stableAttributesFor(element: Element): readonly LocatorStableAttribute[] {
  const attributes: LocatorStableAttribute[] = [];
  for (const attribute of element.attributes) {
    const name = attribute.name.toLowerCase();
    const value = normalizeAttributeValue(attribute.value);
    if (!isStableAttribute(name, value)) {
      continue;
    }
    attributes.push(Object.freeze([name, value]) as LocatorStableAttribute);
  }

  attributes.sort(compareAttributes);
  return Object.freeze(attributes.slice(0, MAX_LOCATOR_ATTRIBUTES));
}

function ancestorSignaturesFor(element: Element): readonly string[] {
  const signatures: string[] = [];
  let ancestor = element.parentElement;
  while (ancestor !== null && signatures.length < MAX_LOCATOR_ANCESTORS) {
    signatures.push(ancestorSignatureFor(ancestor));
    ancestor = ancestor.parentElement;
  }
  return Object.freeze(signatures);
}

function ancestorSignatureFor(element: Element): string {
  return JSON.stringify([tagNameFor(element), stableAttributesFor(element)]);
}

function tagNameFor(element: Element): string {
  return element.localName.toLowerCase();
}

function isStableAttribute(name: string, value: string): boolean {
  if (
    !/^[a-z][a-z0-9:_-]*$/u.test(name) ||
    Array.from(name).length > MAX_LOCATOR_ATTRIBUTE_NAME_CODE_POINTS ||
    !isSafeLocatorField(value) ||
    name === 'class' ||
    name === 'data-scg-id' ||
    name === 'slot' ||
    name === 'style' ||
    name.startsWith('on')
  ) {
    return false;
  }
  return STABLE_ATTRIBUTE_NAMES.has(name) || name.startsWith('aria-') || name.startsWith('data-');
}

function normalizeAttributeValue(value: string): string {
  return truncateCodePoints(value.trim(), MAX_LOCATOR_ATTRIBUTE_VALUE_CODE_POINTS);
}

function visibleTextFor(element: Element): string {
  const innerText = 'innerText' in element ? element.innerText : undefined;
  const source = typeof innerText === 'string' ? innerText : element.textContent;
  return truncateCodePoints(
    (source ?? '').replace(/\s+/gu, ' ').trim(),
    MAX_LOCATOR_TEXT_CODE_POINTS,
  );
}

async function digestVisibleText(text: string): Promise<LocatorFingerprint['textDigest']> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new Error('Scene Glass requires Web Crypto to capture a locator');
  }

  const bytes = new TextEncoder().encode(text);
  const digest = await subtle.digest('SHA-256', bytes);
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}` as LocatorFingerprint['textDigest'];
}

function truncateCodePoints(value: string, maximum: number): string {
  const codePoints = Array.from(value);
  return codePoints.length <= maximum ? value : codePoints.slice(0, maximum).join('');
}

function isSafeLocatorField(value: string): boolean {
  return (
    value.trim().length > 0 &&
    !containsAsciiControlCharacter(value) &&
    new TextEncoder().encode(value).byteLength <= 512
  );
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

function compareAttributes(left: LocatorStableAttribute, right: LocatorStableAttribute): number {
  const [leftName, leftValue] = left;
  const [rightName, rightValue] = right;
  if (leftName !== rightName) {
    return leftName < rightName ? -1 : 1;
  }
  if (leftValue === rightValue) {
    return 0;
  }
  return leftValue < rightValue ? -1 : 1;
}

function freezeFingerprint(fingerprint: LocatorFingerprint): LocatorFingerprint {
  return Object.freeze({
    tag: fingerprint.tag,
    stableAttributes: Object.freeze(
      fingerprint.stableAttributes.map(
        ([name, value]): LocatorStableAttribute =>
          Object.freeze([name, value]) as LocatorStableAttribute,
      ),
    ),
    ancestorSignatures: Object.freeze([...fingerprint.ancestorSignatures]),
    textDigest: fingerprint.textDigest,
  });
}
