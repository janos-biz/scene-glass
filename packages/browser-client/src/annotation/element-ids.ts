/**
 * Stamps a stable `data-scg-id` on the host's own elements so an annotation can
 * be re-found exactly, instead of being scored against a fingerprint.
 *
 * The fingerprint collapses on two shapes this runs into constantly. A control
 * inside a data grid carries no text and no id, so its only distinguishing token
 * is a positional attribute such as `aria-rowindex` — which changes on the first
 * sort. A bare layout `<div>` has no attributes, no text and only `<div>`
 * ancestors, so it fingerprints identically to dozens of its siblings. Both bind
 * at capture time and orphan on the next render.
 *
 * Doing this in the loader keeps it off the host: no build step, no directive,
 * and nothing to remember when a new screen is added.
 *
 * Nothing is persisted. The attribute is recomputed on every load, so the value
 * has to be derived deterministically from the DOM: identity where the DOM
 * offers it, position only where it does not. An element carrying `id`,
 * `data-testid`, `row-id` or `col-id` contributes that value; everything else
 * contributes its tag plus its index among same-tag siblings. Grid rows survive
 * sorting for free, because AG Grid already emits `row-id` and `col-id`.
 */

export const SCENE_GLASS_ID_ATTRIBUTE = 'data-scg-id';

/** Attributes trusted to name an element. Read in order; the first hit wins. */
const IDENTITY_ATTRIBUTES = ['id', 'data-testid', 'row-id', 'col-id'] as const;

/** Bounds one pass so a large screen cannot stall the frame. */
const MAX_STAMPED_ELEMENTS = 6_000;

function identityOf(element: Element): string | undefined {
  for (const name of IDENTITY_ATTRIBUTES) {
    const value = element.getAttribute(name);
    if (value !== null && value !== '' && value.length <= 64) {
      return `${name}=${value}`;
    }
  }
  return undefined;
}

function indexAmongSameTag(element: Element): number {
  let index = 1;
  let sibling = element.previousElementSibling;
  while (sibling !== null) {
    if (sibling.localName === element.localName) index += 1;
    sibling = sibling.previousElementSibling;
  }
  return index;
}

/**
 * Elements this module labelled. Anything else carrying the attribute was put
 * there by the host and is left alone — a host that pins an id means it, and
 * overwriting it would silently break every selector and annotation built on it.
 */
const stampedBySceneGlass = new WeakSet<Element>();

/** Writes only on change: a redundant write is still a mutation to every observer. */
function setId(element: Element, id: string): boolean {
  const current = element.getAttribute(SCENE_GLASS_ID_ATTRIBUTE);
  if (current !== null && !stampedBySceneGlass.has(element)) {
    return false;
  }
  if (current !== id) {
    element.setAttribute(SCENE_GLASS_ID_ATTRIBUTE, id);
  }
  stampedBySceneGlass.add(element);
  return true;
}

/**
 * Stamps every element beneath `root`, deriving each path from its parent's so
 * the walk stays linear. Scene Glass' own UI is skipped — it is not annotatable
 * and must not collide with host ids.
 */
export function stampElementIds(root: Element, isOwned: (element: Element) => boolean): void {
  const paths = new WeakMap<Element, string>();
  paths.set(root, '');
  let stamped = 0;

  for (const element of root.querySelectorAll('*')) {
    if (stamped >= MAX_STAMPED_ELEMENTS) return;
    if (isOwned(element)) continue;
    const parent = element.parentElement;
    if (parent === null) continue;
    const parentPath = paths.get(parent);
    // A parent skipped by the bound or by ownership breaks the path; so does its
    // subtree, which would otherwise be named relative to the wrong ancestor.
    if (parentPath === undefined) continue;

    const identity = identityOf(element);
    const step =
      identity === undefined
        ? `${element.localName}${indexAmongSameTag(element)}`
        : `${element.localName}[${identity}]`;
    const path = `${parentPath}/${step}`;
    paths.set(element, path);
    if (setId(element, path)) {
      stamped += 1;
    }
  }
}
