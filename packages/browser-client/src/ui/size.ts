/**
 * Reports one element's own box: how big it is, and the space it holds inside
 * (padding) and claims outside (margin).
 *
 * The gap tool answers "how far apart are these two"; this one answers "what is
 * this one". Both start from the same click, so the two read as one habit — pick
 * an element, get a number you can compare against a token.
 *
 * Size is the border box, the same rectangle every other surface here outlines,
 * so the number on screen always describes the box being drawn. Padding and
 * margin are not visible in that rectangle, and printing four more numbers next
 * to it would bury the size, so they live behind one badge at the corner: click
 * it and the two boxes are drawn where they actually sit — margin outside the
 * outline, padding inside it.
 */

export interface BoxSides {
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
  readonly left: number;
}

export interface ElementBoxMetrics {
  /** Border-box width and height — the outlined rectangle itself. */
  readonly width: number;
  readonly height: number;
  readonly padding: BoxSides;
  readonly margin: BoxSides;
}

/** The computed values this reads. Named as a type so tests can stand one up. */
export interface BoxStyleValues {
  readonly paddingTop: string;
  readonly paddingRight: string;
  readonly paddingBottom: string;
  readonly paddingLeft: string;
  readonly marginTop: string;
  readonly marginRight: string;
  readonly marginBottom: string;
  readonly marginLeft: string;
}

export interface SizeInspectorSurface {
  /** Tracks this element until told otherwise, redrawing as the page moves. */
  show(element: Element): void;
  /** Closes the padding/margin card only. True when there was one to close. */
  collapse(): boolean;
  hide(): void;
  destroy(): void;
}

/** Rounds to a tenth: sub-pixel layout is real, but 12 decimals are noise. */
function round(value: number): number {
  return Math.round(value * 10) / 10;
}

/**
 * `auto` margins and empty strings resolve to no length. Negative margins are
 * kept as they are — a pulled-up element is exactly what someone measuring a
 * layout is looking for.
 */
function parseLength(value: string | undefined): number {
  const parsed = Number.parseFloat(value ?? '');
  return Number.isFinite(parsed) ? round(parsed) : 0;
}

export function readBoxMetrics(
  size: { readonly width: number; readonly height: number },
  style: Partial<BoxStyleValues>,
): ElementBoxMetrics {
  return Object.freeze({
    width: round(size.width),
    height: round(size.height),
    padding: Object.freeze({
      top: parseLength(style.paddingTop),
      right: parseLength(style.paddingRight),
      bottom: parseLength(style.paddingBottom),
      left: parseLength(style.paddingLeft),
    }),
    margin: Object.freeze({
      top: parseLength(style.marginTop),
      right: parseLength(style.marginRight),
      bottom: parseLength(style.marginBottom),
      left: parseLength(style.marginLeft),
    }),
  });
}

/** Reads the live box of a mounted element. Falls back to bare size when the
 *  view cannot compute style (a detached document, a stubbed environment). */
export function measureElementBox(element: Element, view: Window | null): ElementBoxMetrics {
  const rect = element.getBoundingClientRect();
  const style =
    view === null || typeof view.getComputedStyle !== 'function'
      ? {}
      : (view.getComputedStyle(element) as unknown as Partial<BoxStyleValues>);
  return readBoxMetrics(rect, style);
}

/** 한 변씩 이름을 붙여 읽는다 — `8 12 8 12` 는 어느 쪽이 위인지 외워야 읽힌다. */
const SIDE_LABELS: readonly { readonly side: keyof BoxSides; readonly text: string }[] = [
  { side: 'top', text: '상' },
  { side: 'right', text: '우' },
  { side: 'bottom', text: '하' },
  { side: 'left', text: '좌' },
];

const BADGE_SIZE = 22;
/** 여백 카드는 뱃지 아래에 붙는다. 화면 가장자리에서는 이만큼 띄워 접는다. */
const VIEWPORT_MARGIN = 8;

export function createSizeInspectorSurface(document: Document): SizeInspectorSurface {
  const view = document.defaultView;

  const layer = document.createElement('div');
  layer.className = 'scg-size-layer';
  layer.hidden = true;

  const outline = document.createElement('div');
  outline.className = 'scg-size-outline';

  // 마진은 테두리 바깥, 패딩은 안쪽에 그린다. 숫자만 적어 두면 어느 변이 어느 값인지
  // 눈으로 맞춰 봐야 하지만, 자리에 칠해 두면 그 대조가 필요 없다.
  const marginBox = document.createElement('div');
  marginBox.className = 'scg-size-box scg-size-box--margin';
  const paddingBox = document.createElement('div');
  paddingBox.className = 'scg-size-box scg-size-box--padding';

  const sizeLabel = document.createElement('span');
  sizeLabel.className = 'scg-size-label';

  const badge = document.createElement('button');
  badge.className = 'scg-size-badge';
  badge.type = 'button';
  badge.setAttribute('aria-label', '패딩과 마진 보기');
  badge.setAttribute('aria-expanded', 'false');
  badge.append(createBadgeIcon(document));

  const popover = document.createElement('div');
  popover.className = 'scg-size-popover';
  popover.hidden = true;
  popover.setAttribute('role', 'group');
  popover.setAttribute('aria-label', '선택한 요소의 패딩과 마진');

  const rows = ['크기(px)', '패딩(px)', '마진(px)'].map((text) => {
    const row = document.createElement('div');
    row.className = 'scg-size-row';
    const label = document.createElement('span');
    label.className = 'scg-size-row-label';
    label.textContent = text;
    const value = document.createElement('span');
    value.className = 'scg-size-row-value';
    row.append(label, value);
    popover.append(row);
    return value;
  });
  const [sizeValue, paddingValue, marginValue] = rows;

  layer.append(marginBox, paddingBox, outline, sizeLabel, badge, popover);

  let target: Element | null = null;
  let expanded = false;
  let mounted = false;
  let destroyed = false;
  let frame: number | null = null;

  const place = (element: HTMLElement, box: DOMRect | Rect): void => {
    element.style.left = `${box.left}px`;
    element.style.top = `${box.top}px`;
    element.style.width = `${Math.max(0, box.width)}px`;
    element.style.height = `${Math.max(0, box.height)}px`;
  };

  const fillSides = (value: HTMLElement | undefined, sides: BoxSides): void => {
    if (value === undefined) {
      return;
    }
    value.replaceChildren(
      ...SIDE_LABELS.map(({ side, text }) => {
        const cell = document.createElement('span');
        cell.className = 'scg-size-side';
        const name = document.createElement('span');
        name.className = 'scg-size-side-name';
        name.textContent = text;
        cell.append(name, String(sides[side]));
        return cell;
      }),
    );
  };

  const render = (): void => {
    frame = null;
    if (destroyed || target === null) {
      return;
    }
    const documentElement = document.documentElement;
    const rect = target.getBoundingClientRect();
    if (
      documentElement === null ||
      !documentElement.contains(target) ||
      (rect.width === 0 && rect.height === 0)
    ) {
      layer.hidden = true;
      return;
    }

    const metrics = measureElementBox(target, view);
    place(outline, rect);
    sizeLabel.textContent = `${metrics.width} × ${metrics.height}`;

    // 위쪽에 자리가 없으면 상자 안으로 들인다 — 화면 밖으로 밀려 잘리는 것보다 낫다.
    const above = rect.top >= 22;
    sizeLabel.classList.toggle('scg-size-label--inside', !above);
    sizeLabel.style.left = `${rect.left}px`;
    sizeLabel.style.top = `${above ? rect.top - 4 : rect.top + 4}px`;

    const innerWidth = view?.innerWidth ?? rect.right + BADGE_SIZE;
    const innerHeight = view?.innerHeight ?? rect.bottom + BADGE_SIZE;
    const badgeLeft = clamp(
      rect.right - BADGE_SIZE / 2,
      VIEWPORT_MARGIN,
      innerWidth - BADGE_SIZE - VIEWPORT_MARGIN,
    );
    const badgeTop = clamp(
      rect.bottom - BADGE_SIZE / 2,
      VIEWPORT_MARGIN,
      innerHeight - BADGE_SIZE - VIEWPORT_MARGIN,
    );
    badge.style.left = `${badgeLeft}px`;
    badge.style.top = `${badgeTop}px`;

    marginBox.hidden = !expanded;
    paddingBox.hidden = !expanded;
    popover.hidden = !expanded;
    if (expanded) {
      const { padding, margin } = metrics;
      place(marginBox, {
        left: rect.left - margin.left,
        top: rect.top - margin.top,
        width: rect.width + margin.left + margin.right,
        height: rect.height + margin.top + margin.bottom,
      });
      place(paddingBox, {
        left: rect.left + padding.left,
        top: rect.top + padding.top,
        width: rect.width - padding.left - padding.right,
        height: rect.height - padding.top - padding.bottom,
      });
      if (sizeValue !== undefined) {
        sizeValue.textContent = `${metrics.width} × ${metrics.height}`;
      }
      fillSides(paddingValue, padding);
      fillSides(marginValue, margin);
      // 카드를 보이게 한 뒤에 잰다 — 숨어 있는 동안의 크기는 0 이라 자리를 잡을 수 없다.
      popover.style.left = `${clamp(badgeLeft, VIEWPORT_MARGIN, innerWidth - popover.offsetWidth - VIEWPORT_MARGIN)}px`;
      popover.style.top = `${clamp(badgeTop + BADGE_SIZE + 6, VIEWPORT_MARGIN, innerHeight - popover.offsetHeight - VIEWPORT_MARGIN)}px`;
    }

    layer.hidden = false;
  };

  const schedule = (): void => {
    if (destroyed || target === null || frame !== null) {
      return;
    }
    frame = view?.requestAnimationFrame(render) ?? (setTimeout(render, 0) as unknown as number);
  };
  const onViewportChange = (): void => schedule();
  view?.addEventListener('scroll', onViewportChange, true);
  view?.addEventListener('resize', onViewportChange);

  const setExpanded = (next: boolean): void => {
    expanded = next;
    badge.setAttribute('aria-expanded', String(next));
    badge.classList.toggle('scg-size-badge--open', next);
    badge.setAttribute('aria-label', next ? '패딩과 마진 닫기' : '패딩과 마진 보기');
  };
  const onBadgeClick = (event: MouseEvent): void => {
    // 측정 중에는 선택기가 클릭을 지켜본다. 여기서 끊지 않으면 뱃지를 누른 것이 곧 페이지를
    // 누른 것이 되어, 카드를 열자마자 다른 요소가 골라진다.
    event.preventDefault();
    event.stopPropagation();
    setExpanded(!expanded);
    render();
  };
  badge.addEventListener('click', onBadgeClick);

  return {
    show(element: Element): void {
      if (destroyed) {
        return;
      }
      if (!mounted) {
        const parent = document.body ?? document.documentElement;
        if (parent === null) {
          return;
        }
        parent.append(layer);
        mounted = true;
      }
      // 대상이 바뀌면 카드는 닫는다 — 앞 요소의 여백이 새 요소의 것처럼 남으면 안 된다.
      if (element !== target) {
        setExpanded(false);
      }
      target = element;
      render();
    },
    collapse(): boolean {
      if (!expanded) {
        return false;
      }
      setExpanded(false);
      render();
      return true;
    },
    hide(): void {
      target = null;
      setExpanded(false);
      layer.hidden = true;
    },
    destroy(): void {
      if (destroyed) {
        return;
      }
      destroyed = true;
      target = null;
      badge.removeEventListener('click', onBadgeClick);
      view?.removeEventListener('scroll', onViewportChange, true);
      view?.removeEventListener('resize', onViewportChange);
      if (frame !== null) {
        if (view === null) {
          clearTimeout(frame);
        } else {
          view.cancelAnimationFrame(frame);
        }
        frame = null;
      }
      layer.remove();
      mounted = false;
    },
  };
}

interface Rect {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(Math.max(value, low), Math.max(low, high));
}

/** 바깥 점선은 마진, 안쪽 면은 패딩 — 뱃지가 무엇을 여는지 그림 하나로 말한다. */
function createBadgeIcon(document: Document): SVGSVGElement {
  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('viewBox', '0 0 16 16');
  icon.setAttribute('fill', 'none');
  icon.setAttribute('stroke', 'currentColor');
  icon.setAttribute('stroke-width', '1.4');
  const outer = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  outer.setAttribute('x', '1.5');
  outer.setAttribute('y', '1.5');
  outer.setAttribute('width', '13');
  outer.setAttribute('height', '13');
  outer.setAttribute('rx', '2');
  outer.setAttribute('stroke-dasharray', '3 2');
  const inner = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  inner.setAttribute('x', '5');
  inner.setAttribute('y', '5');
  inner.setAttribute('width', '6');
  inner.setAttribute('height', '6');
  inner.setAttribute('rx', '1');
  icon.append(outer, inner);
  return icon;
}
