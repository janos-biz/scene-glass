/**
 * Draws the gap between two elements, the way a design tool does.
 *
 * The useful number when checking a layout is the **edge gap**, not the distance
 * between centres: "these two are 24px apart" means the space between them, and
 * that is what a spacing token has to match. So each axis reports the clear space
 * between the facing edges, and reports nothing when the boxes overlap on that
 * axis — an overlap has no gap to state.
 *
 * Both axes are drawn when the boxes miss each other diagonally, because neither
 * number alone describes that arrangement.
 */

export interface MeasuredInset {
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
  readonly left: number;
}

export interface MeasuredGap {
  /** Clear space between facing vertical edges, or undefined when they overlap. */
  readonly horizontal?: number;
  /** Clear space between facing horizontal edges, or undefined when they overlap. */
  readonly vertical?: number;
  /**
   * Distance from each edge of the inner box to the matching edge of the outer
   * one, when one box contains the other. Nesting is the common case — a control
   * inside its card — and there the useful number is the padding on each side,
   * not "these overlap".
   */
  readonly inset?: MeasuredInset;
}

/** The containing box and the contained one, when one encloses the other. */
export function containment(
  base: MeasurementRect,
  target: MeasurementRect,
): { readonly outer: MeasurementRect; readonly inner: MeasurementRect } | undefined {
  const contains = (outer: MeasurementRect, inner: MeasurementRect): boolean =>
    outer.left <= inner.left &&
    outer.top <= inner.top &&
    outer.right >= inner.right &&
    outer.bottom >= inner.bottom;
  if (contains(base, target)) return { outer: base, inner: target };
  if (contains(target, base)) return { outer: target, inner: base };
  return undefined;
}

export interface MeasurementRect {
  readonly left: number;
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
}

export interface MeasurementSurface {
  show(base: MeasurementRect, target: MeasurementRect): void;
  hide(): void;
  destroy(): void;
}

/** Rounds to a tenth: sub-pixel layout is real, but 12 decimals are noise. */
function round(value: number): number {
  return Math.round(value * 10) / 10;
}

export function measureGap(base: MeasurementRect, target: MeasurementRect): MeasuredGap {
  const horizontal =
    target.left >= base.right
      ? target.left - base.right
      : base.left >= target.right
        ? base.left - target.right
        : undefined;
  const vertical =
    target.top >= base.bottom
      ? target.top - base.bottom
      : base.top >= target.bottom
        ? base.top - target.bottom
        : undefined;

  const nested =
    horizontal === undefined && vertical === undefined ? containment(base, target) : undefined;

  return Object.freeze({
    ...(horizontal === undefined ? {} : { horizontal: round(horizontal) }),
    ...(vertical === undefined ? {} : { vertical: round(vertical) }),
    ...(nested === undefined
      ? {}
      : {
          inset: Object.freeze({
            top: round(nested.inner.top - nested.outer.top),
            right: round(nested.outer.right - nested.inner.right),
            bottom: round(nested.outer.bottom - nested.inner.bottom),
            left: round(nested.inner.left - nested.outer.left),
          }),
        }),
  });
}

/** The segment that spans a horizontal gap, drawn at the shared vertical band. */
function horizontalSegment(
  base: MeasurementRect,
  target: MeasurementRect,
): { readonly from: number; readonly to: number; readonly at: number } {
  const [left, right] =
    target.left >= base.right ? [base.right, target.left] : [target.right, base.left];
  // Sit the line where the two boxes actually face each other; fall back to the
  // midpoint between them when they share no vertical band.
  const overlapTop = Math.max(base.top, target.top);
  const overlapBottom = Math.min(base.bottom, target.bottom);
  const at =
    overlapBottom > overlapTop
      ? (overlapTop + overlapBottom) / 2
      : (Math.min(base.bottom, target.bottom) + Math.max(base.top, target.top)) / 2;
  return { from: left, to: right, at };
}

function verticalSegment(
  base: MeasurementRect,
  target: MeasurementRect,
): { readonly from: number; readonly to: number; readonly at: number } {
  const [top, bottom] =
    target.top >= base.bottom ? [base.bottom, target.top] : [target.bottom, base.top];
  const overlapLeft = Math.max(base.left, target.left);
  const overlapRight = Math.min(base.right, target.right);
  const at =
    overlapRight > overlapLeft
      ? (overlapLeft + overlapRight) / 2
      : (Math.min(base.right, target.right) + Math.max(base.left, target.left)) / 2;
  return { from: top, to: bottom, at };
}

export function createMeasurementSurface(document: Document): MeasurementSurface {
  const layer = document.createElement('div');
  layer.className = 'scg-measure-layer';
  layer.hidden = true;

  const baseOutline = document.createElement('div');
  baseOutline.className = 'scg-measure-outline scg-measure-outline--base';
  const targetOutline = document.createElement('div');
  targetOutline.className = 'scg-measure-outline scg-measure-outline--target';

  const horizontalLine = document.createElement('div');
  horizontalLine.className = 'scg-measure-line scg-measure-line--horizontal';
  const horizontalLabel = document.createElement('span');
  horizontalLabel.className = 'scg-measure-label';

  const verticalLine = document.createElement('div');
  verticalLine.className = 'scg-measure-line scg-measure-line--vertical';
  const verticalLabel = document.createElement('span');
  verticalLabel.className = 'scg-measure-label';

  /** 네 변 여백용 선과 라벨. 포함 관계일 때만 쓴다. */
  const insetSides = ['top', 'right', 'bottom', 'left'] as const;
  const insetParts = insetSides.map((side) => {
    const line = document.createElement('div');
    line.className = `scg-measure-line scg-measure-line--${side === 'left' || side === 'right' ? 'horizontal' : 'vertical'}`;
    const label = document.createElement('span');
    label.className = 'scg-measure-label';
    return { side, line, label };
  });

  layer.append(
    baseOutline,
    targetOutline,
    horizontalLine,
    horizontalLabel,
    verticalLine,
    verticalLabel,
    ...insetParts.flatMap(({ line, label }) => [line, label]),
  );

  let mounted = false;
  let destroyed = false;

  const place = (element: HTMLElement, rect: MeasurementRect): void => {
    element.style.left = `${rect.left}px`;
    element.style.top = `${rect.top}px`;
    element.style.width = `${Math.max(0, rect.right - rect.left)}px`;
    element.style.height = `${Math.max(0, rect.bottom - rect.top)}px`;
  };

  return {
    show(base: MeasurementRect, target: MeasurementRect): void {
      if (destroyed) return;
      if (!mounted) {
        const parent = document.body ?? document.documentElement;
        if (parent === null) return;
        parent.append(layer);
        mounted = true;
      }

      place(baseOutline, base);
      place(targetOutline, target);

      const gap = measureGap(base, target);

      // 포함 관계면 네 변 여백만 그린다 — 축 간격은 정의되지 않는다.
      const nested = gap.inset === undefined ? undefined : containment(base, target);
      for (const { side, line, label } of insetParts) {
        const show = nested !== undefined && gap.inset !== undefined;
        line.hidden = !show;
        label.hidden = !show;
        if (!show || nested === undefined || gap.inset === undefined) continue;
        const { outer, inner } = nested;
        const midX = (inner.left + inner.right) / 2;
        const midY = (inner.top + inner.bottom) / 2;
        const value = gap.inset[side];
        label.textContent = `${value}px`;
        if (side === 'top' || side === 'bottom') {
          const from = side === 'top' ? outer.top : inner.bottom;
          line.style.left = `${midX}px`;
          line.style.top = `${from}px`;
          line.style.height = `${value}px`;
          line.style.width = '';
          label.style.left = `${midX}px`;
          label.style.top = `${from + value / 2}px`;
        } else {
          const from = side === 'left' ? outer.left : inner.right;
          line.style.left = `${from}px`;
          line.style.top = `${midY}px`;
          line.style.width = `${value}px`;
          line.style.height = '';
          label.style.left = `${from + value / 2}px`;
          label.style.top = `${midY}px`;
        }
      }

      const showHorizontal = gap.horizontal !== undefined;
      horizontalLine.hidden = !showHorizontal;
      horizontalLabel.hidden = !showHorizontal;
      if (showHorizontal) {
        const segment = horizontalSegment(base, target);
        horizontalLine.style.left = `${segment.from}px`;
        horizontalLine.style.top = `${segment.at}px`;
        horizontalLine.style.width = `${segment.to - segment.from}px`;
        horizontalLabel.textContent = `${gap.horizontal}px`;
        horizontalLabel.style.left = `${(segment.from + segment.to) / 2}px`;
        horizontalLabel.style.top = `${segment.at}px`;
      }

      const showVertical = gap.vertical !== undefined;
      verticalLine.hidden = !showVertical;
      verticalLabel.hidden = !showVertical;
      if (showVertical) {
        const segment = verticalSegment(base, target);
        verticalLine.style.left = `${segment.at}px`;
        verticalLine.style.top = `${segment.from}px`;
        verticalLine.style.height = `${segment.to - segment.from}px`;
        verticalLabel.textContent = `${gap.vertical}px`;
        verticalLabel.style.left = `${segment.at}px`;
        verticalLabel.style.top = `${(segment.from + segment.to) / 2}px`;
      }

      // Boxes that touch or overlap on both axes have no gap to state; keep the
      // outlines so the pair is still visible, and say so instead of drawing
      // nothing at all.
      if (!showHorizontal && !showVertical && gap.inset === undefined) {
        horizontalLabel.hidden = false;
        horizontalLabel.textContent = '겹침';
        horizontalLabel.style.left = `${(Math.max(base.left, target.left) + Math.min(base.right, target.right)) / 2}px`;
        horizontalLabel.style.top = `${(Math.max(base.top, target.top) + Math.min(base.bottom, target.bottom)) / 2}px`;
      }

      layer.hidden = false;
    },
    hide(): void {
      layer.hidden = true;
    },
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      layer.remove();
      mounted = false;
    },
  };
}
