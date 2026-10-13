import { describe, expect, it } from 'vitest';

import { readBoxMetrics } from '../../packages/browser-client/src/ui/size.js';

/** 계산된 스타일이 내주는 모양 그대로 — 값은 언제나 문자열이고 단위가 붙어 있다. */
const style = (values: Record<string, string>) => values;

const uniform = (padding: string, margin: string) =>
  style({
    paddingTop: padding,
    paddingRight: padding,
    paddingBottom: padding,
    paddingLeft: padding,
    marginTop: margin,
    marginRight: margin,
    marginBottom: margin,
    marginLeft: margin,
  });

describe('element box contract', () => {
  it('reports the border box as the size, matching the rectangle drawn on screen', () => {
    const metrics = readBoxMetrics({ width: 320, height: 48 }, uniform('8px', '16px'));
    expect(metrics.width).toBe(320);
    expect(metrics.height).toBe(48);
  });

  it('keeps each side separate instead of collapsing to a shorthand', () => {
    // 네 변이 다른 것이 흔한 경우다 — 한 값으로 접으면 어느 변인지 다시 재야 한다.
    const metrics = readBoxMetrics(
      { width: 100, height: 100 },
      style({
        paddingTop: '4px',
        paddingRight: '12px',
        paddingBottom: '8px',
        paddingLeft: '12px',
        marginTop: '0px',
        marginRight: '24px',
        marginBottom: '32px',
        marginLeft: '24px',
      }),
    );
    expect(metrics.padding).toEqual({ top: 4, right: 12, bottom: 8, left: 12 });
    expect(metrics.margin).toEqual({ top: 0, right: 24, bottom: 32, left: 24 });
  });

  it('keeps a negative margin as it is', () => {
    // 끌어올린 요소는 감출 것이 아니라 재려는 것이다.
    const metrics = readBoxMetrics({ width: 10, height: 10 }, uniform('0px', '-12px'));
    expect(metrics.margin.top).toBe(-12);
  });

  it('reads a length that carries no length as none', () => {
    // `auto` 마진과 빈 값에는 잴 길이가 없다. NaN 을 화면에 적을 수는 없다.
    const metrics = readBoxMetrics(
      { width: 10, height: 10 },
      style({ marginLeft: 'auto', marginRight: 'auto', paddingTop: '' }),
    );
    expect(metrics.margin.left).toBe(0);
    expect(metrics.margin.right).toBe(0);
    expect(metrics.padding.top).toBe(0);
    expect(metrics.padding.bottom).toBe(0);
  });

  it('keeps sub-pixel layout without reporting float noise', () => {
    // 거리 측정과 같은 자릿수로 자른다 — 두 도구의 숫자가 서로 대조되기 때문이다.
    const metrics = readBoxMetrics({ width: 320.44, height: 47.96 }, uniform('7.55px', '0px'));
    expect(metrics.width).toBe(320.4);
    expect(metrics.height).toBe(48);
    expect(metrics.padding.left).toBe(7.6);
  });
});
