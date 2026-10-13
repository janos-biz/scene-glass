import { describe, expect, it } from 'vitest';

import { measureGap } from '../../packages/browser-client/src/ui/measure.js';

/** 기준 상자. 다른 상자를 이 주위에 놓아 각 배치를 만든다. */
const base = { left: 100, top: 100, right: 200, bottom: 200 } as const;

const rect = (left: number, top: number, right: number, bottom: number) =>
  ({ left, top, right, bottom }) as const;

describe('measured gap contract', () => {
  it('reports the clear space between facing edges, not centre to centre', () => {
    // 오른쪽으로 24 떨어진 상자. 중심 간 거리(124)가 아니라 가장자리 사이(24)여야 한다 —
    // 간격 토큰과 대조할 수 있는 값이 그쪽이다.
    expect(measureGap(base, rect(224, 100, 324, 200))).toEqual({ horizontal: 24 });
    expect(measureGap(base, rect(100, 224, 200, 324))).toEqual({ vertical: 24 });
  });

  it('measures the same gap whichever side the other box is on', () => {
    expect(measureGap(base, rect(40, 100, 60, 200))).toEqual({ horizontal: 40 });
    expect(measureGap(base, rect(100, 40, 200, 60))).toEqual({ vertical: 40 });
  });

  it('states no gap on an axis the boxes overlap', () => {
    // 세로로 겹치므로 가로 간격만 남는다. 겹친 축에 0 을 적으면 "붙어 있다" 로 읽혀 오해된다.
    expect(measureGap(base, rect(300, 150, 400, 250))).toEqual({ horizontal: 100 });
    // 양축이 겹치되 어느 쪽도 상대를 품지 않으면 말할 간격이 없다.
    expect(measureGap(base, rect(150, 150, 250, 250))).toEqual({});
  });

  it('reports four insets when one box sits inside the other', () => {
    // 자식은 부모 안에 있으니 언제나 양축이 겹친다. 거기서 필요한 값은 "겹친다" 가 아니라
    // 네 변까지의 여백이다 — 안쪽 여백이 곧 확인하려는 간격이다.
    expect(measureGap(base, rect(120, 130, 180, 190))).toEqual({
      inset: { top: 30, right: 20, bottom: 10, left: 20 },
    });
    // 어느 쪽을 기준으로 잡든 여백은 바깥에서 안쪽까지의 거리다.
    expect(measureGap(rect(120, 130, 180, 190), base)).toEqual({
      inset: { top: 30, right: 20, bottom: 10, left: 20 },
    });
  });

  it('treats an exactly coincident box as a zero inset, not as nothing', () => {
    expect(measureGap(base, { ...base })).toEqual({
      inset: { top: 0, right: 0, bottom: 0, left: 0 },
    });
  });

  it('reports both axes when the boxes miss each other diagonally', () => {
    // 어느 한 숫자만으로는 이 배치를 설명할 수 없다.
    expect(measureGap(base, rect(260, 280, 360, 380))).toEqual({ horizontal: 60, vertical: 80 });
  });

  it('treats touching edges as a zero gap, not as an overlap', () => {
    expect(measureGap(base, rect(200, 100, 300, 200))).toEqual({ horizontal: 0 });
    expect(measureGap(base, rect(100, 200, 200, 300))).toEqual({ vertical: 0 });
  });

  it('keeps sub-pixel layout without reporting float noise', () => {
    // 서브픽셀은 실재하므로 버리지 않되, 소수 열두 자리는 읽는 사람에게 잡음이다.
    expect(measureGap(base, rect(224.44, 100, 324, 200))).toEqual({ horizontal: 24.4 });
    expect(measureGap(base, rect(224.06, 100, 324, 200))).toEqual({ horizontal: 24.1 });
  });

  it('is symmetric: swapping the boxes does not change the gap', () => {
    const other = rect(260, 280, 360, 380);
    expect(measureGap(other, base)).toEqual(measureGap(base, other));
  });
});
