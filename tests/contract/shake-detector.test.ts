import { describe, expect, it } from 'vitest';

import { createShakeDetector } from '../../packages/browser-client/src/ui/shake.js';

/** Feeds a path and reports whether any sample completed a shake. */
function feed(
  points: readonly (readonly [number, number, number])[],
  options?: Parameters<typeof createShakeDetector>[0],
): boolean {
  const detector = createShakeDetector(options);
  return points.reduce<boolean>(
    (fired, [x, y, at]) => (detector.push(x, y, at) ? true : fired),
    false,
  );
}

/** A shake: `legs` reversals of `distance`, `stepMs` apart, along one axis. */
function shakePath(
  legs: number,
  distance: number,
  stepMs: number,
  axis: 'x' | 'y' = 'x',
): (readonly [number, number, number])[] {
  const points: (readonly [number, number, number])[] = [];
  let position = 0;
  let at = 0;
  points.push([0, 0, 0]);
  for (let leg = 0; leg < legs + 1; leg += 1) {
    position += leg % 2 === 0 ? distance : -distance;
    at += stepMs;
    points.push(axis === 'x' ? [position, 0, at] : [0, position, at]);
  }
  return points;
}

describe('shake detector contract', () => {
  it('recognises a deliberate back-and-forth shake', () => {
    expect(feed(shakePath(5, 80, 60))).toBe(true);
    // 세로로 흔드는 것도 같은 동작이다.
    expect(feed(shakePath(5, 80, 60, 'y'))).toBe(true);
  });

  it('ignores moving across the screen, however far', () => {
    // 방향 전환이 없다 — 화면을 가로지르는 평범한 이동이다.
    const straight = Array.from({ length: 20 }, (_, i) => [i * 60, 0, i * 20] as const);
    expect(feed(straight)).toBe(false);
  });

  it('ignores a small wiggle around one spot', () => {
    // 방향은 계속 바뀌지만 거리가 없다 — 손이 마우스에 얹혀 있는 상태다.
    expect(feed(shakePath(10, 6, 40))).toBe(false);
  });

  it('ignores a half-hearted shake that never swings far enough', () => {
    // 흔들 뜻은 있지만 손목만 까딱한 크기다 — 켜려면 팔을 실제로 휘둘러야 한다.
    expect(feed(shakePath(5, 45, 60))).toBe(false);
    expect(feed(shakePath(5, 60, 60))).toBe(true);
  });

  it('ignores reversals spread out over time', () => {
    // 같은 횟수를 흔들어도 느리면 의도한 동작이 아니다.
    expect(feed(shakePath(5, 80, 400))).toBe(false);
  });

  it('fires once, not repeatedly, for one gesture', () => {
    const detector = createShakeDetector();
    const fired = shakePath(9, 80, 50).filter(([x, y, at]) => detector.push(x, y, at));
    expect(fired).toHaveLength(1);
  });

  it('needs a fresh gesture after firing', () => {
    const detector = createShakeDetector();
    for (const [x, y, at] of shakePath(5, 80, 60)) detector.push(x, y, at);
    // 방금 발동했으므로 한 번 더 꺾는 것만으로는 다시 발동하지 않는다.
    expect(detector.push(200, 0, 500)).toBe(false);
    expect(detector.push(0, 0, 540)).toBe(false);
  });

  it('honours a stricter threshold', () => {
    expect(feed(shakePath(5, 80, 60), { reversals: 8 })).toBe(false);
    expect(feed(shakePath(5, 80, 60), { minimumLegPx: 200 })).toBe(false);
  });
});
