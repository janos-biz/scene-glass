/**
 * Recognises a deliberate back-and-forth shake of the pointer.
 *
 * Reaching the panel to start selecting is not always possible: a modal traps
 * focus, so clicking Scene Glass' own button pulls focus out of the dialog and
 * the host closes it. A gesture never moves focus, so it stays available exactly
 * where clicking does not.
 *
 * The whole difficulty is telling a shake from ordinary movement. Three
 * conditions have to hold together, and each one alone is common:
 *
 * - the pointer reverses direction several times,
 * - each leg covers real distance, not jitter around one spot,
 * - and it all happens inside a short window.
 *
 * Sweeping across the screen fails the first, a slow wiggle fails the second,
 * and normal work fails the third.
 */

export interface ShakeDetectorOptions {
  /** Direction changes required. Each reversal is one back or one forth. */
  readonly reversals?: number;
  /** How long the whole gesture may take. */
  readonly windowMs?: number;
  /** Distance a leg must cover to count as intentional. */
  readonly minimumLegPx?: number;
}

export interface ShakeDetector {
  /** Feeds one pointer sample. Returns true once, on the sample that completes a shake. */
  push(x: number, y: number, at: number): boolean;
  reset(): void;
}

const DEFAULT_REVERSALS = 4;
const DEFAULT_WINDOW_MS = 700;
// 구간 길이가 곧 손목을 얼마나 크게 휘두르느냐다. 창이 그대로이므로 더 긴 구간은 더 빠르게
// 흔들라는 뜻이기도 하다 — 강도를 올리는 데는 이 값 하나면 되고, 반전 횟수는 정수라 잔돈을
// 담을 수 없으며 창을 좁히면 같은 요구가 두 번 걸린다.
const DEFAULT_MINIMUM_LEG_PX = 50;

export function createShakeDetector(options: ShakeDetectorOptions = {}): ShakeDetector {
  const reversalsNeeded = options.reversals ?? DEFAULT_REVERSALS;
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const minimumLegPx = options.minimumLegPx ?? DEFAULT_MINIMUM_LEG_PX;

  /** Sign of the current leg on the dominant axis; 0 until the first real move. */
  let direction = 0;
  /** Where the current leg began, so its length is measured end to end. */
  let legOriginX = 0;
  let legOriginY = 0;
  let lastX = 0;
  let lastY = 0;
  let started = false;
  /** Times of the reversals still inside the window. */
  let reversalTimes: number[] = [];

  const reset = (): void => {
    direction = 0;
    started = false;
    reversalTimes = [];
  };

  return {
    push(x: number, y: number, at: number): boolean {
      if (!started) {
        started = true;
        legOriginX = x;
        legOriginY = y;
        lastX = x;
        lastY = y;
        return false;
      }

      const stepX = x - lastX;
      const stepY = y - lastY;
      // 이번 표본이 어느 축으로 움직였는지로 방향을 본다. 가로로 흔들든 세로로 흔들든
      // 같은 동작이므로 축을 미리 고정하지 않는다.
      const horizontal = Math.abs(stepX) >= Math.abs(stepY);
      const step = horizontal ? stepX : stepY;
      if (step === 0) {
        return false;
      }
      const stepDirection = step > 0 ? 1 : -1;

      if (direction === 0) {
        direction = stepDirection;
        lastX = x;
        lastY = y;
        return false;
      }
      if (stepDirection === direction) {
        lastX = x;
        lastY = y;
        return false;
      }

      // 방향이 꺾였다. 꺾인 지점은 **직전 좌표**이므로, 방금 끝난 구간은 시작점에서 거기까지다.
      // 현재 좌표로 재면 이미 되돌아온 만큼이 상쇄되어 길이가 0 에 가깝게 나온다.
      const legX = lastX - legOriginX;
      const legY = lastY - legOriginY;
      const leg = Math.abs(legX) >= Math.abs(legY) ? legX : legY;
      legOriginX = lastX;
      legOriginY = lastY;
      direction = stepDirection;
      lastX = x;
      lastY = y;

      // 구간이 실제로 이동한 경우에만 센다 — 손이 마우스에 얹혀 떨리는 것을 걸러낸다.
      if (Math.abs(leg) < minimumLegPx) {
        return false;
      }

      reversalTimes = [...reversalTimes, at].filter((time) => at - time <= windowMs);
      if (reversalTimes.length < reversalsNeeded) {
        return false;
      }
      reset();
      return true;
    },
    reset,
  };
}
