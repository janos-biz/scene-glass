export type UnsupportedSelectionReason =
  'canvas-subobject' | 'iframe-internal' | 'not-element' | 'shadow-child' | 'unmounted';

export interface SelectedElement {
  readonly status: 'selected';
  readonly element: Element;
  readonly rect: DOMRectReadOnly;
}

export interface UnsupportedElementSelection {
  readonly status: 'unsupported';
  readonly reason: UnsupportedSelectionReason;
  readonly host?: Element;
}

export type ElementSelection = SelectedElement | UnsupportedElementSelection | undefined;

export type SelectorCallbackPhase = 'selection-change' | 'select' | 'unsupported-select';

export interface SelectorCallbackError {
  readonly phase: SelectorCallbackPhase;
  readonly error: unknown;
}

export interface ElementSelectorOptions {
  readonly document?: Document;
  readonly onCallbackError: (callbackError: SelectorCallbackError) => void;
  readonly onSelectionChange?: (selection: ElementSelection) => void;
  readonly onSelect?: (selection: ElementSelection) => void;
  readonly onUnsupportedSelect?: (selection: UnsupportedElementSelection) => void;
}

export interface ElementSelector {
  readonly isReviewing: boolean;
  start(): void;
  stop(): void;
  destroy(): void;
}

export const SCENE_GLASS_OWNED_ATTRIBUTE = 'data-scg-owned';
export const SCENE_GLASS_SELECTOR_OVERLAY_ATTRIBUTE = 'data-scg-selector-overlay';

/**
 * 겹쳐 그리는 층도 우리 것이다. 여기에 넣지 않으면 그 안에서 일어난 DOM 변화를 호스트의
 * 변화로 세어 페이지를 다시 읽고, 모퉁이 뱃지를 누른 것이 "페이지를 눌렀다" 로 읽힌다.
 */
const SCENE_GLASS_OWNED_ROOT_SELECTOR =
  '.scg-ui-overlay, .scg-ui-styles, .scg-diag-panel, .scg-diag-styles, .scg-measure-layer, .scg-size-layer';

/**
 * Classifies only mounted elements in the host document's light DOM. Elements
 * inside an iframe or shadow root are intentionally not selectable; only a
 * mounted direct light-DOM boundary host is returned.
 */
export function classifySelectionTarget(
  target: EventTarget | null,
  document: Document,
): ElementSelection {
  if (!isElement(target)) {
    return Object.freeze({ status: 'unsupported', reason: 'not-element' });
  }

  if (target.ownerDocument !== document) {
    return unsupportedIframeTarget(target, document);
  }

  if (isSceneGlassOwnedElement(target)) {
    return undefined;
  }

  const documentElement = document.documentElement;
  const root = target.getRootNode();
  if (root !== document) {
    const shadowHost = shadowHostFor(root);
    if (shadowHost !== undefined) {
      if (documentElement === null || !documentElement.contains(shadowHost)) {
        return Object.freeze({ status: 'unsupported', reason: 'unmounted' });
      }
      return Object.freeze({
        status: 'unsupported',
        reason: 'shadow-child',
        host: shadowHost,
      });
    }
    return Object.freeze({ status: 'unsupported', reason: 'unmounted' });
  }

  if (documentElement === null || !documentElement.contains(target)) {
    return Object.freeze({ status: 'unsupported', reason: 'unmounted' });
  }

  return Object.freeze({
    status: 'selected',
    element: target,
    rect: target.getBoundingClientRect(),
  });
}

/**
 * Reports an object drawn inside a canvas without rejecting the canvas element
 * itself. Browser pointer events target the canvas, so this is exposed for
 * integrations that also receive a renderer-level subobject target.
 */
export function classifyCanvasSubobject(canvas: HTMLCanvasElement): ElementSelection {
  return Object.freeze({
    status: 'unsupported',
    reason: 'canvas-subobject',
    host: canvas,
  });
}

/**
 * Mounts a pointer-transparent light-DOM outline only while explicit review
 * mode is active. The capture-phase click handler prevents host interaction
 * only for a successful review selection.
 */
/** `click` 보다 먼저 도착해 호스트를 움직이는 단계들. 선택 모드에서는 전부 막는다. */
const POINTER_GUARD_EVENTS = [
  'pointerdown',
  'mousedown',
  'mouseup',
  'touchstart',
  'contextmenu',
] as const;

/** 스스로 비활성인 폼 컨트롤. `fieldset` 은 자손까지 함께 비활성으로 만든다. */
const DISABLED_CONTROL_SELECTOR =
  'button[disabled], input[disabled], select[disabled], textarea[disabled], optgroup[disabled], option[disabled]';

/**
 * 눌러도 `click` 이 오지 않는 대상인지.
 *
 * 비활성 폼 컨트롤 위에서 브라우저는 `mousedown`·`mouseup`·`click` 을 아예 발생시키지 않는다.
 * 포인터 이벤트는 그대로 오므로 강조는 요소를 따라다니는데 확정만 되지 않았다 — 비활성 요소는
 * 재려고 해도 고를 수 없는 것처럼 보였던 이유다. 그런 대상만 `pointerup` 에서 확정한다.
 *
 * 비활성 `fieldset` 의 첫 `legend` 안은 예외로 남는다. 명세가 그 안을 여전히 조작 가능한 것으로
 * 두고, 실제로 `click` 이 그대로 온다 — 여기서 미리 확정해 버리면 뒤따라온 클릭이 가드가 걷힌
 * 뒤에 호스트에 닿아, 고르기만 하려던 손짓이 그 버튼을 누르게 된다.
 */
export function suppressesClick(element: Element): boolean {
  if (typeof element.closest !== 'function') {
    return false;
  }
  if (element.closest(DISABLED_CONTROL_SELECTOR) !== null) {
    return true;
  }
  const fieldset = element.closest('fieldset[disabled]');
  if (fieldset === null) {
    return false;
  }
  const legend =
    typeof fieldset.querySelector === 'function' ? fieldset.querySelector(':scope > legend') : null;
  return legend === null || typeof legend.contains !== 'function' || !legend.contains(element);
}

export function createElementSelector(options: ElementSelectorOptions): ElementSelector {
  const document = options.document ?? currentDocument();
  let isReviewing = false;
  let isDestroyed = false;
  let reviewGeneration = 0;
  let overlay: HTMLDivElement | undefined;
  let current: ElementSelection;
  /** 눌린 채로 있는 요소. 비활성 대상을 뗄 때 확정할지 판단하는 데만 쓴다. */
  let pressed: Element | null = null;
  const pendingCallbackErrors: SelectorCallbackError[] = [];
  let isReportingCallbackErrors = false;

  const reportCallbackError = (phase: SelectorCallbackPhase, error: unknown): void => {
    pendingCallbackErrors.push(Object.freeze({ phase, error }));
    if (isReportingCallbackErrors) {
      return;
    }

    isReportingCallbackErrors = true;
    try {
      for (let index = 0; index < pendingCallbackErrors.length; index += 1) {
        const callbackError = pendingCallbackErrors[index];
        if (callbackError === undefined) {
          continue;
        }
        try {
          options.onCallbackError(callbackError);
        } catch {
          // The reporter is terminal: never route its failure back through itself.
        }
      }
    } finally {
      pendingCallbackErrors.length = 0;
      isReportingCallbackErrors = false;
    }
  };

  const invokeCallback = <Value>(
    phase: SelectorCallbackPhase,
    callback: ((value: Value) => void) | undefined,
    value: Value,
  ): void => {
    if (callback === undefined) {
      return;
    }
    try {
      callback(value);
    } catch (error) {
      reportCallbackError(phase, error);
    }
  };

  const publish = (selection: ElementSelection): void => {
    current = selection;
    renderOverlay(overlay, selection);
    invokeCallback<ElementSelection>('selection-change', options.onSelectionChange, selection);
  };

  const selectAt = (x: number, y: number): ElementSelection => {
    if (document === undefined) {
      return undefined;
    }
    return classifySelectionTarget(document.elementFromPoint(x, y), document);
  };

  const onPointerMove = (event: PointerEvent): void => {
    publish(selectAt(event.clientX, event.clientY));
  };

  /**
   * 선택 모드에서는 `click` 앞에 오는 포인터 단계를 통째로 막는다.
   *
   * 막지 않으면 호스트가 먼저 반응한다 — selectbox 는 `pointerdown`/`mousedown` 에서 열리므로
   * 드롭다운이 펼쳐지며 DOM 이 바뀌고, 뒤늦게 도착한 `click` 이 그 자리에서 좌표를 다시 읽어
   * 엉뚱한 요소(대개 `html`)를 집는다. 선택 자체는 예전대로 `click` 에서 확정한다 —
   * `preventDefault` 는 기본 동작만 없앨 뿐 `click` 발생을 막지 않는다.
   *
   * Scene Glass 자신의 UI 는 통과시킨다. 막으면 패널 버튼이 눌리지 않는다.
   */
  const onPointerGuard = (event: Event): void => {
    if (!isReviewing) {
      return;
    }
    const target = event.target;
    if (target instanceof Element && isSceneGlassOwnedElement(target)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
  };

  const confirm = (selection: SelectedElement, event: Event): void => {
    event.preventDefault();
    event.stopPropagation();
    stop();
    invokeCallback<ElementSelection>('select', options.onSelect, selection);
  };

  const onClick = (event: MouseEvent): void => {
    const generation = reviewGeneration;
    const selection = selectAt(event.clientX, event.clientY);
    publish(selection);
    if (!isReviewing || reviewGeneration !== generation) {
      return;
    }
    if (selection?.status === 'unsupported') {
      invokeCallback<UnsupportedElementSelection>(
        'unsupported-select',
        options.onUnsupportedSelect,
        selection,
      );
      return;
    }
    if (selection?.status !== 'selected') {
      return;
    }

    confirm(selection, event);
  };

  /** 누른 자리를 기억해 둔다. 확정은 뗀 자리가 같은 요소일 때만 한다 — `click` 의 약속이다. */
  const onPointerDown = (event: PointerEvent): void => {
    const selection = isReviewing ? selectAt(event.clientX, event.clientY) : undefined;
    pressed = selection?.status === 'selected' ? selection.element : null;
  };

  /**
   * `click` 이 오지 않을 대상만 여기서 확정한다. 나머지는 예전 그대로 `click` 을 기다린다 —
   * 뗀 자리에서 미리 확정하면 뒤따라온 클릭이 호스트에 닿는다.
   */
  const onPointerUp = (event: PointerEvent): void => {
    const pressedElement = pressed;
    pressed = null;
    const generation = reviewGeneration;
    if (!isReviewing || pressedElement === null) {
      return;
    }
    const selection = selectAt(event.clientX, event.clientY);
    if (
      selection?.status !== 'selected' ||
      selection.element !== pressedElement ||
      !suppressesClick(selection.element)
    ) {
      return;
    }
    publish(selection);
    if (!isReviewing || reviewGeneration !== generation) {
      return;
    }
    confirm(selection, event);
  };

  const onViewportChange = (): void => {
    renderOverlay(overlay, current);
  };

  const detach = (): void => {
    if (document === undefined) {
      return;
    }
    document.removeEventListener('pointermove', onPointerMove);
    document.removeEventListener('pointerdown', onPointerDown, true);
    document.removeEventListener('pointerup', onPointerUp, true);
    document.removeEventListener('click', onClick, true);
    for (const name of POINTER_GUARD_EVENTS) {
      document.removeEventListener(name, onPointerGuard, true);
    }
    const view = document.defaultView;
    view?.removeEventListener('resize', onViewportChange);
    view?.removeEventListener('scroll', onViewportChange, true);
  };

  const stop = (): void => {
    if (!isReviewing) {
      return;
    }
    isReviewing = false;
    reviewGeneration += 1;
    pressed = null;
    detach();
    overlay?.remove();
    overlay = undefined;
    current = undefined;
    invokeCallback<ElementSelection>('selection-change', options.onSelectionChange, undefined);
  };

  return {
    get isReviewing(): boolean {
      return isReviewing;
    },
    start(): void {
      if (isDestroyed || isReviewing || document === undefined) {
        return;
      }
      const parent = document.body ?? document.documentElement;
      if (parent === null) {
        return;
      }
      overlay = createOverlay(document);
      parent.append(overlay);
      reviewGeneration += 1;
      isReviewing = true;
      document.addEventListener('pointermove', onPointerMove, { passive: true });
      document.addEventListener('pointerdown', onPointerDown, true);
      document.addEventListener('pointerup', onPointerUp, true);
      document.addEventListener('click', onClick, true);
      for (const name of POINTER_GUARD_EVENTS) {
        document.addEventListener(name, onPointerGuard, true);
      }
      const view = document.defaultView;
      view?.addEventListener('resize', onViewportChange);
      view?.addEventListener('scroll', onViewportChange, true);
    },
    stop,
    destroy(): void {
      if (isDestroyed) {
        return;
      }
      isDestroyed = true;
      stop();
    },
  };
}

function currentDocument(): Document | undefined {
  return typeof globalThis.document === 'undefined' ? undefined : globalThis.document;
}

function unsupportedIframeTarget(target: Element, document: Document): UnsupportedElementSelection {
  const frameElement = target.ownerDocument.defaultView?.frameElement;
  if (
    !isElement(frameElement) ||
    frameElement.ownerDocument !== document ||
    document.documentElement === null ||
    !document.documentElement.contains(frameElement)
  ) {
    return Object.freeze({ status: 'unsupported', reason: 'unmounted' });
  }
  return Object.freeze({
    status: 'unsupported',
    reason: 'iframe-internal',
    host: frameElement,
  });
}

function shadowHostFor(root: Node): Element | undefined {
  const host = (root as Node & { readonly host?: unknown }).host;
  return isElement(host) ? host : undefined;
}

function isElement(value: unknown): value is Element {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { readonly nodeType?: unknown }).nodeType === 1 &&
    typeof (value as { readonly getAttribute?: unknown }).getAttribute === 'function'
  );
}

export function isSceneGlassOwnedElement(element: Element): boolean {
  if (
    element.getAttribute(SCENE_GLASS_OWNED_ATTRIBUTE) === 'true' ||
    element.getAttribute(SCENE_GLASS_SELECTOR_OVERLAY_ATTRIBUTE) === 'true'
  ) {
    return true;
  }
  return (
    typeof element.closest === 'function' &&
    element.closest(SCENE_GLASS_OWNED_ROOT_SELECTOR) !== null
  );
}

function createOverlay(document: Document): HTMLDivElement {
  const overlay = document.createElement('div');
  overlay.setAttribute(SCENE_GLASS_OWNED_ATTRIBUTE, 'true');
  overlay.setAttribute(SCENE_GLASS_SELECTOR_OVERLAY_ATTRIBUTE, 'true');
  overlay.setAttribute('aria-hidden', 'true');
  Object.assign(overlay.style, {
    display: 'none',
    position: 'fixed',
    pointerEvents: 'none',
    zIndex: '2147483647',
    boxSizing: 'border-box',
    border: '2px solid #4f8cff',
    background: 'rgba(79, 140, 255, 0.12)',
  });
  return overlay;
}

function renderOverlay(overlay: HTMLDivElement | undefined, selection: ElementSelection): void {
  if (overlay === undefined || selection?.status !== 'selected') {
    if (overlay !== undefined) {
      overlay.style.display = 'none';
    }
    return;
  }

  const rect = selection.element.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) {
    overlay.style.display = 'none';
    return;
  }
  overlay.style.display = 'block';
  overlay.style.left = `${rect.left}px`;
  overlay.style.top = `${rect.top}px`;
  overlay.style.width = `${rect.width}px`;
  overlay.style.height = `${rect.height}px`;
}
