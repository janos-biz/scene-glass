import { afterAll, describe, expect, it } from 'vitest';

import {
  classifyCanvasSubobject,
  classifySelectionTarget,
  createElementSelector,
  type ElementSelection,
  type SelectorCallbackError,
  type UnsupportedElementSelection,
} from '../../packages/browser-client/src/annotation/selector.js';

/**
 * 포인터 가드는 이벤트 대상을 `instanceof Element` 로 좁힌다. 이 환경에는 그 이름이 없어
 * 누름을 흉내 내는 순간 참조 오류가 난다. 최소한의 대역만 세워 그 좁히기가 평가되게 한다 —
 * 여기 가짜들은 평범한 객체라 그 대역의 인스턴스가 아니고, 그래서 호스트 요소로 취급된다.
 */
const globals = globalThis as { Element?: unknown };
const hadElementGlobal = 'Element' in globals;
globals.Element ??= class {};
afterAll(() => {
  if (!hadElementGlobal) {
    delete globals.Element;
  }
});

type ElementBehavior = {
  attributeCalls: number;
  rectCalls: number;
  rootCalls: number;
};

type FakeElement = {
  readonly behavior: ElementBehavior;
  readonly element: Element;
  readonly rect: DOMRectReadOnly;
};

type FakeDocument = {
  readonly document: Document;
  mount(element: Element): void;
};

type FakeClick = {
  readonly defaultPrevented: boolean;
  readonly propagationStopped: boolean;
};

type FakeSelectorDocument = FakeDocument & {
  setTarget(target: EventTarget | null): void;
  click(): FakeClick;
  /** 비활성 대상 위에서 브라우저가 실제로 보내는 것 — 누름과 뗌만 오고 클릭은 오지 않는다. */
  pointerDown(): FakeClick;
  pointerUp(): FakeClick;
  resourceCounts(): { readonly listeners: number; readonly overlays: number };
};

function createDocument(): FakeDocument {
  const mounted = new Set<Element>();
  const document = {
    documentElement: {
      contains(target: Node): boolean {
        return mounted.has(target as unknown as Element);
      },
    },
  } as unknown as Document;

  return {
    document,
    mount(element: Element): void {
      mounted.add(element);
    },
  };
}

function createSelectorDocument(): FakeSelectorDocument {
  const mounted = new Set<Element>();
  const documentListeners = new Map<string, Set<unknown>>();
  const viewListeners = new Map<string, Set<unknown>>();
  const clickListeners = new Set<(event: MouseEvent) => void>();
  const pointerListeners = new Map<string, Set<(event: PointerEvent) => void>>();
  const overlays = new Set<HTMLDivElement>();
  let target: EventTarget | null = null;
  const addListener = (
    listeners: Map<string, Set<unknown>>,
    type: string,
    listener: unknown,
  ): void => {
    if (typeof listener !== 'function') {
      return;
    }
    let listenersForType = listeners.get(type);
    if (listenersForType === undefined) {
      listenersForType = new Set<unknown>();
      listeners.set(type, listenersForType);
    }
    listenersForType.add(listener);
  };
  const removeListener = (
    listeners: Map<string, Set<unknown>>,
    type: string,
    listener: unknown,
  ): void => {
    const listenersForType = listeners.get(type);
    if (listenersForType === undefined) {
      return;
    }
    listenersForType.delete(listener);
    if (listenersForType.size === 0) {
      listeners.delete(type);
    }
  };
  const countListeners = (listeners: Map<string, Set<unknown>>): number => {
    let count = 0;
    for (const listenersForType of listeners.values()) {
      count += listenersForType.size;
    }
    return count;
  };
  const view = {
    addEventListener(type: string, listener: unknown): void {
      addListener(viewListeners, type, listener);
    },
    removeEventListener(type: string, listener: unknown): void {
      removeListener(viewListeners, type, listener);
    },
  } as unknown as Window;
  const document = {
    body: {
      append(overlay: HTMLDivElement): void {
        overlays.add(overlay);
      },
    },
    defaultView: view,
    documentElement: {
      contains(node: Node): boolean {
        return mounted.has(node as unknown as Element);
      },
    },
    createElement(): HTMLDivElement {
      const overlay = {
        remove(): void {
          overlays.delete(overlay as unknown as HTMLDivElement);
        },
        setAttribute(): void {},
        style: {},
      } as unknown as HTMLDivElement;
      return overlay;
    },
    elementFromPoint(): Element | null {
      return target as Element | null;
    },
    addEventListener(type: string, listener: unknown): void {
      addListener(documentListeners, type, listener);
      if (type === 'click' && typeof listener === 'function') {
        clickListeners.add(listener as (event: MouseEvent) => void);
      }
      if ((type === 'pointerdown' || type === 'pointerup') && typeof listener === 'function') {
        const listeners = pointerListeners.get(type) ?? new Set<(event: PointerEvent) => void>();
        listeners.add(listener as (event: PointerEvent) => void);
        pointerListeners.set(type, listeners);
      }
    },
    removeEventListener(type: string, listener: unknown): void {
      removeListener(documentListeners, type, listener);
      if (type === 'click' && typeof listener === 'function') {
        clickListeners.delete(listener as (event: MouseEvent) => void);
      }
      if ((type === 'pointerdown' || type === 'pointerup') && typeof listener === 'function') {
        pointerListeners.get(type)?.delete(listener as (event: PointerEvent) => void);
      }
    },
  } as unknown as Document;

  const dispatchPointer = (type: 'pointerdown' | 'pointerup'): FakeClick => {
    let defaultPrevented = false;
    let propagationStopped = false;
    const event = {
      type,
      target,
      clientX: 0,
      clientY: 0,
      preventDefault(): void {
        defaultPrevented = true;
      },
      stopPropagation(): void {
        propagationStopped = true;
      },
    } as unknown as PointerEvent;

    for (const listener of [...(pointerListeners.get(type) ?? [])]) {
      listener(event);
    }

    return { defaultPrevented, propagationStopped };
  };

  return {
    document,
    mount(element: Element): void {
      mounted.add(element);
    },
    setTarget(nextTarget: EventTarget | null): void {
      target = nextTarget;
    },
    click(): FakeClick {
      let defaultPrevented = false;
      let propagationStopped = false;
      const event = {
        clientX: 0,
        clientY: 0,
        preventDefault(): void {
          defaultPrevented = true;
        },
        stopPropagation(): void {
          propagationStopped = true;
        },
      } as unknown as MouseEvent;

      for (const listener of [...clickListeners]) {
        listener(event);
      }

      return { defaultPrevented, propagationStopped };
    },
    pointerDown(): FakeClick {
      return dispatchPointer('pointerdown');
    },
    pointerUp(): FakeClick {
      return dispatchPointer('pointerup');
    },
    resourceCounts(): { readonly listeners: number; readonly overlays: number } {
      return {
        listeners: countListeners(documentListeners) + countListeners(viewListeners),
        overlays: overlays.size,
      };
    },
  };
}

function createElement(ownerDocument: Document, root: Node): FakeElement {
  const behavior: ElementBehavior = {
    attributeCalls: 0,
    rectCalls: 0,
    rootCalls: 0,
  };
  const rect = {} as DOMRectReadOnly;
  const element = {
    nodeType: 1,
    ownerDocument,
    getAttribute(): null {
      behavior.attributeCalls += 1;
      return null;
    },
    getBoundingClientRect(): DOMRectReadOnly {
      behavior.rectCalls += 1;
      return rect;
    },
    getRootNode(): Node {
      behavior.rootCalls += 1;
      return root;
    },
  } as unknown as Element;

  return { behavior, element, rect };
}

/** 비활성 폼 컨트롤. `closest` 가 그 선택자에 걸리는 것으로 흉내 낸다. */
function createDisabledElement(ownerDocument: Document, root: Node): FakeElement {
  const fake = createElement(ownerDocument, root);
  Object.assign(fake.element, {
    closest(selector: string): Element | null {
      return selector.includes('[disabled]') && !selector.startsWith('fieldset')
        ? fake.element
        : null;
    },
  });
  return fake;
}

/**
 * 선택 모드가 켜져 있을 때 문서·뷰에 붙는 리스너 수.
 * pointermove·pointerdown·pointerup·click, 포인터 가드 5종(pointerdown·mousedown·mouseup·
 * touchstart·contextmenu), resize·scroll. 정확한 수 자체가 계약은 아니고, 떼어내면 0 이 되는
 * 것이 계약이다.
 */
const ACTIVE_LISTENER_COUNT = 11;

describe('selector boundaries contract', () => {
  it('exposes only a mounted direct iframe host without host behavior and keeps it selectable', () => {
    const hostDocument = createDocument();
    const iframeHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    hostDocument.mount(iframeHost.element);
    const iframeDocument = {
      defaultView: { frameElement: iframeHost.element },
    } as unknown as Document;
    const iframeChild = createElement(iframeDocument, iframeDocument as unknown as Node);

    const selection = classifySelectionTarget(iframeChild.element, hostDocument.document);

    expect(selection).toEqual({
      status: 'unsupported',
      reason: 'iframe-internal',
      host: iframeHost.element,
    });
    expect(Object.isFrozen(selection)).toBe(true);
    expect(iframeHost.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });
    expect(classifySelectionTarget(iframeHost.element, hostDocument.document)).toEqual({
      status: 'selected',
      element: iframeHost.element,
      rect: iframeHost.rect,
    });
  });
  it('does not expose a detached iframe host', () => {
    const hostDocument = createDocument();
    const iframeHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    const iframeDocument = {
      defaultView: { frameElement: iframeHost.element },
    } as unknown as Document;
    const iframeChild = createElement(iframeDocument, iframeDocument as unknown as Node);

    expect(classifySelectionTarget(iframeChild.element, hostDocument.document)).toEqual({
      status: 'unsupported',
      reason: 'unmounted',
    });
    expect(iframeHost.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });
  });

  it('does not expose a nested iframe host from a foreign document', () => {
    const hostDocument = createDocument();
    const outerIframeHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    hostDocument.mount(outerIframeHost.element);
    const outerIframeDocument = {
      defaultView: { frameElement: outerIframeHost.element },
    } as unknown as Document;
    const nestedIframeHost = createElement(
      outerIframeDocument,
      outerIframeDocument as unknown as Node,
    );
    const nestedIframeDocument = {
      defaultView: { frameElement: nestedIframeHost.element },
    } as unknown as Document;
    const nestedIframeChild = createElement(
      nestedIframeDocument,
      nestedIframeDocument as unknown as Node,
    );

    expect(classifySelectionTarget(nestedIframeChild.element, hostDocument.document)).toEqual({
      status: 'unsupported',
      reason: 'unmounted',
    });
    expect(nestedIframeHost.behavior).toEqual({
      attributeCalls: 0,
      rectCalls: 0,
      rootCalls: 0,
    });
  });

  it('returns a mounted shadow host without host behavior and keeps the host selectable', () => {
    const hostDocument = createDocument();
    const shadowHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    hostDocument.mount(shadowHost.element);
    const shadowRoot = { host: shadowHost.element } as unknown as Node;
    const shadowChild = createElement(hostDocument.document, shadowRoot);

    const selection = classifySelectionTarget(shadowChild.element, hostDocument.document);

    expect(selection).toEqual({
      status: 'unsupported',
      reason: 'shadow-child',
      host: shadowHost.element,
    });
    expect(Object.isFrozen(selection)).toBe(true);
    expect(shadowHost.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });
    expect(classifySelectionTarget(shadowHost.element, hostDocument.document)).toEqual({
      status: 'selected',
      element: shadowHost.element,
      rect: shadowHost.rect,
    });
  });
  it('does not expose a nested shadow host outside the light-DOM boundary', () => {
    const hostDocument = createDocument();
    const outerShadowHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    hostDocument.mount(outerShadowHost.element);
    const outerShadowRoot = { host: outerShadowHost.element } as unknown as Node;
    const nestedShadowHost = createElement(hostDocument.document, outerShadowRoot);
    const nestedShadowRoot = { host: nestedShadowHost.element } as unknown as Node;
    const nestedShadowChild = createElement(hostDocument.document, nestedShadowRoot);

    expect(classifySelectionTarget(nestedShadowChild.element, hostDocument.document)).toEqual({
      status: 'unsupported',
      reason: 'unmounted',
    });
    expect(nestedShadowHost.behavior).toEqual({
      attributeCalls: 0,
      rectCalls: 0,
      rootCalls: 0,
    });
  });
  it('does not expose an unmounted shadow host', () => {
    const hostDocument = createDocument();
    const shadowHost = createElement(
      hostDocument.document,
      hostDocument.document as unknown as Node,
    );
    const shadowRoot = { host: shadowHost.element } as unknown as Node;
    const shadowChild = createElement(hostDocument.document, shadowRoot);

    expect(classifySelectionTarget(shadowChild.element, hostDocument.document)).toEqual({
      status: 'unsupported',
      reason: 'unmounted',
    });
  });

  it('returns a canvas host without host behavior and keeps the canvas selectable', () => {
    const hostDocument = createDocument();
    const canvas = createElement(hostDocument.document, hostDocument.document as unknown as Node);
    hostDocument.mount(canvas.element);

    const selection = classifyCanvasSubobject(canvas.element as HTMLCanvasElement);

    expect(selection).toEqual({
      status: 'unsupported',
      reason: 'canvas-subobject',
      host: canvas.element,
    });
    expect(Object.isFrozen(selection)).toBe(true);
    expect(canvas.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });
    expect(classifySelectionTarget(canvas.element, hostDocument.document)).toEqual({
      status: 'selected',
      element: canvas.element,
      rect: canvas.rect,
    });
  });

  it('selects a disabled control on release, which is the only signal it sends', () => {
    // 비활성 폼 컨트롤 위에서 브라우저는 click 을 아예 만들지 않는다(Chromium·Firefox 확인).
    // 클릭만 기다리면 강조는 따라다니는데 확정만 되지 않아, 고를 수 없는 요소로 보인다.
    const selectorDocument = createSelectorDocument();
    const target = createDisabledElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(target.element);
    selectorDocument.setTarget(target.element);

    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelect(selection): void {
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });

    selector.start();
    selectorDocument.pointerDown();
    const release = selectorDocument.pointerUp();

    expect(selected).toEqual([target.element]);
    expect(release).toEqual({ defaultPrevented: true, propagationStopped: true });
    expect(selector.isReviewing).toBe(false);
  });

  it('leaves a target that still sends a click to the click path', () => {
    // 뗀 자리에서 미리 확정하면 뒤따라온 클릭이 가드가 걷힌 뒤 호스트에 닿는다 — 고르기만
    // 하려던 손짓이 그 버튼을 누르게 된다. 클릭이 올 대상은 예전 그대로 클릭을 기다린다.
    const selectorDocument = createSelectorDocument();
    const target = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(target.element);
    selectorDocument.setTarget(target.element);

    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelect(selection): void {
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });

    selector.start();
    selectorDocument.pointerDown();
    selectorDocument.pointerUp();

    expect(selected).toEqual([]);
    expect(selector.isReviewing).toBe(true);

    selectorDocument.click();
    expect(selected).toEqual([target.element]);
  });

  it('ignores a release that landed somewhere other than the press', () => {
    // click 의 약속을 그대로 지킨다 — 누른 요소와 뗀 요소가 같아야 고른 것이다.
    const selectorDocument = createSelectorDocument();
    const pressedTarget = createDisabledElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    const releasedTarget = createDisabledElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(pressedTarget.element);
    selectorDocument.mount(releasedTarget.element);

    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelect(selection): void {
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });

    selector.start();
    selectorDocument.setTarget(pressedTarget.element);
    selectorDocument.pointerDown();
    selectorDocument.setTarget(releasedTarget.element);
    selectorDocument.pointerUp();

    expect(selected).toEqual([]);
    expect(selector.isReviewing).toBe(true);
  });

  it('stops selection before the selected callback so rapid clicks are single-shot', () => {
    const selectorDocument = createSelectorDocument();
    const target = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(target.element);
    selectorDocument.setTarget(target.element);

    const callbackOrder: string[] = [];
    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelectionChange(selection): void {
        callbackOrder.push(selection?.status ?? 'cleared');
      },
      onSelect(selection): void {
        callbackOrder.push(`select:${selector.isReviewing ? 'reviewing' : 'stopped'}`);
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });

    selector.start();
    const firstClick = selectorDocument.click();
    const secondClick = selectorDocument.click();

    expect(firstClick).toEqual({ defaultPrevented: true, propagationStopped: true });
    expect(secondClick).toEqual({ defaultPrevented: false, propagationStopped: false });
    expect(selector.isReviewing).toBe(false);
    expect(selected).toEqual([target.element]);
    expect(callbackOrder).toEqual(['selected', 'cleared', 'select:stopped']);
  });
  it('abandons a selected click when publication restarts review', () => {
    const selectorDocument = createSelectorDocument();
    const target = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(target.element);
    selectorDocument.setTarget(target.element);

    let selectCalls = 0;
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelectionChange(selection): void {
        if (selection?.status === 'selected') {
          selector.stop();
          selector.start();
        }
      },
      onSelect(): void {
        selectCalls += 1;
      },
    });

    selector.start();
    expect(selectorDocument.click()).toEqual({
      defaultPrevented: false,
      propagationStopped: false,
    });
    expect(selectCalls).toBe(0);
    expect(selector.isReviewing).toBe(true);
    expect(selectorDocument.resourceCounts()).toEqual({
      listeners: ACTIVE_LISTENER_COUNT,
      overlays: 1,
    });
    selector.destroy();
  });

  it('abandons an unsupported click when publication destroys review', () => {
    const selectorDocument = createSelectorDocument();
    selectorDocument.setTarget({} as EventTarget);

    let unsupportedCalls = 0;
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelectionChange(selection): void {
        if (selection?.status === 'unsupported') {
          selector.destroy();
        }
      },
      onUnsupportedSelect(): void {
        unsupportedCalls += 1;
      },
    });

    selector.start();
    expect(selectorDocument.click()).toEqual({
      defaultPrevented: false,
      propagationStopped: false,
    });
    expect(unsupportedCalls).toBe(0);
    expect(selector.isReviewing).toBe(false);
    expect(selectorDocument.resourceCounts()).toEqual({ listeners: 0, overlays: 0 });
  });
  it('leaves Scene Glass overlay and diagnostic control clicks available to the controls', () => {
    const selectorDocument = createSelectorDocument();
    const controls = [
      createElement(selectorDocument.document, selectorDocument.document as unknown as Node),
      createElement(selectorDocument.document, selectorDocument.document as unknown as Node),
    ];
    for (const control of controls) {
      selectorDocument.mount(control.element);
      Object.assign(control.element, {
        closest(): Element {
          return control.element;
        },
      });
    }

    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelect(selection): void {
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });
    selector.start();

    for (const control of controls) {
      selectorDocument.setTarget(control.element);
      expect(selectorDocument.click()).toEqual({
        defaultPrevented: false,
        propagationStopped: false,
      });
    }

    expect(selected).toEqual([]);
    expect(selector.isReviewing).toBe(true);
    selector.destroy();
  });
  it('rejects restart from a destroy stop callback and removes every resource', () => {
    const selectorDocument = createSelectorDocument();
    let stopCallbackCalls = 0;
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelectionChange(selection): void {
        if (selection !== undefined) {
          return;
        }
        stopCallbackCalls += 1;
        selector.start();
        throw new Error('stop callback failed');
      },
    });

    selector.start();

    expect(selectorDocument.resourceCounts()).toEqual({
      listeners: ACTIVE_LISTENER_COUNT,
      overlays: 1,
    });
    expect(() => selector.stop()).not.toThrow();
    expect(stopCallbackCalls).toBe(1);
    expect(selector.isReviewing).toBe(true);
    expect(selectorDocument.resourceCounts()).toEqual({
      listeners: ACTIVE_LISTENER_COUNT,
      overlays: 1,
    });

    expect(() => selector.destroy()).not.toThrow();
    expect(stopCallbackCalls).toBe(2);
    expect(selector.isReviewing).toBe(false);
    expect(selectorDocument.resourceCounts()).toEqual({ listeners: 0, overlays: 0 });

    selector.destroy();

    expect(stopCallbackCalls).toBe(2);
    expect(selectorDocument.resourceCounts()).toEqual({ listeners: 0, overlays: 0 });
  });

  it('publishes exact unsupported click results without interfering with the host or review', () => {
    const selectorDocument = createSelectorDocument();
    const iframeHost = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(iframeHost.element);
    const iframeDocument = {
      defaultView: { frameElement: iframeHost.element },
    } as unknown as Document;
    const iframeChild = createElement(iframeDocument, iframeDocument as unknown as Node);

    const shadowHost = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    selectorDocument.mount(shadowHost.element);
    const shadowRoot = { host: shadowHost.element } as unknown as Node;
    const shadowChild = createElement(selectorDocument.document, shadowRoot);

    const unmounted = createElement(
      selectorDocument.document,
      selectorDocument.document as unknown as Node,
    );
    const selectionChanges: ElementSelection[] = [];
    const unsupportedSelections: UnsupportedElementSelection[] = [];
    const callbackReviewStates: boolean[] = [];
    const callbackOrder: string[] = [];
    const selected: Element[] = [];
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(): void {},
      onSelectionChange(selection): void {
        selectionChanges.push(selection);
        callbackOrder.push(
          `change:${selection?.status === 'unsupported' ? selection.reason : (selection?.status ?? 'cleared')}`,
        );
      },
      onUnsupportedSelect(selection): void {
        unsupportedSelections.push(selection);
        callbackOrder.push(`unsupported:${selection.reason}`);
        callbackReviewStates.push(selector.isReviewing);
      },
      onSelect(selection): void {
        if (selection?.status === 'selected') {
          selected.push(selection.element);
        }
      },
    });
    const expectedSelections = [
      { status: 'unsupported', reason: 'iframe-internal', host: iframeHost.element },
      { status: 'unsupported', reason: 'shadow-child', host: shadowHost.element },
      { status: 'unsupported', reason: 'not-element' },
      { status: 'unsupported', reason: 'unmounted' },
    ];

    selector.start();
    const unsupportedClicks = [
      iframeChild.element,
      shadowChild.element,
      {} as EventTarget,
      unmounted.element,
    ].map((target) => {
      selectorDocument.setTarget(target);
      return selectorDocument.click();
    });

    expect(unsupportedClicks).toEqual([
      { defaultPrevented: false, propagationStopped: false },
      { defaultPrevented: false, propagationStopped: false },
      { defaultPrevented: false, propagationStopped: false },
      { defaultPrevented: false, propagationStopped: false },
    ]);
    expect(selector.isReviewing).toBe(true);
    expect(selected).toEqual([]);
    expect(unsupportedSelections).toEqual(expectedSelections);
    expect(callbackReviewStates).toEqual([true, true, true, true]);
    expect(callbackOrder).toEqual([
      'change:iframe-internal',
      'unsupported:iframe-internal',
      'change:shadow-child',
      'unsupported:shadow-child',
      'change:not-element',
      'unsupported:not-element',
      'change:unmounted',
      'unsupported:unmounted',
    ]);
    for (const [index, selection] of unsupportedSelections.entries()) {
      expect(Object.isFrozen(selection)).toBe(true);
      expect(selectionChanges[index]).toBe(selection);
    }
    expect(iframeHost.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });
    expect(shadowHost.behavior).toEqual({ attributeCalls: 0, rectCalls: 0, rootCalls: 0 });

    selectorDocument.setTarget(iframeHost.element);
    const hostClick = selectorDocument.click();

    expect(hostClick).toEqual({ defaultPrevented: true, propagationStopped: true });
    expect(selected).toEqual([iframeHost.element]);
    expect(selector.isReviewing).toBe(false);
    expect(unsupportedSelections).toHaveLength(4);
  });

  it('reports every public callback failure while preserving host click behavior', () => {
    const reports: SelectorCallbackError[] = [];
    const onCallbackError = (callbackError: SelectorCallbackError): void => {
      reports.push(callbackError);
    };
    const selectionChangeError = new Error('selection-change callback failed');
    const unsupportedSelectError = new Error('unsupported-select callback failed');
    const selectError = new Error('select callback failed');

    const selectionChangeDocument = createSelectorDocument();
    selectionChangeDocument.setTarget({} as EventTarget);
    const selectionChangeSelector = createElementSelector({
      document: selectionChangeDocument.document,
      onCallbackError,
      onSelectionChange(): void {
        throw selectionChangeError;
      },
    });
    selectionChangeSelector.start();

    const unsupportedSelectDocument = createSelectorDocument();
    unsupportedSelectDocument.setTarget({} as EventTarget);
    const unsupportedSelectSelector = createElementSelector({
      document: unsupportedSelectDocument.document,
      onCallbackError,
      onUnsupportedSelect(): void {
        throw unsupportedSelectError;
      },
    });
    unsupportedSelectSelector.start();

    const selectDocument = createSelectorDocument();
    const selectedTarget = createElement(
      selectDocument.document,
      selectDocument.document as unknown as Node,
    );
    selectDocument.mount(selectedTarget.element);
    selectDocument.setTarget(selectedTarget.element);
    const selectSelector = createElementSelector({
      document: selectDocument.document,
      onCallbackError,
      onSelect(): void {
        throw selectError;
      },
    });
    selectSelector.start();

    expect(selectionChangeDocument.click()).toEqual({
      defaultPrevented: false,
      propagationStopped: false,
    });
    expect(unsupportedSelectDocument.click()).toEqual({
      defaultPrevented: false,
      propagationStopped: false,
    });
    expect(selectDocument.click()).toEqual({
      defaultPrevented: true,
      propagationStopped: true,
    });
    expect(selectionChangeSelector.isReviewing).toBe(true);
    expect(unsupportedSelectSelector.isReviewing).toBe(true);
    expect(selectSelector.isReviewing).toBe(false);
    expect(reports).toEqual([
      { phase: 'selection-change', error: selectionChangeError },
      { phase: 'unsupported-select', error: unsupportedSelectError },
      { phase: 'select', error: selectError },
    ]);
    expect(reports[0]?.error).toBe(selectionChangeError);
    expect(reports[1]?.error).toBe(unsupportedSelectError);
    expect(reports[2]?.error).toBe(selectError);
    expect(reports.every((callbackError) => Object.isFrozen(callbackError))).toBe(true);
  });

  it('queues callback errors from reporter-triggered cleanup without recursion', () => {
    const selectorDocument = createSelectorDocument();
    selectorDocument.setTarget({} as EventTarget);
    const reports: SelectorCallbackError[] = [];
    const publishError = new Error('selection-change callback failed');
    const cleanupError = new Error('cleanup callback failed');
    const reporterError = new Error('error reporter failed');
    let reporterDepth = 0;
    let maximumReporterDepth = 0;
    const selector = createElementSelector({
      document: selectorDocument.document,
      onCallbackError(callbackError): void {
        reports.push(callbackError);
        reporterDepth += 1;
        maximumReporterDepth = Math.max(maximumReporterDepth, reporterDepth);
        try {
          if (callbackError.error === publishError) {
            selector.stop();
          }
        } finally {
          reporterDepth -= 1;
        }
        throw reporterError;
      },
      onSelectionChange(selection): void {
        throw selection === undefined ? cleanupError : publishError;
      },
    });
    selector.start();

    let click: FakeClick | undefined;
    expect(() => {
      click = selectorDocument.click();
    }).not.toThrow();

    expect(click).toEqual({ defaultPrevented: false, propagationStopped: false });
    expect(selector.isReviewing).toBe(false);
    expect(selectorDocument.resourceCounts()).toEqual({ listeners: 0, overlays: 0 });
    expect(maximumReporterDepth).toBe(1);
    expect(reports).toEqual([
      { phase: 'selection-change', error: publishError },
      { phase: 'selection-change', error: cleanupError },
    ]);
  });
});
