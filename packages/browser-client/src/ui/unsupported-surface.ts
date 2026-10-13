import { safeCode } from './status.js';

export type SceneGlassUnavailableReason = 'unavailable' | 'unauthorized' | 'unsupported';

export interface UnsupportedSurfaceState {
  readonly reason: SceneGlassUnavailableReason;
  readonly code?: string;
}

export interface UnsupportedSurfaceOptions {
  readonly container?: HTMLElement;
  readonly document?: Document;
}

export interface UnsupportedSurface {
  open(): void;
  show(state: UnsupportedSurfaceState): void;
  hide(): void;
  destroy(): void;
}

export function createUnsupportedSurface(
  options: UnsupportedSurfaceOptions = {},
): UnsupportedSurface {
  const document = resolveDocument(options);
  if (document === null) {
    return unavailableSurface();
  }
  let container: HTMLElement | null = options.container ?? null;

  const element = document.createElement('section');
  element.className = 'scg-ui-unavailable';
  element.setAttribute('aria-live', 'polite');
  element.setAttribute('role', 'status');
  element.hidden = true;

  const title = document.createElement('strong');
  title.className = 'scg-ui-unavailable-title';
  title.textContent = 'Scene Glass를 사용할 수 없습니다.';

  const message = document.createElement('span');
  message.className = 'scg-ui-unavailable-message';

  element.append(title, message);

  let destroyed = false;
  let opened = false;
  let openRequested = false;
  let mountFallback: ReturnType<typeof setTimeout> | undefined;

  const show = (state: UnsupportedSurfaceState): void => {
    if (destroyed) {
      return;
    }

    const code = safeCode(state.code);
    message.textContent = unavailableMessage(state.reason, code);
    element.dataset.reason = state.reason;
    element.hidden = false;
  };
  const mount = (): boolean => {
    const host = resolveMountContainer(document, container);
    if (destroyed || opened || host === null) {
      return false;
    }
    host.append(element);
    opened = true;
    stopMountRetries();
    return true;
  };

  /** See the overlay: `DOMContentLoaded` still reports `interactive`, so the mount
   * container stays unresolved and a `once` retry is spent for nothing. */
  const stopMountRetries = (): void => {
    document.removeEventListener('DOMContentLoaded', onDocumentReady);
    document.removeEventListener('readystatechange', onDocumentReady);
    document.defaultView?.removeEventListener('load', onDocumentReady);
    if (mountFallback !== undefined) {
      clearTimeout(mountFallback);
      mountFallback = undefined;
    }
  };

  const onDocumentReady = (): void => {
    if (openRequested) {
      mount();
    }
  };

  return {
    open(): void {
      if (destroyed || opened) {
        return;
      }
      openRequested = true;
      if (!mount()) {
        document.addEventListener('DOMContentLoaded', onDocumentReady, { once: true });
        document.addEventListener('readystatechange', onDocumentReady);
        document.defaultView?.addEventListener('load', onDocumentReady, { once: true });
        if (document.readyState === 'interactive' && mountFallback === undefined) {
          mountFallback = setTimeout(onDocumentReady, 50);
        }
      }
    },
    show,
    hide(): void {
      if (!destroyed) {
        element.hidden = true;
      }
    },
    destroy(): void {
      if (!destroyed) {
        destroyed = true;
        container = null;
        openRequested = false;
        stopMountRetries();
        message.textContent = '';
        element.replaceChildren();
        element.remove();
      }
    },
  };
}

function resolveMountContainer(
  document: Document,
  container: HTMLElement | null,
): HTMLElement | null {
  if (container !== null) {
    return container;
  }

  const view = document.defaultView;
  const roots =
    view === null
      ? []
      : [...document.querySelectorAll('[data-scg-root]')].filter(
          (element): element is HTMLElement => element instanceof view.HTMLElement,
        );
  const [root] = roots;
  if (root !== undefined && roots.length === 1) {
    return root;
  }
  if (roots.length > 1 || document.readyState === 'complete') {
    return document.body;
  }
  return null;
}
function resolveDocument(options: UnsupportedSurfaceOptions): Document | null {
  if (options.document !== undefined) {
    return options.document;
  }
  if (options.container !== undefined) {
    return options.container.ownerDocument;
  }
  return typeof globalThis.document === 'undefined' ? null : globalThis.document;
}

function unavailableMessage(reason: SceneGlassUnavailableReason, code: string | null): string {
  const base =
    reason === 'unsupported'
      ? '이 브라우저 화면은 지원되지 않습니다. 호스트 페이지는 계속 사용할 수 있습니다.'
      : reason === 'unauthorized'
        ? '이 페이지는 Scene Glass 사용 권한이 없습니다. 호스트 페이지는 계속 사용할 수 있습니다.'
        : '로컬 서비스에 연결할 수 없습니다. 호스트 페이지는 계속 사용할 수 있습니다.';
  return code === null ? base : `${base} (${code})`;
}

function unavailableSurface(): UnsupportedSurface {
  return {
    open(): void {},
    show(): void {},
    hide(): void {},
    destroy(): void {},
  };
}
