export type SceneGlassStatusKind = 'idle' | 'working' | 'ready' | 'error';

export interface SceneGlassStatusInput {
  readonly kind: SceneGlassStatusKind;
  readonly code?: string;
}

export interface SceneGlassStatusSurface {
  readonly element: HTMLElement | null;
  set(status: SceneGlassStatusInput): void;
  destroy(): void;
}

const SAFE_CODE = /^SCG_[A-Z0-9_]{1,80}$/;

export function createSceneGlassStatus(document: Document | null): SceneGlassStatusSurface {
  if (document === null) {
    return unavailableStatusSurface();
  }

  const element = document.createElement('output');
  element.className = 'scg-ui-status';
  element.setAttribute('aria-live', 'polite');
  element.setAttribute('aria-atomic', 'true');
  element.setAttribute('role', 'status');

  let destroyed = false;

  const set = (status: SceneGlassStatusInput): void => {
    if (destroyed) {
      return;
    }

    const code = safeCode(status.code);
    const text = statusText(status.kind);
    element.textContent = code === null ? text : `${text} (${code})`;
    element.dataset.state = status.kind;
    if (status.kind === 'error') {
      element.setAttribute('role', 'alert');
    } else {
      element.setAttribute('role', 'status');
    }
  };

  set({ kind: 'idle' });

  return {
    element,
    set,
    destroy(): void {
      destroyed = true;
      element.textContent = '';
      element.removeAttribute('data-state');
      element.remove();
    },
  };
}

export function safeCode(value: string | undefined): string | null {
  return value !== undefined && SAFE_CODE.test(value) ? value : null;
}

function unavailableStatusSurface(): SceneGlassStatusSurface {
  return {
    element: null,
    set(): void {},
    destroy(): void {},
  };
}

function statusText(kind: SceneGlassStatusKind): string {
  switch (kind) {
    case 'idle':
      return 'Scene Glass 준비됨.';
    case 'working':
      return 'Scene Glass 처리 중…';
    case 'ready':
      return 'Scene Glass 작업 완료.';
    case 'error':
      return 'Scene Glass가 작업을 완료하지 못했습니다.';
  }
}
