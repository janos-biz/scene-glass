import {
  DIAGNOSTIC_STEP_NAMES,
  type DiagnosticStepSnapshot,
  type DiagnosticsController,
  type DiagnosticsSnapshot,
} from './controller.js';

export interface DiagnosticsPanelOptions {
  readonly controller: DiagnosticsController;
  readonly container?: HTMLElement;
  readonly document?: Document;
}

export interface DiagnosticsPanel {
  open(): void;
  destroy(): void;
}

type StepElement = {
  readonly row: HTMLLIElement;
  readonly state: HTMLOutputElement;
  readonly duration: HTMLElement;
};

export function createDiagnosticsPanel(options: DiagnosticsPanelOptions): DiagnosticsPanel {
  const document = resolveDocument(options);
  if (document === null) {
    return unavailablePanel();
  }
  let container: HTMLElement | null = options.container ?? null;
  let controller: DiagnosticsController | null = options.controller;

  const style = document.createElement('style');
  style.className = 'scg-diag-styles';
  style.textContent = PANEL_STYLES;

  const element = document.createElement('aside');
  element.className = 'scg-diag-panel';
  element.setAttribute('aria-label', 'Scene Glass 진단');

  const heading = document.createElement('h2');
  heading.className = 'scg-diag-heading';
  heading.textContent = 'Scene Glass 진단';

  const description = document.createElement('p');
  description.className = 'scg-diag-description';
  description.textContent = '민감한 값을 표시하지 않고 짧은 진단을 실행합니다.';

  const runButton = document.createElement('button');
  runButton.className = 'scg-diag-run';
  runButton.type = 'button';
  runButton.textContent = '진단 실행';

  const runState = document.createElement('output');
  runState.className = 'scg-diag-run-state';
  runState.setAttribute('aria-live', 'polite');
  runState.setAttribute('aria-atomic', 'true');
  runState.setAttribute('role', 'status');

  const stepsList = document.createElement('ol');
  stepsList.className = 'scg-diag-steps';
  const stepElements = {} as Record<(typeof DIAGNOSTIC_STEP_NAMES)[number], StepElement>;
  for (const step of DIAGNOSTIC_STEP_NAMES) {
    const row = createStep(document, stepLabel(step));
    stepElements[step] = row;
    stepsList.append(row.row);
  }

  const cleanupHeading = document.createElement('h3');
  cleanupHeading.className = 'scg-diag-cleanup-heading';
  cleanupHeading.textContent = '정리';
  const cleanup = createStep(document, 'DELETE 종료');
  cleanup.row.classList.add('scg-diag-cleanup');
  const cleanupList = document.createElement('ul');
  cleanupList.className = 'scg-diag-cleanup-list';
  cleanupList.append(cleanup.row);

  const error = document.createElement('section');
  error.className = 'scg-diag-error';
  error.setAttribute('role', 'alert');
  error.hidden = true;

  const errorCode = document.createElement('strong');
  errorCode.className = 'scg-diag-error-code';
  const errorMessage = document.createElement('p');
  errorMessage.className = 'scg-diag-error-message';
  const remediation = document.createElement('p');
  remediation.className = 'scg-diag-remediation';
  error.append(errorCode, errorMessage, remediation);

  element.append(
    heading,
    description,
    runButton,
    runState,
    stepsList,
    cleanupHeading,
    cleanupList,
    error,
  );

  let destroyed = false;
  let opened = false;
  let openRequested = false;
  let mountFallback: ReturnType<typeof setTimeout> | undefined;
  let unsubscribe: (() => void) | null = null;

  const render = (snapshot: DiagnosticsSnapshot): void => {
    if (destroyed) {
      return;
    }
    runState.textContent = `${runStateLabel(snapshot.state)} ${formatDuration(snapshot.durationMs)}`;
    runState.dataset.state = snapshot.state;
    runButton.disabled = snapshot.state !== 'idle';

    for (const step of DIAGNOSTIC_STEP_NAMES) {
      renderStep(stepElements[step], snapshot.steps[step]);
    }
    renderStep(cleanup, snapshot.cleanup);

    if (snapshot.failure === null) {
      error.hidden = true;
      errorCode.textContent = '';
      errorMessage.textContent = '';
      remediation.textContent = '';
      return;
    }

    error.hidden = false;
    errorCode.textContent = snapshot.failure.code;
    errorMessage.textContent = snapshot.failure.message;
    remediation.textContent = snapshot.failure.remediation;
  };

  const onRun = (): void => {
    const activeController = controller;
    if (activeController === null) {
      return;
    }
    void activeController.run().catch(() => {
      // The controller already reports stable failures; the host must remain usable.
    });
  };

  runButton.addEventListener('click', onRun);
  const mount = (): boolean => {
    const host = resolveMountContainer(document, container);
    const activeController = controller;
    if (destroyed || opened || host === null || activeController === null) {
      return false;
    }
    host.append(style, element);
    unsubscribe = activeController.subscribe(render);
    opened = true;
    document.removeEventListener('DOMContentLoaded', onDocumentReady);
    if (mountFallback !== undefined) {
      clearTimeout(mountFallback);
      mountFallback = undefined;
    }
    return true;
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
      const activeController = controller;
      if (activeController === null) {
        return;
      }
      activeController.open();
      openRequested = true;
      if (!mount()) {
        document.addEventListener('DOMContentLoaded', onDocumentReady, { once: true });
        if (document.readyState === 'interactive' && mountFallback === undefined) {
          mountFallback = setTimeout(onDocumentReady, 50);
        }
      }
    },
    destroy(): void {
      if (destroyed) {
        return;
      }
      destroyed = true;
      runButton.removeEventListener('click', onRun);
      unsubscribe?.();
      unsubscribe = null;
      controller = null;
      container = null;
      openRequested = false;
      document.removeEventListener('DOMContentLoaded', onDocumentReady);
      if (mountFallback !== undefined) {
        clearTimeout(mountFallback);
        mountFallback = undefined;
      }
      errorCode.textContent = '';
      errorMessage.textContent = '';
      remediation.textContent = '';
      runState.textContent = '';
      element.replaceChildren();
      style.textContent = '';
      style.remove();
      element.remove();
    },
  };
}

function createStep(document: Document, label: string): StepElement {
  const row = document.createElement('li');
  row.className = 'scg-diag-step';

  const title = document.createElement('span');
  title.className = 'scg-diag-step-label';
  title.textContent = label;

  const state = document.createElement('output');
  state.className = 'scg-diag-step-state';
  state.setAttribute('aria-live', 'polite');

  const duration = document.createElement('span');
  duration.className = 'scg-diag-step-duration';

  row.append(title, state, duration);
  return { row, state, duration };
}

function renderStep(element: StepElement, snapshot: DiagnosticStepSnapshot): void {
  element.row.dataset.state = snapshot.state;
  element.state.textContent = stepStateLabel(snapshot.state);
  element.duration.textContent = formatDuration(snapshot.durationMs);
}

function stepLabel(step: (typeof DIAGNOSTIC_STEP_NAMES)[number]): string {
  switch (step) {
    case 'test-token':
      return '토큰 테스트';
    case 'connection':
      return '연결';
    case 'authentication':
      return '인증';
    case 'round-trip':
      return '왕복 통신';
  }
}

function stepStateLabel(state: DiagnosticStepSnapshot['state']): string {
  switch (state) {
    case 'idle':
      return '시작되지 않음';
    case 'running':
      return '실행 중';
    case 'passed':
      return '통과';
    case 'failed':
      return '실패';
    case 'cleaned':
      return '정리됨';
  }
}

function runStateLabel(state: DiagnosticsSnapshot['state']): string {
  switch (state) {
    case 'idle':
      return '시작되지 않음.';
    case 'running':
      return '실행 중.';
    case 'passed':
      return '검사를 통과했습니다. 정리 중입니다.';
    case 'failed':
      return '진단에 실패했습니다.';
    case 'cleaned':
      return '진단 정리가 완료되었습니다.';
  }
}

function formatDuration(durationMs: number): string {
  return `${Math.max(0, Math.round(durationMs))}밀리초`;
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
function resolveDocument(options: DiagnosticsPanelOptions): Document | null {
  if (options.document !== undefined) {
    return options.document;
  }
  if (options.container !== undefined) {
    return options.container.ownerDocument;
  }
  return typeof globalThis.document === 'undefined' ? null : globalThis.document;
}

function unavailablePanel(): DiagnosticsPanel {
  return {
    open(): void {},
    destroy(): void {},
  };
}

const PANEL_STYLES = `
.scg-diag-panel {
  background: #fff;
  border: 1px solid #475569;
  color: #0f172a;
  font: 14px/1.4 system-ui, sans-serif;
  margin: 1rem;
  max-width: 32rem;
  padding: 1rem;
}
.scg-diag-heading,
.scg-diag-cleanup-heading { margin: 0 0 .5rem; }
.scg-diag-description { margin: 0 0 .75rem; }
.scg-diag-run { margin: 0 .75rem .75rem 0; }
.scg-diag-steps { margin: .75rem 0; padding-left: 1.25rem; }
.scg-diag-cleanup-list { list-style: none; margin: .5rem 0; padding: 0; }
.scg-diag-step { display: grid; gap: .5rem; grid-template-columns: 1fr auto auto; margin: .25rem 0; }
.scg-diag-step-state { font-weight: 600; }
.scg-diag-step-duration { color: #475569; font-variant-numeric: tabular-nums; min-width: 4rem; text-align: right; }
.scg-diag-error { border-left: 3px solid #b91c1c; margin-top: .75rem; padding-left: .75rem; }
.scg-diag-error-message,
.scg-diag-remediation { margin: .25rem 0; }
`;
