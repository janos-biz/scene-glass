import { isSceneGlassOwnedElement } from '../annotation/selector.js';
import {
  createSceneGlassStatus,
  safeCode,
  type SceneGlassStatusInput,
  type SceneGlassStatusSurface,
} from './status.js';

export type OverlayResolution = 'resolved' | 'ambiguous' | 'not-found';

export interface OverlayAnnotation {
  readonly id: string;
  readonly memo: string;
  readonly resolution: OverlayResolution;
  readonly element?: Element;
}

export interface SceneGlassOverlayCapabilities {
  readonly canCreateMemo?: boolean;
  readonly canDeleteMemo?: boolean;
  readonly canDeleteAllCurrentPage?: boolean;
  readonly canExportCurrentPage?: boolean;
  readonly canExportProject?: boolean;
  readonly canOpenDiagnostics?: boolean;
  readonly canRetry?: boolean;
  readonly canSelect?: boolean;
  readonly canMeasure?: boolean;
  readonly canInspectSize?: boolean;
  readonly canUpdateMemo?: boolean;
}

export interface SceneGlassOverlayState {
  readonly actionEpoch?: number;
  readonly annotations?: readonly OverlayAnnotation[];
  readonly capabilities?: SceneGlassOverlayCapabilities;
  readonly diagnosticsOpen?: boolean;
  readonly pendingSelectionElement?: Element | null;
  readonly selectionMode?: boolean;
  readonly measureMode?: boolean;
  readonly sizeMode?: boolean;
  readonly pageReady?: boolean;
  readonly status?: SceneGlassStatusInput;
}

type AsyncAction<T> = (input: T) => void | Promise<void>;
type PromptExportAction = (input: Record<never, never>) => string | void | Promise<string | void>;

export interface SceneGlassOverlayOptions {
  readonly container?: HTMLElement;
  readonly document?: Document;
  readonly onSelectionModeChange?: AsyncAction<{ readonly active: boolean }>;
  readonly onMeasureModeChange?: AsyncAction<{ readonly active: boolean }>;
  readonly onSizeModeChange?: AsyncAction<{ readonly active: boolean }>;
  readonly onCreateMemo?: AsyncAction<{ readonly memo: string }>;
  readonly onUpdateMemo?: AsyncAction<{
    readonly annotationId: string;
    readonly memo: string;
  }>;
  readonly onDeleteMemo?: AsyncAction<{ readonly annotationId: string }>;
  readonly onDeleteAllCurrentPage?: AsyncAction<Record<never, never>>;
  readonly onRetry?: AsyncAction<Record<never, never>>;
  readonly onOpenDiagnostics?: AsyncAction<Record<never, never>>;
  readonly onCloseDiagnostics?: AsyncAction<Record<never, never>>;
  readonly onExportProject?: PromptExportAction;
  readonly onExportCurrentPage?: PromptExportAction;
}

export interface SceneGlassOverlay {
  open(): void;
  setState(state: SceneGlassOverlayState): void;
  destroy(): void;
}

type OverlayHandlers = {
  readonly selectionModeChange: AsyncAction<{ readonly active: boolean }> | undefined;
  readonly measureModeChange: AsyncAction<{ readonly active: boolean }> | undefined;
  readonly sizeModeChange: AsyncAction<{ readonly active: boolean }> | undefined;
  readonly createMemo: AsyncAction<{ readonly memo: string }> | undefined;
  readonly updateMemo:
    AsyncAction<{ readonly annotationId: string; readonly memo: string }> | undefined;
  readonly deleteMemo: AsyncAction<{ readonly annotationId: string }> | undefined;
  readonly deleteAllCurrentPage: AsyncAction<Record<never, never>> | undefined;
  readonly retry: AsyncAction<Record<never, never>> | undefined;
  readonly openDiagnostics: AsyncAction<Record<never, never>> | undefined;
  readonly closeDiagnostics: AsyncAction<Record<never, never>> | undefined;
  readonly exportProject: PromptExportAction | undefined;
  readonly exportCurrentPage: PromptExportAction | undefined;
};
let nextOverlayId = 0;

export function createSceneGlassOverlay(options: SceneGlassOverlayOptions = {}): SceneGlassOverlay {
  const document = resolveDocument(options);
  if (document === null) {
    return unavailableOverlay();
  }

  let container: HTMLElement | null = options.container ?? null;
  let handlers: OverlayHandlers | null = {
    selectionModeChange: options.onSelectionModeChange,
    measureModeChange: options.onMeasureModeChange,
    sizeModeChange: options.onSizeModeChange,
    createMemo: options.onCreateMemo,
    updateMemo: options.onUpdateMemo,
    deleteMemo: options.onDeleteMemo,
    deleteAllCurrentPage: options.onDeleteAllCurrentPage,
    retry: options.onRetry,
    openDiagnostics: options.onOpenDiagnostics,
    closeDiagnostics: options.onCloseDiagnostics,
    exportProject: options.onExportProject,
    exportCurrentPage: options.onExportCurrentPage,
  };

  const style = document.createElement('style');
  style.className = 'scg-ui-styles';
  style.textContent = OVERLAY_STYLES;

  const element = document.createElement('aside');
  element.className = 'scg-ui-overlay';
  element.setAttribute('aria-label', 'Scene Glass 메모 제어');

  const heading = document.createElement('h2');
  heading.className = 'scg-ui-heading';
  heading.textContent = 'Scene Glass';

  const minimizeButton = document.createElement('button');
  minimizeButton.className = 'scg-ui-minimize';
  minimizeButton.type = 'button';
  minimizeButton.setAttribute('aria-label', '미니마이즈');
  minimizeButton.textContent = '−';

  const headingRow = document.createElement('div');
  headingRow.className = 'scg-ui-heading-row';
  headingRow.append(heading, minimizeButton);

  const launcher = document.createElement('button');
  launcher.className = 'scg-ui-launcher';
  launcher.type = 'button';
  launcher.setAttribute('aria-label', 'Scene Glass 열기');
  launcher.hidden = true;
  const launcherIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  launcherIcon.setAttribute('aria-hidden', 'true');
  launcherIcon.setAttribute('viewBox', '0 0 24 24');
  launcherIcon.setAttribute('fill', 'none');
  launcherIcon.setAttribute('stroke', 'currentColor');
  launcherIcon.setAttribute('stroke-width', '2.5');
  const launcherLens = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  launcherLens.setAttribute('cx', '10.5');
  launcherLens.setAttribute('cy', '10.5');
  launcherLens.setAttribute('r', '5.5');
  const launcherHandle = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  launcherHandle.setAttribute('d', 'm15 15 5 5');
  launcherIcon.append(launcherLens, launcherHandle);
  launcher.append(launcherIcon);

  const selectionButton = document.createElement('button');
  selectionButton.className = 'scg-ui-action scg-ui-selection';
  selectionButton.type = 'button';

  const measureButton = document.createElement('button');
  measureButton.className = 'scg-ui-action scg-ui-measure';
  measureButton.type = 'button';

  const sizeButton = document.createElement('button');
  sizeButton.className = 'scg-ui-action scg-ui-size';
  sizeButton.type = 'button';

  const retryButton = document.createElement('button');
  retryButton.className = 'scg-ui-action scg-ui-retry';
  retryButton.type = 'button';
  retryButton.textContent = '재연결';

  const diagnosticsButton = document.createElement('button');
  diagnosticsButton.className = 'scg-ui-action scg-ui-diagnostics';
  diagnosticsButton.type = 'button';
  const exportProjectButton = document.createElement('button');
  exportProjectButton.className = 'scg-ui-action scg-ui-export-project';
  exportProjectButton.type = 'button';
  exportProjectButton.textContent = '프로젝트 전체 복사';

  const exportPageButton = document.createElement('button');
  exportPageButton.className = 'scg-ui-action scg-ui-export-page';
  exportPageButton.type = 'button';
  exportPageButton.textContent = '현재 페이지 복사';

  const deleteAllButton = document.createElement('button');
  deleteAllButton.className = 'scg-ui-action scg-ui-delete-all';
  deleteAllButton.type = 'button';
  deleteAllButton.textContent = '현재 페이지 메모 전체 삭제';

  const deleteAllCancelButton = document.createElement('button');
  deleteAllCancelButton.className = 'scg-ui-action scg-ui-delete-all-cancel';
  deleteAllCancelButton.type = 'button';
  deleteAllCancelButton.textContent = '취소';
  deleteAllCancelButton.hidden = true;

  const deleteAllHint = createHint(document, '현재 페이지의 메모를 모두 삭제합니다.');

  const selectionHint = createHint(
    document,
    '페이지의 요소를 클릭해 메모를 달 대상으로 지정합니다.',
  );
  const measureHint = createHint(
    document,
    '기준 요소를 고른 뒤 다른 요소에 마우스를 올리면 두 요소 사이 간격을 표시합니다. Esc 로 끕니다.',
  );
  const sizeHint = createHint(
    document,
    '요소를 클릭하면 가로·세로 크기를 표시합니다. 모퉁이 뱃지를 누르면 패딩과 마진까지 봅니다. Esc 로 끕니다.',
  );
  const retryHint = createHint(document, 'Scene Glass 연결을 다시 시도합니다.');
  const diagnosticsHint = createHint(document, '연결과 환경 진단 정보를 표시합니다.');
  const exportProjectHint = createHint(
    document,
    '이 프로젝트의 모든 메모를 AI 프롬프트로 만들어 클립보드에 복사합니다.',
  );
  const exportPageHint = createHint(
    document,
    '현재 페이지의 메모로 AI 프롬프트를 만들어 클립보드에 복사합니다.',
  );

  const controls = document.createElement('div');
  controls.className = 'scg-ui-controls';
  // 버튼과 그 도움말을 한 칸으로 묶는다. 형제로 늘어놓으면 도움말이 격자 칸을 하나씩
  // 차지해 버튼 폭이 줄마다 어긋난다 — 묶어야 모든 칩이 같은 크기로 선다.
  const controlCell = (...parts: readonly Node[]): HTMLDivElement => {
    const cell = document.createElement('div');
    cell.className = 'scg-ui-control-cell';
    cell.append(...parts);
    return cell;
  };
  controls.append(
    controlCell(selectionButton, selectionHint),
    controlCell(exportPageButton, exportPageHint),
    controlCell(measureButton, measureHint),
    controlCell(sizeButton, sizeHint),
    controlCell(retryButton, retryHint),
    controlCell(exportProjectButton, exportProjectHint),
    controlCell(diagnosticsButton, diagnosticsHint),
    controlCell(deleteAllButton, deleteAllCancelButton, deleteAllHint),
  );

  const editor = document.createElement('form');
  editor.className = 'scg-ui-editor';
  const memoInputId = `scg-ui-memo-${nextOverlayId}`;
  nextOverlayId += 1;

  const editorLabel = document.createElement('label');
  editorLabel.className = 'scg-ui-editor-label';
  editorLabel.htmlFor = memoInputId;

  // 무엇에 메모를 다는지 먼저 보여 준다 — 태그 한 줄, 그 아래 경로 한 줄.
  const targetTag = document.createElement('code');
  targetTag.className = 'scg-ui-target-tag';
  const targetPath = document.createElement('code');
  targetPath.className = 'scg-ui-target-path';
  const targetBlock = document.createElement('div');
  targetBlock.className = 'scg-ui-target';
  targetBlock.append(targetTag, targetPath);

  const memoInput = document.createElement('textarea');
  memoInput.className = 'scg-ui-memo';
  memoInput.id = memoInputId;
  memoInput.name = 'memo';
  memoInput.rows = 4;
  memoInput.required = true;
  memoInput.placeholder = '피드백 혹은 메모';

  const saveMemoButton = document.createElement('button');
  saveMemoButton.className = 'scg-ui-action scg-ui-save-memo';
  saveMemoButton.type = 'submit';
  const saveMemoLabel = document.createElement('span');
  saveMemoLabel.className = 'scg-ui-save-memo-label';
  const saveMemoKeys = document.createElement('kbd');
  saveMemoKeys.className = 'scg-ui-keycap';
  saveMemoKeys.textContent = `${isAppleLikePlatform(document) ? '⌘' : 'Ctrl'} ↵`;
  saveMemoButton.append(saveMemoLabel, saveMemoKeys);

  const cancelEditButton = document.createElement('button');
  cancelEditButton.className = 'scg-ui-action scg-ui-cancel-edit';
  cancelEditButton.type = 'button';
  cancelEditButton.textContent = '취소';
  // 보이는 글자는 목업대로 짧게, 읽히는 이름은 무엇을 취소하는지 그대로 남긴다.
  cancelEditButton.setAttribute('aria-label', '편집 취소');

  const saveMemoHint = createHint(document, '작성한 메모를 저장합니다.');
  const editorActions = document.createElement('div');
  editorActions.className = 'scg-ui-editor-actions';
  editorActions.append(cancelEditButton, saveMemoButton, saveMemoHint);
  editor.append(editorLabel, targetBlock, memoInput, editorActions);

  // 메모칸에서 ⌘↵ / Ctrl↵ 로 바로 저장한다 — 버튼의 키캡이 약속하는 동작이다.
  memoInput.addEventListener('keydown', (event: KeyboardEvent) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && !saveMemoButton.disabled) {
      event.preventDefault();
      editor.requestSubmit(saveMemoButton);
    }
  });

  const annotationsToggle = document.createElement('button');
  annotationsToggle.className = 'scg-ui-annotations-toggle';
  annotationsToggle.type = 'button';
  const annotationListId = `scg-ui-annotations-${nextOverlayId}`;
  nextOverlayId += 1;
  annotationsToggle.setAttribute('aria-controls', annotationListId);

  const annotationList = document.createElement('ul');
  annotationList.className = 'scg-ui-annotations';
  annotationList.id = annotationListId;

  const orphansToggle = document.createElement('button');
  orphansToggle.className = 'scg-ui-orphans-toggle';
  orphansToggle.type = 'button';
  const orphanListId = `scg-ui-orphans-${nextOverlayId}`;
  nextOverlayId += 1;
  orphansToggle.setAttribute('aria-controls', orphanListId);

  const orphanList = document.createElement('ul');
  orphanList.className = 'scg-ui-orphans';
  orphanList.id = orphanListId;

  const promptOutputId = `scg-ui-prompt-${nextOverlayId}`;
  nextOverlayId += 1;
  // 메모 목록과 같은 접이 제목. 프롬프트는 내보내기를 눌러야 생기는 것이라, 빈 상자가 패널
  // 아래를 늘 차지하고 있을 이유가 없다.
  const promptToggle = document.createElement('button');
  promptToggle.className = 'scg-ui-prompt-toggle';
  promptToggle.type = 'button';
  promptToggle.setAttribute('aria-controls', promptOutputId);

  const promptOutput = document.createElement('textarea');
  promptOutput.className = 'scg-ui-generated-prompt';
  promptOutput.id = promptOutputId;
  promptOutput.readOnly = true;
  promptOutput.rows = 6;
  promptOutput.setAttribute('aria-label', '생성된 프롬프트');

  const status: SceneGlassStatusSurface = createSceneGlassStatus(document);
  const statusElement = status.element;

  element.append(
    headingRow,
    controls,
    editor,
    annotationsToggle,
    annotationList,
    orphansToggle,
    orphanList,
    promptToggle,
    promptOutput,
  );
  if (statusElement !== null) {
    element.append(statusElement);
  }

  let annotations: readonly OverlayAnnotation[] = [];
  let capabilities: SceneGlassOverlayCapabilities = {};
  let diagnosticsOpen = false;
  let selectionMode = false;
  let measureMode = false;
  let sizeMode = false;
  let pageReady = false;
  let pendingSelectionElement: Element | null = null;
  let deleteAllConfirming = false;
  let actionEpoch = 0;
  let editingAnnotationId: string | null = null;
  let annotationsExpanded = false;
  let orphansExpanded = false;
  let promptExpanded = false;
  let minimized = false;
  /**
   * 선택 모드가 켜지는 순간의 최소화 상태. 패널이 화면을 가려 고르려는 요소를 덮으므로
   * 선택 중에는 접어 두고, 선택이 끝나면 사용자가 두었던 상태로 되돌린다. null 이면
   * 우리가 접은 것이 아니므로 건드리지 않는다.
   */
  let minimizedBeforeSelection: boolean | null = null;
  let activeAction: { readonly epoch: number; readonly id: number } | null = null;
  let nextActionId = 0;
  let destroyed = false;
  let opened = false;
  let openRequested = false;
  let openBadgeId: string | null = null;
  let mountFallback: ReturnType<typeof setTimeout> | undefined;
  let badgeContainer: HTMLElement | null = null;
  let badgePositionFrame: number | null = null;
  let lastBadgeSignature: string | null = null;
  const badgeTargets = new Map<string, Element>();
  let launcherPosition: { readonly x: number; readonly y: number } | null = null;
  let launcherDrag: {
    readonly pointerId: number;
    readonly startX: number;
    readonly startY: number;
    readonly launcherX: number;
    readonly launcherY: number;
    dragging: boolean;
  } | null = null;
  let suppressLauncherClick = false;
  let clearLauncherClickSuppression: ReturnType<typeof setTimeout> | undefined;
  let highlightBox: HTMLElement | null = null;
  let highlightTarget: Element | null = null;
  let highlightTimer: ReturnType<typeof setTimeout> | undefined;
  const badgeWindow = document.defaultView;

  const positionBadges = (): void => {
    badgePositionFrame = null;
    if (destroyed || badgeContainer === null) {
      return;
    }
    for (const badge of badgeContainer.querySelectorAll<HTMLElement>('.scg-ui-badge')) {
      const target = badgeTargets.get(badge.dataset.scgBadgeFor ?? '');
      const rect = target?.getBoundingClientRect();
      const attached =
        target !== undefined &&
        document.documentElement !== null &&
        document.documentElement.contains(target);
      if (!attached || rect === undefined || rect.width === 0 || rect.height === 0) {
        badge.hidden = true;
        continue;
      }
      badge.hidden = false;
      badge.style.left = `${Math.max(0, rect.left - 8)}px`;
      badge.style.top = `${Math.max(0, rect.top - 8)}px`;
      if (badge.classList.contains('scg-ui-badge--open')) {
        positionPopover(badge, badge.querySelector<HTMLElement>('.scg-ui-badge-popover'));
      }
    }
    positionHighlight();
    positionEditor();
  };
  const scheduleBadgePosition = (): void => {
    if (destroyed || badgePositionFrame !== null) {
      return;
    }
    badgePositionFrame =
      badgeWindow?.requestAnimationFrame(positionBadges) ??
      (setTimeout(positionBadges, 0) as unknown as number);
  };
  const positionPopover = (anchor: HTMLElement, popover: HTMLElement | null): void => {
    const view = document.defaultView;
    if (popover === null || view === null) {
      return;
    }
    const rect = anchor.getBoundingClientRect();
    popover.style.top = `${rect.bottom + 6}px`;
    popover.style.left = `${Math.max(8, Math.min(rect.left, view.innerWidth - popover.offsetWidth - 8))}px`;
  };
  const positionEditor = (): void => {
    if (editor.hidden) {
      return;
    }
    const annotation = annotations.find((candidate) => candidate.id === editingAnnotationId);
    const target =
      editingAnnotationId === null
        ? pendingSelectionElement
        : (badgeTargets.get(editingAnnotationId) ?? annotation?.element ?? null);
    const view = document.defaultView;
    const attached =
      target !== null &&
      document.documentElement !== null &&
      document.documentElement.contains(target);
    if (!attached || view === null) {
      hideHighlight();
      editor.style.top = '8px';
      editor.style.left = '8px';
      return;
    }
    const rect = target.getBoundingClientRect();
    editor.style.top = `${Math.max(8, Math.min(rect.bottom + 6, view.innerHeight - editor.offsetHeight - 8))}px`;
    editor.style.left = `${Math.max(8, Math.min(rect.left, view.innerWidth - editor.offsetWidth - 8))}px`;
    showHighlight(target);
  };
  const setOpenBadge = (annotationId: string | null): void => {
    openBadgeId = annotationId;
    for (const badge of badgeContainer?.querySelectorAll<HTMLElement>('.scg-ui-badge') ?? []) {
      const open = badge.dataset.scgBadgeFor === openBadgeId;
      badge.classList.toggle('scg-ui-badge--open', open);
      badge.setAttribute('aria-expanded', String(open));
      if (open) {
        positionPopover(badge, badge.querySelector<HTMLElement>('.scg-ui-badge-popover'));
      }
    }
  };
  const rebuildBadges = (): void => {
    const body = document.body;
    if (body === null) {
      return;
    }
    if (badgeContainer === null) {
      badgeContainer = document.createElement('div');
      badgeContainer.className = 'scg-ui-badges';
      body.append(badgeContainer);
    }
    const resolvedAnnotations = annotations.filter(
      (annotation): annotation is OverlayAnnotation & { readonly element: Element } =>
        annotation.resolution === 'resolved' && annotation.element !== undefined,
    );
    badgeTargets.clear();
    for (const annotation of resolvedAnnotations) {
      badgeTargets.set(annotation.id, annotation.element);
    }
    const badgeSignature = resolvedAnnotations
      .map((annotation) => `${annotation.id}|${annotation.memo}`)
      .join('\n');
    if (badgeSignature === lastBadgeSignature) {
      scheduleBadgePosition();
      return;
    }
    const badges = resolvedAnnotations.map((annotation, index) => {
      const badge = document.createElement('button');
      badge.className = 'scg-ui-badge';
      badge.type = 'button';
      badge.dataset.scgBadgeFor = annotation.id;
      badge.append(String(index + 1));
      badge.setAttribute('aria-label', `메모 ${index + 1}: ${annotation.memo}`);
      badge.setAttribute('aria-expanded', 'false');
      badge.addEventListener('click', () => {
        const opening = openBadgeId !== annotation.id;
        setOpenBadge(opening ? annotation.id : null);
        if (opening) {
          scrollToAnnotation(annotation);
        }
      });

      const popover = document.createElement('span');
      popover.className = 'scg-ui-badge-popover';
      // 작성기와 같은 골격 — 무엇에 달린 메모인지 먼저 밝히고 본문을 보인다.
      const target = document.createElement('code');
      target.className = 'scg-ui-badge-target';
      target.textContent =
        annotation.element === undefined ? '' : annotation.element.localName.toLowerCase();
      target.hidden = annotation.element === undefined;
      const memo = document.createElement('span');
      memo.className = 'scg-ui-badge-memo';
      memo.textContent = truncateMemo(annotation.memo);
      memo.title = annotation.memo;
      const edit = document.createElement('button');
      edit.className = 'scg-ui-action scg-ui-badge-edit';
      edit.type = 'button';
      edit.textContent = '수정';
      edit.addEventListener('click', (event) => {
        event.stopPropagation();
        setOpenBadge(annotation.id);
        beginEdit(annotation);
      });
      const remove = document.createElement('button');
      remove.className = 'scg-ui-action scg-ui-badge-delete';
      remove.type = 'button';
      remove.textContent = '삭제';
      remove.addEventListener('click', (event) => {
        event.stopPropagation();
        deleteAnnotation(annotation);
      });
      const actions = document.createElement('span');
      actions.className = 'scg-ui-badge-actions';
      actions.append(edit, remove);
      popover.append(target, memo, actions);
      popover.addEventListener('click', (event) => event.stopPropagation());
      badge.append(popover);
      return badge;
    });
    badgeContainer.replaceChildren(...badges);
    lastBadgeSignature = badgeSignature;
    markSceneGlassUi(badgeContainer);
    setOpenBadge(openBadgeId);
    scheduleBadgePosition();
  };
  const onBadgeViewportChange = (): void => scheduleBadgePosition();
  badgeWindow?.addEventListener('scroll', onBadgeViewportChange, true);
  badgeWindow?.addEventListener('resize', onBadgeViewportChange);
  const onDocumentClick = (event: MouseEvent): void => {
    if (
      openBadgeId !== null &&
      event.target instanceof Node &&
      !badgeContainer?.contains(event.target)
    ) {
      setOpenBadge(null);
    }
  };
  const onDocumentKeydown = (event: KeyboardEvent): void => {
    if (event.key === 'Escape' && openBadgeId !== null) {
      const badge = [
        ...(badgeContainer?.querySelectorAll<HTMLElement>('.scg-ui-badge') ?? []),
      ].find((candidate) => candidate.dataset.scgBadgeFor === openBadgeId);
      setOpenBadge(null);
      badge?.focus();
    }
  };
  /**
   * Scene Glass 자기 UI 를 만진 것은 호스트에게 "바깥을 눌렀다" 가 아니다.
   *
   * 모달은 바깥 포인터를 닫기 신호로 읽는다. 패널이 그 바깥에 있으므로, 팝업이 뜬 화면에서
   * 「요소 선택」을 누르면 그 클릭이 호스트까지 흘러가 팝업이 닫혀 버렸다 — 팝업을 띄운 채
   * 검토하는 일 자체가 불가능했다. 자기 표면에서 시작된 것만 여기서 멈춘다. 호스트 요소를
   * 누른 것은 그대로 흘려보내므로 모달의 동작은 바뀌지 않는다.
   */
  const onOwnPointerDown = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element) || !isSceneGlassOwnedElement(target)) {
      return;
    }
    event.stopImmediatePropagation();
    // **포커스를 빼앗지 않는다.** 모달은 포커스가 밖으로 나가면 닫히거나 도로 끌어간다.
    // 패널 버튼이 포커스를 가져가는 순간 팝업이 닫혀, 팝업을 띄운 채 검토할 수 없었다.
    // mousedown 의 기본 동작만 막으면 click 은 그대로 발생하므로 버튼은 정상 동작한다.
    // 글자를 넣는 칸은 예외다 — 포커스가 없으면 아예 쓸 수 없다.
    if (!isTextEntry(target)) {
      event.preventDefault();
    }
    // 여기서 끊기는 것은 호스트만이 아니다. window 캡처에서 즉시 멈추므로 눌림은 우리 요소에도
    // 닿지 못한다 — 런처를 끌어 옮기는 길이 그래서 막혀 있었다. 버튼을 눌러 여는 것은 click 이라
    // 멀쩡했고, 끌기만 조용히 죽어 원인이 잘 드러나지 않았다. 삼킨 눌림으로 하려던 일은
    // 여기서 이어 준다 — 호스트는 여전히 이 눌림을 보지 못한다.
    if (
      event.type === 'pointerdown' &&
      event instanceof PointerEvent &&
      launcher.contains(target)
    ) {
      onLauncherPointerDown(event);
    }
  };
  /**
   * 메모 칸에 들어온 포커스를 모달이 도로 끌어가지 못하게 한다.
   *
   * 모달의 포커스 덫은 `focusin` 을 듣다가 포커스가 대화상자 밖으로 나가면 곧바로 안으로
   * 되돌린다. 작성기는 그 "밖" 이라, 칸을 눌러도 포커스가 즉시 대화상자로 돌아가 한 글자도
   * 쓸 수 없었다 — 팝업 안 요소를 골라 놓고 정작 메모를 못 쓰는 상태다.
   *
   * 포커스가 우리 표면으로 들어온 사실만 감춘다. 호스트끼리 오가는 포커스는 그대로 흘려보내고,
   * 우리 UI 를 벗어나는 순간부터는 다시 호스트의 몫이므로 덫도 평소대로 동작한다.
   */
  const onOwnFocusChange = (event: Event): void => {
    const arriving = event.type === 'focusin' ? event.target : (event as FocusEvent).relatedTarget;
    if (arriving instanceof Element && isSceneGlassOwnedElement(arriving)) {
      event.stopImmediatePropagation();
    }
  };
  // `window` 에 건다. 모달의 감시도 window 캡처에 있어 document 보다 먼저 도착하는데,
  // 이 로더는 모달이 열리기 전에 이미 붙어 있으므로 같은 노드에서 우리가 먼저 실행된다.
  const ownPointerTarget: EventTarget = document.defaultView ?? document;
  for (const name of ['pointerdown', 'mousedown', 'touchstart'] as const) {
    ownPointerTarget.addEventListener(name, onOwnPointerDown, true);
  }
  for (const name of ['focusin', 'focusout'] as const) {
    ownPointerTarget.addEventListener(name, onOwnFocusChange, true);
  }
  document.addEventListener('click', onDocumentClick, true);
  document.addEventListener('keydown', onDocumentKeydown);

  const render = (): void => {
    if (destroyed) {
      return;
    }
    const selectionDescription = selectionMode
      ? '선택 모드를 종료합니다.'
      : '페이지의 요소를 클릭해 메모를 달 대상으로 지정합니다.';
    selectionButton.textContent = selectionMode ? '선택 종료' : '요소 선택';
    updateHint(selectionHint, selectionDescription);
    selectionButton.setAttribute('aria-pressed', String(selectionMode));
    measureButton.textContent = measureMode ? '거리 측정 종료' : '거리 측정';
    measureButton.setAttribute('aria-pressed', String(measureMode));
    sizeButton.textContent = sizeMode ? '크기 측정 종료' : '크기 측정';
    sizeButton.setAttribute('aria-pressed', String(sizeMode));
    diagnosticsButton.textContent = diagnosticsOpen ? '진단 닫기' : '진단 열기';
    updateHint(
      diagnosticsHint,
      diagnosticsOpen ? '진단 패널을 닫습니다.' : '연결과 환경 진단 정보를 표시합니다.',
    );
    // 대상이 화면에서 사라져도 작성기는 살아 있어야 한다. 고른 순간에 locator·문맥·주변
    // 텍스트를 이미 갈무리했으므로 저장에 살아 있는 요소가 필요 없다. 팝업 안 요소에 메모를
    // 달면 그 팝업이 닫히면서 대상이 사라지는데, 그때 작성기까지 접히면 쓰던 글을 잃는다.
    const createEditorVisible =
      editingAnnotationId === null &&
      pendingSelectionElement !== null &&
      pageActionAvailable(capabilities.canCreateMemo);
    // 작성기는 패널 접힘과 무관하다. 패널을 접는 것은 "화면을 가리지 말라" 는 뜻이지
    // "쓰던 메모를 치우라" 는 뜻이 아니다. 묶어 두면 접힌 채로 요소를 고른 순간 작성기가
    // 나타나지 않아, 패널을 도로 펼쳐야만 메모를 쓸 수 있었다 — 접어 둔 이유와 정반대다.
    const editorVisible = editingAnnotationId !== null || createEditorVisible;
    editor.hidden = !editorVisible;
    editorLabel.textContent = editingAnnotationId === null ? '새 메모' : '메모 편집';
    saveMemoLabel.textContent = editingAnnotationId === null ? '추가' : '저장';
    // 키캡이 접근성 이름에 섞이지 않도록 이름을 직접 정한다.
    saveMemoButton.setAttribute(
      'aria-label',
      editingAnnotationId === null ? '메모 작성' : '메모 저장',
    );
    const editorTarget =
      editingAnnotationId === null
        ? pendingSelectionElement
        : (annotations.find((item) => item.id === editingAnnotationId)?.element ?? null);
    targetTag.textContent = editorTarget === null ? '' : editorTarget.localName.toLowerCase();
    const editorPath = editorTarget === null ? '' : describeElementPath(editorTarget);
    targetPath.textContent = editorPath;
    // 말줄임으로 잘린 경로는 호버하면 전문이 보여야 한다.
    targetPath.title = editorPath;
    targetBlock.hidden = editorTarget === null;
    cancelEditButton.hidden = !editorVisible;
    // 접었는데 쓰던 메모가 있으면 패널을 통째로 숨기지 않는다. 숨기면 조상이 hidden 이 되어
    // 작성기까지 사라져, 접어 둔 채로는 메모를 쓸 수 없다. 껍데기를 투명하게 비우고 작성기만
    // 남긴다 — 접어 둔 뜻(화면을 가리지 말 것)은 지키면서 쓰던 것은 잃지 않는다.
    const composerOnly = minimized && editorVisible;
    element.hidden = minimized && !composerOnly;
    element.classList.toggle('scg-ui-overlay--composer-only', composerOnly);
    launcher.hidden = !minimized;
    if (launcherPosition !== null) {
      applyLauncherPosition(launcherPosition.x, launcherPosition.y);
    }
    if (annotations.length === 0) {
      deleteAllConfirming = false;
    }
    deleteAllButton.textContent = deleteAllConfirming
      ? '정말 전체 삭제? 다시 클릭'
      : '현재 페이지 메모 전체 삭제';
    deleteAllButton.dataset.confirming = String(deleteAllConfirming);
    deleteAllCancelButton.hidden = !deleteAllConfirming;
    if (!editorVisible) {
      hideHighlight();
    }
    const resolvedAnnotations = annotations.filter(
      (annotation) => annotation.resolution === 'resolved',
    );
    const orphanedAnnotations = annotations.filter(
      (annotation) => annotation.resolution !== 'resolved',
    );
    annotationsToggle.textContent = `${annotationsExpanded ? '▾' : '▸'} 메모 (${resolvedAnnotations.length})`;
    annotationsToggle.setAttribute('aria-expanded', String(annotationsExpanded));
    annotationList.hidden = !annotationsExpanded;

    orphansToggle.hidden = orphanedAnnotations.length === 0;
    orphanList.hidden = orphanedAnnotations.length === 0 || !orphansExpanded;
    orphansToggle.textContent = `${orphansExpanded ? '▾' : '▸'} 유실 데이터 (${orphanedAnnotations.length})`;
    orphansToggle.setAttribute('aria-expanded', String(orphansExpanded));

    promptToggle.textContent = `${promptExpanded ? '▾' : '▸'} 생성된 프롬프트`;
    promptToggle.setAttribute('aria-expanded', String(promptExpanded));
    promptOutput.hidden = !promptExpanded;

    const rows = resolvedAnnotations.map((annotation, index) =>
      createAnnotationRow(document, annotation, {
        ordinal: index + 1,
        onEdit: () => beginEdit(annotation),
        onDelete: () => deleteAnnotation(annotation),
        onScroll: () => scrollToAnnotation(annotation),
      }),
    );
    const orphanRows = orphanedAnnotations.map((annotation) =>
      createOrphanAnnotationRow(document, annotation, {
        onEdit: () => beginEdit(annotation),
        onDelete: () => deleteAnnotation(annotation),
      }),
    );
    annotationList.replaceChildren(...rows);
    orphanList.replaceChildren(...orphanRows);
    markSceneGlassUi(element);
    rebuildBadges();
    setControlsDisabled();
    if (editorVisible) {
      positionEditor();
    }
  };

  const setUnavailableStatus = (): void => {
    status.set({ kind: 'error', code: 'SCG_CLIENT_UNAVAILABLE' });
  };
  const setActionUnavailableStatus = (code: string): void => {
    status.set({ kind: 'error', code });
  };

  const isActionInFlight = (): boolean => activeAction?.epoch === actionEpoch;

  const ownsAction = (owner: { readonly epoch: number; readonly id: number }): boolean =>
    !destroyed &&
    owner.epoch === actionEpoch &&
    activeAction?.epoch === owner.epoch &&
    activeAction.id === owner.id;

  const pageActionAvailable = (capability: boolean | undefined): boolean =>
    pageReady && capability === true;

  /** 선택 모드 전환을 한 곳에서 처리한다 — 패널 토글과 외부 상태가 같은 규칙을 타게. */
  const applySelectionMode = (next: boolean): void => {
    if (next === selectionMode) {
      return;
    }
    if (next) {
      minimizedBeforeSelection = minimized;
      minimized = true;
    } else if (minimizedBeforeSelection !== null) {
      minimized = minimizedBeforeSelection;
      minimizedBeforeSelection = null;
    }
    selectionMode = next;
  };

  const setControlsDisabled = (): void => {
    const actionInFlight = isActionInFlight();
    const canSaveMemo =
      editingAnnotationId === null
        ? capabilities.canCreateMemo === true
        : capabilities.canUpdateMemo === true;
    selectionButton.disabled = actionInFlight || !pageActionAvailable(capabilities.canSelect);
    measureButton.disabled = actionInFlight || !pageActionAvailable(capabilities.canMeasure);
    sizeButton.disabled = actionInFlight || !pageActionAvailable(capabilities.canInspectSize);
    retryButton.disabled = actionInFlight || capabilities.canRetry !== true;
    diagnosticsButton.disabled =
      actionInFlight || (!diagnosticsOpen && capabilities.canOpenDiagnostics !== true);
    exportProjectButton.disabled = actionInFlight || capabilities.canExportProject !== true;
    exportPageButton.disabled =
      actionInFlight || !pageActionAvailable(capabilities.canExportCurrentPage);
    deleteAllButton.disabled =
      actionInFlight ||
      annotations.length === 0 ||
      !pageActionAvailable(capabilities.canDeleteAllCurrentPage);
    deleteAllCancelButton.disabled = actionInFlight;
    memoInput.disabled = actionInFlight || !pageActionAvailable(canSaveMemo);
    saveMemoButton.disabled = actionInFlight || !pageActionAvailable(canSaveMemo);
    cancelEditButton.disabled = actionInFlight;
    for (const button of element.querySelectorAll<HTMLButtonElement>('.scg-ui-edit-memo')) {
      button.disabled = actionInFlight || !pageActionAvailable(capabilities.canUpdateMemo);
    }
    for (const button of element.querySelectorAll<HTMLButtonElement>('.scg-ui-delete-memo')) {
      button.disabled = actionInFlight || !pageActionAvailable(capabilities.canDeleteMemo);
    }
    for (const button of badgeContainer?.querySelectorAll<HTMLButtonElement>(
      '.scg-ui-badge-edit',
    ) ?? []) {
      button.disabled = actionInFlight || !pageActionAvailable(capabilities.canUpdateMemo);
    }
    for (const button of badgeContainer?.querySelectorAll<HTMLButtonElement>(
      '.scg-ui-badge-delete',
    ) ?? []) {
      button.disabled = actionInFlight || !pageActionAvailable(capabilities.canDeleteMemo);
    }
  };

  const performAction = async <T>(
    action: () => T | Promise<T>,
    fallbackCode: string,
    onSuccess?: (result: T) => SceneGlassStatusInput | void,
  ): Promise<void> => {
    const owner = Object.freeze({ epoch: actionEpoch, id: (nextActionId += 1) });
    activeAction = owner;
    setControlsDisabled();
    status.set({ kind: 'working' });
    try {
      const result = await action();
      if (!ownsAction(owner)) {
        return;
      }
      status.set(onSuccess?.(result) ?? { kind: 'ready' });
    } catch (error: unknown) {
      if (ownsAction(owner)) {
        status.set({ kind: 'error', code: actionErrorCode(error, fallbackCode) });
      }
    } finally {
      if (ownsAction(owner)) {
        activeAction = null;
        setControlsDisabled();
      }
    }
  };
  const onDeleteAllCurrentPage = (): void => {
    const deleteAllCurrentPage = handlers?.deleteAllCurrentPage;
    if (
      destroyed ||
      isActionInFlight() ||
      !pageActionAvailable(capabilities.canDeleteAllCurrentPage)
    ) {
      return;
    }
    if (deleteAllCurrentPage === undefined) {
      setUnavailableStatus();
      return;
    }
    if (!deleteAllConfirming) {
      deleteAllConfirming = true;
      render();
      return;
    }
    void performAction(() => deleteAllCurrentPage({}), 'SCG_CLIENT_DELETE_FAILED').finally(() => {
      deleteAllConfirming = false;
      render();
    });
  };
  const onCancelDeleteAll = (): void => {
    if (isActionInFlight()) {
      return;
    }
    deleteAllConfirming = false;
    render();
  };
  const beginEdit = (annotation: OverlayAnnotation): void => {
    if (destroyed || isActionInFlight() || !pageActionAvailable(capabilities.canUpdateMemo)) {
      return;
    }
    editingAnnotationId = annotation.id;
    memoInput.value = annotation.memo;
    render();
    memoInput.focus();
  };

  const deleteAnnotation = (annotation: OverlayAnnotation): void => {
    const onDeleteMemo = handlers?.deleteMemo;
    if (destroyed || isActionInFlight() || !pageActionAvailable(capabilities.canDeleteMemo)) {
      return;
    }
    if (onDeleteMemo === undefined) {
      setUnavailableStatus();
      return;
    }
    void performAction(
      () => onDeleteMemo({ annotationId: annotation.id }),
      'SCG_CLIENT_DELETE_FAILED',
    );
  };

  const ensureHighlightBox = (): HTMLElement | null => {
    const body = document.body;
    if (body !== null && highlightBox === null) {
      highlightBox = document.createElement('div');
      highlightBox.className = 'scg-ui-highlight';
      highlightBox.hidden = true;
      highlightBox.setAttribute('data-scg-selector-overlay', 'true');
      body.append(highlightBox);
    }
    return highlightBox;
  };
  const hideHighlight = (): void => {
    if (highlightTimer !== undefined) {
      clearTimeout(highlightTimer);
      highlightTimer = undefined;
    }
    highlightTarget = null;
    if (highlightBox !== null) {
      highlightBox.hidden = true;
    }
  };
  const showHighlight = (target: Element): void => {
    if (highlightTimer !== undefined) {
      clearTimeout(highlightTimer);
      highlightTimer = undefined;
    }
    if (ensureHighlightBox() === null) {
      return;
    }
    highlightTarget = target;
    positionHighlight();
  };
  const positionHighlight = (): void => {
    if (highlightBox === null || highlightTarget === null) {
      return;
    }
    const rect = highlightTarget.getBoundingClientRect();
    const attached =
      document.documentElement !== null &&
      document.documentElement.contains(highlightTarget) &&
      rect.width > 0 &&
      rect.height > 0;
    if (!attached) {
      highlightBox.hidden = true;
      return;
    }
    highlightBox.hidden = false;
    highlightBox.style.left = `${rect.left - 4}px`;
    highlightBox.style.top = `${rect.top - 4}px`;
    highlightBox.style.width = `${rect.width + 8}px`;
    highlightBox.style.height = `${rect.height + 8}px`;
  };
  const scrollToAnnotation = (annotation: OverlayAnnotation): void => {
    const target = badgeTargets.get(annotation.id) ?? annotation.element;
    if (target === undefined) {
      return;
    }
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    // Highlight via an SCG-owned overlay box positioned OVER the element, never
    // by mutating the host element's attributes (which would trip the host
    // runtime's mutation observer and make the badges flicker).
    if (ensureHighlightBox() === null) {
      return;
    }
    showHighlight(target);
    scheduleBadgePosition();
    highlightTimer = setTimeout(() => {
      highlightTarget = null;
      highlightTimer = undefined;
      if (highlightBox !== null) {
        highlightBox.hidden = true;
      }
    }, 1000);
  };

  const onSelectionMode = (): void => {
    const onSelectionModeChange = handlers?.selectionModeChange;
    if (!pageActionAvailable(capabilities.canSelect)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (onSelectionModeChange === undefined) {
      setUnavailableStatus();
      return;
    }
    const nextSelectionMode = !selectionMode;
    void performAction(
      () => onSelectionModeChange({ active: nextSelectionMode }),
      'SCG_CLIENT_SELECTION_FAILED',
      () => {
        applySelectionMode(nextSelectionMode);
        render();
      },
    );
  };

  const onMeasureMode = (): void => {
    const onMeasureModeChange = handlers?.measureModeChange;
    if (!pageActionAvailable(capabilities.canMeasure)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (onMeasureModeChange === undefined) {
      setUnavailableStatus();
      return;
    }
    const nextMeasureMode = !measureMode;
    void performAction(
      () => onMeasureModeChange({ active: nextMeasureMode }),
      'SCG_CLIENT_MEASURE_FAILED',
      () => {
        measureMode = nextMeasureMode;
        render();
      },
    );
  };

  const onSizeMode = (): void => {
    const onSizeModeChange = handlers?.sizeModeChange;
    if (!pageActionAvailable(capabilities.canInspectSize)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (onSizeModeChange === undefined) {
      setUnavailableStatus();
      return;
    }
    const nextSizeMode = !sizeMode;
    void performAction(
      () => onSizeModeChange({ active: nextSizeMode }),
      'SCG_CLIENT_SIZE_FAILED',
      () => {
        sizeMode = nextSizeMode;
        render();
      },
    );
  };

  const onRetry = (): void => {
    const onRetry = handlers?.retry;
    if (capabilities.canRetry !== true) {
      setUnavailableStatus();
      return;
    }
    if (onRetry === undefined) {
      setUnavailableStatus();
      return;
    }
    void performAction(() => onRetry({}), 'SCG_CLIENT_RETRY_FAILED');
  };

  const onDiagnostics = (): void => {
    if (diagnosticsOpen) {
      void performAction(() => {
        const closeDiagnostics = handlers?.closeDiagnostics;
        if (closeDiagnostics === undefined) {
          setUnavailableStatus();
          return;
        }
        return closeDiagnostics({});
      }, 'SCG_CLIENT_DIAGNOSTICS_FAILED');
      return;
    }

    const onOpenDiagnostics = handlers?.openDiagnostics;
    if (capabilities.canOpenDiagnostics !== true) {
      setUnavailableStatus();
      return;
    }
    if (onOpenDiagnostics === undefined) {
      setUnavailableStatus();
      return;
    }
    void performAction(() => onOpenDiagnostics({}), 'SCG_CLIENT_DIAGNOSTICS_FAILED');
  };

  const onExportProject = (): void => {
    const onExportProject = handlers?.exportProject;
    if (capabilities.canExportProject !== true) {
      setUnavailableStatus();
      return;
    }
    if (onExportProject === undefined) {
      setUnavailableStatus();
      return;
    }
    void performAction(
      async () => {
        const markdown = await onExportProject({});
        if (typeof markdown !== 'string') {
          return { markdown, copied: false };
        }
        try {
          if (typeof navigator.clipboard?.writeText === 'function') {
            await navigator.clipboard.writeText(markdown);
            return { markdown, copied: true };
          }
        } catch {
          // Export remains available when clipboard access is blocked.
        }
        return { markdown, copied: false };
      },
      'SCG_CLIENT_EXPORT_FAILED',
      ({ markdown, copied }) => {
        if (typeof markdown === 'string') {
          promptOutput.value = markdown;
          promptExpanded = true;
        }
        return copied ? { kind: 'ready', code: 'SCG_CLIPBOARD_COPIED' } : undefined;
      },
    );
  };

  const onExportCurrentPage = (): void => {
    const onExportCurrentPage = handlers?.exportCurrentPage;
    if (!pageActionAvailable(capabilities.canExportCurrentPage)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (onExportCurrentPage === undefined) {
      setUnavailableStatus();
      return;
    }
    void performAction(
      async () => {
        const markdown = await onExportCurrentPage({});
        if (typeof markdown !== 'string') {
          return { markdown, copied: false };
        }
        try {
          if (typeof navigator.clipboard?.writeText === 'function') {
            await navigator.clipboard.writeText(markdown);
            return { markdown, copied: true };
          }
        } catch {
          // Export remains available when clipboard access is blocked.
        }
        return { markdown, copied: false };
      },
      'SCG_CLIENT_EXPORT_FAILED',
      ({ markdown, copied }) => {
        if (typeof markdown === 'string') {
          promptOutput.value = markdown;
          promptExpanded = true;
        }
        return copied ? { kind: 'ready', code: 'SCG_CLIPBOARD_COPIED' } : undefined;
      },
    );
  };

  const onMemoSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (isActionInFlight()) {
      return;
    }
    const memo = memoInput.value;
    if (editingAnnotationId === null && !pageActionAvailable(capabilities.canCreateMemo)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (editingAnnotationId !== null && !pageActionAvailable(capabilities.canUpdateMemo)) {
      setActionUnavailableStatus('SCG_PAGE_UNREADY');
      return;
    }
    if (memo.trim().length === 0) {
      status.set({ kind: 'error', code: 'SCG_MEMO_BLANK' });
      return;
    }

    const activeHandlers = handlers;
    if (editingAnnotationId === null) {
      const onCreateMemo = activeHandlers?.createMemo;
      if (onCreateMemo === undefined) {
        setUnavailableStatus();
        return;
      }
      void performAction(
        () => onCreateMemo({ memo }),
        'SCG_CLIENT_CREATE_FAILED',
        () => {
          memoInput.value = '';
          pendingSelectionElement = null;
          hideHighlight();
          render();
        },
      );
      return;
    }

    const onUpdateMemo = activeHandlers?.updateMemo;
    if (onUpdateMemo === undefined) {
      setUnavailableStatus();
      return;
    }
    const annotationId = editingAnnotationId;
    void performAction(
      () => onUpdateMemo({ annotationId, memo }),
      'SCG_CLIENT_UPDATE_FAILED',
      () => {
        editingAnnotationId = null;
        hideHighlight();
        memoInput.value = '';
        render();
      },
    );
  };

  /**
   * 작성을 접으면 골라 둔 대상도 함께 버린다.
   *
   * 패널에서만 지우면 런타임은 그 대상을 계속 쥐고 있다. 아무도 쓰지 않는 상태인데도 남아
   * 있으면 대상을 지키려고 잠가 둔 길들이 함께 잠긴 채로 있다 — 흔들기로는 다시 고를 수 없게
   * 된다. 취소는 화면에서 이미 끝난 일이라, 알리는 데 실패해도 되돌릴 것은 없다.
   */
  const discardPendingSelection = async (): Promise<void> => {
    const onSelectionModeChange = handlers?.selectionModeChange;
    if (onSelectionModeChange === undefined) {
      return;
    }
    try {
      await onSelectionModeChange({ active: false });
    } catch {
      // 취소 자체는 이미 반영되었다.
    }
  };

  const onCancelEdit = (): void => {
    if (isActionInFlight()) {
      return;
    }
    const discardsSelection = editingAnnotationId === null && pendingSelectionElement !== null;
    editingAnnotationId = null;
    pendingSelectionElement = null;
    memoInput.value = '';
    hideHighlight();
    render();
    if (discardsSelection) {
      void discardPendingSelection();
    }
  };

  const hints = [
    selectionHint,
    measureHint,
    sizeHint,
    retryHint,
    diagnosticsHint,
    exportProjectHint,
    exportPageHint,
    deleteAllHint,
    saveMemoHint,
  ];
  const setHintVisible = (hint: HTMLSpanElement, visible: boolean): void => {
    hint.classList.toggle('scg-ui-hint--open', visible);
    if (visible) {
      positionPopover(hint, hint.querySelector<HTMLElement>('.scg-ui-hint-popover'));
    }
  };
  const onHintEnter = (event: Event): void => {
    setHintVisible(event.currentTarget as HTMLSpanElement, true);
  };
  const onHintLeave = (event: Event): void => {
    setHintVisible(event.currentTarget as HTMLSpanElement, false);
  };
  const clampLauncherPosition = (
    x: number,
    y: number,
  ): { readonly x: number; readonly y: number } => {
    const view = document.defaultView;
    return {
      x: Math.min(Math.max(0, x), Math.max(0, (view?.innerWidth ?? 42) - 42)),
      y: Math.min(Math.max(0, y), Math.max(0, (view?.innerHeight ?? 42) - 42)),
    };
  };
  const applyLauncherPosition = (x: number, y: number): void => {
    const position = clampLauncherPosition(x, y);
    launcherPosition = position;
    launcher.style.left = `${position.x}px`;
    launcher.style.top = `${position.y}px`;
    launcher.style.right = 'auto';
    launcher.style.bottom = 'auto';
  };
  const onLauncherPointerDown = (event: PointerEvent): void => {
    if (event.button !== 0) {
      return;
    }
    const rect = launcher.getBoundingClientRect();
    launcherDrag = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      launcherX: rect.left,
      launcherY: rect.top,
      dragging: false,
    };
    launcher.setPointerCapture(event.pointerId);
  };
  const onLauncherPointerMove = (event: PointerEvent): void => {
    if (launcherDrag === null || event.pointerId !== launcherDrag.pointerId) {
      return;
    }
    const deltaX = event.clientX - launcherDrag.startX;
    const deltaY = event.clientY - launcherDrag.startY;
    if (!launcherDrag.dragging && deltaX * deltaX + deltaY * deltaY > 16) {
      launcherDrag.dragging = true;
      launcher.classList.add('scg-ui-launcher--dragging');
    }
    if (launcherDrag.dragging) {
      event.preventDefault();
      applyLauncherPosition(launcherDrag.launcherX + deltaX, launcherDrag.launcherY + deltaY);
    }
  };
  const endLauncherDrag = (event: PointerEvent): void => {
    if (launcherDrag === null || event.pointerId !== launcherDrag.pointerId) {
      return;
    }
    const wasDragging = launcherDrag.dragging;
    launcherDrag = null;
    launcher.classList.remove('scg-ui-launcher--dragging');
    if (launcher.hasPointerCapture(event.pointerId)) {
      launcher.releasePointerCapture(event.pointerId);
    }
    if (wasDragging) {
      suppressLauncherClick = true;
      clearLauncherClickSuppression = setTimeout(() => {
        suppressLauncherClick = false;
        clearLauncherClickSuppression = undefined;
      }, 0);
    }
  };
  const onLauncherClick = (event: MouseEvent): void => {
    if (suppressLauncherClick) {
      event.preventDefault();
      event.stopPropagation();
      suppressLauncherClick = false;
      if (clearLauncherClickSuppression !== undefined) {
        clearTimeout(clearLauncherClickSuppression);
        clearLauncherClickSuppression = undefined;
      }
      return;
    }
    minimized = false;
    minimizedBeforeSelection = null;
    render();
  };
  for (const hint of hints) {
    hint.addEventListener('mouseenter', onHintEnter);
    hint.addEventListener('mouseleave', onHintLeave);
    hint.addEventListener('focus', onHintEnter);
    hint.addEventListener('blur', onHintLeave);
  }
  selectionButton.addEventListener('click', onSelectionMode);
  measureButton.addEventListener('click', onMeasureMode);
  sizeButton.addEventListener('click', onSizeMode);
  retryButton.addEventListener('click', onRetry);
  diagnosticsButton.addEventListener('click', onDiagnostics);
  exportProjectButton.addEventListener('click', onExportProject);
  exportPageButton.addEventListener('click', onExportCurrentPage);
  deleteAllButton.addEventListener('click', onDeleteAllCurrentPage);
  deleteAllCancelButton.addEventListener('click', onCancelDeleteAll);
  editor.addEventListener('submit', onMemoSubmit);
  cancelEditButton.addEventListener('click', onCancelEdit);
  minimizeButton.addEventListener('click', () => {
    minimized = true;
    // 사용자가 직접 접었으면 선택이 끝날 때 펼쳐 주면 안 된다 — 기억을 버린다.
    minimizedBeforeSelection = null;
    render();
  });
  launcher.addEventListener('pointerdown', onLauncherPointerDown);
  launcher.addEventListener('pointermove', onLauncherPointerMove);
  launcher.addEventListener('pointerup', endLauncherDrag);
  launcher.addEventListener('pointercancel', endLauncherDrag);
  launcher.addEventListener('click', onLauncherClick);
  const onAnnotationsToggle = (): void => {
    annotationsExpanded = !annotationsExpanded;
    render();
  };
  const onOrphansToggle = (): void => {
    orphansExpanded = !orphansExpanded;
    render();
  };
  const onPromptToggle = (): void => {
    promptExpanded = !promptExpanded;
    render();
  };
  promptToggle.addEventListener('click', onPromptToggle);
  annotationsToggle.addEventListener('click', onAnnotationsToggle);
  orphansToggle.addEventListener('click', onOrphansToggle);
  markSceneGlassUi(launcher);
  render();
  const mount = (): boolean => {
    const host = resolveMountContainer(document, container);
    if (destroyed || opened || host === null) {
      return false;
    }
    host.append(style, element, launcher);
    if (badgeContainer !== null && badgeContainer.parentElement === null) {
      document.body?.append(badgeContainer);
    }
    rebuildBadges();
    opened = true;
    stopMountRetries();
    return true;
  };

  /**
   * Without a `[data-scg-root]` the mount container resolves only once the
   * document reaches `complete`, which an async loader normally beats. Listening
   * for `DOMContentLoaded` alone is not enough: at that point the state is still
   * `interactive`, so the retry fails and — being `once` — never fires again. Wait
   * for the state that actually unblocks the mount as well.
   */
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
    setState(next: SceneGlassOverlayState): void {
      if (destroyed) {
        return;
      }
      if (next.actionEpoch !== undefined && next.actionEpoch !== actionEpoch) {
        actionEpoch = next.actionEpoch;
        activeAction = null;
        selectionMode = false;
        editingAnnotationId = null;
        memoInput.value = '';
        promptOutput.value = '';
      }
      if (next.pendingSelectionElement !== undefined) {
        pendingSelectionElement = next.pendingSelectionElement;
      }
      if (next.annotations !== undefined) {
        annotations = next.annotations.map((annotation) => ({
          id: annotation.id,
          memo: annotation.memo,
          resolution: annotation.resolution,
          ...(annotation.element === undefined ? {} : { element: annotation.element }),
        }));
        if (
          editingAnnotationId !== null &&
          !annotations.some((annotation) => annotation.id === editingAnnotationId)
        ) {
          editingAnnotationId = null;
          memoInput.value = '';
        }
      }
      if (next.capabilities !== undefined) {
        capabilities = { ...next.capabilities };
      }
      if (next.selectionMode !== undefined) {
        applySelectionMode(next.selectionMode);
      }
      if (next.measureMode !== undefined) {
        measureMode = next.measureMode;
      }
      if (next.sizeMode !== undefined) {
        sizeMode = next.sizeMode;
      }
      if (next.diagnosticsOpen !== undefined) {
        diagnosticsOpen = next.diagnosticsOpen;
      }
      if (next.pageReady !== undefined) {
        pageReady = next.pageReady;
      }
      if (next.status !== undefined) {
        status.set(next.status);
      }
      render();
    },
    destroy(): void {
      if (destroyed) {
        return;
      }
      destroyed = true;
      handlers = null;
      container = null;
      openRequested = false;
      stopMountRetries();
      annotations = [];
      editingAnnotationId = null;
      memoInput.value = '';
      promptOutput.value = '';
      selectionButton.removeEventListener('click', onSelectionMode);
      measureButton.removeEventListener('click', onMeasureMode);
      sizeButton.removeEventListener('click', onSizeMode);
      retryButton.removeEventListener('click', onRetry);
      diagnosticsButton.removeEventListener('click', onDiagnostics);
      exportProjectButton.removeEventListener('click', onExportProject);
      exportPageButton.removeEventListener('click', onExportCurrentPage);
      deleteAllButton.removeEventListener('click', onDeleteAllCurrentPage);
      deleteAllCancelButton.removeEventListener('click', onCancelDeleteAll);
      for (const hint of hints) {
        hint.removeEventListener('mouseenter', onHintEnter);
        hint.removeEventListener('mouseleave', onHintLeave);
        hint.removeEventListener('focus', onHintEnter);
        hint.removeEventListener('blur', onHintLeave);
      }
      for (const name of ['pointerdown', 'mousedown', 'touchstart'] as const) {
        ownPointerTarget.removeEventListener(name, onOwnPointerDown, true);
      }
      for (const name of ['focusin', 'focusout'] as const) {
        ownPointerTarget.removeEventListener(name, onOwnFocusChange, true);
      }
      document.removeEventListener('click', onDocumentClick, true);
      document.removeEventListener('keydown', onDocumentKeydown);
      editor.removeEventListener('submit', onMemoSubmit);
      cancelEditButton.removeEventListener('click', onCancelEdit);
      launcher.removeEventListener('pointerdown', onLauncherPointerDown);
      launcher.removeEventListener('pointermove', onLauncherPointerMove);
      launcher.removeEventListener('pointerup', endLauncherDrag);
      launcher.removeEventListener('pointercancel', endLauncherDrag);
      launcher.removeEventListener('click', onLauncherClick);
      annotationsToggle.removeEventListener('click', onAnnotationsToggle);
      orphansToggle.removeEventListener('click', onOrphansToggle);
      if (launcherDrag !== null && launcher.hasPointerCapture(launcherDrag.pointerId)) {
        launcher.releasePointerCapture(launcherDrag.pointerId);
      }
      launcherDrag = null;
      if (clearLauncherClickSuppression !== undefined) {
        clearTimeout(clearLauncherClickSuppression);
        clearLauncherClickSuppression = undefined;
      }
      if (highlightTimer !== undefined) {
        clearTimeout(highlightTimer);
        highlightTimer = undefined;
      }
      highlightTarget = null;
      highlightBox?.remove();
      highlightBox = null;
      annotationList.replaceChildren();
      orphanList.replaceChildren();
      badgeWindow?.removeEventListener('scroll', onBadgeViewportChange, true);
      badgeWindow?.removeEventListener('resize', onBadgeViewportChange);
      if (badgePositionFrame !== null) {
        if (badgeWindow !== null) {
          badgeWindow.cancelAnimationFrame(badgePositionFrame);
        } else {
          clearTimeout(badgePositionFrame);
        }
        badgePositionFrame = null;
      }
      badgeContainer?.remove();
      badgeContainer = null;
      status.destroy();
      element.replaceChildren();
      style.textContent = '';
      style.remove();
      element.remove();
      launcher.remove();
    },
  };
}

function createAnnotationRow(
  document: Document,
  annotation: OverlayAnnotation,
  handlers: {
    readonly ordinal: number;
    readonly onEdit: () => void;
    readonly onDelete: () => void;
    readonly onScroll: () => void;
  },
): HTMLLIElement {
  const item = document.createElement('li');
  item.className = 'scg-ui-annotation';
  item.dataset.resolution = annotation.resolution;

  // 목록의 번호는 화면에 뜬 배지와 같은 값이다 — 둘을 눈으로 잇는 유일한 단서다.
  const ordinal = document.createElement('span');
  ordinal.className = 'scg-ui-annotation-ordinal';
  ordinal.textContent = String(handlers.ordinal);
  ordinal.setAttribute('aria-hidden', 'true');

  const body = document.createElement('div');
  body.className = 'scg-ui-annotation-body';

  const target = document.createElement('code');
  target.className = 'scg-ui-annotation-target';
  target.textContent =
    annotation.element === undefined ? '' : annotation.element.localName.toLowerCase();
  target.hidden = annotation.element === undefined;

  const memo = document.createElement('p');
  memo.className = 'scg-ui-annotation-memo';

  const scroll = document.createElement('button');
  scroll.className = 'scg-ui-annotation-scroll';
  scroll.type = 'button';
  scroll.textContent = annotation.memo;
  scroll.title = annotation.memo;
  scroll.disabled = annotation.element === undefined;
  scroll.addEventListener('click', handlers.onScroll);
  memo.append(scroll);

  const resolution = document.createElement('span');
  resolution.className = 'scg-ui-annotation-resolution';
  resolution.textContent = annotation.resolution === 'resolved' ? '연결됨' : '검토 필요';

  const edit = document.createElement('button');
  edit.className = 'scg-ui-action scg-ui-edit-memo';
  edit.type = 'button';
  edit.textContent = '수정';
  edit.addEventListener('click', handlers.onEdit);

  const remove = document.createElement('button');
  remove.className = 'scg-ui-action scg-ui-delete-memo';
  remove.type = 'button';
  remove.textContent = '삭제';
  remove.addEventListener('click', handlers.onDelete);

  const actions = document.createElement('div');
  actions.className = 'scg-ui-annotation-actions';
  actions.append(edit, remove);

  body.append(target, memo, resolution);
  item.append(ordinal, body, actions);
  return item;
}
function createOrphanAnnotationRow(
  document: Document,
  annotation: OverlayAnnotation,
  handlers: {
    readonly onEdit: () => void;
    readonly onDelete: () => void;
  },
): HTMLLIElement {
  const item = document.createElement('li');
  item.className = 'scg-ui-annotation';
  item.dataset.resolution = annotation.resolution;

  const body = document.createElement('div');
  body.className = 'scg-ui-annotation-body';

  const memo = document.createElement('p');
  memo.className = 'scg-ui-annotation-memo';
  memo.textContent = annotation.memo;
  memo.title = annotation.memo;

  const resolution = document.createElement('span');
  resolution.className = 'scg-ui-annotation-resolution';
  resolution.textContent = '검토 필요';

  const edit = document.createElement('button');
  edit.className = 'scg-ui-action scg-ui-edit-memo';
  edit.type = 'button';
  edit.textContent = '수정';
  edit.addEventListener('click', handlers.onEdit);

  const remove = document.createElement('button');
  remove.className = 'scg-ui-action scg-ui-delete-memo';
  remove.type = 'button';
  remove.textContent = '삭제';
  remove.addEventListener('click', handlers.onDelete);

  const actions = document.createElement('div');
  actions.className = 'scg-ui-annotation-actions';
  actions.append(edit, remove);

  body.append(memo, resolution);
  item.append(body, actions);
  return item;
}
/** 포커스가 반드시 필요한 입력 요소인가. */
function isTextEntry(element: Element): boolean {
  const tag = element.localName;
  return (
    tag === 'input' ||
    tag === 'textarea' ||
    tag === 'select' ||
    (element as HTMLElement).isContentEditable === true
  );
}

function markSceneGlassUi(element: HTMLElement): void {
  element.setAttribute('data-scg-selector-overlay', 'true');
  for (const child of element.querySelectorAll('*')) {
    child.setAttribute('data-scg-selector-overlay', 'true');
  }
}
function createHint(document: Document, description: string): HTMLSpanElement {
  const hint = document.createElement('span');
  hint.className = 'scg-ui-hint';
  hint.tabIndex = 0;
  hint.setAttribute('role', 'img');
  hint.textContent = 'ⓘ';

  const popover = document.createElement('span');
  popover.className = 'scg-ui-hint-popover';
  hint.append(popover);
  updateHint(hint, description);
  return hint;
}

function updateHint(hint: HTMLSpanElement, description: string): void {
  hint.setAttribute('aria-label', description);
  const popover = hint.querySelector('.scg-ui-hint-popover');
  if (popover !== null) {
    popover.textContent = description;
  }
}

function truncateMemo(memo: string): string {
  const maximumLength = 160;
  return memo.length > maximumLength ? `${memo.slice(0, maximumLength - 1)}…` : memo;
}

function actionErrorCode(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const candidate = (error as { readonly code?: unknown }).code;
    if (typeof candidate === 'string' && safeCode(candidate) !== null) {
      return candidate;
    }
  }
  return fallback;
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
function resolveDocument(options: SceneGlassOverlayOptions): Document | null {
  if (options.document !== undefined) {
    return options.document;
  }
  if (options.container !== undefined) {
    return options.container.ownerDocument;
  }
  return typeof globalThis.document === 'undefined' ? null : globalThis.document;
}

function unavailableOverlay(): SceneGlassOverlay {
  return {
    open(): void {},
    setState(): void {},
    destroy(): void {},
  };
}

/** 저장 키캡 표기는 플랫폼을 따른다 — macOS 는 ⌘, 나머지는 Ctrl. */
function isAppleLikePlatform(document: Document): boolean {
  const platform = document.defaultView?.navigator?.platform ?? '';
  return /mac|iphone|ipad|ipod/iu.test(platform);
}

/**
 * 메모를 다는 대상을 한 줄로 알아보게 적는다. 저장되는 `context.cssPath` 와 달리 이건 화면
 * 표시용이라 짧게 끊는다 — 조상 두 단계까지만 태그와 첫 클래스를 적는다.
 */
function describeElementPath(element: Element): string {
  const parts: string[] = [];
  let current: Element | null = element;
  for (let depth = 0; depth < 3 && current !== null; depth += 1) {
    const tag = current.localName.toLowerCase();
    const id = current.id === '' ? '' : `#${current.id}`;
    const className =
      typeof current.className === 'string' && current.className.trim() !== ''
        ? `.${current.className.trim().split(/\s+/u)[0]}`
        : '';
    parts.unshift(`${tag}${id}${className}`);
    current = current.parentElement;
  }
  return parts.join(' > ');
}

const OVERLAY_STYLES = `
.scg-ui-overlay {
  -webkit-font-smoothing: antialiased;
  background: rgba(15, 23, 42, .96);
  border: 1px solid rgba(148, 163, 184, .28);
  border-radius: 18px;
  bottom: 20px;
  box-shadow: 0 24px 64px rgba(2, 6, 23, .34), 0 4px 16px rgba(2, 6, 23, .18);
  box-sizing: border-box;
  color: #e2e8f0;
  font: 500 13px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  letter-spacing: 0;
  max-height: min(680px, calc(100vh - 40px));
  overflow-y: auto;
  padding: 16px;
  position: fixed;
  right: 20px;
  text-align: left;
  width: min(360px, calc(100vw - 40px));
  z-index: 2147483646;
}
.scg-ui-overlay *,
.scg-ui-overlay *::before,
.scg-ui-overlay *::after { box-sizing: border-box; }
.scg-ui-heading {
  color: #f8fafc;
  font-size: 16px;
  font-weight: 720;
  letter-spacing: -.02em;
  margin: 0 0 12px;
}
.scg-ui-heading-row {
  align-items: center;
  display: flex;
  justify-content: space-between;
  margin-bottom: 12px;
}
.scg-ui-heading-row .scg-ui-heading { margin-bottom: 0; }
.scg-ui-minimize,
.scg-ui-launcher {
  appearance: none;
  background: #0284c7;
  border: 1px solid #38bdf8;
  color: #fff;
  cursor: pointer;
}
.scg-ui-minimize {
  border-radius: 8px;
  font: 700 18px/1 Inter, ui-sans-serif, system-ui, sans-serif;
  height: 28px;
  width: 28px;
}
.scg-ui-minimize:focus-visible,
.scg-ui-launcher:focus-visible,
.scg-ui-annotations-toggle:focus-visible,
.scg-ui-orphans-toggle:focus-visible,
.scg-ui-annotation-scroll:focus-visible {
  outline: 2px solid #38bdf8;
  outline-offset: 2px;
}
/* 접었을 때 화면에 남는 유일한 표시다 — 호스트 UI 와 섞이지 않도록 앰버로 세워 둔다.
   글자 없이 아이콘만 있으므로 획이 배경에 묻지 않게 어두운 앰버로 그린다. */
.scg-ui-launcher {
  align-items: center;
  background: #f59e0b;
  border-color: #fbbf24;
  border-radius: 50%;
  bottom: 20px;
  box-shadow: 0 8px 20px rgba(2, 6, 23, .35);
  color: #78350f;
  display: flex;
  height: 42px;
  justify-content: center;
  padding: 0;
  position: fixed;
  right: 20px;
  width: 42px;
  cursor: grab;
  touch-action: none;
  user-select: none;
  z-index: 2147483646;
}
.scg-ui-launcher--dragging { cursor: grabbing; }
.scg-ui-launcher svg {
  height: 22px;
  width: 22px;
}
.scg-ui-launcher[hidden],
.scg-ui-editor[hidden],
.scg-ui-annotations[hidden],
.scg-ui-orphans[hidden],
.scg-ui-badge[hidden] {
  display: none;
}
.scg-ui-annotations-toggle,
.scg-ui-orphans-toggle {
  appearance: none;
  background: transparent;
  border: 0;
  color: #cbd5e1;
  cursor: pointer;
  font: 700 12px/1.45 Inter, ui-sans-serif, system-ui, sans-serif;
  letter-spacing: .08em;
  margin: 14px 0 8px;
  padding: 0;
  text-align: left;
  text-transform: uppercase;
}
.scg-ui-controls,
.scg-ui-editor-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  margin-bottom: 12px;
}
.scg-ui-action {
  appearance: none;
  background: rgba(51, 65, 85, .82);
  border: 1px solid rgba(148, 163, 184, .24);
  border-radius: 9px;
  color: #e2e8f0;
  cursor: pointer;
  font: inherit;
  font-size: 12px;
  font-weight: 650;
  min-height: 32px;
  padding: 6px 10px;
  transition: background 120ms ease, border-color 120ms ease, transform 120ms ease;
}
.scg-ui-action:hover:not(:disabled) {
  background: #475569;
  border-color: rgba(203, 213, 225, .45);
  transform: translateY(-1px);
}
.scg-ui-action:focus-visible {
  outline: 2px solid #38bdf8;
  outline-offset: 2px;
}
.scg-ui-action:disabled {
  cursor: not-allowed;
  opacity: .42;
}
.scg-ui-selection {
  background: #0284c7;
  border-color: #38bdf8;
  color: #fff;
}
.scg-ui-editor {
  background: #0f172a;
  border: 1px solid rgba(148, 163, 184, .45);
  border-radius: 10px;
  box-shadow: 0 8px 20px rgba(2, 6, 23, .35);
  display: grid;
  gap: 7px;
  max-width: min(360px, calc(100vw - 16px));
  padding: 10px;
  position: fixed;
  width: max-content;
  z-index: 2147483645;
}
.scg-ui-editor-label,
.scg-ui-prompt-label {
  color: #cbd5e1;
  display: block;
  font-size: 12px;
  font-weight: 650;
  margin-bottom: 5px;
}
.scg-ui-memo,
.scg-ui-generated-prompt {
  appearance: none;
  background: rgba(2, 6, 23, .62);
  border: 1px solid rgba(148, 163, 184, .3);
  border-radius: 10px;
  color: #f8fafc;
  font: 500 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
  min-height: 76px;
  outline: none;
  padding: 10px;
  resize: vertical;
  width: 100%;
}
.scg-ui-memo:focus,
.scg-ui-generated-prompt:focus {
  border-color: #38bdf8;
  box-shadow: 0 0 0 3px rgba(56, 189, 248, .14);
}
.scg-ui-annotations,
.scg-ui-orphans {
  display: grid;
  gap: 8px;
  list-style: none;
  margin: 0 0 12px;
  padding: 0;
}
.scg-ui-annotation {
  background: rgba(30, 41, 59, .74);
  border: 1px solid rgba(148, 163, 184, .2);
  border-radius: 11px;
  padding: 10px;
}
.scg-ui-annotation-memo {
  color: #f1f5f9;
  margin: 0 0 5px;
  white-space: pre-wrap;
}
.scg-ui-annotation-scroll {
  appearance: none;
  background: transparent;
  border: 0;
  color: inherit;
  cursor: pointer;
  font: inherit;
  padding: 0;
  text-align: left;
  white-space: pre-wrap;
}
.scg-ui-annotation-scroll:disabled {
  cursor: default;
  opacity: .7;
}
.scg-ui-highlight {
  border: 3px solid #38bdf8;
  border-radius: 6px;
  box-sizing: border-box;
  pointer-events: none;
  position: fixed;
  z-index: 2147483644;
}
.scg-ui-annotation-resolution {
  color: #94a3b8;
  display: block;
  font-size: 11px;
  margin-bottom: 8px;
}
.scg-ui-status {
  color: #94a3b8;
  display: block;
  font-size: 11px;
  margin-top: 9px;
}
.scg-ui-hint {
  align-items: center;
  border: 1px solid rgba(148, 163, 184, .38);
  border-radius: 50%;
  color: #bae6fd;
  cursor: help;
  display: inline-flex;
  font-size: 12px;
  height: 18px;
  justify-content: center;
  position: relative;
  width: 18px;
}
.scg-ui-hint:focus-visible {
  outline: 2px solid #38bdf8;
  outline-offset: 2px;
}
.scg-ui-hint-popover,
.scg-ui-badge-popover {
  background: #0f172a;
  border: 1px solid rgba(148, 163, 184, .45);
  border-radius: 7px;
  box-shadow: 0 8px 20px rgba(2, 6, 23, .35);
  color: #f8fafc;
  display: none;
  font-size: 11px;
  font-weight: 500;
  line-height: 1.35;
  max-width: min(260px, calc(100vw - 24px));
  padding: 6px 8px;
  position: fixed;
  white-space: normal;
  width: max-content;
  z-index: 2147483647;
}
.scg-ui-badge-popover {
  pointer-events: auto;
}
.scg-ui-badge-memo {
  display: block;
  margin-bottom: 7px;
}
.scg-ui-badge-edit,
.scg-ui-badge-delete {
  margin-right: 5px;
  min-height: 26px;
  padding: 3px 7px;
}
.scg-ui-hint--open .scg-ui-hint-popover,
.scg-ui-badge--open .scg-ui-badge-popover { display: block; }
.scg-ui-badges {
  inset: 0;
  pointer-events: none;
  position: fixed;
  z-index: 2147483645;
}
.scg-ui-badge {
  align-items: center;
  background: #0284c7;
  border: 2px solid #fff;
  border-radius: 50%;
  color: #fff;
  cursor: pointer;
  display: flex;
  font: 700 11px/1 Inter, ui-sans-serif, system-ui, sans-serif;
  height: 22px;
  justify-content: center;
  padding: 0;
  pointer-events: auto;
  position: fixed;
  width: 22px;
}
.scg-ui-badge::after {
  background: #fff;
  border-radius: 2px;
  content: "";
  height: 7px;
  position: absolute;
  right: -4px;
  top: 17px;
  transform: rotate(-45deg);
  width: 3px;
}
.scg-ui-badge:focus-visible {
  outline: 2px solid #facc15;
  outline-offset: 2px;
}
.scg-ui-badge-popover {
  min-width: 140px;
}
@media (max-width: 480px) {
  .scg-ui-overlay {
    bottom: 10px;
    max-height: calc(100vh - 20px);
    right: 10px;
    width: calc(100vw - 20px);
  }
  .scg-ui-launcher {
    bottom: 10px;
    right: 10px;
  }
}

/* ---------------------------------------------------------------------------
 * 밝은 카드 표면. 위쪽 규칙들이 세운 어두운 패널을 여기서 덮는다 — 선택자 특정성을
 * 같게 두고 순서로만 이기므로, 위 블록은 레이아웃 정의로 그대로 살아 있다.
 * ------------------------------------------------------------------------- */
.scg-ui-overlay {
  background: #fff;
  border: 1px solid rgba(0, 0, 0, .08);
  border-radius: 16px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, .12), 0 2px 8px rgba(0, 0, 0, .06);
  color: #18181b;
  padding: 14px;
}
.scg-ui-heading { color: #18181b; font-size: 14px; font-weight: 650; }
.scg-ui-minimize { background: #18181b; border: 0; border-radius: 8px; color: #fff; }

/* 메모 대상 — 태그 한 줄, 경로 한 줄. 경로는 넘치면 말줄임한다. */
.scg-ui-target { margin: 2px 0 10px; }
.scg-ui-target-tag,
.scg-ui-target-path,
.scg-ui-annotation-target {
  display: block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.scg-ui-target-tag { color: #18181b; font-size: 14px; font-weight: 600; }
.scg-ui-target-path {
  color: #a1a1aa;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scg-ui-memo,
.scg-ui-generated-prompt {
  background: #fff;
  border: 1px solid rgba(0, 0, 0, .12);
  border-radius: 12px;
  color: #18181b;
  padding: 12px;
  width: 100%;
}
.scg-ui-memo::placeholder { color: #a1a1aa; }
.scg-ui-memo:focus-visible,
.scg-ui-generated-prompt:focus-visible { border-color: #18181b; outline: none; }

/* 푸터 — 취소는 글자 버튼, 저장은 검은 알약에 키캡을 얹는다. */
.scg-ui-editor-actions {
  align-items: center;
  display: flex;
  gap: 8px;
  justify-content: flex-end;
  margin-top: 10px;
}
.scg-ui-cancel-edit {
  background: transparent;
  border: 0;
  border-radius: 10px;
  color: #52525b;
  font-weight: 600;
  padding: 8px 10px;
}
/* 다른 옅은 버튼(목록의 수정·삭제, 배지 카드)과 같은 호버로 맞춘다. */
.scg-ui-cancel-edit:hover:enabled {
  background: #f4f4f5;
  color: #18181b;
}
.scg-ui-save-memo {
  align-items: center;
  background: #18181b;
  border: 0;
  border-radius: 10px;
  color: #fff;
  display: inline-flex;
  font-weight: 650;
  gap: 8px;
  padding: 9px 12px;
}
.scg-ui-save-memo:disabled { background: #d4d4d8; color: #fff; }
.scg-ui-keycap {
  background: rgba(255, 255, 255, .18);
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
  padding: 2px 6px;
}

/* 두 접이 제목은 각자 한 줄을 쓴다 — 나란히 두면 어디까지가 한 항목인지 읽히지 않는다. */
.scg-ui-annotations-toggle,
.scg-ui-orphans-toggle {
  background: transparent;
  border: 0;
  border-top: 1px solid rgba(0, 0, 0, .07);
  color: #52525b;
  display: block;
  font-weight: 600;
  padding: 10px 0;
  text-align: left;
  width: 100%;
}

/* 목록 한 줄 — 번호 배지 · 본문 · 오른쪽 동작. */
.scg-ui-annotation {
  align-items: flex-start;
  border-top: 1px solid rgba(0, 0, 0, .07);
  display: flex;
  gap: 10px;
  padding: 10px 0;
}
.scg-ui-annotation-ordinal {
  background: #18181b;
  border-radius: 999px;
  color: #fff;
  flex: 0 0 auto;
  font-size: 11px;
  font-weight: 700;
  line-height: 20px;
  min-width: 20px;
  text-align: center;
}
.scg-ui-annotation-body { flex: 1 1 auto; min-width: 0; }
.scg-ui-annotation-target { color: #18181b; font-size: 12px; font-weight: 600; }
.scg-ui-annotation-memo { color: #3f3f46; margin: 2px 0 0; }
.scg-ui-annotation-scroll {
  background: transparent;
  border: 0;
  color: inherit;
  padding: 0;
  text-align: left;
}
.scg-ui-annotation-resolution { color: #a1a1aa; font-size: 11px; }
.scg-ui-annotation-actions { display: flex; flex: 0 0 auto; gap: 4px; }
.scg-ui-annotation-actions .scg-ui-action {
  background: transparent;
  border: 0;
  border-radius: 8px;
  color: #71717a;
  font-size: 12px;
  padding: 4px 6px;
}
.scg-ui-annotation-actions .scg-ui-action:hover:enabled {
  background: #f4f4f5;
  color: #18181b;
}

.scg-ui-prompt-toggle {
  background: transparent;
  border: 0;
  border-top: 1px solid rgba(0, 0, 0, .07);
  color: #52525b;
  display: block;
  font-weight: 600;
  padding: 10px 0;
  text-align: left;
  width: 100%;
}
.scg-ui-generated-prompt[hidden] { display: none; }

/* 접힌 채 메모를 쓰는 동안의 패널 — 자리만 지키고 아무것도 그리지 않는다. */
.scg-ui-overlay--composer-only {
  background: none !important;
  border: 0 !important;
  box-shadow: none !important;
  height: 0 !important;
  overflow: visible !important;
  padding: 0 !important;
  width: 0 !important;
}
.scg-ui-overlay--composer-only > *:not(.scg-ui-editor) { display: none !important; }

/* 모달이 열리면 라이브러리는 바깥 요소 전체의 포인터를 끈다. Scene Glass 는 그 "바깥" 에
   있으므로 패널이 보이는데도 눌리지 않게 된다 — 팝업이 뜬 화면은 리뷰가 불가능해진다.
   자기 소유 표면만 되찾는다. 호스트 요소는 하나도 건드리지 않으므로 모달의 차단은 그대로다.
   호스트가 인라인이나 유틸리티 클래스로 거는 것을 이겨야 해서 !important 가 필요하다. */
.scg-ui-overlay,
.scg-ui-launcher,
.scg-ui-editor,
.scg-ui-badge,
.scg-ui-badge-popover,
.scg-ui-hint,
.scg-ui-hint-popover {
  pointer-events: auto !important;
}
/* 이 셋은 화면을 덮되 통과시키는 것이 원래 동작이다 — 되찾아 주면 안 된다.
   크기 측정 층에서 눌리는 것은 모퉁이 뱃지와 그 카드뿐이라, 그 둘만 아래에서 되살린다. */
.scg-ui-badges,
.scg-measure-layer,
.scg-size-layer {
  pointer-events: none !important;
}
.scg-size-badge,
.scg-size-popover {
  pointer-events: auto !important;
}

/* 배지를 눌러 보는 메모 카드 — 작성기와 같은 흰 카드로 맞춘다. 위쪽 규칙이 세운 어두운
   팝오버를 덮되, 도움말 툴팁(.scg-ui-hint-popover)은 그대로 어둡게 둔다. */
.scg-ui-badge-popover {
  background: #fff;
  border: 1px solid rgba(0, 0, 0, .08);
  border-radius: 16px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, .12), 0 2px 8px rgba(0, 0, 0, .06);
  color: #18181b;
  font: 500 13px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
  max-width: min(320px, calc(100vw - 24px));
  padding: 12px;
}
.scg-ui-badge-popover,
.scg-ui-badge-popover * { box-sizing: border-box; }
.scg-ui-badge-target {
  color: #18181b;
  display: block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 600;
}
.scg-ui-badge-target[hidden] { display: none; }
.scg-ui-badge-memo {
  color: #3f3f46;
  display: block;
  margin: 2px 0 10px;
}
.scg-ui-badge-actions {
  display: flex;
  gap: 4px;
  justify-content: flex-end;
}
.scg-ui-badge-popover .scg-ui-action {
  background: transparent;
  border: 0;
  border-radius: 8px;
  color: #71717a;
  font-size: 12px;
  font-weight: 600;
  margin: 0;
  min-height: 28px;
  padding: 4px 8px;
}
.scg-ui-badge-popover .scg-ui-action:hover:enabled { background: #f4f4f5; color: #18181b; }
.scg-ui-badge-popover .scg-ui-badge-delete {
  border: 1px solid rgba(220, 38, 38, .35);
  color: #dc2626;
}
.scg-ui-badge-popover .scg-ui-badge-delete:hover:enabled {
  background: #fef2f2;
  border-color: #dc2626;
  color: #b91c1c;
}

/* 다크 테마가 남긴 면들을 걷는다 — 행은 카드가 아니라 실선으로만 나뉜다. */
.scg-ui-annotations,
.scg-ui-orphans {
  list-style: none;
  margin: 0;
  padding: 0;
}
.scg-ui-annotation {
  background: transparent;
  border-bottom: 0;
  border-left: 0;
  border-radius: 0;
  border-right: 0;
  box-shadow: none;
  margin: 0;
}
.scg-ui-annotation:first-child { border-top: 0; }
.scg-ui-annotation-memo,
.scg-ui-annotation-scroll { color: #3f3f46; }

/* 상단 동작 — 칩 폭이 글자 길이를 따라 들쑥날쑥하지 않도록 2열 격자에 세운다.
   한 칸의 높이를 고정해 어느 줄에서도 같은 크기로 선다. */
.scg-ui-controls {
  align-items: stretch;
  display: grid;
  gap: 6px;
  grid-template-columns: 1fr 1fr;
  margin-bottom: 12px;
}
.scg-ui-controls .scg-ui-action {
  align-items: center;
  background: #f4f4f5;
  border: 1px solid rgba(0, 0, 0, .06);
  border-radius: 10px;
  color: #3f3f46;
  display: flex;
  font-weight: 600;
  justify-content: center;
  min-height: 34px;
  padding: 0 10px;
  text-align: center;
  width: 100%;
}
.scg-ui-controls .scg-ui-action:hover:enabled { background: #e4e4e7; }
.scg-ui-controls .scg-ui-action:disabled { color: #a1a1aa; opacity: 1; }

/* 요소 선택은 이 패널의 본 기능이다 — 한 줄을 통째로 쓰고 색으로 앞세운다. */
.scg-ui-controls .scg-ui-selection {
  background: #2563eb;
  border-color: #2563eb;
  color: #fff;
  font-weight: 700;
  grid-column: 1 / -1;
  min-height: 38px;
}
.scg-ui-controls .scg-ui-selection:hover:enabled { background: #1d4ed8; }
.scg-ui-controls .scg-ui-selection[aria-pressed="true"] {
  background: #18181b;
  border-color: #18181b;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, .28);
}

/* 한 칸 = 버튼 + 도움말을 나란히. 겹쳐 얹었더니 도움말이 버튼 위를 덮어 호버해도 설명이
   뜨지 않고 그 자리를 누르면 클릭까지 가로챘다 — 요소 선택이 여러 번 눌러야 켜지던 원인이다. */
.scg-ui-control-cell {
  align-items: center;
  display: flex;
  gap: 4px;
}
/* 글자가 긴 것과 본 기능은 한 줄을 통째로 쓴다 — 반 칸에 가두면 두 줄로 깨진다. */
.scg-ui-control-cell:has(.scg-ui-selection),
.scg-ui-control-cell:has(.scg-ui-export-page),
.scg-ui-control-cell:has(.scg-ui-delete-all) { grid-column: 1 / -1; }
.scg-ui-control-cell .scg-ui-action { flex: 1 1 auto; min-width: 0; }
.scg-ui-control-cell .scg-ui-hint { flex: 0 0 auto; }

/* 페이지를 통째로 내보내는 것은 다른 버튼과 무게가 다르다 — 삭제가 빨간 테두리로 구분되듯
   테두리로 세워 둔다. 색은 초록이다: 앰버는 옆 칸의 빨강과 붙어 보여 가져오는 일과 지우는
   일이 한눈에 갈리지 않았다. 되돌릴 수 없는 일은 아니므로 글자색은 건드리지 않는다. */
.scg-ui-controls .scg-ui-export-page {
  border: 1px solid rgba(16, 185, 129, .55);
}
.scg-ui-controls .scg-ui-export-page:hover:enabled {
  border-color: #10b981;
}

/* 지우는 동작은 되돌릴 수 없다 — 빨간 테두리로 다른 것들과 구분해 둔다. */
.scg-ui-controls .scg-ui-delete-all,
.scg-ui-annotation-actions .scg-ui-delete-memo {
  border: 1px solid rgba(220, 38, 38, .35);
  color: #dc2626;
}
.scg-ui-controls .scg-ui-delete-all:hover:enabled,
.scg-ui-annotation-actions .scg-ui-delete-memo:hover:enabled {
  background: #fef2f2;
  border-color: #dc2626;
  color: #b91c1c;
}
/* 두 번째 확인을 기다리는 동안은 채워서 되돌릴 수 없음을 더 분명히 한다. */
.scg-ui-controls .scg-ui-delete-all[data-confirming="true"] {
  background: #dc2626;
  border-color: #dc2626;
  color: #fff;
}

/* 거리 측정 — 화면 위에 겹쳐 그리는 층. 클릭을 가로채면 안 되므로 전부 통과시킨다. */
.scg-measure-layer {
  inset: 0;
  pointer-events: none;
  position: fixed;
  z-index: 2147483644;
}
.scg-measure-layer[hidden] { display: none; }
.scg-measure-outline {
  border-radius: 2px;
  position: fixed;
}
.scg-measure-outline--base { outline: 2px solid #2563eb; }
.scg-measure-outline--target { outline: 2px dashed #ec4899; }
.scg-measure-line {
  background: #ec4899;
  position: fixed;
}
.scg-measure-line--horizontal { height: 1px; }
.scg-measure-line--vertical { width: 1px; }
.scg-measure-line[hidden] { display: none; }
.scg-measure-label {
  background: #ec4899;
  border-radius: 4px;
  color: #fff;
  font: 600 11px/1.2 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  padding: 2px 5px;
  position: fixed;
  transform: translate(-50%, -50%);
  white-space: nowrap;
}
.scg-measure-label[hidden] { display: none; }

/* 크기 측정 — 고른 요소 하나만 그린다. 거리 측정과 같은 층 높이에 둔다. */
.scg-size-layer {
  inset: 0;
  pointer-events: none;
  position: fixed;
  z-index: 2147483644;
}
.scg-size-layer[hidden] { display: none; }
.scg-size-layer *, .scg-size-layer *::before, .scg-size-layer *::after { box-sizing: border-box; }
.scg-size-outline {
  border-radius: 2px;
  outline: 2px solid #7c3aed;
  position: fixed;
}
/* 마진은 바깥, 패딩은 안쪽 — 자리에 칠해 두면 어느 숫자가 어느 변인지 맞춰 볼 필요가 없다. */
.scg-size-box {
  position: fixed;
}
.scg-size-box[hidden] { display: none; }
.scg-size-box--margin {
  background: rgba(249, 115, 22, .16);
  outline: 1px dashed rgba(234, 88, 12, .8);
}
.scg-size-box--padding {
  background: rgba(16, 185, 129, .16);
  outline: 1px dashed rgba(5, 150, 105, .8);
}
.scg-size-label {
  background: #7c3aed;
  border-radius: 4px;
  color: #fff;
  font: 600 11px/1.2 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  padding: 2px 5px;
  position: fixed;
  transform: translateY(-100%);
  white-space: nowrap;
}
/* 위쪽에 자리가 없어 상자 안으로 들어온 라벨 — 끌어올리지 않는다. */
.scg-size-label--inside { transform: none; }
.scg-size-label[hidden] { display: none; }

/* 모퉁이 뱃지 — 대각선 방향 모서리에 걸쳐 앉는다. 누르면 여백 카드가 열린다. */
.scg-size-badge {
  align-items: center;
  pointer-events: auto;
  background: #7c3aed;
  border: 2px solid #fff;
  border-radius: 999px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, .25);
  color: #fff;
  cursor: pointer;
  display: flex;
  height: 22px;
  justify-content: center;
  padding: 0;
  position: fixed;
  width: 22px;
}
.scg-size-badge svg { height: 13px; width: 13px; }
.scg-size-badge:hover { background: #6d28d9; }
.scg-size-badge--open { background: #18181b; }
.scg-size-badge[hidden] { display: none; }

.scg-size-popover {
  background: #fff;
  pointer-events: auto;
  border: 1px solid rgba(0, 0, 0, .08);
  border-radius: 12px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, .12), 0 2px 8px rgba(0, 0, 0, .06);
  color: #18181b;
  font: 500 12px/1.4 Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
  padding: 10px 12px;
  position: fixed;
  white-space: nowrap;
}
.scg-size-popover[hidden] { display: none; }
.scg-size-row {
  align-items: center;
  display: flex;
  gap: 10px;
  justify-content: space-between;
}
.scg-size-row + .scg-size-row { margin-top: 4px; }
.scg-size-row-label {
  color: #71717a;
  font-size: 11px;
  font-weight: 600;
}
.scg-size-row-value {
  color: #18181b;
  display: flex;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-weight: 600;
  gap: 8px;
}
.scg-size-side-name {
  color: #a1a1aa;
  font-weight: 500;
  margin-right: 3px;
}

/* 작성기는 대상 옆에 따로 떠 있는 표면이라 패널 규칙이 닿지 않는다 — 같은 카드로 맞춘다. */
.scg-ui-editor {
  background: #fff;
  border: 1px solid rgba(0, 0, 0, .08);
  border-radius: 16px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, .12), 0 2px 8px rgba(0, 0, 0, .06);
  color: #18181b;
  max-width: min(420px, calc(100vw - 24px));
  overflow: hidden;
  padding: 14px;
  width: min(420px, calc(100vw - 24px));
}
/* 작성기는 .scg-ui-overlay 밖에 떠 있어 위쪽 * 규칙이 닿지 않는다. 여기서 다시 걸지 않으면
   width:100% 에 padding·border 가 더해져 카드 밖으로 삐져나간다. */
.scg-ui-editor,
.scg-ui-editor *,
.scg-ui-editor *::before,
.scg-ui-editor *::after { box-sizing: border-box; }
/* 긴 경로가 칸을 밀어내지 못하게 — 넘치면 줄이지 말고 잘라 낸다. */
.scg-ui-editor > * { max-width: 100%; min-width: 0; }
.scg-ui-memo { max-width: 100%; resize: vertical; }
.scg-ui-editor-label {
  color: #71717a;
  display: block;
  font-size: 11px;
  font-weight: 600;
  margin-bottom: 6px;
}
`;
