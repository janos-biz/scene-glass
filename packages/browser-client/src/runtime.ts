import {
  assertLowercaseUuidV4,
  type AnnotationContext,
  type ElementAnnotation,
  type LowercaseUuidV4,
  type PageIdentityInput,
  type ResolutionInput,
} from '@scene-glass/contracts';

import {
  AnnotationController,
  type AnnotationBinding,
  type AnnotationControllerState,
  type AnnotationOperationResult,
  type AnnotationSnapshot,
  type CreatedAnnotation,
  type DeletedAnnotation,
  type UpdatedAnnotation,
} from './annotation/controller.js';
import { captureElementLocator, type ElementLocator } from './annotation/locator.js';
import { SCENE_GLASS_ID_ATTRIBUTE, stampElementIds } from './annotation/element-ids.js';
import { captureAnnotationContext } from './annotation/context.js';
import {
  createElementSelector,
  isSceneGlassOwnedElement,
  type ElementSelection,
  type ElementSelector,
  type SelectorCallbackError,
  type UnsupportedElementSelection,
} from './annotation/selector.js';
import {
  createDiagnosticsController,
  type DiagnosticConnection,
  type DiagnosticsController,
  type DiagnosticsTransport,
} from './diagnostics/controller.js';
import { createDiagnosticsPanel, type DiagnosticsPanel } from './diagnostics/panel.js';
import {
  resolvePageIdentity,
  type PageIdentityAuthority,
  type PageIdentityLocationSnapshot,
} from './identity/resolver.js';
import {
  SceneGlassClient,
  type DiagnosticsPanelOpener,
  type SceneGlassApi,
  type SceneGlassState,
} from './client.js';
import {
  McpClient,
  type AnnotationListToolResult,
  type AnnotationMutationToolResult,
  type DiagnosticRunCapability,
  type McpClientDependencies,
  type PromptExportToolResult,
} from './mcp-client.js';
import { createMeasurementSurface, type MeasurementSurface } from './ui/measure.js';
import { createSizeInspectorSurface, type SizeInspectorSurface } from './ui/size.js';
import { createShakeDetector, type ShakeDetector } from './ui/shake.js';
import { createDocumentNavigationAdapter } from './navigation/document.js';
import { createRenderSettler, type RenderSettler } from './navigation/render-settled.js';
import { createSpaNavigationAdapter } from './navigation/spa.js';
import type { NavigationAdapter } from './navigation/adapter.js';
import {
  createSceneGlassOverlay,
  type OverlayAnnotation,
  type SceneGlassOverlay,
  type SceneGlassOverlayCapabilities,
  type SceneGlassOverlayState,
} from './ui/overlay.js';

const DOM_QUIET_DEBOUNCE_MS = 75;
const MAX_SURROUNDING_TEXT_CODE_POINTS = 500;
const MAX_SURROUNDING_TEXT_BYTES = 4_096;
const MAX_DOM_ORDER = 2_147_483_647;

interface CapturedTarget {
  readonly context?: AnnotationContext;
  readonly domOrder: number;
  readonly locator: ElementLocator;
  readonly navigationGeneration: number;
  readonly resolution: ResolutionInput;
  readonly selectionGeneration: number;
  readonly surroundingText: string;
}
type RuntimeActionError = Error & {
  readonly code: string;
  readonly cleanupErrors?: readonly unknown[];
};

interface PageActionContext {
  readonly controllerGeneration: number;
  readonly navigationGeneration: number;
  readonly page: PageIdentityInput;
  readonly readyGeneration: number;
}

interface DiagnosticsSurface {
  readonly controller: DiagnosticsController;
  readonly panel: DiagnosticsPanel;
  readonly transport: DiagnosticMcpTransport;
}

export interface SceneGlassRuntimeOptions extends McpClientDependencies {
  readonly endpoint: string;
  readonly diagnosticEndpoint: string;
  readonly token: string;
  readonly projectId: string;
  readonly navigation: 'document' | 'spa';
  readonly window: Window;
  readonly document: Document;
  readonly openDiagnosticsPanel?: DiagnosticsPanelOpener;
  readonly pageIdentity?: PageIdentityAuthority;
}

/** Composes the browser primitives behind the stable one-line-loader API. */
export class SceneGlassRuntime {
  private readonly window: Window;
  private readonly document: Document;
  private readonly projectId: string;
  private readonly dependencies: McpClientDependencies;
  private readonly crypto: Pick<Crypto, 'getRandomValues'>;
  private readonly navigation: NavigationAdapter;
  private readonly settler: RenderSettler;
  private readonly client: SceneGlassClient;
  private readonly pageIdentityOverride: PageIdentityAuthority['override'];
  private readonly pageIdentityPolicy: PageIdentityAuthority['policy'];
  private readonly controller: AnnotationController;
  private readonly selector: ElementSelector;
  private readonly overlay: SceneGlassOverlay;
  private readonly api: SceneGlassApi;
  private diagnostics: DiagnosticsSurface | null = null;
  private diagnosticsTask: Promise<void> | null = null;
  private diagnosticsCleanupTask: Promise<void> | null = null;
  private diagnosticsOwner = 0;
  private mutationObserver: MutationObserver | null = null;
  private hostMutationTimer: number | null = null;
  private selectedTarget: CapturedTarget | null = null;
  /** 거리 측정: 기준 요소와 그리기 표면. 주석 선택과 독립적으로 동작한다. */
  private measurementSelector: ElementSelector | null = null;
  private measurementSurface: MeasurementSurface | null = null;
  private measureBase: Element | null = null;
  private measureEscapeBound = false;
  /** 크기 측정: 고른 요소 하나와 그 상자를 그리는 표면. */
  private sizeSelector: ElementSelector | null = null;
  private sizeSurface: SizeInspectorSurface | null = null;
  private sizeEscapeBound = false;
  private selectionEscapeBound = false;
  /** 마우스를 흔들어 선택을 켜는 제스처. 클릭이 아니라 포커스를 옮기지 않는다. */
  private readonly shake: ShakeDetector = createShakeDetector();
  private shakeBound = false;
  private captureTask: Promise<void> | null = null;
  private pageLoadTask: Promise<void> | null = null;
  private navigationGeneration = 0;
  private pageReadyGeneration = 0;
  private actionEpoch = 0;
  private selectionGeneration = 0;
  private pageReadyNavigationGeneration: number | null = null;
  private readyControllerGeneration: number | null = null;
  private readyPageId: PageIdentityInput['pageId'] | null = null;
  private navigationStarted = false;
  private navigationFailure: RuntimeActionError | null = null;
  private selectorCallbackFailure: RuntimeActionError | null = null;
  private destroyTask: Promise<void> | null = null;
  private destroyed = false;

  public constructor(options: SceneGlassRuntimeOptions) {
    this.window = options.window;
    this.document = options.document;
    this.projectId = options.projectId;
    this.dependencies = optionalDependencies(options);
    this.crypto = options.crypto ?? browserCrypto();
    this.navigation =
      options.navigation === 'spa'
        ? createSpaNavigationAdapter({ window: this.window, observeHashChanges: true })
        : createDocumentNavigationAdapter({ window: this.window });
    this.settler = createRenderSettler({ window: this.window, document: this.document });
    const pageIdentity = options.pageIdentity;
    const pageIdentityPolicy = pageIdentity?.policy;
    this.pageIdentityOverride = pageIdentity?.override;
    this.pageIdentityPolicy =
      pageIdentityPolicy === undefined
        ? undefined
        : Object.freeze({
            ...(pageIdentityPolicy.includeQuery === undefined
              ? {}
              : { includeQuery: pageIdentityPolicy.includeQuery }),
            ...(pageIdentityPolicy.includeHash === undefined
              ? {}
              : { includeHash: pageIdentityPolicy.includeHash }),
          });

    const diagnosticOpener = options.openDiagnosticsPanel ?? this.openDefaultDiagnostics;
    this.client = new SceneGlassClient({
      endpoint: options.endpoint,
      diagnosticEndpoint: options.diagnosticEndpoint,
      token: options.token,
      ...this.dependencies,
      openDiagnosticsPanel: diagnosticOpener,
      onHostReady: this.onHostReady,
      onStateChange: this.onClientState,
    });
    this.controller = new AnnotationController({
      port: {
        listAnnotations: async (page: PageIdentityInput): Promise<AnnotationSnapshot> =>
          annotationSnapshotFromToolResult(await this.client.listAnnotations(page)),
        createAnnotation: async (input): Promise<CreatedAnnotation> =>
          createdAnnotationFromToolResult(await this.client.createAnnotation(input)),
        updateAnnotation: async (input): Promise<UpdatedAnnotation> =>
          updatedAnnotationFromToolResult(await this.client.updateAnnotation(input)),
        deleteAnnotation: async (input): Promise<DeletedAnnotation> =>
          deletedAnnotationFromToolResult(await this.client.deleteAnnotation(input)),
      },
      onStateChange: this.onAnnotationState,
    });
    this.selector = createElementSelector({
      document: this.document,
      onCallbackError: this.onSelectorCallbackError,
      onSelect: this.onSelection,
      onUnsupportedSelect: this.onUnsupportedSelection,
    });
    this.overlay = createSceneGlassOverlay({
      document: this.document,
      onSelectionModeChange: this.setSelectionMode,
      onMeasureModeChange: this.setMeasureMode,
      onSizeModeChange: this.setSizeMode,
      onCreateMemo: this.createMemo,
      onUpdateMemo: this.updateMemo,
      onDeleteMemo: this.deleteMemo,
      onDeleteAllCurrentPage: this.deleteAllCurrentPage,
      onRetry: this.retryFromOverlay,
      onOpenDiagnostics: this.openDiagnosticsFromOverlay,
      onCloseDiagnostics: this.closeDiagnosticsFromOverlay,
      onExportProject: this.exportProject,
      onExportCurrentPage: this.exportCurrentPage,
    });
    this.overlay.open();

    const client = this.client;
    this.api = Object.freeze({
      get state(): SceneGlassState {
        return client.state;
      },
      notifyReady: (): void => client.notifyReady(),
      retry: (): Promise<void> => client.retry(),
      openDiagnostics: (): Promise<void> => client.openDiagnostics(),
      destroy: (): Promise<void> => this.destroy(),
    });
  }

  public getApi(): SceneGlassApi {
    return this.api;
  }

  public start(): Promise<void> {
    return this.client.start();
  }

  public destroy(): Promise<void> {
    if (this.destroyTask !== null) {
      return this.destroyTask;
    }
    if (this.destroyed) {
      return Promise.resolve();
    }
    this.destroyed = true;
    this.diagnosticsOwner += 1;
    this.navigationGeneration += 1;
    this.pageReadyGeneration += 1;
    this.actionEpoch += 1;
    this.selectionGeneration += 1;
    this.pageReadyNavigationGeneration = null;
    this.readyControllerGeneration = null;
    this.readyPageId = null;

    const deferred = createDeferredTask<void>();
    this.destroyTask = deferred.promise;
    void Promise.resolve()
      .then(() => this.performDestroy())
      .then(deferred.resolve, deferred.reject);
    return deferred.promise;
  }

  private async performDestroy(): Promise<void> {
    const cleanupErrors: unknown[] = [];
    const attemptCleanup = (cleanup: () => void): void => {
      try {
        cleanup();
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
    };

    attemptCleanup(() => {
      if (this.shakeBound && typeof this.document.removeEventListener === 'function') {
        this.document.removeEventListener('pointermove', this.onShakeMove);
      }
      this.shakeBound = false;
    });
    attemptCleanup(() => this.releaseSelectionEscape());
    attemptCleanup(() => this.stopMeasuring());
    attemptCleanup(() => this.measurementSurface?.destroy());
    attemptCleanup(() => this.stopSizeInspecting());
    attemptCleanup(() => this.sizeSurface?.destroy());
    attemptCleanup(() => this.stopMutationObserver());
    attemptCleanup(() => this.navigation.teardown());
    attemptCleanup(() => this.settler.teardown());
    attemptCleanup(() => this.selector.destroy());
    attemptCleanup(() => this.overlay.destroy());
    this.selectedTarget = null;
    this.captureTask = null;
    this.pageLoadTask = null;

    const diagnosticsCleanup = this.destroyDiagnostics();
    try {
      await diagnosticsCleanup;
    } catch (error: unknown) {
      cleanupErrors.push(error);
    }

    attemptCleanup(() => this.controller.destroy());

    let clientCleanup: Promise<void>;
    try {
      clientCleanup = this.client.destroy();
    } catch (error: unknown) {
      cleanupErrors.push(error);
      clientCleanup = Promise.resolve();
    }

    try {
      await clientCleanup;
    } catch (error: unknown) {
      cleanupErrors.push(error);
    }

    if (cleanupErrors.length > 0) {
      throw new AggregateError(cleanupErrors, 'Scene Glass runtime cleanup failed');
    }
  }

  private readonly onClientState = (state: SceneGlassState): void => {
    if (this.destroyed) {
      return;
    }
    switch (state) {
      case 'ready':
        this.startNavigation();
        return;
      case 'booting':
      case 'connecting':
        this.invalidatePage();
        return;
      case 'unavailable':
        this.invalidatePage();
        this.setOverlayState({ status: { kind: 'error', code: 'SCG_CLIENT_UNAVAILABLE' } });
        return;
      case 'access-error':
        this.invalidatePage();
        this.setOverlayState({ status: { kind: 'error', code: 'SCG_CLIENT_ACCESS_DENIED' } });
        return;
      case 'destroyed':
        return;
    }
  };

  private readonly onHostReady = (): void => {
    if (!this.destroyed && this.client.state === 'ready' && this.navigationFailure === null) {
      this.startNavigation();
    }
  };

  private readonly onAnnotationState = (state: AnnotationControllerState): void => {
    if (!this.isCurrentPageState(state)) {
      return;
    }
    this.renderAnnotationState(state);
  };

  private readonly onSelection = (selection: ElementSelection): void => {
    if (selection?.status !== 'selected' || this.destroyed || !this.isPageReady()) {
      return;
    }
    this.selectionGeneration += 1;
    this.selectedTarget = null;
    this.captureTask = null;
    const navigationGeneration = this.navigationGeneration;
    const selectionGeneration = this.selectionGeneration;
    const task = this.captureSelectedElement(
      selection.element,
      navigationGeneration,
      selectionGeneration,
    );
    this.captureTask = task;
    void task.then(
      () => {
        if (this.captureTask === task) {
          this.captureTask = null;
        }
      },
      () => {
        // Keep the rejected task available to createMemo so infrastructure and
        // publication failures remain observable instead of being reclassified.
      },
    );
  };

  /** 선택 모드를 Esc 로 끈다. 버튼 토글과 같은 경로라 패널 표시도 함께 돌아온다. */
  /**
   * 마우스를 흔들면 요소 선택을 켠다.
   *
   * 패널 버튼을 누르는 길이 언제나 열려 있지는 않다. 모달이 포커스를 가두면 Scene Glass 버튼을
   * 누르는 순간 포커스가 대화상자 밖으로 나가고 호스트가 팝업을 닫아 버린다. 제스처는 포커스를
   * 건드리지 않으므로, 클릭이 막힌 자리에서도 그대로 쓸 수 있다.
   *
   * 켜는 쪽으로만 쓴다. 끄는 길은 이미 둘(버튼·Esc) 있고, 흔들어서 끄면 선택하려고 마우스를
   * 크게 움직이다 실수로 꺼질 수 있다.
   */
  private readonly onShakeMove = (event: PointerEvent): void => {
    if (this.destroyed || !this.isPageReady()) {
      return;
    }
    // 이미 고르는 중이거나, 방금 고른 요소로 메모를 쓰는 중이면 제스처가 할 일이 없다. 다시
    // 켜면 선택 세대가 올라가 작성기가 기대고 있던 대상이 사라진다 — 쓰던 글은 남고 저장만
    // 되지 않는 상태다. 대상은 저장하거나 작성을 취소할 때 풀리고, 그때 제스처도 돌아온다.
    if (
      this.selector.isReviewing ||
      this.measurementSelector !== null ||
      this.sizeSelector !== null ||
      this.selectedTarget !== null
    ) {
      this.shake.reset();
      return;
    }
    if (!this.shake.push(event.clientX, event.clientY, event.timeStamp)) {
      return;
    }
    void this.setSelectionMode({ active: true }).catch(() => {
      // 제스처로 켜는 것이 실패해도 화면을 막지 않는다. 버튼은 그대로 쓸 수 있다.
    });
  };

  private readonly onSelectionKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape' || event.altKey || event.ctrlKey || event.metaKey) {
      return;
    }
    if (!this.selectionEscapeBound) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void this.setSelectionMode({ active: false }).catch(() => {
      // 끄기가 실패해도 화면을 막지 않는다.
    });
  };

  private releaseSelectionEscape(): void {
    if (this.selectionEscapeBound) {
      this.document.removeEventListener('keydown', this.onSelectionKeyDown, true);
      this.selectionEscapeBound = false;
    }
  }

  private readonly onUnsupportedSelection = (selection: UnsupportedElementSelection): void => {
    if (this.destroyed || !this.isPageReady()) {
      return;
    }
    this.selectionGeneration += 1;
    this.selectedTarget = null;
    this.captureTask = null;
    this.setOverlayState({
      pendingSelectionElement: null,
      status: { kind: 'error', code: unsupportedSelectionCode(selection.reason) },
    });
  };

  private readonly onSelectorCallbackError = ({ error, phase }: SelectorCallbackError): void => {
    const failure = Object.assign(actionError('SCG_SELECTOR_CALLBACK_FAILED', error), { phase });
    const publicationErrors: unknown[] = [];
    const attemptPublication = (publication: () => void): void => {
      try {
        publication();
      } catch (publicationError: unknown) {
        publicationErrors.push(publicationError);
      }
    };

    this.selectorCallbackFailure = failure;
    if (!this.destroyed) {
      attemptPublication(() =>
        this.controller.setManualError('Scene Glass 요소 선택 콜백에 실패했습니다.', failure.code),
      );
      attemptPublication(() =>
        this.setOverlayState({ status: { kind: 'error', code: failure.code } }),
      );
    }
    if (publicationErrors.length > 0) {
      this.selectorCallbackFailure = retainCleanupErrors(failure, publicationErrors);
    }
  };

  /**
   * 거리 측정 모드. 클릭으로 기준 요소를 고르고, 그 뒤 마우스를 올리는 요소와의 간격을 그린다.
   * 다시 클릭하면 기준이 그 요소로 바뀌므로, 끄지 않고도 기준을 옮길 수 있다.
   *
   * 주석 선택기와 별도의 선택기를 쓴다. 하나를 공유하면 측정 중에 메모 편집기가 열리거나,
   * 메모를 쓰는 도중 기준이 바뀐다.
   */
  private readonly setMeasureMode = async ({
    active,
  }: {
    readonly active: boolean;
  }): Promise<void> => {
    if (this.destroyed) {
      throw actionError('SCG_CLIENT_DESTROYED');
    }
    this.stopMeasuring();
    if (!active) {
      this.setOverlayState({ measureMode: false });
      return;
    }

    this.stopSizeInspecting();
    this.measurementSurface ??= createMeasurementSurface(this.document);
    const selector = createElementSelector({
      document: this.document,
      onCallbackError: this.onSelectorCallbackError,
      onSelect: this.onMeasureSelect,
      onSelectionChange: this.onMeasureHover,
    });
    this.measurementSelector = selector;
    selector.start();
    // 측정 중에는 Esc 가 Scene Glass 의 것이다. 다른 모드가 없는 동안만 잡고, 끌 때 돌려준다.
    this.document.addEventListener('keydown', this.onMeasureKeyDown, true);
    this.measureEscapeBound = true;
    if (!selector.isReviewing) {
      this.stopMeasuring();
      throw actionError('SCG_SELECTION_UNAVAILABLE');
    }
    this.setOverlayState({ measureMode: true, sizeMode: false });
  };

  /** 클릭한 요소를 기준으로 삼는다. 선택기는 계속 켜 두어 곧바로 다음 요소를 훑을 수 있다. */
  private readonly onMeasureSelect = (selection: ElementSelection): void => {
    if (selection?.status !== 'selected' || this.destroyed) {
      return;
    }
    this.measureBase = selection.element;
    this.measurementSurface?.hide();
    this.measurementSelector?.start();
  };

  /** 기준이 정해진 뒤에만 그린다. 같은 요소 위에서는 잴 것이 없다. */
  private readonly onMeasureHover = (selection: ElementSelection): void => {
    const base = this.measureBase;
    const surface = this.measurementSurface;
    if (base === null || surface === null || this.destroyed) {
      return;
    }
    if (selection?.status !== 'selected' || selection.element === base) {
      surface.hide();
      return;
    }
    if (!this.document.documentElement?.contains(base)) {
      this.measureBase = null;
      surface.hide();
      return;
    }
    surface.show(base.getBoundingClientRect(), selection.element.getBoundingClientRect());
  };

  /**
   * Esc 로 측정을 끈다. 버튼 토글과 같은 경로를 타므로 패널 표시도 함께 돌아온다.
   *
   * 캡처 단계에서 잡고 전파를 멈춘다 — 측정 중 Esc 는 팝업을 닫는 등 호스트의 동작이 아니라
   * 이 모드를 끄는 뜻이어야 한다. 조합키가 눌린 Esc 는 호스트 것으로 넘긴다.
   */
  private readonly onMeasureKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape' || event.altKey || event.ctrlKey || event.metaKey) {
      return;
    }
    if (this.measurementSelector === null) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void this.setMeasureMode({ active: false }).catch(() => {
      // 끄는 동작이 실패해도 화면을 막지 않는다. 선택기와 표면은 이미 정리된 뒤다.
    });
  };

  private stopMeasuring(): void {
    if (this.measureEscapeBound) {
      this.document.removeEventListener('keydown', this.onMeasureKeyDown, true);
      this.measureEscapeBound = false;
    }
    this.measurementSelector?.stop();
    this.measurementSelector = null;
    this.measureBase = null;
    this.measurementSurface?.hide();
  }

  /**
   * 크기 측정 모드. 거리 측정과 같은 손놀림으로 요소를 고르되, 재는 대상이 둘 사이가 아니라
   * 고른 요소 자신이다 — 가로·세로를 곧바로 보여 주고, 모퉁이 뱃지를 누르면 패딩과 마진까지
   * 편다. 다시 클릭하면 대상이 그 요소로 옮겨 가므로 끄지 않고 계속 훑을 수 있다.
   *
   * 거리 측정과는 한 번에 하나만 켠다. 둘 다 켜면 선택기가 둘이라 한 번의 클릭이 두 곳에서
   * 처리되고, Esc 도 어느 쪽을 끄는 것인지 정해지지 않는다.
   */
  private readonly setSizeMode = async ({
    active,
  }: {
    readonly active: boolean;
  }): Promise<void> => {
    if (this.destroyed) {
      throw actionError('SCG_CLIENT_DESTROYED');
    }
    this.stopSizeInspecting();
    if (!active) {
      this.setOverlayState({ sizeMode: false });
      return;
    }

    this.stopMeasuring();
    this.sizeSurface ??= createSizeInspectorSurface(this.document);
    const selector = createElementSelector({
      document: this.document,
      onCallbackError: this.onSelectorCallbackError,
      onSelect: this.onSizeSelect,
    });
    this.sizeSelector = selector;
    selector.start();
    this.document.addEventListener('keydown', this.onSizeKeyDown, true);
    this.sizeEscapeBound = true;
    if (!selector.isReviewing) {
      this.stopSizeInspecting();
      throw actionError('SCG_SELECTION_UNAVAILABLE');
    }
    this.setOverlayState({ measureMode: false, sizeMode: true });
  };

  /** 고른 요소를 계속 그린다. 선택기는 다시 켜 두어 곧바로 다음 요소로 옮겨 갈 수 있다. */
  private readonly onSizeSelect = (selection: ElementSelection): void => {
    if (selection?.status !== 'selected' || this.destroyed) {
      return;
    }
    this.sizeSurface?.show(selection.element);
    this.sizeSelector?.start();
  };

  /**
   * Esc 로 접는다. 여백 카드가 열려 있으면 그것부터 닫는다 — 카드를 보려고 켠 모드를 카드
   * 하나 닫자고 통째로 끄면, 다시 고르는 일부터 시작해야 한다.
   */
  private readonly onSizeKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape' || event.altKey || event.ctrlKey || event.metaKey) {
      return;
    }
    if (this.sizeSelector === null) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (this.sizeSurface?.collapse() === true) {
      return;
    }
    void this.setSizeMode({ active: false }).catch(() => {
      // 끄는 동작이 실패해도 화면을 막지 않는다. 선택기와 표면은 이미 정리된 뒤다.
    });
  };

  private stopSizeInspecting(): void {
    if (this.sizeEscapeBound) {
      this.document.removeEventListener('keydown', this.onSizeKeyDown, true);
      this.sizeEscapeBound = false;
    }
    this.sizeSelector?.stop();
    this.sizeSelector = null;
    this.sizeSurface?.hide();
  }

  private readonly setSelectionMode = async ({
    active,
  }: {
    readonly active: boolean;
  }): Promise<void> => {
    if (this.destroyed) {
      throw actionError('SCG_CLIENT_DESTROYED');
    }
    if (active) {
      this.selectorCallbackFailure = null;
      this.captureReadyPage();
      this.selectionGeneration += 1;
      this.selectedTarget = null;
      this.captureTask = null;
      // 재는 일과 고르는 일을 겹쳐 켜지 않는다. 선택기가 둘이면 한 번의 클릭이 양쪽에서
      // 처리되어, 메모 대상을 고르는 클릭이 재던 대상까지 옮겨 버린다.
      this.stopSizeInspecting();
      // 패널에도 알린다. 버튼으로 켜면 패널이 스스로 상태를 바꾸지만 제스처처럼 런타임에서
      // 켜는 길은 그렇지 않아, 알리지 않으면 자동 최소화도 버튼 표시도 걸리지 않는다.
      this.setOverlayState({ pendingSelectionElement: null, selectionMode: true, sizeMode: false });
      this.selector.stop();
      this.selector.start();
      if (!this.selector.isReviewing) {
        this.releaseSelectionEscape();
        throw actionError('SCG_SELECTION_UNAVAILABLE');
      }
      // 측정과 같은 약속이다 — 켜 두는 동안만 Esc 를 잡고, 끌 때 호스트에 돌려준다.
      this.document.addEventListener('keydown', this.onSelectionKeyDown, true);
      this.selectionEscapeBound = true;
      return;
    }
    this.releaseSelectionEscape();
    this.invalidateSelection();
  };

  private readonly createMemo = async ({ memo }: { readonly memo: string }): Promise<void> => {
    const context = this.captureReadyPage();
    const selectionGeneration = this.selectionGeneration;
    const pendingCapture = this.captureTask;
    if (pendingCapture !== null) {
      await pendingCapture;
      this.assertCurrentPageAction(context);
    }
    if (this.selectionGeneration !== selectionGeneration) {
      throw actionError('SCG_SELECTION_REQUIRED');
    }
    if (this.selectorCallbackFailure !== null) {
      throw this.selectorCallbackFailure;
    }
    const target = this.selectedTarget;
    if (
      target === null ||
      target.navigationGeneration !== context.navigationGeneration ||
      target.selectionGeneration !== selectionGeneration
    ) {
      throw actionError('SCG_SELECTION_REQUIRED');
    }
    this.assertCurrentPageAction(context);
    const result = await this.controller.create({
      operationId: createOperationId(this.crypto),
      locator: target.locator,
      memo,
      surroundingText: target.surroundingText,
      domOrder: target.domOrder,
      resolution: target.resolution,
      ...(target.context === undefined ? {} : { context: target.context }),
    });
    this.assertCurrentPageAction(context);
    requireApplied(result);
    if (this.selectionGeneration === selectionGeneration) {
      this.selectedTarget = null;
    }
    this.setOverlayState({ pendingSelectionElement: null });
  };

  private readonly updateMemo = async ({
    annotationId,
    memo,
  }: {
    readonly annotationId: string;
    readonly memo: string;
  }): Promise<void> => {
    const context = this.captureReadyPage();
    const result = await this.controller.update({
      annotationId: annotationId as ElementAnnotation['id'],
      operationId: createOperationId(this.crypto),
      patch: { memo },
    });
    this.assertCurrentPageAction(context);
    requireApplied(result);
  };

  private readonly deleteMemo = async ({
    annotationId,
  }: {
    readonly annotationId: string;
  }): Promise<void> => {
    const context = this.captureReadyPage();
    const result = await this.controller.delete({
      annotationId: annotationId as ElementAnnotation['id'],
      operationId: createOperationId(this.crypto),
    });
    this.assertCurrentPageAction(context);
    requireApplied(result);
  };

  private readonly deleteAllCurrentPage = async (): Promise<void> => {
    const context = this.captureReadyPage();
    const annotationIds = this.controller.getState().annotations.map((annotation) => annotation.id);
    for (const annotationId of annotationIds) {
      this.assertCurrentPageAction(context);
      const result = await this.controller.delete({
        annotationId,
        operationId: createOperationId(this.crypto),
      });
      this.assertCurrentPageAction(context);
      requireApplied(result);
    }
    this.assertCurrentPageAction(context);
  };

  private readonly retryFromOverlay = async (): Promise<void> => {
    if (this.destroyed) {
      throw actionError('SCG_CLIENT_DESTROYED');
    }
    const retryNavigation = this.navigationFailure !== null;
    if (this.client.state === 'unavailable') {
      await this.client.retry();
      const retryState = this.client.state as SceneGlassState;
      if (retryState !== 'ready') {
        throw actionError(
          retryState === 'access-error' ? 'SCG_CLIENT_ACCESS_DENIED' : 'SCG_CLIENT_UNAVAILABLE',
        );
      }
    } else if (this.client.state !== 'ready' || (this.navigationStarted && !retryNavigation)) {
      throw actionError(
        this.client.state === 'access-error'
          ? 'SCG_CLIENT_ACCESS_DENIED'
          : 'SCG_CLIENT_UNAVAILABLE',
      );
    }

    if (this.navigationStarted && retryNavigation) {
      this.navigationFailure = null;
      this.requestPageReload();
    } else if (!this.navigationStarted) {
      this.navigationFailure = null;
      this.startNavigation();
    }
    if (!this.navigationStarted) {
      throw actionError('SCG_NAVIGATION_UNAVAILABLE');
    }
  };

  private readonly openDiagnosticsFromOverlay = async (): Promise<void> => {
    this.assertClientReady();
    await this.client.openDiagnostics();
  };

  private readonly closeDiagnosticsFromOverlay = async (): Promise<void> => {
    await this.destroyDiagnostics();
  };

  private readonly exportProject = async (): Promise<string> => {
    this.assertClientReady();
    const result = await this.client.exportPrompt({ mode: 'project' });
    return markdownFrom(result);
  };

  private readonly exportCurrentPage = async (): Promise<string> => {
    const context = this.captureReadyPage();
    const result = await this.client.exportPrompt({
      mode: 'page',
      pageId: context.page.pageId,
    });
    this.assertCurrentPageAction(context);
    return markdownFrom(result);
  };

  private readonly openDefaultDiagnostics = (
    capability: DiagnosticRunCapability,
  ): Promise<void> => {
    const owner = ++this.diagnosticsOwner;
    return this.enqueueDiagnosticsOperation(() => this.replaceDiagnostics(owner, capability));
  };

  private async replaceDiagnostics(
    owner: number,
    capability: DiagnosticRunCapability,
  ): Promise<void> {
    this.assertCurrentDiagnosticsOwner(owner);
    await this.destroyDiagnosticsSurface();
    this.assertCurrentDiagnosticsOwner(owner);

    let transport: DiagnosticMcpTransport | null = null;
    let controller: DiagnosticsController | null = null;
    let panel: DiagnosticsPanel | null = null;
    try {
      transport = new DiagnosticMcpTransport(capability, this.dependencies);
      this.assertCurrentDiagnosticsOwner(owner);

      controller = createDiagnosticsController({
        projectId: this.projectId,
        transport,
      });
      this.assertCurrentDiagnosticsOwner(owner);

      panel = createDiagnosticsPanel({ document: this.document, controller });
      this.assertCurrentDiagnosticsOwner(owner);

      panel.open();
      this.assertCurrentDiagnosticsOwner(owner);
      this.diagnostics = { transport, controller, panel };
      if (!this.destroyed) {
        this.setOverlayState({ diagnosticsOpen: true });
      }
    } catch (error: unknown) {
      const cleanupErrors: unknown[] = [];
      try {
        await this.destroyDiagnosticResources({ transport, controller, panel });
      } catch (cleanupError: unknown) {
        cleanupErrors.push(cleanupError);
      }
      throw retainConstructionCleanupErrors(error, cleanupErrors);
    }
  }

  private startNavigation(): void {
    if (this.destroyed) {
      return;
    }
    if (this.navigationStarted) {
      this.requestPageReload();
      return;
    }

    try {
      this.navigation.start(() => this.requestPageReload());
      this.navigationStarted = true;
      this.startMutationObserver();
      // 제스처는 편의 기능이다 — 이벤트를 못 붙이는 문서(축소된 테스트 대역 등)에서도
      // 나머지 기동은 그대로 진행되어야 한다.
      if (typeof this.document.addEventListener === 'function') {
        this.document.addEventListener('pointermove', this.onShakeMove, { passive: true });
        this.shakeBound = true;
      }
      this.stampHostElementIds();
      this.restoreOwnAccessibility();
      this.navigationFailure = null;
      this.requestPageReload();
    } catch (error: unknown) {
      this.navigationStarted = false;
      const cleanupErrors: unknown[] = [];
      try {
        this.navigation.teardown();
      } catch (cleanupError: unknown) {
        cleanupErrors.push(cleanupError);
      }
      try {
        this.stopMutationObserver();
      } catch (cleanupError: unknown) {
        cleanupErrors.push(cleanupError);
      }
      this.navigationFailure = retainCleanupErrors(navigationStartupFailure(error), cleanupErrors);
      this.invalidatePage();
      this.setOverlayState({
        status: { kind: 'error', code: this.navigationFailure.code },
      });
    }
  }

  /**
   * `soft` re-resolves the same page after the host mutated its own DOM. The page
   * did not change, so nothing may be invalidated: a host that re-renders
   * continuously would otherwise blank and refill the badges on every frame,
   * clear a memo the user is typing, and strand the captured selection.
   */
  private requestPageReload(soft = false): void {
    if (
      !this.navigationStarted ||
      this.navigationFailure !== null ||
      this.destroyed ||
      this.client.state !== 'ready'
    ) {
      return;
    }
    const generation = this.invalidatePage(soft);
    const task = this.settlePage(generation, soft);
    this.pageLoadTask = task;
    void task.then(
      () => {
        if (this.pageLoadTask === task) {
          this.pageLoadTask = null;
        }
      },
      (error: unknown) => {
        if (this.pageLoadTask === task) {
          this.pageLoadTask = null;
        }
        if (this.isCurrentNavigationGeneration(generation)) {
          this.setNavigationFailure(actionError('SCG_NAVIGATION_UNAVAILABLE', error));
        }
      },
    );
  }

  private async settlePage(generation: number, soft = false): Promise<void> {
    const settled = await this.settler.waitFor(generation);
    if (!this.isCurrentNavigationGeneration(generation)) {
      return;
    }
    if (!settled) {
      this.setNavigationFailure(actionError('SCG_RENDER_SETTLEMENT_FAILED'));
      return;
    }

    const location: PageIdentityLocationSnapshot = Object.freeze({
      pathname: this.window.location.pathname,
      search: this.window.location.search,
      hash: this.window.location.hash,
    });
    const configuredOverride = this.pageIdentityOverride;
    let override: string | undefined;
    let page: PageIdentityInput;
    try {
      if (typeof configuredOverride === 'function') {
        override = await configuredOverride(
          Object.freeze({
            location,
            navigationGeneration: generation,
          }),
        );
        if (!this.isCurrentNavigationGeneration(generation)) {
          return;
        }
      } else {
        override = configuredOverride;
      }

      if (!this.isCurrentNavigationGeneration(generation)) {
        return;
      }
      page = await resolvePageIdentity({
        location,
        ...(override === undefined ? {} : { override }),
        ...(this.pageIdentityPolicy === undefined ? {} : { policy: this.pageIdentityPolicy }),
      });
    } catch (error: unknown) {
      if (this.isCurrentNavigationGeneration(generation)) {
        const failure = actionError('SCG_PAGE_IDENTITY', error);
        const publicationErrors: unknown[] = [];
        const attemptPublication = (publication: () => void): void => {
          try {
            publication();
          } catch (publicationError: unknown) {
            publicationErrors.push(publicationError);
          }
        };
        this.navigationFailure = failure;
        attemptPublication(() =>
          this.controller.setManualError(
            'Scene Glass가 메모 검토를 위해 현재 페이지를 확인하지 못했습니다.',
            failure.code,
          ),
        );
        attemptPublication(() =>
          this.setOverlayState({ status: { kind: 'error', code: failure.code } }),
        );
        if (publicationErrors.length > 0) {
          this.navigationFailure = retainCleanupErrors(failure, publicationErrors);
        }
      }
      return;
    }

    if (!this.isCurrentNavigationGeneration(generation)) {
      return;
    }
    this.controller.setPage(page);
    const result = await this.controller.load();
    if (!this.isCurrentNavigationGeneration(generation)) {
      return;
    }
    if (result.status !== 'applied') {
      if (result.status === 'failed') {
        this.setOverlayState({ status: { kind: 'error', code: result.error.code } });
      }
      return;
    }
    const state = this.controller.getState();
    if (state.page === undefined || state.revision === undefined) {
      this.setOverlayState({ status: { kind: 'error', code: 'SCG_ANNOTATION_STATE' } });
      return;
    }
    if (!soft) {
      this.pageReadyGeneration += 1;
      this.actionEpoch += 1;
    }
    this.pageReadyNavigationGeneration = generation;
    this.readyControllerGeneration = state.generation;
    this.readyPageId = state.page.pageId;
    this.renderAnnotationState(state);
    this.setOverlayState({ pageReady: true, status: { kind: 'ready' } });
  }

  private isCurrentNavigationGeneration(generation: number): boolean {
    return (
      !this.destroyed &&
      this.navigationStarted &&
      this.client.state === 'ready' &&
      this.navigationGeneration === generation &&
      this.settler.isCurrent(generation)
    );
  }

  private invalidatePage(soft = false): number {
    if (soft) {
      // Invalidate nothing: same page, same navigation, same selection. Bumping a
      // generation here would strand the selection that createMemo matches
      // against navigationGeneration and fail every save with
      // SCG_SELECTION_REQUIRED.
      return this.navigationGeneration;
    }
    this.navigationGeneration += 1;
    this.pageReadyGeneration += 1;
    this.actionEpoch += 1;
    this.pageReadyNavigationGeneration = null;
    this.readyControllerGeneration = null;
    this.readyPageId = null;
    this.invalidateSelection();
    this.setOverlayState({
      annotations: [],
      pageReady: false,
      status: { kind: 'working' },
    });
    return this.navigationGeneration;
  }

  private invalidateSelection(): void {
    this.selectionGeneration += 1;
    this.selectedTarget = null;
    this.captureTask = null;
    this.selector.stop();
    this.setOverlayState({ pendingSelectionElement: null, selectionMode: false });
  }

  private overlayCapabilities(): SceneGlassOverlayCapabilities {
    const clientReady = !this.destroyed && this.client.state === 'ready';
    const pageReady = this.isPageReady();
    return Object.freeze({
      canCreateMemo: pageReady,
      canDeleteMemo: pageReady,
      canDeleteAllCurrentPage: pageReady,
      canExportCurrentPage: pageReady,
      canExportProject: clientReady,
      canOpenDiagnostics: clientReady,
      canRetry:
        this.client.state === 'unavailable' || (clientReady && this.navigationFailure !== null),
      canMeasure: clientReady,
      canInspectSize: clientReady,
      canSelect: pageReady,
      canUpdateMemo: pageReady,
    });
  }

  private setOverlayState(state: SceneGlassOverlayState): void {
    this.overlay.setState({
      ...state,
      actionEpoch: this.actionEpoch,
      capabilities: this.overlayCapabilities(),
    });
  }

  private assertClientReady(): void {
    if (this.destroyed) {
      throw actionError('SCG_CLIENT_DESTROYED');
    }
    if (this.client.state !== 'ready') {
      throw actionError(
        this.client.state === 'access-error'
          ? 'SCG_CLIENT_ACCESS_DENIED'
          : 'SCG_CLIENT_UNAVAILABLE',
      );
    }
  }

  private isCurrentPageState(state: AnnotationControllerState): boolean {
    return (
      this.isPageReady() &&
      this.readyControllerGeneration === state.generation &&
      this.readyPageId === state.page?.pageId
    );
  }

  private isPageReady(): boolean {
    return (
      !this.destroyed &&
      this.navigationStarted &&
      this.client.state === 'ready' &&
      this.pageReadyNavigationGeneration === this.navigationGeneration &&
      this.readyControllerGeneration !== null &&
      this.readyPageId !== null
    );
  }

  private captureReadyPage(): PageActionContext {
    const state = this.controller.getState();
    if (
      !this.isCurrentPageState(state) ||
      state.page === undefined ||
      state.revision === undefined
    ) {
      throw actionError('SCG_PAGE_UNREADY');
    }
    return Object.freeze({
      controllerGeneration: state.generation,
      navigationGeneration: this.navigationGeneration,
      page: state.page,
      readyGeneration: this.pageReadyGeneration,
    });
  }

  private assertCurrentPageAction(context: PageActionContext): void {
    const state = this.controller.getState();
    if (
      !this.isCurrentPageState(state) ||
      context.navigationGeneration !== this.navigationGeneration ||
      context.readyGeneration !== this.pageReadyGeneration ||
      context.controllerGeneration !== state.generation ||
      context.page.pageId !== state.page?.pageId
    ) {
      throw actionError('SCG_PAGE_TRANSITION');
    }
  }

  private renderAnnotationState(state: AnnotationControllerState): void {
    this.setOverlayState({
      annotations: toOverlayAnnotations(state.annotations, state.bindings),
      pageReady: true,
      ...(state.error === undefined
        ? {}
        : { status: { kind: 'error' as const, code: state.error.code } }),
    });
  }

  private async captureSelectedElement(
    element: Element,
    navigationGeneration: number,
    selectionGeneration: number,
  ): Promise<void> {
    let locator: ElementLocator;
    try {
      locator = await captureElementLocator(element);
    } catch (error: unknown) {
      this.publishSelectionCaptureFailure(error, navigationGeneration, selectionGeneration);
      return;
    }

    if (!this.isCurrentSelection(navigationGeneration, selectionGeneration)) {
      return;
    }
    if (
      !isMountedHostLightDomElement(element, this.document) ||
      isSceneGlassOwnedElement(element)
    ) {
      this.publishSelectionCaptureFailure(
        actionError('SCG_SELECTION_CAPTURE_FAILED'),
        navigationGeneration,
        selectionGeneration,
      );
      return;
    }
    const domOrder = domOrderFor(element, this.document);
    if (domOrder === undefined) {
      this.publishSelectionCaptureFailure(
        actionError('SCG_SELECTION_CAPTURE_FAILED'),
        navigationGeneration,
        selectionGeneration,
      );
      return;
    }

    if (!this.isCurrentSelection(navigationGeneration, selectionGeneration)) {
      return;
    }
    let annotationContext: AnnotationContext | undefined;
    try {
      annotationContext = captureAnnotationContext(element);
    } catch {
      // Context is optional; failure must not prevent memo creation.
    }
    this.selectedTarget = Object.freeze({
      locator,
      surroundingText: surroundingTextFor(element),
      domOrder,
      navigationGeneration,
      resolution: Object.freeze({ status: 'resolved', reason: null }),
      selectionGeneration,
      ...(annotationContext === undefined ? {} : { context: annotationContext }),
    });
    this.selector.stop();
    this.releaseSelectionEscape();
    this.setOverlayState({ pendingSelectionElement: element, selectionMode: false });
  }

  private publishSelectionCaptureFailure(
    error: unknown,
    navigationGeneration: number,
    selectionGeneration: number,
  ): void {
    if (!this.isCurrentSelection(navigationGeneration, selectionGeneration)) {
      return;
    }

    const primary = selectionCaptureFailure(error);
    const cleanupErrors: unknown[] = [];
    const attemptPublication = (publication: () => void): void => {
      try {
        publication();
      } catch (publicationError: unknown) {
        cleanupErrors.push(publicationError);
      }
    };

    this.selectedTarget = null;
    attemptPublication(() => this.selector.stop());
    attemptPublication(() =>
      this.setOverlayState({ pendingSelectionElement: null, selectionMode: false }),
    );
    attemptPublication(() =>
      this.controller.setManualError(
        'Scene Glass가 선택한 요소를 캡처하지 못했습니다.',
        primary.code,
      ),
    );

    if (cleanupErrors.length > 0) {
      throw retainCleanupErrors(primary, cleanupErrors);
    }
  }

  private isCurrentSelection(navigationGeneration: number, selectionGeneration: number): boolean {
    return (
      !this.destroyed &&
      this.navigationGeneration === navigationGeneration &&
      this.selectionGeneration === selectionGeneration
    );
  }

  private startMutationObserver(): void {
    if (this.mutationObserver !== null || this.destroyed) {
      return;
    }
    const MutationObserverConstructor =
      this.document.defaultView?.MutationObserver ?? globalThis.MutationObserver;
    if (typeof MutationObserverConstructor !== 'function') {
      throw actionError('SCG_MUTATION_OBSERVER_UNAVAILABLE');
    }
    const root = this.document.documentElement;
    if (root === null) {
      throw actionError('SCG_MUTATION_OBSERVER_UNAVAILABLE');
    }

    let observer: MutationObserver | null = null;
    try {
      observer = new MutationObserverConstructor(this.onHostMutations);
      observer.observe(root, {
        attributes: true,
        characterData: true,
        childList: true,
        subtree: true,
      });
      this.mutationObserver = observer;
    } catch (error: unknown) {
      const cleanupErrors: unknown[] = [];
      const observerToDisconnect = observer;
      this.mutationObserver = null;
      observer = null;
      try {
        observerToDisconnect?.disconnect();
      } catch (cleanupError: unknown) {
        cleanupErrors.push(cleanupError);
      }
      throw retainCleanupErrors(
        actionError('SCG_MUTATION_OBSERVER_UNAVAILABLE', error),
        cleanupErrors,
      );
    }
  }
  private stopMutationObserver(): void {
    const hostMutationTimer = this.hostMutationTimer;
    const observer = this.mutationObserver;
    this.hostMutationTimer = null;
    this.mutationObserver = null;

    const cleanupErrors: unknown[] = [];
    if (hostMutationTimer !== null) {
      try {
        this.window.clearTimeout(hostMutationTimer);
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
    }
    try {
      observer?.disconnect();
    } catch (error: unknown) {
      cleanupErrors.push(error);
    }
    if (cleanupErrors.length === 1) {
      throw cleanupErrors[0];
    }
    if (cleanupErrors.length > 1) {
      throw new AggregateError(cleanupErrors, 'Scene Glass mutation observer cleanup failed');
    }
  }

  /**
   * 모달이 열리면 라이브러리는 바깥 요소를 `aria-hidden` 으로 가린다. Scene Glass 는 그
   * "바깥" 에 있어 함께 가려지지만, 이 패널은 모달에 갇혀야 할 호스트 UI 가 아니라 그 위에서
   * 화면을 검토하는 도구다. 자기 소유 요소에 붙은 표시만 걷는다 — 호스트 요소는 건드리지
   * 않으므로 모달이 나머지를 가리는 동작은 그대로다.
   */
  private restoreOwnAccessibility(): void {
    if (typeof this.document.querySelectorAll !== 'function') {
      return;
    }
    for (const element of this.document.querySelectorAll(
      '.scg-ui-overlay, .scg-ui-launcher, .scg-ui-editor, .scg-ui-badges, .scg-measure-layer, .scg-size-layer',
    )) {
      if (element.getAttribute('aria-hidden') === 'true') {
        element.removeAttribute('aria-hidden');
      }
      if (element.hasAttribute('inert')) {
        element.removeAttribute('inert');
      }
    }
  }

  /** Re-labels the host's elements so a re-render cannot strand an annotation. */
  private stampHostElementIds(): void {
    const root = this.document.documentElement;
    if (root === null || this.destroyed) {
      return;
    }
    try {
      stampElementIds(root, isSceneGlassOwnedElement);
    } catch {
      // Labelling improves on the fingerprint; it is never a precondition, so a
      // host that refuses the attribute must still be reviewable.
    }
  }

  private readonly onHostMutations = (records: MutationRecord[]): void => {
    if (!this.navigationStarted || this.destroyed || this.client.state !== 'ready') {
      return;
    }
    if (!records.some((record) => mutationIncludesHostDom(record))) {
      return;
    }
    if (this.hostMutationTimer !== null) {
      this.window.clearTimeout(this.hostMutationTimer);
    }
    this.hostMutationTimer = this.window.setTimeout(() => {
      this.hostMutationTimer = null;
      this.stampHostElementIds();
      this.restoreOwnAccessibility();
      this.requestPageReload(true);
    }, DOM_QUIET_DEBOUNCE_MS);
  };

  private setNavigationFailure(failure: RuntimeActionError): void {
    this.navigationFailure = failure;
    this.setOverlayState({
      status: { kind: 'error', code: failure.code },
    });
  }

  private enqueueDiagnosticsOperation(operation: () => Promise<void>): Promise<void> {
    const previous = this.diagnosticsTask ?? Promise.resolve();
    const deferred = createDeferredTask<void>();
    const task = deferred.promise;
    this.diagnosticsTask = task;
    void previous.then(operation, operation).then(deferred.resolve, deferred.reject);
    void task.then(
      () => {
        if (this.diagnosticsTask === task) {
          this.diagnosticsTask = null;
        }
      },
      () => {
        if (this.diagnosticsTask === task) {
          this.diagnosticsTask = null;
        }
      },
    );
    return task;
  }

  private assertCurrentDiagnosticsOwner(owner: number): void {
    if (this.destroyed || this.diagnosticsOwner !== owner) {
      throw actionError('SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE');
    }
  }

  private destroyDiagnostics(): Promise<void> {
    const predecessorCleanup = this.diagnosticsCleanupTask;
    return this.enqueueDiagnosticsOperation(async () => {
      const cleanupErrors: unknown[] = [];
      if (predecessorCleanup !== null) {
        try {
          await predecessorCleanup;
        } catch (error: unknown) {
          cleanupErrors.push(error);
        }
      }
      try {
        await this.destroyDiagnosticsSurface();
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
      if (cleanupErrors.length === 1) {
        throw cleanupErrors[0];
      }
      if (cleanupErrors.length > 1) {
        throw new AggregateError(cleanupErrors, 'Scene Glass diagnostics cleanup failed');
      }
    });
  }

  private async destroyDiagnosticsSurface(): Promise<void> {
    const diagnostics = this.diagnostics;
    this.diagnostics = null;
    if (diagnostics === null) {
      if (!this.destroyed) {
        this.setOverlayState({ diagnosticsOpen: false });
      }
      return;
    }
    const task = this.destroyDiagnosticResources(diagnostics);
    this.diagnosticsCleanupTask = task;
    void task.then(
      () => {
        if (this.diagnosticsCleanupTask === task) {
          this.diagnosticsCleanupTask = null;
        }
      },
      () => {
        if (this.diagnosticsCleanupTask === task) {
          this.diagnosticsCleanupTask = null;
        }
      },
    );
    try {
      await task;
    } finally {
      if (!this.destroyed) {
        this.setOverlayState({ diagnosticsOpen: false });
      }
    }
  }

  private async destroyDiagnosticResources(resources: {
    readonly controller: DiagnosticsController | null;
    readonly panel: DiagnosticsPanel | null;
    readonly transport: DiagnosticMcpTransport | null;
  }): Promise<void> {
    const cleanupErrors: unknown[] = [];
    const attemptCleanup = (cleanup: () => void): void => {
      try {
        cleanup();
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
    };

    if (resources.panel !== null) {
      const panel = resources.panel;
      attemptCleanup(() => panel.destroy());
    }
    if (resources.controller !== null) {
      const controller = resources.controller;
      attemptCleanup(() => controller.destroy());
    }
    if (resources.transport !== null) {
      try {
        await resources.transport.destroy();
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
    }

    if (cleanupErrors.length > 0) {
      throw new AggregateError(cleanupErrors, 'Scene Glass diagnostics cleanup failed');
    }
  }
}

export function createSceneGlassRuntime(options: SceneGlassRuntimeOptions): SceneGlassRuntime {
  return new SceneGlassRuntime(options);
}

class DiagnosticMcpTransport implements DiagnosticsTransport {
  private capability: DiagnosticRunCapability | null;
  private client: McpClient | null = null;
  private closed = false;
  private initializingClient: McpClient | null = null;
  private readonly closingClients = new WeakMap<McpClient, Promise<void>>();
  private closeTask: Promise<void> | null = null;

  public constructor(
    capability: DiagnosticRunCapability,
    private readonly dependencies: McpClientDependencies,
  ) {
    this.capability = capability;
  }

  public async issueProjectTestToken(): Promise<{ readonly token: string }> {
    const capability = this.capability;
    if (this.closed || capability === null) {
      throw actionError('SCG_DIAGNOSTIC_CAPABILITY_UNAVAILABLE');
    }
    return Object.freeze({ token: capability.token });
  }

  public async initialize(input: {
    readonly projectId: string;
    readonly token: string;
  }): Promise<DiagnosticConnection> {
    const capability = this.capability;
    if (
      this.closed ||
      capability === null ||
      input.token !== capability.token ||
      this.initializingClient !== null ||
      this.client !== null
    ) {
      throw actionError('SCG_DIAGNOSTIC_CAPABILITY_UNAVAILABLE');
    }

    const client = new McpClient({
      endpoint: capability.endpoint,
      diagnosticEndpoint: capability.endpoint,
      token: capability.token,
      ...this.dependencies,
    });
    this.initializingClient = client;
    try {
      await client.initializeSession();
    } catch (error: unknown) {
      const superseded = this.closed || this.initializingClient !== client || this.client !== null;
      if (this.initializingClient === client) {
        this.initializingClient = null;
        this.capability = null;
      }
      if (superseded) {
        const failure = actionError('SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE', error);
        try {
          await this.closeAndDispose(client);
        } catch (cleanupError: unknown) {
          throw retainCleanupErrors(failure, [cleanupError]);
        }
        throw failure;
      }
      client.dispose();
      throw error;
    }

    if (this.closed || this.initializingClient !== client || this.client !== null) {
      if (this.initializingClient === client) {
        this.initializingClient = null;
      }
      const failure = actionError('SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE');
      try {
        await this.closeAndDispose(client);
      } catch (cleanupError: unknown) {
        throw retainCleanupErrors(failure, [cleanupError]);
      }
      throw failure;
    }

    this.client = client;
    this.initializingClient = null;
    this.capability = null;
    return Object.freeze({ id: capability.runId });
  }

  public async sendInitializedNotification(): Promise<void> {
    const client = this.requireClient();
    await client.sendInitializedNotification();
  }

  public async ping(): Promise<void> {
    const client = this.requireClient();
    await client.ping();
  }

  public deleteClose(): Promise<void> {
    return this.destroy();
  }

  public destroy(): Promise<void> {
    if (this.closeTask !== null) {
      return this.closeTask;
    }
    if (this.closed) {
      return Promise.resolve();
    }

    const deferred = createDeferredTask<void>();
    this.closeTask = deferred.promise;
    this.closed = true;
    this.capability = null;
    const client = this.client;
    const initializingClient = this.initializingClient;
    this.client = null;
    this.initializingClient = null;

    const clients = new Set<McpClient>();
    if (client !== null) {
      clients.add(client);
    }
    if (initializingClient !== null) {
      clients.add(initializingClient);
    }

    void Promise.resolve()
      .then(() => this.closeClients(clients))
      .then(deferred.resolve, deferred.reject);
    return deferred.promise;
  }

  private async closeClients(clients: ReadonlySet<McpClient>): Promise<void> {
    const cleanupErrors: unknown[] = [];
    for (const client of clients) {
      try {
        await this.closeAndDispose(client);
      } catch (error: unknown) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(cleanupErrors, 'Scene Glass diagnostic cleanup failed');
    }
  }

  private closeAndDispose(client: McpClient): Promise<void> {
    const closingTask = this.closingClients.get(client);
    if (closingTask !== undefined) {
      return closingTask;
    }

    const deferred = createDeferredTask<void>();
    const task = deferred.promise;
    this.closingClients.set(client, task);
    void Promise.resolve()
      .then(async (): Promise<void> => {
        try {
          await client.close();
        } finally {
          client.dispose();
        }
      })
      .then(deferred.resolve, deferred.reject);
    return task;
  }

  private requireClient(): McpClient {
    if (this.closed || this.client === null) {
      throw actionError('SCG_DIAGNOSTIC_CONNECTION_UNAVAILABLE');
    }
    return this.client;
  }
}

function optionalDependencies(options: McpClientDependencies): McpClientDependencies {
  return {
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.crypto === undefined ? {} : { crypto: options.crypto }),
  };
}

function toOverlayAnnotations(
  annotations: readonly ElementAnnotation[],
  bindings: readonly AnnotationBinding[],
): readonly OverlayAnnotation[] {
  const resolutionById = new Map(
    bindings.map((binding) => [binding.annotation.id, binding.resolution]),
  );
  return annotations.map((annotation) => {
    const resolution = resolutionById.get(annotation.id);
    return Object.freeze({
      id: annotation.id,
      memo: annotation.memo,
      resolution:
        resolution === undefined
          ? annotation.resolution.status
          : resolution.status === 'resolved'
            ? 'resolved'
            : resolution.reason,
      ...(resolution?.status === 'resolved' ? { element: resolution.element } : {}),
    });
  });
}

function annotationSnapshotFromToolResult(result: AnnotationListToolResult): AnnotationSnapshot {
  return Object.freeze({
    annotations: result.annotations,
    revision: result.revision,
  });
}

function createdAnnotationFromToolResult(result: AnnotationMutationToolResult): CreatedAnnotation {
  const { replay, revision } = result;
  if (replay.kind !== 'create') {
    throw actionError('SCG_ANNOTATION_REPLAY_INVALID');
  }
  return Object.freeze({ revision, annotation: replay.annotation });
}

function updatedAnnotationFromToolResult(result: AnnotationMutationToolResult): UpdatedAnnotation {
  const { replay, revision } = result;
  if (replay.kind !== 'update') {
    throw actionError('SCG_ANNOTATION_REPLAY_INVALID');
  }
  return Object.freeze({ revision, annotation: replay.annotation });
}

function deletedAnnotationFromToolResult(result: AnnotationMutationToolResult): DeletedAnnotation {
  const { replay, revision } = result;
  if (replay.kind !== 'delete') {
    throw actionError('SCG_ANNOTATION_REPLAY_INVALID');
  }
  return Object.freeze({ revision, annotationId: replay.annotationId });
}
function requireApplied(result: AnnotationOperationResult): void {
  if (result.status === 'applied') {
    return;
  }
  if (result.status === 'failed') {
    throw actionError(result.error.code);
  }
  throw actionError('SCG_ANNOTATION_STALE');
}
function unsupportedSelectionCode(
  reason: UnsupportedElementSelection['reason'],
): `SCG_SELECTION_UNSUPPORTED_${string}` {
  switch (reason) {
    case 'canvas-subobject':
      return 'SCG_SELECTION_UNSUPPORTED_CANVAS_SUBOBJECT';
    case 'iframe-internal':
      return 'SCG_SELECTION_UNSUPPORTED_IFRAME_INTERNAL';
    case 'not-element':
      return 'SCG_SELECTION_UNSUPPORTED_NOT_ELEMENT';
    case 'shadow-child':
      return 'SCG_SELECTION_UNSUPPORTED_SHADOW_CHILD';
    case 'unmounted':
      return 'SCG_SELECTION_UNSUPPORTED_UNMOUNTED';
  }
}

function markdownFrom(value: PromptExportToolResult): string {
  return value.markdown;
}

function surroundingTextFor(element: Element): string {
  const innerText = 'innerText' in element ? element.innerText : undefined;
  const source = typeof innerText === 'string' ? innerText : (element.textContent ?? '');
  const normalized = source.replace(/\s+/gu, ' ').trim();
  const encoder = new TextEncoder();
  let text = '';
  let bytes = 0;
  let codePoints = 0;
  for (const codePoint of normalized) {
    if (codePoints >= MAX_SURROUNDING_TEXT_CODE_POINTS) {
      break;
    }
    const length = encoder.encode(codePoint).byteLength;
    if (bytes + length > MAX_SURROUNDING_TEXT_BYTES) {
      break;
    }
    text += codePoint;
    bytes += length;
    codePoints += 1;
  }
  return text;
}

function isMountedHostLightDomElement(element: Element, document: Document): boolean {
  const documentElement = document.documentElement;
  return (
    element.ownerDocument === document &&
    documentElement !== null &&
    documentElement.contains(element) &&
    element.getRootNode() === document
  );
}

function domOrderFor(element: Element, document: Document): number | undefined {
  let order = 0;
  for (const candidate of document.querySelectorAll('*')) {
    if (isSceneGlassOwnedElement(candidate)) {
      continue;
    }
    if (candidate === element) {
      return order;
    }
    if (order >= MAX_DOM_ORDER) {
      return MAX_DOM_ORDER;
    }
    order += 1;
  }
  return undefined;
}

function mutationIncludesHostDom(record: MutationRecord): boolean {
  if (record.type === 'attributes' && record.attributeName === SCENE_GLASS_ID_ATTRIBUTE) {
    // 로더가 스스로 찍는 식별자다. 호스트 변경으로 세면 스탬프 → 갱신 → 스탬프 로 돈다.
    return false;
  }
  if (record.type !== 'childList') {
    return !isSceneGlassNode(record.target);
  }
  if (isSceneGlassNode(record.target)) {
    return false;
  }
  for (const node of record.addedNodes) {
    if (!isSceneGlassNode(node)) {
      return true;
    }
  }
  for (const node of record.removedNodes) {
    if (!isSceneGlassNode(node)) {
      return true;
    }
  }
  return false;
}

function isSceneGlassNode(node: Node): boolean {
  const element = node.nodeType === Node.ELEMENT_NODE ? (node as Element) : node.parentElement;
  return element !== null && isSceneGlassOwnedElement(element);
}

function createOperationId(crypto: Pick<Crypto, 'getRandomValues'>): LowercaseUuidV4 {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return assertLowercaseUuidV4(
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    'operationId',
  );
}

function retainCleanupErrors(
  primary: RuntimeActionError,
  cleanupErrors: readonly unknown[],
): RuntimeActionError {
  if (cleanupErrors.length === 0) {
    return primary;
  }
  Object.defineProperty(primary, 'cleanupErrors', {
    configurable: true,
    enumerable: true,
    value: Object.freeze([...(primary.cleanupErrors ?? []), ...cleanupErrors]),
    writable: false,
  });
  return primary;
}
function retainConstructionCleanupErrors(
  primary: unknown,
  cleanupErrors: readonly unknown[],
): unknown {
  if (cleanupErrors.length === 0) {
    return primary;
  }
  if (primary instanceof Error) {
    const cleanupAwarePrimary = primary as Error & {
      cleanupErrors?: readonly unknown[];
    };
    Object.defineProperty(cleanupAwarePrimary, 'cleanupErrors', {
      configurable: true,
      enumerable: true,
      value: Object.freeze([...(cleanupAwarePrimary.cleanupErrors ?? []), ...cleanupErrors]),
      writable: false,
    });
    return cleanupAwarePrimary;
  }
  return new AggregateError(
    [primary, ...cleanupErrors],
    'Scene Glass diagnostics construction and cleanup failed',
  );
}
function selectionCaptureFailure(error: unknown): RuntimeActionError {
  return typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === 'SCG_SELECTION_CAPTURE_FAILED' &&
    (error as { readonly name?: unknown }).name === 'SceneGlassRuntimeError'
    ? (error as RuntimeActionError)
    : actionError('SCG_SELECTION_CAPTURE_FAILED', error);
}

function createDeferredTask<T>(): {
  readonly promise: Promise<T>;
  readonly reject: (reason?: unknown) => void;
  readonly resolve: (value: T | PromiseLike<T>) => void;
} {
  let reject: ((reason?: unknown) => void) | undefined;
  let resolve: ((value: T | PromiseLike<T>) => void) | undefined;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  if (resolve === undefined || reject === undefined) {
    throw new Error('Scene Glass could not create a deferred task');
  }
  return Object.freeze({ promise, resolve, reject });
}

function navigationStartupFailure(error: unknown): RuntimeActionError {
  const code = navigationFailureCode(error);
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === code &&
    (error as { readonly name?: unknown }).name === 'SceneGlassRuntimeError'
  ) {
    return error as RuntimeActionError;
  }
  return actionError(code, error);
}

function navigationFailureCode(
  error: unknown,
): 'SCG_MUTATION_OBSERVER_UNAVAILABLE' | 'SCG_NAVIGATION_UNAVAILABLE' {
  return typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === 'SCG_MUTATION_OBSERVER_UNAVAILABLE'
    ? 'SCG_MUTATION_OBSERVER_UNAVAILABLE'
    : 'SCG_NAVIGATION_UNAVAILABLE';
}

function actionError(code: string, cause?: unknown): RuntimeActionError {
  const error = Object.assign(new Error(code), { code });
  if (cause !== undefined) {
    Object.defineProperty(error, 'cause', { value: cause });
  }
  error.name = 'SceneGlassRuntimeError';
  return error;
}

function browserCrypto(): Pick<Crypto, 'getRandomValues'> {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw actionError('SCG_CRYPTO_UNAVAILABLE');
  }
  return globalThis.crypto;
}
