<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue';

type SceneGlassApi = {
  notifyReady: () => void;
};

declare global {
  interface Window {
    SceneGlass?: SceneGlassApi;
  }
}

const delayedRenderMs = 150;
const virtualWindowSize = 3;
const virtualItemCount = 6;

const route = ref(currentRoute());
const delayedContentVisible = ref(false);
const readySignalCount = ref(0);
const virtualStart = ref(0);
const canvas = ref<HTMLCanvasElement>();
const shadowHost = ref<HTMLDivElement>();

let delayedRenderTimer: number | undefined;

const pageTitle = computed(() => {
  if (route.value === '/') {
    return 'Initial route';
  }

  return `Route: ${route.value}`;
});

const virtualItems = computed(() => {
  const end = Math.min(virtualStart.value + virtualWindowSize, virtualItemCount);

  return Array.from({ length: end - virtualStart.value }, (_, offset) => {
    const index = virtualStart.value + offset;

    return {
      id: `virtual-item-${index}`,
      label: `Virtual item ${index}`,
    };
  });
});

const iframeDocument =
  '<!doctype html><html lang="en"><body><button data-scg-id="iframe-child" type="button">Iframe child</button></body></html>';

function currentRoute(): string {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

function updateRoute(): void {
  route.value = currentRoute();
}

function notifySceneGlassReady(): void {
  window.SceneGlass?.notifyReady();
  readySignalCount.value += 1;
}

async function settleRoute(): Promise<void> {
  await nextTick();
  notifySceneGlassReady();
}

function navigateWithHistory(method: 'pushState' | 'replaceState', target: string): void {
  window.history[method]({ fixtureRoute: target }, '', target);
  updateRoute();
  void settleRoute();
}

function navigateBack(): void {
  window.history.back();
}

function navigateHash(): void {
  if (window.location.hash === '#fixture-hash') {
    updateRoute();
    void settleRoute();
    return;
  }

  window.location.hash = 'fixture-hash';
}

function renderDelayedContent(): void {
  delayedContentVisible.value = false;

  if (delayedRenderTimer !== undefined) {
    window.clearTimeout(delayedRenderTimer);
  }

  delayedRenderTimer = window.setTimeout(() => {
    delayedContentVisible.value = true;
    void nextTick().then(notifySceneGlassReady);
  }, delayedRenderMs);
}

function showPreviousVirtualItems(): void {
  virtualStart.value = Math.max(0, virtualStart.value - 1);
}

function showNextVirtualItems(): void {
  virtualStart.value = Math.min(virtualItemCount - virtualWindowSize, virtualStart.value + 1);
}

function drawCanvas(): void {
  const context = canvas.value?.getContext('2d');

  if (context === null || context === undefined) {
    return;
  }

  context.fillStyle = '#1e293b';
  context.fillRect(0, 0, 240, 80);
  context.fillStyle = '#f8fafc';
  context.font = '16px sans-serif';
  context.fillText('Canvas boundary', 16, 46);
}

function installShadowHost(): void {
  const host = shadowHost.value;

  if (host === undefined || host.shadowRoot !== null) {
    return;
  }

  const root = host.attachShadow({ mode: 'open' });
  const button = document.createElement('button');

  button.type = 'button';
  button.dataset.scgId = 'shadow-child';
  button.textContent = 'Shadow child';
  root.append(button);
}

function handleBrowserNavigation(): void {
  updateRoute();
  void settleRoute();
}

onMounted(() => {
  drawCanvas();
  installShadowHost();
  window.addEventListener('popstate', handleBrowserNavigation);
  window.addEventListener('hashchange', handleBrowserNavigation);
  void settleRoute();
});

onBeforeUnmount(() => {
  window.removeEventListener('popstate', handleBrowserNavigation);
  window.removeEventListener('hashchange', handleBrowserNavigation);

  if (delayedRenderTimer !== undefined) {
    window.clearTimeout(delayedRenderTimer);
  }
});
</script>

<template>
  <main data-scg-id="spa-root">
    <h1 data-scg-id="fixture-title">Scene Glass Vue SPA fixture</h1>

    <section data-scg-id="navigation-fixture" aria-labelledby="route-title">
      <h2 id="route-title" data-scg-id="route-heading">{{ pageTitle }}</h2>
      <p data-scg-id="route-current">{{ route }}</p>
      <div data-scg-id="navigation-controls" aria-label="Navigation controls">
        <button
          data-scg-id="history-push"
          type="button"
          @click="navigateWithHistory('pushState', '/pushed')"
        >
          Push route
        </button>
        <button
          data-scg-id="history-replace"
          type="button"
          @click="navigateWithHistory('replaceState', '/replaced')"
        >
          Replace route
        </button>
        <button data-scg-id="history-back" type="button" @click="navigateBack">Back</button>
        <button data-scg-id="hash-route" type="button" @click="navigateHash">Hash route</button>
      </div>
      <p data-scg-id="annotation-target">
        Deterministic light-DOM annotation target for the current route.
      </p>
      <output data-scg-id="ready-signal-count">Ready signals: {{ readySignalCount }}</output>
    </section>

    <section data-scg-id="delayed-render-fixture" aria-labelledby="delayed-render-title">
      <h2 id="delayed-render-title" data-scg-id="delayed-render-heading">Delayed render</h2>
      <button data-scg-id="delayed-render-control" type="button" @click="renderDelayedContent">
        Render delayed content
      </button>
      <p v-if="delayedContentVisible" data-scg-id="delayed-rendered-content">
        Delayed content is rendered.
      </p>
    </section>

    <section data-scg-id="boundary-fixture" aria-labelledby="boundary-title">
      <h2 id="boundary-title" data-scg-id="boundary-heading">Boundary fixtures</h2>
      <iframe
        data-scg-id="iframe-host"
        title="Iframe boundary fixture"
        :srcdoc="iframeDocument"
      ></iframe>
      <canvas
        ref="canvas"
        data-scg-id="canvas-host"
        aria-label="Canvas boundary fixture"
        height="80"
        width="240"
      ></canvas>
      <div
        ref="shadowHost"
        data-scg-id="shadow-host"
        aria-label="Shadow DOM boundary fixture"
        role="group"
      ></div>
      <div data-scg-id="virtualized-container" aria-label="Virtualized list fixture" role="list">
        <p data-scg-id="virtualized-range">
          Mounted items {{ virtualStart }} through {{ virtualStart + virtualItems.length - 1 }} of
          {{ virtualItemCount - 1 }}.
        </p>
        <button data-scg-id="virtual-previous" type="button" @click="showPreviousVirtualItems">
          Previous virtual items
        </button>
        <button data-scg-id="virtual-next" type="button" @click="showNextVirtualItems">
          Next virtual items
        </button>
        <div v-for="item in virtualItems" :key="item.id" :data-scg-id="item.id" role="listitem">
          {{ item.label }}
        </div>
      </div>
    </section>
  </main>
</template>
