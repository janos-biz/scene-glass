import {
  createNavigationEmitter,
  type NavigationAdapter,
  type NavigationListener,
} from './adapter.js';

export interface DocumentNavigationAdapterOptions {
  readonly window?: Window;
}

/** Emits once for the current document and again whenever it is shown. */
export class DocumentNavigationAdapter implements NavigationAdapter {
  private readonly emitter = createNavigationEmitter();
  private readonly window: Window;

  public constructor(options: DocumentNavigationAdapterOptions = {}) {
    this.window = options.window ?? globalThis.window;
  }

  public start(listener: NavigationListener): void {
    if (!this.emitter.start(listener)) {
      return;
    }

    this.window.addEventListener('pageshow', this.onPageShow);
    this.emitter.emit('bootstrap');
  }

  public teardown(): void {
    if (!this.emitter.teardown()) {
      return;
    }

    this.window.removeEventListener('pageshow', this.onPageShow);
  }

  private readonly onPageShow = (): void => {
    this.emitter.emit('pageshow');
  };
}

export function createDocumentNavigationAdapter(
  options?: DocumentNavigationAdapterOptions,
): DocumentNavigationAdapter {
  return new DocumentNavigationAdapter(options);
}
