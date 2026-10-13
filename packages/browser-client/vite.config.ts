import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/loader.ts',
      formats: ['iife'],
      name: 'SceneGlassLoader',
      fileName: () => 'scene-glass-loader.js',
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
});
