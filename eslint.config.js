import js from '@eslint/js';
import vitest from '@vitest/eslint-plugin';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/coverage/**', '**/dist/**', '**/node_modules/**'],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    files: ['scripts/**/*.{js,mjs}', 'packages/onboarding/scripts/**/*.{js,mjs}'],
    languageOptions: {
      globals: {
        Buffer: 'readonly',
        process: 'readonly',
      },
    },
  },
  {
    files: ['**/*.{test,spec}.ts', 'tests/**/*.ts'],
    plugins: {
      vitest,
    },
    rules: vitest.configs.recommended.rules,
  },
);
