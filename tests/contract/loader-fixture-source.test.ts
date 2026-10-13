import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const LOADER_SOURCE = '%VITE_SCENE_GLASS_LOADER_URL%';
const LOADER_TAG_PATTERN = new RegExp(
  `<script\\b(?=[^>]*\\bsrc="${LOADER_SOURCE}")[^>]*><\\/script>`,
  'g',
);

const FIXTURES = [
  {
    file: '../../fixtures/vue3-spa/index.html',
    navigation: 'spa',
  },
  {
    file: '../../fixtures/static-html/index.html',
    navigation: 'document',
  },
  {
    file: '../../fixtures/static-html/page-two.html',
    navigation: 'document',
  },
] as const;

describe('loader fixture source contract', () => {
  it.each(FIXTURES)(
    'keeps the Scene Glass loader tag on one physical line in $file',
    ({ file, navigation }) => {
      const source = readFileSync(new URL(file, import.meta.url), 'utf8');
      const loaderTags = Array.from(source.matchAll(LOADER_TAG_PATTERN), ([tag]) => tag);

      expect(loaderTags).toHaveLength(1);

      const [loaderTag] = loaderTags;
      if (loaderTag === undefined) {
        throw new Error(`Missing Scene Glass loader tag in ${file}`);
      }

      expect(loaderTag).not.toMatch(/[\r\n]/);
      expect(loaderTag).toBe(
        `<script async src="${LOADER_SOURCE}" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="${navigation}"></script>`,
      );
    },
  );
});
