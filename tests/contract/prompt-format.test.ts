import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_LIMITS,
  serializeCanonicalPageFileV1,
  type PageFileV1,
  type PageId,
} from '@scene-glass/contracts';
import {
  exportCurrentPageReviewMarkdown,
  exportProjectReviewMarkdown,
  exportReviewMarkdown,
  type PromptExportLimits,
  type PromptExportOptions,
} from '../../packages/core/src/prompt-export.js';

const PAGE_IDS = {
  alpha: `p_${'0'.repeat(63)}4`,
  canonicalA: `p_${'0'.repeat(63)}2`,
  pageIdOne: `p_${'0'.repeat(63)}1`,
  pageIdThree: `p_${'0'.repeat(63)}3`,
  special: `p_${'f'.repeat(64)}`,
};

const ANNOTATION_IDS = {
  first: '00000000-0000-4000-8000-000000000001',
  second: '00000000-0000-4000-8000-000000000002',
  third: '00000000-0000-4000-8000-000000000003',
  fourth: '00000000-0000-4000-8000-000000000004',
  fifth: '00000000-0000-4000-8000-000000000005',
};
const INPUT_DIGEST = `sha256:${'a'.repeat(64)}`;

interface AnnotationOptions {
  readonly id: string;
  readonly domOrder: number;
  readonly memo: string;
  readonly surroundingText: string;
  readonly dataScgId: string;
  readonly resolution?: 'ambiguous' | 'not-found' | 'resolved';
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly context?: unknown;
}

function annotation({
  id,
  domOrder,
  memo,
  surroundingText,
  dataScgId,
  resolution = 'resolved',
  context,
  createdAt = '2025-01-01T00:00:00.000Z',
  updatedAt = '2025-01-01T00:00:00.000Z',
}: AnnotationOptions) {
  return {
    id,
    locator: { dataScgId },
    memo,
    surroundingText,
    domOrder,
    resolution: {
      status: resolution,
      reason: resolution === 'resolved' ? null : resolution,
    },
    ...(context === undefined ? {} : { context }),
    createdAt,
    updatedAt,
  };
}
function replayTail(revision: number): readonly unknown[] {
  return Array.from({ length: Math.min(revision, 32) }, (_, index) => {
    const appliedRevision = revision - Math.min(revision, 32) + index + 1;
    return {
      operationId: `00000000-0000-4000-8000-${(index + 1).toString(16).padStart(12, '0')}`,
      kind: 'delete',
      inputDigest: INPUT_DIGEST,
      appliedRevision,
      result: {
        kind: 'delete',
        revision: appliedRevision,
        annotationId: ANNOTATION_IDS.first,
      },
    };
  });
}

const DEFAULT_EXPORT_LIMITS: PromptExportLimits = BUILT_IN_LIMITS;

function exportLimits(overrides: Partial<PromptExportLimits>): PromptExportLimits {
  return { ...DEFAULT_EXPORT_LIMITS, ...overrides };
}

function pageFile({
  route,
  canonicalIdentity,
  pageId,
  annotations,
  revision = 5,
  replayWindow = replayTail(revision),
}: {
  readonly route: string;
  readonly canonicalIdentity: string;
  readonly pageId: string;
  readonly annotations: readonly unknown[];
  readonly revision?: number;
  readonly replayWindow?: readonly unknown[];
}): PageFileV1 {
  return {
    schemaVersion: 1,
    page: {
      policyVersion: 1,
      route,
      canonicalIdentity,
      pageId,
    },
    revision,
    annotations,
    replayWindow,
  } as unknown as PageFileV1;
}

const expectedAlpha =
  [
    '# Scene Glass Review',
    '',
    '## Page Feedback: /a',
    '',
    '### Annotation 1',
    'Locator:',
    '```',
    '{"dataScgId":"dom-one"}',
    '```',
    'Memo: dom-order-one',
    'Surrounding text:',
    '```',
    'zero',
    '```',
    '',
    '### Annotation 2',
    'Locator:',
    '```',
    '{"dataScgId":"id-one"}',
    '```',
    'Memo: annotation-id-one',
    'Surrounding text:',
    '```',
    'one',
    '```',
    '',
    '### Annotation 3',
    'Locator:',
    '```',
    '{"dataScgId":"id-two"}',
    '```',
    'Memo: annotation-id-two',
    'Surrounding text:',
    '```',
    'two',
    '```',
  ].join('\n') + '\n';

const expectedProject = [
  expectedAlpha.slice(0, -1),
  '',
  '## Page Feedback: /same',
  '',
  '### Annotation 1',
  'Locator:',
  '```',
  '{"dataScgId":"canonical-a"}',
  '```',
  'Memo: canonical-a',
  'Surrounding text:',
  '```',
  'canonical-a',
  '```',
  '',
  '## Page Feedback: /same',
  '',
  '### Annotation 1',
  'Locator:',
  '```',
  '{"dataScgId":"page-id-one"}',
  '```',
  'Memo: page-id-one',
  'Surrounding text:',
  '```',
  'page-id-one',
  '```',
  '',
  '## Page Feedback: /same',
  '',
  '### Annotation 1',
  'Locator:',
  '```',
  '{"dataScgId":"page-id-three"}',
  '```',
  'Memo: page-id-three',
  'Surrounding text:',
  '```',
  'page-id-three',
  '```',
  '',
].join('\n');

describe('prompt Markdown export contract', () => {
  it('renders project and current-page exports in route/canonical/page and domOrder/id order', () => {
    const alpha = pageFile({
      route: '/a',
      canonicalIdentity: 'https://z.example/a',
      pageId: PAGE_IDS.alpha,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.second,
          domOrder: 2,
          memo: 'annotation-id-two',
          surroundingText: 'two',
          dataScgId: 'id-two',
        }),
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 2,
          memo: 'annotation-id-one',
          surroundingText: 'one',
          dataScgId: 'id-one',
        }),
        annotation({
          id: ANNOTATION_IDS.third,
          domOrder: 1,
          memo: 'dom-order-one',
          surroundingText: 'zero',
          dataScgId: 'dom-one',
        }),
      ],
    });
    const canonicalA = pageFile({
      route: '/same',
      canonicalIdentity: 'https://a.example/same',
      pageId: PAGE_IDS.canonicalA,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.fourth,
          domOrder: 1,
          memo: 'canonical-a',
          surroundingText: 'canonical-a',
          dataScgId: 'canonical-a',
        }),
      ],
    });
    const pageIdOne = pageFile({
      route: '/same',
      canonicalIdentity: 'https://b.example/same',
      pageId: PAGE_IDS.pageIdOne,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.fifth,
          domOrder: 1,
          memo: 'page-id-one',
          surroundingText: 'page-id-one',
          dataScgId: 'page-id-one',
        }),
      ],
    });
    const pageIdThree = pageFile({
      route: '/same',
      canonicalIdentity: 'https://b.example/same',
      pageId: PAGE_IDS.pageIdThree,
      annotations: [
        annotation({
          id: '00000000-0000-4000-8000-000000000006',
          domOrder: 1,
          memo: 'page-id-three',
          surroundingText: 'page-id-three',
          dataScgId: 'page-id-three',
        }),
      ],
    });
    const alphaWithAnnotationsShuffled = pageFile({
      route: '/a',
      canonicalIdentity: 'https://z.example/a',
      pageId: PAGE_IDS.alpha,
      annotations: [alpha.annotations[0]!, alpha.annotations[2]!, alpha.annotations[1]!],
    });

    const shuffled = [pageIdThree, alpha, pageIdOne, canonicalA];
    const project = exportProjectReviewMarkdown(shuffled);
    const currentPage = exportCurrentPageReviewMarkdown(shuffled, alpha.page.pageId);
    const currentPageWithAnnotationsShuffled = exportCurrentPageReviewMarkdown(
      [alphaWithAnnotationsShuffled],
      alpha.page.pageId,
    );

    const reordered = exportProjectReviewMarkdown([
      canonicalA,
      pageIdOne,
      alphaWithAnnotationsShuffled,
      pageIdThree,
    ]);

    expect(project).toBe(expectedProject);
    expect(currentPage).toBe(expectedAlpha);
    expect(currentPageWithAnnotationsShuffled).toBe(expectedAlpha);
    expect(reordered).toBe(expectedProject);
    expect([...new TextEncoder().encode(reordered)]).toEqual([
      ...new TextEncoder().encode(project),
    ]);
    expect([...new TextEncoder().encode(currentPageWithAnnotationsShuffled)]).toEqual([
      ...new TextEncoder().encode(currentPage),
    ]);
  });
  it('renders context-rich annotations while preserving legacy annotation blocks', () => {
    const page = pageFile({
      route: '/context',
      canonicalIdentity: 'https://example.test/context',
      pageId: `p_${'1'.repeat(64)}`,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 1,
          memo: 'Apply settings',
          surroundingText: 'legacy source is omitted',
          dataScgId: 'full-context',
          resolution: 'not-found',
          context: {
            viewport: [1440, 900],
            rect: [-12, 34, 320, 48],
            tag: 'button',
            classes: ['primary', 'cta'],
            cssPath: '#app > main > button.primary.cta',
            selectedText: 'Save settings',
            sourceFile: 'src/components/SaveButton.tsx',
            componentTrail: ['App', 'SettingsPanel', 'SaveButton'],
          },
        }),
        annotation({
          id: ANNOTATION_IDS.second,
          domOrder: 2,
          memo: 'No optional context values',
          surroundingText: 'legacy source is omitted',
          dataScgId: 'sparse-context',
          context: {
            viewport: [800, 600],
            rect: [0, 8, 200, 16],
            tag: 'div',
            classes: [],
            cssPath: 'main > div',
            selectedText: '   ',
          },
        }),
        annotation({
          id: ANNOTATION_IDS.third,
          domOrder: 3,
          memo: '# memo *unsafe*',
          surroundingText: 'legacy source is omitted',
          dataScgId: 'unsafe-context',
          context: {
            viewport: [1, 2],
            rect: [3, 4, 5, 6],
            tag: 'button',
            classes: ['danger*`class'],
            cssPath: 'button[data-label="a`b"]',
            selectedText: '<script> & *selected* `value`',
          },
        }),
      ],
    });

    expect(exportProjectReviewMarkdown([page])).toBe(
      [
        '# Scene Glass Review',
        '',
        '## Page Feedback: /context',
        '',
        '### 1. button.primary.cta',
        '> WARNING: unresolved (not-found)',
        '**Location:** `\\#app > main > button.primary.cta`',
        '**Source:** src/components/SaveButton.tsx',
        '**Classes:** `primary cta`',
        '**Component:** <App> <SettingsPanel> <SaveButton>',
        '**Position:** -12, 34 (320x48)',
        '**Viewport:** 1440x900',
        '**Selected:** "Save settings"',
        '**Memo:** Apply settings',
        '',
        '### 2. div',
        '**Location:** `main > div`',
        '**Position:** 0, 8 (200x16)',
        '**Viewport:** 800x600',
        '**Memo:** No optional context values',
        '',
        '### 3. button.danger\\*\\`class',
        '**Location:** ``button\\[data-label="a\\`b"\\]``',
        '**Classes:** ``danger\\*\\`class``',
        '**Position:** 3, 4 (5x6)',
        '**Viewport:** 1x2',
        '**Selected:** "&lt;script> &amp; \\*selected\\* \\`value\\`"',
        '**Memo:** \\# memo \\*unsafe\\*',
        '',
      ].join('\n'),
    );
  });

  it('writes a byte-stable LF-only Markdown document without timestamps or a BOM', () => {
    const page = pageFile({
      route: '/docs/*[guide]#1! (🧪)',
      canonicalIdentity: 'https://example.test/docs/🧪',
      pageId: PAGE_IDS.special,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.fifth,
          domOrder: 1,
          memo: 'memo `*_{}[]()#+.!>|~- 🧪',
          surroundingText: 'first\r\ncontrol:\u0001, emoji:🧪\n```` fence',
          dataScgId: 'node-special',
          resolution: 'ambiguous',
          createdAt: '2020-02-02T02:02:02.000Z',
          updatedAt: '2030-03-03T03:03:03.000Z',
        }),
      ],
    });
    const timestampChanged = pageFile({
      route: page.page.route,
      canonicalIdentity: page.page.canonicalIdentity,
      pageId: page.page.pageId,
      annotations: page.annotations.map((value) => ({
        ...value,
        createdAt: '2040-04-04T04:04:04.000Z',
        updatedAt: '2050-05-05T05:05:05.000Z',
      })),
    });
    const expected = [
      '# Scene Glass Review',
      '',
      '## Page Feedback: /docs/\\*\\[guide\\]#1! (🧪)',
      '',
      '### Annotation 1',
      '> WARNING: unresolved (ambiguous)',
      'Locator:',
      '```',
      '{"dataScgId":"node-special"}',
      '```',
      'Memo: memo \\`\\*\\_{}\\[\\]()#+.!>|~- 🧪',
      'Surrounding text:',
      '`````',
      'first',
      'control:\\u0001, emoji:🧪',
      '```` fence',
      '`````',
      '',
    ].join('\n');

    const markdown = exportProjectReviewMarkdown([page]);
    const bytes = new TextEncoder().encode(markdown);

    expect(markdown).toBe(expected);
    expect(exportProjectReviewMarkdown([timestampChanged])).toBe(expected);
    expect([...bytes.subarray(0, 3)]).toEqual([0x23, 0x20, 0x53]);
    expect([...bytes.subarray(-1)]).toEqual([0x0a]);
    expect(markdown.endsWith('\n')).toBe(true);
    expect(markdown).not.toContain('\r');
    expect(markdown).not.toContain('2020-02-02');
    expect(markdown).not.toContain('2030-03-03');
    expect(markdown.endsWith('\n\n')).toBe(false);
    expect(markdown).toContain('Locator:\n```\n{"dataScgId":"node-special"}\n```');
    expect(markdown).not.toContain('\\"dataScgId\\"');
  });

  it('renders untrusted route, memo, and locator content as normalized Markdown-safe text', () => {
    const unsafe = pageFile({
      route: '/cafe\u0301 & <script><!--route--><https://route.test>',
      canonicalIdentity: 'https://example.test/caf\u00e9',
      pageId: `p_${'c'.repeat(64)}`,
      annotations: [
        {
          ...annotation({
            id: ANNOTATION_IDS.first,
            domOrder: 1,
            memo: '<!--memo--> &amp; <https://memo.test>\n# heading\n- list\n> quote\n1. ordered\n+ list\n* list\n= setext\n| table\n~~strike~~\n![image]\n    indented\n``backticks``',
            surroundingText: 'source\n`````',
            dataScgId: 'cafe\u0301 & <script><!--locator-->',
          }),
          locator: {
            fingerprint: {
              tag: 'button',
              stableAttributes: [],
              ancestorSignatures: [],
              textDigest: INPUT_DIGEST,
            },
            dataScgId: 'cafe\u0301 & <script><!--locator-->',
          },
        },
      ],
    });
    const supplementaryPlane = pageFile({
      route: '/\u{10000}',
      canonicalIdentity: 'https://example.test/supplementary',
      pageId: `p_${'d'.repeat(64)}`,
      annotations: [],
    });
    const emoji = pageFile({
      route: '/🧪',
      canonicalIdentity: 'https://example.test/emoji',
      pageId: `p_${'e'.repeat(64)}`,
      annotations: [],
    });

    const markdown = exportProjectReviewMarkdown([emoji, unsafe, supplementaryPlane]);

    expect(markdown).toContain('## Page Feedback: /café &amp; &lt;script>');
    expect(markdown).toContain('Locator:\n```\n{"dataScgId":"café & <script><!--locator-->"');
    expect(markdown).toContain('café &amp; &lt;script>');
    expect(markdown).toContain('&amp;amp;');
    expect(markdown).toContain('&lt;https://memo.test>');
    expect(markdown).toContain('\n\\# heading\n\\- list\n\\> quote\n1\\. ordered');
    expect(markdown).toContain(
      '\n\\+ list\n\\* list\n\\= setext\n\\| table\n\\~~strike\\~~\n\\!\\[image\\]',
    );
    expect(markdown).toContain('\n&#32;&#32;&#32;&#32;indented');
    expect(markdown).toContain('\\`\\`backticks\\`\\`');
    expect(markdown).toContain('``````\nsource\n`````\n``````');
    expect(markdown).not.toContain('Memo: <!--');
    expect(markdown).not.toContain('Memo: <https://');
    expect(markdown).not.toContain('cafe\u0301');
    expect(markdown.indexOf('## Page Feedback: /\u{10000}')).toBeLessThan(
      markdown.indexOf('## Page Feedback: /🧪'),
    );
  });
  it('renders locators as raw JSON in a fence longer than internal backtick runs', () => {
    const page = pageFile({
      route: '/locator-fence',
      canonicalIdentity: 'https://example.test/locator-fence',
      pageId: `p_${'b'.repeat(64)}`,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 1,
          memo: 'locator fence',
          surroundingText: 'source',
          dataScgId: 'target-````-value',
        }),
      ],
    });

    const markdown = exportProjectReviewMarkdown([page]);

    expect(markdown).toContain('Locator:\n`````\n{"dataScgId":"target-````-value"}\n`````');
    expect(markdown).not.toContain('\\"dataScgId\\"');
  });
  it('expands JSON-encoded fingerprint signatures only in the rendered Locator block', () => {
    const page = pageFile({
      route: '/fingerprint-locator',
      canonicalIdentity: 'https://example.test/fingerprint-locator',
      pageId: `p_${'a'.repeat(64)}`,
      annotations: [
        {
          ...annotation({
            id: ANNOTATION_IDS.first,
            domOrder: 1,
            memo: 'fingerprint locator',
            surroundingText: 'source',
            dataScgId: 'unused',
          }),
          locator: {
            fingerprint: {
              tag: 'button',
              stableAttributes: [['aria-label', 'Save']],
              ancestorSignatures: ['["section",[]]', '["main",[["id","app"]]]'],
              textDigest: INPUT_DIGEST,
            },
          },
        },
      ],
    });
    const expectedLocator =
      `{"fingerprint":{"ancestorSignatures":[["section",[]],["main",[["id","app"]]]],` +
      `"stableAttributes":[["aria-label","Save"]],"tag":"button","textDigest":"${INPUT_DIGEST}"}}`;

    const markdown = exportProjectReviewMarkdown([page]);
    const locatorMatch = markdown.match(/Locator:\n(`+)\n([\s\S]*?)\n\1/);

    expect(locatorMatch).not.toBeNull();
    if (locatorMatch === null) {
      throw new Error('Locator block is missing');
    }
    expect(locatorMatch[2]).toBe(expectedLocator);
    expect(locatorMatch[2]).not.toContain('\\"');
    expect(JSON.parse(locatorMatch[2]!)).toEqual({
      fingerprint: {
        ancestorSignatures: [
          ['section', []],
          ['main', [['id', 'app']]],
        ],
        stableAttributes: [['aria-label', 'Save']],
        tag: 'button',
        textDigest: INPUT_DIGEST,
      },
    });
  });

  it('rejects corrupt PageFile identity, annotation, locator, resolution, and replay data', () => {
    const valid = pageFile({
      route: '/valid',
      canonicalIdentity: 'https://example.test/valid',
      pageId: `p_${'9'.repeat(64)}`,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 1,
          memo: 'valid memo',
          surroundingText: 'valid source',
          dataScgId: 'valid-node',
        }),
      ],
    });
    const validAnnotation = valid.annotations[0]!;
    const firstReplayRecord = valid.replayWindow[0]!;
    const secondReplayRecord = valid.replayWindow[1]!;
    const corruptions: readonly {
      readonly pageFile: PageFileV1;
      readonly message: string;
    }[] = [
      {
        pageFile: {
          ...valid,
          page: { ...valid.page, canonicalIdentity: '' },
        } as unknown as PageFileV1,
        message: 'canonicalIdentity contains an empty or control value',
      },
      {
        pageFile: {
          ...valid,
          annotations: [{ ...validAnnotation, id: 'invalid-annotation-id' }],
        } as unknown as PageFileV1,
        message: 'annotation id must be a lowercase UUID v4',
      },
      {
        pageFile: {
          ...valid,
          annotations: [{ ...validAnnotation, locator: {} }],
        } as unknown as PageFileV1,
        message: 'locator requires dataScgId or fingerprint',
      },
      {
        pageFile: {
          ...valid,
          annotations: [
            { ...validAnnotation, resolution: { status: 'resolved', reason: 'ambiguous' } },
          ],
        } as unknown as PageFileV1,
        message: 'resolved resolution reason must be null',
      },
      {
        pageFile: {
          ...valid,
          replayWindow: valid.replayWindow.slice(1),
        } as unknown as PageFileV1,
        message: 'replayWindow must contain the exact replay tail',
      },
      {
        pageFile: {
          ...valid,
          replayWindow: [
            {
              ...firstReplayRecord,
              result: { ...firstReplayRecord.result, revision: 0 },
            },
            ...valid.replayWindow.slice(1),
          ],
        } as unknown as PageFileV1,
        message: 'replay result revision must equal appliedRevision',
      },
      {
        pageFile: {
          ...valid,
          replayWindow: [
            firstReplayRecord,
            {
              ...secondReplayRecord,
              appliedRevision: secondReplayRecord.appliedRevision + 1,
              result: {
                ...secondReplayRecord.result,
                revision: secondReplayRecord.result.revision + 1,
              },
            },
            ...valid.replayWindow.slice(2),
          ],
        } as unknown as PageFileV1,
        message: 'replayWindow must contain contiguous revisions ending at page revision',
      },
    ];

    for (const corruption of corruptions) {
      expect(() => exportProjectReviewMarkdown([corruption.pageFile])).toThrow(corruption.message);
    }
  });

  it('rejects unknown generic export modes without widening to project scope', () => {
    const valid = pageFile({
      route: '/mode',
      canonicalIdentity: 'https://example.test/mode',
      pageId: `p_${'8'.repeat(64)}`,
      annotations: [],
    });

    expect(() => exportReviewMarkdown([valid], { mode: 'workspace' } as never)).toThrow(
      'prompt export mode is invalid',
    );
  });

  it('rejects inconsistent generic export option shapes', () => {
    const valid = pageFile({
      route: '/mode-shape',
      canonicalIdentity: 'https://example.test/mode-shape',
      pageId: `p_${'9'.repeat(64)}`,
      annotations: [],
    });

    expect(() =>
      exportReviewMarkdown([valid], { mode: 'project', pageId: valid.page.pageId } as never),
    ).toThrow('project export does not accept a pageId');
  });

  it('runs cooperative checkpoints for each page and annotation and aborts on failure', () => {
    const pageWithoutAnnotations = pageFile({
      route: '/checkpoint/a',
      canonicalIdentity: 'https://example.test/checkpoint/a',
      pageId: `p_${'6'.repeat(64)}`,
      annotations: [],
    });
    const secondPageWithoutAnnotations = pageFile({
      route: '/checkpoint/b',
      canonicalIdentity: 'https://example.test/checkpoint/b',
      pageId: `p_${'7'.repeat(64)}`,
      annotations: [],
    });
    const pageWithOneAnnotation = pageFile({
      route: '/checkpoint/a',
      canonicalIdentity: 'https://example.test/checkpoint/a',
      pageId: `p_${'6'.repeat(64)}`,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 1,
          memo: 'checkpoint',
          surroundingText: 'checkpoint',
          dataScgId: 'checkpoint',
        }),
      ],
    });
    const countCheckpoints = (pageFiles: readonly PageFileV1[]): number => {
      let checkpoints = 0;
      expect(
        exportReviewMarkdown(pageFiles, {
          mode: 'project',
          checkpoint: () => {
            checkpoints += 1;
          },
        }),
      ).toContain('# Scene Glass Review');
      return checkpoints;
    };

    const onePageCheckpoints = countCheckpoints([pageWithoutAnnotations]);
    const twoPageCheckpoints = countCheckpoints([
      pageWithoutAnnotations,
      secondPageWithoutAnnotations,
    ]);
    const oneAnnotationCheckpoints = countCheckpoints([pageWithOneAnnotation]);

    expect(onePageCheckpoints).toBe(10);
    expect(twoPageCheckpoints).toBe(onePageCheckpoints + 7);
    expect(oneAnnotationCheckpoints).toBe(onePageCheckpoints + 1);

    const checkpointFailure = new Error('checkpoint cancellation');
    let failedCheckpoints = 0;
    expect(() =>
      exportReviewMarkdown([pageWithoutAnnotations], {
        mode: 'project',
        checkpoint: () => {
          failedCheckpoints += 1;
          throw checkpointFailure;
        },
      }),
    ).toThrow(checkpointFailure);
    expect(failedCheckpoints).toBe(1);
  });

  it('uses canonical PageFile bytes for full validation, scan, and render limits', () => {
    const page = pageFile({
      route: '/budget',
      canonicalIdentity: 'https://example.test/budget',
      pageId: `p_${'b'.repeat(64)}`,
      annotations: [
        annotation({
          id: ANNOTATION_IDS.first,
          domOrder: 1,
          memo: 'bounded memo',
          surroundingText: 'bounded surrounding text 🧪',
          dataScgId: 'budget-node',
        }),
      ],
    });
    const complete = exportCurrentPageReviewMarkdown([page], page.page.pageId);
    const renderBytes = new TextEncoder().encode(complete).byteLength;
    const canonicalPageFileBytes = new TextEncoder().encode(
      serializeCanonicalPageFileV1(page),
    ).byteLength;

    expect(canonicalPageFileBytes).toBeGreaterThan(
      new TextEncoder().encode(JSON.stringify(page)).byteLength,
    );
    expect(
      exportCurrentPageReviewMarkdown(
        [page],
        page.page.pageId,
        exportLimits({
          pageFileBytes: canonicalPageFileBytes,
          exportScanBytes: canonicalPageFileBytes,
          exportRenderBytes: renderBytes,
        }),
      ),
    ).toBe(complete);
    expect(() =>
      exportCurrentPageReviewMarkdown(
        [page],
        page.page.pageId,
        exportLimits({
          pageFileBytes: canonicalPageFileBytes - 1,
          exportScanBytes: canonicalPageFileBytes,
          exportRenderBytes: renderBytes,
        }),
      ),
    ).toThrow('page file exceeds its effective byte limit');
    expect(() =>
      exportCurrentPageReviewMarkdown(
        [page],
        page.page.pageId,
        exportLimits({
          pageFileBytes: canonicalPageFileBytes,
          exportScanBytes: canonicalPageFileBytes - 1,
          exportRenderBytes: renderBytes,
        }),
      ),
    ).toThrow('export scan exceeds its effective byte limit');
    expect(() =>
      exportCurrentPageReviewMarkdown(
        [page],
        page.page.pageId,
        exportLimits({
          pageFileBytes: canonicalPageFileBytes,
          exportScanBytes: canonicalPageFileBytes,
          exportRenderBytes: renderBytes - 1,
        }),
      ),
    ).toThrow('export output exceeds its effective byte limit');
  });
});

function assertDiscriminatedExportOptionsCompileTime(pageId: PageId): void {
  // @ts-expect-error page mode requires pageId
  exportReviewMarkdown([], { mode: 'page' });
  // @ts-expect-error project mode cannot carry pageId
  exportReviewMarkdown([], { mode: 'project', pageId });
  const valid: PromptExportOptions = { mode: 'page', pageId };
  void valid;
}
void assertDiscriminatedExportOptionsCompileTime;
