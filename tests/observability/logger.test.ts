import { describe, expect, it } from 'vitest';

import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';

describe('SceneGlassLogger terminal lifecycle', () => {
  it('delivers redacted records to the injected sink without implicit terminal events', () => {
    const captured: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({
      sink: (record) => captured.push(record),
      now: () => new Date('2026-07-16T01:02:03.000Z'),
    });

    const emitted = logger.emit(
      'auth.accepted',
      { projectId: 'alpha', code: 'SCG_AUTH_ACCEPTED' },
      { requestId: 'request-a' },
    );

    expect(captured).toEqual([emitted]);
    expect(Object.isFrozen(emitted)).toBe(true);
    expect(emitted.timestamp).toBe('2026-07-16T01:02:03.000Z');
    expect(emitted.event).toBe('auth.accepted');
    expect(emitted.scope).toEqual({
      requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/),
    });
    expect(emitted.data).toEqual({
      projectIdHash: expect.stringMatching(/^project_[a-f0-9]{24}$/),
      code: 'SCG_AUTH_ACCEPTED',
    });
    expect(captured.filter((record) => record.event.startsWith('terminal.'))).toHaveLength(0);
  });
  it('allowlists lifecycle Origin application records while redacting authority-bearing values', () => {
    const captured: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger((record) => captured.push(record));
    const emitted = logger.emit('origin.applied', {
      count: 2,
      digest: 'private-digest',
      origin: 'http://127.0.0.1:4175',
      path: '/private/project',
      projectId: 'alpha',
      root: '/private/root',
      source: 'private-source',
      stage: 'lifecycle-origin-application',
      token: 'private-token',
    });

    expect(emitted).toMatchObject({
      event: 'origin.applied',
      data: {
        count: 2,
        projectIdHash: expect.stringMatching(/^project_[a-f0-9]{24}$/),
        stage: 'lifecycle-origin-application',
      },
    });
    expect(emitted.data).not.toHaveProperty('digest');
    expect(emitted.data).not.toHaveProperty('origin');
    expect(emitted.data).not.toHaveProperty('path');
    expect(emitted.data).not.toHaveProperty('root');
    expect(emitted.data).not.toHaveProperty('source');
    expect(emitted.data).not.toHaveProperty('token');
    expect(JSON.stringify(captured)).not.toContain('private-');
  });
  it('keeps terminal outcome stages opaque and emits one redacted record per request', () => {
    const captured: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger((record) => captured.push(record));
    const outcomes = [
      ['success', 'success'],
      ['failure', 'protocol-rejected'],
      ['failure', 'authentication-rejected'],
      ['failure', 'scope-rejected'],
      ['failure', 'admission-rejected'],
      ['failure', 'handler-error'],
      ['failure', 'request-timeout'],
      ['cancelled', 'disconnect'],
    ] as const;

    for (const [outcome, stage] of outcomes) {
      logger.terminal({ requestId: `request-secret-${stage}` }, outcome, {
        authorization: 'Bearer top-secret-token',
        body: { params: { hidden: true } },
        error: new Error('raw error message'),
        origin: 'https://private-origin.example',
        stage,
      });
    }

    expect(captured).toHaveLength(outcomes.length);
    expect(captured).toEqual(
      outcomes.map(([outcome, stage]) =>
        expect.objectContaining({
          data: { stage },
          event: `terminal.${outcome}`,
          scope: { requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/) },
        }),
      ),
    );
    const serialized = JSON.stringify(captured);
    expect(serialized).not.toContain('top-secret-token');
    expect(serialized).not.toContain('private-origin.example');
    expect(serialized).not.toContain('raw error message');
  });

  it('keeps terminal assertions bounded without owning lifecycle deduplication', () => {
    const captured: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger((record) => captured.push(record));
    const scope = { requestId: 'request-9', runId: 'diagnostic-run-9' };
    const expiringScope = { requestId: 'expiring-request' };

    const terminal = logger.terminal(scope, 'success', {
      operationId: 'op_b9d65d65250b4bda9520acdf48505061',
    });

    logger.assertOneTerminalEvent(scope);
    expect(terminal.event).toBe('terminal.success');
    logger.terminal({ requestId: 'request-10', runId: 'diagnostic-run-9' }, 'failure');
    logger.terminal({ requestId: 'request-9', runId: 'diagnostic-run-10' }, 'cancelled');
    expect(() => logger.assertOneTerminalEvent(scope)).toThrow(
      'Expected exactly one terminal log event',
    );

    logger.terminal(expiringScope, 'success');
    logger.assertOneTerminalEvent(expiringScope);
    for (let index = 0; index <= 1_024; index += 1) {
      logger.terminal({ requestId: `bounded-request-${index}` }, 'success');
    }
    logger.terminal(expiringScope, 'success');
    logger.assertOneTerminalEvent(expiringScope);
    logger.assertOneTerminalEvent({ requestId: 'bounded-request-1024' });
    expect(captured).toHaveLength(1_030);
  });

  it('rejects terminal events without a request or run identity before invoking the sink', () => {
    const captured: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger((record) => captured.push(record));

    expect(() => logger.terminal({}, 'failure')).toThrow(
      'Terminal log events require a requestId or runId',
    );
    expect(captured).toHaveLength(0);
  });

  it('retains terminal proof and bounded sink-failure evidence when delivery throws', () => {
    const logger = new SceneGlassLogger(() => {
      throw new Error('host sink failed');
    });
    const scope = { requestId: 'throwing-sink-request' };

    expect(() => logger.terminal(scope, 'success')).not.toThrow();
    logger.assertOneTerminalEvent(scope);
    expect(logger.sinkFailureCount).toBe(1);
  });
});
