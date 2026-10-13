import { describe, expect, it } from 'vitest';

import {
  SceneGlassLogger,
  type SceneGlassLogRecord,
} from '../../packages/server/src/observability/logger.js';
import { hashProjectId } from '../../packages/server/src/observability/redaction.js';

describe('serialized security logs', () => {
  it('redacts credentials, filesystem authority, annotation text, errors, and nested secrets', () => {
    const rawToken = 'raw-token-never-for-logs-3V9xKp2Lm7Qa4Rt8Uw1Yz6Bc0De5Fh9Gj';
    const authorization = `Bearer ${rawToken}`;
    const root = '/Users/scene-glass/private-project';
    const memo = 'Memo visible only to the reviewer';
    const surroundingText = 'Customer account number: 1234-5678';
    const stack = 'Error: private failure\n    at privateHandler (server.ts:12:3)';
    const nestedSecret = 'nested-secret-api-key-should-never-be-observable';
    const requestId = 'request-external-77';
    const runId = 'diagnostic-run-external-31';
    const projectId = 'project-alpha';
    const records: SceneGlassLogRecord[] = [];
    const logger = new SceneGlassLogger({
      sink: (record) => records.push(record),
      now: () => new Date('2026-07-16T00:00:00.000Z'),
    });

    const record = logger.terminal({ requestId, runId }, 'failure', {
      projectId,
      operationId: 'op_9c07b3e0a70b4b5ca395e4d7d6c0cb97',
      code: 'SCG_AUTH_INVALID',
      rawBearer: rawToken,
      Authorization: authorization,
      root,
      memo,
      surroundingText,
      stack,
      nested: {
        secretLikeValue: nestedSecret,
        privateKey: nestedSecret,
        accessToken: rawToken,
        authorization,
      },
    });

    const serialized = logger.serialize(record);
    for (const sensitive of [
      rawToken,
      authorization,
      root,
      memo,
      surroundingText,
      stack,
      nestedSecret,
      requestId,
      runId,
      projectId,
      'Authorization',
      'rawBearer',
      'surroundingText',
    ]) {
      expect(serialized).not.toContain(sensitive);
    }

    expect(records).toEqual([record]);
    expect(JSON.parse(serialized)).toEqual({
      timestamp: '2026-07-16T00:00:00.000Z',
      event: 'terminal.failure',
      scope: {
        requestIdHash: expect.stringMatching(/^request_[a-f0-9]{24}$/),
        runIdHash: expect.stringMatching(/^run_[a-f0-9]{24}$/),
      },
      data: {
        projectIdHash: hashProjectId(projectId),
        operationId: 'op_9c07b3e0a70b4b5ca395e4d7d6c0cb97',
        code: 'SCG_AUTH_INVALID',
        nested: {},
      },
    });
  });
});
