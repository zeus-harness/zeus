import { describe, expect, it } from 'vitest';

import {
  appendRunEvent,
  changesRunSnapshot,
  getTerminalRunStatus,
  isTerminalRunEvent,
  mergeRunEvents,
  RunEventSseParser,
  SseParser,
  type TerminalRunStatus
} from './run-stream';
import type { RunEvent } from '$lib/api/runs';

function runEvent(
  sequence: number,
  eventType = 'run.status_changed',
  payload: unknown = { status: 'running' }
): RunEvent {
  return {
    id: `event-${sequence}`,
    run_id: 'run-1',
    sequence,
    schema_version: 1,
    event_type: eventType,
    payload,
    occurred_at: '2026-09-01T00:00:00Z'
  };
}

function frame(event: RunEvent, sseId = event.sequence.toString()): string {
  return `id: ${sseId}\nevent: ${event.event_type}\ndata: ${JSON.stringify(event)}\n\n`;
}

describe('SseParser', () => {
  it('handles CRLF split across chunks, event fields, and multi-line data', () => {
    const event = runEvent(42);
    const json = JSON.stringify(event);
    const split = json.indexOf(',"run_id"') + 1;
    const parser = new SseParser();

    expect(parser.push('id: 42\r')).toEqual([]);
    expect(parser.push('\nevent: run.status_')).toEqual([]);
    expect(parser.push('changed\r\ndata: ' + json.slice(0, split) + '\r\n')).toEqual([]);

    const [message] = parser.push(`data: ${json.slice(split)}\r\n\r\n`);

    expect(message).toEqual({
      id: '42',
      event: 'run.status_changed',
      data: `${json.slice(0, split)}\n${json.slice(split)}`
    });
    expect(parser.lastEventId).toBe('42');
  });

  it('ignores comments and keep-alive frames', () => {
    const parser = new SseParser();

    expect(parser.push(': keep-alive\r\n\r\n')).toEqual([]);
    expect(parser.push(':\n\n')).toEqual([]);
    expect(parser.lastEventId).toBeNull();
  });
});

describe('RunEventSseParser', () => {
  it('maps Last-Event-ID to the accepted event sequence', () => {
    const parser = new RunEventSseParser();
    const event = runEvent(7);

    expect(parser.push(frame(event))).toEqual([event]);
    expect(parser.lastEventId).toBe('7');
    expect(parser.lastSequence).toBe(7);
  });

  it('rejects malformed JSON and events missing required RunEvent fields', () => {
    const parser = new RunEventSseParser();

    expect(parser.push('id: 1\ndata: {not-json}\n\n')).toEqual([]);
    expect(parser.push('id: 2\ndata: {"sequence":2,"event_type":"run.failed"}\n\n')).toEqual(
      []
    );
    expect(parser.lastEventId).toBeNull();
  });

  it('does not accept an SSE id for a different sequence', () => {
    const parser = new RunEventSseParser();

    expect(parser.push(frame(runEvent(8), '7'))).toEqual([]);
    expect(parser.lastSequence).toBeNull();
  });
});

describe('run event merging', () => {
  it('deduplicates by sequence, sorts, and keeps the existing event on collision', () => {
    const existing = runEvent(2, 'existing');
    const firstIncoming = runEvent(1, 'incoming');
    const duplicateIncoming = runEvent(2, 'replacement');
    const lastIncoming = runEvent(3, 'incoming');

    expect(mergeRunEvents([existing], [lastIncoming, duplicateIncoming, firstIncoming])).toEqual([
      firstIncoming,
      existing,
      lastIncoming
    ]);
    expect(appendRunEvent([existing], duplicateIncoming)).toEqual([existing]);
  });
});

describe('terminal run events', () => {
  it('recognizes terminal payload statuses', () => {
    const statuses: TerminalRunStatus[] = ['succeeded', 'failed', 'canceled'];

    for (const status of statuses) {
      const event = runEvent(1, 'run.status_changed', { status });
      expect(getTerminalRunStatus(event)).toBe(status);
      expect(isTerminalRunEvent(event)).toBe(true);
    }
  });

  it('recognizes dotted and underscored explicit terminal event names', () => {
    const eventStatuses: Array<[string, TerminalRunStatus]> = [
      ['run.succeeded', 'succeeded'],
      ['run_succeeded', 'succeeded'],
      ['run.failed', 'failed'],
      ['run_failed', 'failed'],
      ['run.canceled', 'canceled'],
      ['run_canceled', 'canceled']
    ];

    for (const [eventType, status] of eventStatuses) {
      expect(getTerminalRunStatus(runEvent(1, eventType, { status: 'running' }))).toBe(status);
    }

    expect(isTerminalRunEvent(runEvent(1, 'runtime.started'))).toBe(false);
  });
});

describe('run snapshot changes', () => {
  it('refreshes durable trace data for approvals, tools, children, usage, and status', () => {
    for (const eventType of [
      'tool.requested',
      'approval_resolved',
      'tool.result',
      'model.completed',
      'run.status_changed',
      'child_run.created'
    ]) {
      expect(changesRunSnapshot(runEvent(1, eventType))).toBe(true);
    }

    expect(changesRunSnapshot(runEvent(1, 'runtime.started'))).toBe(false);
  });
});
