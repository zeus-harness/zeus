import type { RunEvent } from '$lib/api/runs';

export interface SseMessage {
  id: string | null;
  event: string;
  data: string;
}

export type SseMessageLike = Pick<SseMessage, 'data'> &
  Partial<Pick<SseMessage, 'event' | 'id'>>;

/**
 * Incrementally parses decoded SSE text chunks.
 *
 * The parser keeps the SSE last-event-id state, including ids received on
 * events that do not contain data. Comments and keep-alive frames produce no
 * messages.
 */
export class SseParser {
  private line = '';
  private pendingCarriageReturn = false;
  private eventName = '';
  private data = '';
  private hasData = false;
  private currentLastEventId: string | null = null;

  get lastEventId(): string | null {
    return this.currentLastEventId;
  }

  push(chunk: string): SseMessage[] {
    const messages: SseMessage[] = [];

    for (let index = 0; index < chunk.length; index += 1) {
      const character = chunk.charAt(index);

      if (this.pendingCarriageReturn) {
        this.pendingCarriageReturn = false;
        if (character === '\n') {
          messages.push(...this.processLine(this.line));
          this.line = '';
          continue;
        }

        messages.push(...this.processLine(this.line));
        this.line = '';
      }

      if (character === '\r') {
        this.pendingCarriageReturn = true;
      } else if (character === '\n') {
        messages.push(...this.processLine(this.line));
        this.line = '';
      } else {
        this.line += character;
      }
    }

    return messages;
  }

  feed(chunk: string): SseMessage[] {
    return this.push(chunk);
  }

  /** Flushes a final line and a final event that was not followed by a blank line. */
  finish(): SseMessage[] {
    const messages: SseMessage[] = [];

    if (this.pendingCarriageReturn) {
      this.pendingCarriageReturn = false;
      messages.push(...this.processLine(this.line));
      this.line = '';
    } else if (this.line.length > 0) {
      messages.push(...this.processLine(this.line));
      this.line = '';
    }

    messages.push(...this.dispatch());
    return messages;
  }

  private processLine(line: string): SseMessage[] {
    if (line.length === 0) {
      return this.dispatch();
    }

    if (line.startsWith(':')) {
      return [];
    }

    const separator = line.indexOf(':');
    const field = separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? '' : line.slice(separator + 1);
    if (value.startsWith(' ')) {
      value = value.slice(1);
    }

    switch (field) {
      case 'data':
        this.data += `${value}\n`;
        this.hasData = true;
        break;
      case 'event':
        this.eventName = value;
        break;
      case 'id':
        if (!value.includes('\u0000')) {
          this.currentLastEventId = value;
        }
        break;
      default:
        break;
    }

    return [];
  }

  private dispatch(): SseMessage[] {
    if (!this.hasData) {
      this.resetEventFields();
      return [];
    }

    const message: SseMessage = {
      id: this.currentLastEventId,
      event: this.eventName || 'message',
      data: this.data.endsWith('\n') ? this.data.slice(0, -1) : this.data
    };
    this.resetEventFields();
    return [message];
  }

  private resetEventFields(): void {
    this.eventName = '';
    this.data = '';
    this.hasData = false;
  }
}

/**
 * Parses an SSE message into the generated RunEvent shape. Invalid JSON,
 * missing API fields, and an SSE id that does not identify the JSON sequence
 * are rejected by returning null.
 */
export function parseRunEvent(message: SseMessageLike): RunEvent | null;
export function parseRunEvent(data: string, sseId?: string | null): RunEvent | null;
export function parseRunEvent(
  input: SseMessageLike | string,
  sseId: string | null = null
): RunEvent | null {
  const message: SseMessageLike =
    typeof input === 'string' ? { data: input, id: sseId, event: 'message' } : input;

  let value: unknown;
  try {
    value = JSON.parse(message.data);
  } catch {
    return null;
  }

  if (!isRecord(value)) {
    return null;
  }

  const sequence = value.sequence;
  if (
    !isNonEmptyString(value.id) ||
    !isNonEmptyString(value.run_id) ||
    !isNonNegativeSafeInteger(sequence) ||
    !isNonNegativeSafeInteger(value.schema_version) ||
    !isNonEmptyString(value.event_type) ||
    !Object.prototype.hasOwnProperty.call(value, 'payload') ||
    !isNonEmptyString(value.occurred_at) ||
    !sseIdMatchesSequence(message.id ?? null, sequence)
  ) {
    return null;
  }

  return value as RunEvent;
}

export class RunEventStreamParser {
  private readonly sseParser = new SseParser();
  private acceptedLastEventId: string | null = null;
  private acceptedLastSequence: number | null = null;

  /** The Last-Event-ID value for the latest accepted RunEvent. */
  get lastEventId(): string | null {
    return this.acceptedLastEventId;
  }

  /** The sequence represented by {@link lastEventId}. */
  get lastSequence(): number | null {
    return this.acceptedLastSequence;
  }

  push(chunk: string): RunEvent[] {
    return this.accept(this.sseParser.push(chunk));
  }

  feed(chunk: string): RunEvent[] {
    return this.push(chunk);
  }

  finish(): RunEvent[] {
    return this.accept(this.sseParser.finish());
  }

  private accept(messages: readonly SseMessage[]): RunEvent[] {
    const events: RunEvent[] = [];

    for (const message of messages) {
      const event = parseRunEvent(message);
      if (event === null) {
        continue;
      }

      events.push(event);
      this.acceptedLastEventId = message.id || String(event.sequence);
      this.acceptedLastSequence = event.sequence;
    }

    return events;
  }
}

export { RunEventStreamParser as RunEventSseParser };

export function mergeRunEvents(
  existing: readonly RunEvent[],
  incoming: Iterable<RunEvent> = []
): RunEvent[] {
  const bySequence = new Map<number, RunEvent>();

  for (const event of existing) {
    if (!bySequence.has(event.sequence)) {
      bySequence.set(event.sequence, event);
    }
  }
  for (const event of incoming) {
    if (!bySequence.has(event.sequence)) {
      bySequence.set(event.sequence, event);
    }
  }

  return [...bySequence.values()].sort((left, right) => left.sequence - right.sequence);
}

export function appendRunEvent(existing: readonly RunEvent[], incoming: RunEvent): RunEvent[] {
  return mergeRunEvents(existing, [incoming]);
}

export type TerminalRunStatus = 'succeeded' | 'failed' | 'canceled';

const TERMINAL_EVENT_STATUS: Readonly<Record<string, TerminalRunStatus>> = {
  'run.canceled': 'canceled',
  run_canceled: 'canceled',
  'run.failed': 'failed',
  run_failed: 'failed',
  'run.succeeded': 'succeeded',
  run_succeeded: 'succeeded'
};

const TERMINAL_STATUSES = new Set<TerminalRunStatus>(['succeeded', 'failed', 'canceled']);

export function getTerminalRunStatus(
  event: Pick<RunEvent, 'event_type' | 'payload'>
): TerminalRunStatus | null {
  const explicitStatus = TERMINAL_EVENT_STATUS[event.event_type.trim().toLowerCase()];
  if (explicitStatus !== undefined) {
    return explicitStatus;
  }

  const payload = isRecord(event.payload) ? event.payload.status : undefined;
  return isTerminalRunStatus(payload) ? payload : null;
}

export function isTerminalRunEvent(
  event: Pick<RunEvent, 'event_type' | 'payload'>
): boolean {
  return getTerminalRunStatus(event) !== null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function sseIdMatchesSequence(sseId: string | null, sequence: number): boolean {
  if (sseId === null || sseId.length === 0) {
    return true;
  }

  const idSequence = Number(sseId);
  return Number.isSafeInteger(idSequence) && idSequence >= 0 && idSequence === sequence;
}

function isTerminalRunStatus(value: unknown): value is TerminalRunStatus {
  return typeof value === 'string' && TERMINAL_STATUSES.has(value as TerminalRunStatus);
}
