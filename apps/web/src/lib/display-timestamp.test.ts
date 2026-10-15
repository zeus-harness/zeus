import { describe, it, expect } from 'vitest';
import { displayTimestamp } from './display-timestamp';
describe('display timestamp', () => {
  it('renders legacy ordinal tuples and RFC3339 consistently', () => {
    expect(displayTimestamp([2026, 261, 3, 46, 57, 890097000, 0, 0, 0]))
      .toBe(displayTimestamp('2026-09-18T03:46:57.890097Z'));
    expect(displayTimestamp('2026-09-18T03:46:57Z')).toContain('11:46');
  });
  it('handles missing and malformed timestamps', () => {
    expect(displayTimestamp(null)).toBe('—');
    expect(displayTimestamp('invalid')).toBe('—');
  });
});
