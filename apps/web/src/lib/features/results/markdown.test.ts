import { describe, it, expect } from 'vitest';
import { parseMarkdown, safeLink } from './markdown';
describe('result markdown', () => {
  it('recognizes real headings, tables and fenced code', () => {
    const tokens = parseMarkdown('# 标题\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```sh\necho hello\n```');
    expect(tokens.map(t => t.type)).toEqual(expect.arrayContaining(['heading', 'table', 'code']));
  });
  it('blocks executable and relative URLs', () => {
    for (const href of ['javascript:alert(1)', 'data:text/html,test', '/account/logout', '//evil.test']) expect(safeLink(href)).toBeNull();
    expect(safeLink('https://example.org')).toBe('https://example.org/');
  });
});
