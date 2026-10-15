import { expect, it } from 'vitest';
import { render } from 'svelte/server';
import ResultContent from './ResultContent.svelte';
it('renders formatted text but never raw HTML, scripts, images or executable links', () => {
  const { body } = render(ResultContent, { props: { text: '# 标题\n\n**重点**\n\n<script>alert(1)</script>\n\n[坏链接](javascript:alert)\n\n![像素](https://example.test/pixel)', actions: false } });
  expect(body).toContain('<strong>');
  expect(body).toContain('&lt;script>');
  expect(body).not.toContain('<script>');
  expect(body).not.toContain('<img');
  expect(body).not.toContain('href="javascript:');
});
