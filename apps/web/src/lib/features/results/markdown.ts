import { marked } from 'marked';

/** Never pass model HTML through to the DOM. Rendering uses Svelte text nodes only. */
export const parseMarkdown = (text: string) => marked.lexer(text, { gfm: true });
export function safeLink(href: string): string | null {
  try {
    const url = new URL(href);
    return ['https:', 'http:'].includes(url.protocol) ? url.href : null;
  } catch { return null; }
}
