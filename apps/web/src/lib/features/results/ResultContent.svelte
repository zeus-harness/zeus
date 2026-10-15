<script lang="ts">
  import type { Token } from 'marked';
  import { parseMarkdown, safeLink } from './markdown';
  let { text, actions = true }: { text: string; actions?: boolean } = $props();
  let tokens = $derived(parseMarkdown(text));
  let feedback = $state('');
  async function copy() {
    try { await navigator.clipboard.writeText(text); feedback = '已复制'; }
    catch { feedback = '复制失败，请选择文字复制或下载结果。'; }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = 'zeus-result.md'; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
</script>

{#snippet render(nodes: Token[])}
  {#each nodes as token, i (i)}
    {#if token.type === 'heading'}
      <svelte:element this={`h${Math.min(token.depth + 1, 6)}`} class="mt-5 mb-2 font-semibold">{@render render(token.tokens ?? [])}</svelte:element>
    {:else if token.type === 'paragraph'}<p class="my-3">{@render render(token.tokens ?? [])}</p>
    {:else if token.type === 'strong'}<strong>{@render render(token.tokens ?? [])}</strong>
    {:else if token.type === 'em'}<em>{@render render(token.tokens ?? [])}</em>
    {:else if token.type === 'del'}<del>{@render render(token.tokens ?? [])}</del>
    {:else if token.type === 'codespan'}<code class="rounded bg-muted px-1">{token.text}</code>
    {:else if token.type === 'code'}<pre class="my-3 max-w-full overflow-auto rounded-lg bg-muted p-4 text-xs"><code>{token.text}</code></pre>
    {:else if token.type === 'list'}
      <svelte:element this={token.ordered ? 'ol' : 'ul'} start={token.ordered ? token.start : undefined} class="my-3 ml-6 {token.ordered ? 'list-decimal' : 'list-disc'}">
        {#each token.items as item, j (j)}<li>{#if item.task}<span aria-label={item.checked ? '已完成' : '未完成'}>{item.checked ? '☑' : '☐'} </span>{/if}{@render render(item.tokens)}</li>{/each}
      </svelte:element>
    {:else if token.type === 'table'}
      <div class="my-3 max-w-full overflow-x-auto"><table class="w-full border-collapse text-sm"><thead><tr>{#each token.header as cell, j (j)}<th class="border border-border p-2 text-left">{@render render(cell.tokens)}</th>{/each}</tr></thead><tbody>{#each token.rows as row, j (j)}<tr>{#each row as cell, k (k)}<td class="border border-border p-2">{@render render(cell.tokens)}</td>{/each}</tr>{/each}</tbody></table></div>
    {:else if token.type === 'blockquote'}<blockquote class="my-3 border-l-2 border-border pl-4">{@render render(token.tokens ?? [])}</blockquote>
    {:else if token.type === 'link'}
      {@const href = safeLink(token.href)}
      {#if href}<a {href} target="_blank" rel="noopener noreferrer" class="underline">{@render render(token.tokens ?? [])}</a>{:else}{@render render(token.tokens ?? [])}{/if}
    {:else if token.type === 'image'}<span>{token.text}（图片未自动加载）</span>
    {:else if token.type === 'br'}<br />
    {:else if token.type === 'hr'}<hr class="my-4 border-border" />
    {:else if token.type === 'text' && token.tokens}{@render render(token.tokens ?? [])}
    {:else if token.type !== 'space'}{'text' in token ? token.text : token.raw}{/if}
  {/each}
{/snippet}

<div class="min-w-0 break-words text-sm leading-7">{@render render(tokens)}</div>
{#if actions}<div class="mt-3 flex flex-wrap gap-4 text-sm"><button type="button" class="underline" onclick={copy}>复制结果</button><button type="button" class="underline" onclick={download}>下载 Markdown</button><span role="status">{feedback}</span></div>{/if}
