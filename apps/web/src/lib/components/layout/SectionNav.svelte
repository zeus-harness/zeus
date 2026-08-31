<script lang="ts">
  import { page } from '$app/state';

  export type SectionNavItem = { href: string; label: string; description?: string };

  let { label, items }: { label: string; items: readonly SectionNavItem[] } = $props();
  let pathname = $derived(page.url.pathname);
</script>

<nav class="flex gap-1 overflow-x-auto border-b border-border px-5 pt-3 lg:px-8" aria-label={label}>
  {#each items as item (item.href)}
    <a
      class={pathname === item.href
        ? 'border-b-2 border-foreground px-3 py-3 text-sm font-medium text-foreground'
        : 'border-b-2 border-transparent px-3 py-3 text-sm text-muted-foreground hover:text-foreground'}
      href={item.href}
      aria-current={pathname === item.href ? 'page' : undefined}
      title={item.description}
    >
      {item.label}
    </a>
  {/each}
</nav>
