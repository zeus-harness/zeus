<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, description, action }: { title: string; description: string; action?: Snippet } = $props();
</script>

<div class="rounded-xl border border-dashed border-border bg-muted/20 px-6 py-12 text-center">
  <h2 class="font-medium">{title}</h2>
  <p class="mx-auto mt-2 max-w-lg text-sm leading-6 text-muted-foreground">{description}</p>
  {#if action}<div class="mt-5 flex justify-center">{@render action()}</div>{/if}
</div>
