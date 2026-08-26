<script lang="ts">
	import TimelineEvent from './TimelineEvent.svelte';
	import type { RunEvent } from '$lib/types';

	interface Props {
		events: RunEvent[];
	}

	let { events }: Props = $props();
	const visibleEvents = $derived(
		events.filter((event) => event.type !== 'approval' || event.approval?.status !== 'pending')
	);

	function keyOf(event: RunEvent): string {
		return `${event.stream ?? 'run'}:${event.id ?? `${event.sequence}:${event.type}`}`;
	}
</script>

<section class="min-h-0 flex-1 overflow-y-auto" aria-label="Run conversation">
	<div class="px-4 py-8 sm:px-6 sm:py-10 gap-7 mx-auto flex w-full max-w-[748px] flex-col">
		{#each visibleEvents as event (keyOf(event))}
			<TimelineEvent {event} />
		{/each}
	</div>
</section>
