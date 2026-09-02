import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('svelte/compiler').CompileOptions & { preprocess: unknown }} */
const config = {
  preprocess: vitePreprocess()
};

export default config;
