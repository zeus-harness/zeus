import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  // The runtime image contains the build only; bundle the QR encoder with SSR.
  ssr: { noExternal: ['qrcode'] },
  test: {
    include: ['src/**/*.{test,spec}.{js,ts}']
  }
});
