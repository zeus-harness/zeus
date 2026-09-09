import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import path from 'node:path';

export default defineConfig({
  testDir: './scripts/e2e/browser',
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 30_000 },
  reporter: 'line',
  outputDir: process.env.ZEUS_BROWSER_OUTPUT_DIR || path.join(tmpdir(), 'zeus-browser-evidence'),
  use: {
    baseURL: 'http://127.0.0.1:3100',
    browserName: 'chromium',
    viewport: { width: 1440, height: 900 },
    // Authentication and model credentials must not enter traces or failure screenshots.
    trace: 'off',
    screenshot: 'off',
    video: 'off'
  }
});
