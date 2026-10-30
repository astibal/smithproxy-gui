import {defineConfig} from '@playwright/test';

const chromiumExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
const previewPort = Number.parseInt(process.env.PLAYWRIGHT_PREVIEW_PORT ?? '4173', 10);
if (!Number.isInteger(previewPort) || previewPort < 1024 || previewPort > 65_535) {
  throw new Error('PLAYWRIGHT_PREVIEW_PORT must be an integer between 1024 and 65535.');
}
const previewUrl = `http://127.0.0.1:${previewPort}`;
type BrowserName = 'chromium' | 'firefox' | 'webkit';
const browserNames: ReadonlyArray<BrowserName> = process.env.PLAYWRIGHT_ALL_BROWSERS === '1'
  ? ['chromium', 'firefox', 'webkit']
  : ['chromium'];

export default defineConfig({
  testDir: './tests',
  reporter: process.env.CI ? [['github'], ['line']] : [['line']],
  ...(process.env.CI ? {workers: 1} : {}),
  use: {
    baseURL: previewUrl,
    locale: 'en-US',
    timezoneId: 'UTC',
    deviceScaleFactor: 1,
    trace: 'retain-on-failure',
  },
  projects: browserNames.map(browserName => ({
    name: browserName,
    use: {
      browserName,
      launchOptions: browserName === 'chromium' && chromiumExecutable
        ? {executablePath: chromiumExecutable}
        : {},
    },
  })),
  webServer: {
    command: `pnpm exec vite preview --host 127.0.0.1 --port ${previewPort} --strictPort`,
    url: previewUrl,
    reuseExistingServer: !process.env.CI,
  },
});
