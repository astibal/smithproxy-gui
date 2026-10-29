import {defineConfig} from '@playwright/test';

const chromiumExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
type BrowserName = 'chromium' | 'firefox' | 'webkit';
const browserNames: ReadonlyArray<BrowserName> = process.env.PLAYWRIGHT_ALL_BROWSERS === '1'
  ? ['chromium', 'firefox', 'webkit']
  : ['chromium'];

export default defineConfig({
  testDir: './tests',
  use: {
    baseURL: 'http://127.0.0.1:4173',
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
    command: 'pnpm preview',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
  },
});
