import {expect, test, type Page} from '@playwright/test';

type MockState = {smithproxy: 'ready' | 'unreachable'};

async function mockSystemApi(page: Page, state: MockState): Promise<void> {
  await page.route('**/api/v1/capabilities', async route => route.fulfill({json: {
    service: 'smithproxy-gui',
    api_version: 'v1',
    base_path: '/',
    smithproxy_state: state.smithproxy,
    features: {config_read: false, config_write: false, jobs: false, events: false, metrics: true},
  }}));
  await page.route('**/api/v1/status', async route => route.fulfill({json: {
    service: 'smithproxy-gui',
    uptime_ms: 65000,
    smithproxy: {
      configured: true,
      state: state.smithproxy,
      detail: state.smithproxy === 'ready' ? 'Connected' : 'Connection timed out',
      checked_at_unix_ms: Date.now(),
      last_success_at_unix_ms: Date.now() - 5000,
      latency_ms: state.smithproxy === 'ready' ? 12 : 2500,
      total_probes: 3,
      consecutive_failures: state.smithproxy === 'ready' ? 0 : 1,
      availability_window: {samples: 2, successful: state.smithproxy === 'ready' ? 2 : 1},
      history: state.smithproxy === 'ready'
        ? [
            {state: 'ready', checked_at_unix_ms: Date.now() - 5000, latency_ms: 11},
            {state: 'ready', checked_at_unix_ms: Date.now(), latency_ms: 12},
          ]
        : [
            {state: 'ready', checked_at_unix_ms: Date.now() - 5000, latency_ms: 11},
            {state: 'unreachable', checked_at_unix_ms: Date.now(), latency_ms: 2500},
          ],
    },
  }}));
  await page.route('**/api/v1/metrics/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current listener metrics' : 'Metrics are stale',
    checked_at_unix_ms: Date.now(),
    last_success_at_unix_ms: Date.now() - 5000,
    totals: {workers: 3, sessions_total: 19, sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
    listeners: [
      {name: 'tcp', workers: 2, sessions_total: 12, sessions_active: 3, bytes_up: 1024, bytes_down: 2048},
      {name: 'tls', workers: 1, sessions_total: 7, sessions_active: 1, bytes_up: 512, bytes_down: 256},
    ],
  }}));
}

test('opens a policy and its referenced address object', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /office office-net/i}).click();
  await expect(page.getByRole('region', {name: 'Edit office'})).toBeVisible();

  await page.getByRole('button', {name: 'office-net', exact: true}).click();
  const addressEditor = page.getByRole('region', {name: 'Edit office-net'});
  await expect(addressEditor).toBeVisible();
  await expect(page.getByText('This shared object is used by 4 configuration entries.')).toBeVisible();

  await addressEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 1 changes')).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(addressEditor).not.toBeVisible();
  await expect(page.getByRole('region', {name: 'Edit office'})).toBeVisible();
});

test('shows live Smithproxy status transitions', async ({page}) => {
  const state: MockState = {smithproxy: 'ready'};
  await mockSystemApi(page, state);
  await page.goto('/');

  await expect(page.getByText('Core: Online')).toBeVisible();
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
  await expect(page.getByText('12 ms')).toBeVisible();
  await expect(page.getByRole('region', {name: 'Probe history'})).toBeVisible();
  await expect(page.getByText(/control-plane health and listener counters are live/i)).toBeVisible();
  await expect(page.getByRole('region', {name: 'Runtime metrics summary'}).getByText('4', {exact: true})).toBeVisible();

  await page.getByRole('button', {name: 'Monitoring', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Listener monitoring'})).toBeVisible();
  await expect(page.getByRole('cell', {name: 'tcp'})).toBeVisible();
  await expect(page.getByRole('cell', {name: 'tls'})).toBeVisible();

  state.smithproxy = 'unreachable';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Unreachable')).toBeVisible();

  state.smithproxy = 'ready';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
});

test('exposes network, object, and system vertical slices', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');

  await page.getByRole('button', {name: 'Network', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Listener workload'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'tcp'})).toBeVisible();
  await expect(page.getByText('3', {exact: true})).toBeVisible();

  await page.getByRole('button', {name: 'Objects', exact: true}).click();
  await expect(page.getByRole('group', {name: 'Address objects'})).toBeVisible();
  await page.getByRole('button', {name: /office-net subnet/i}).click();
  await expect(page.getByRole('region', {name: 'Edit office-net'})).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByRole('button', {name: 'System', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'System integration'})).toBeVisible();
  await expect(page.getByText('Smithproxy key')).toBeVisible();
  await expect(page.getByText('Never exposed')).toBeVisible();
});

test('declares the Saslik appearance contract and remains usable on mobile', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/');

  await expect(page.locator('link[data-saslik-theme]')).toHaveAttribute('href', '/saslik-theme.css');
  await expect(page.locator('script[data-app="smithproxy-gui"]')).toHaveAttribute('src', '/saslik-theme.js');
  await page.getByRole('button', {name: 'Objects', exact: true}).click();
  await page.getByRole('button', {name: /office-net subnet/i}).click();
  const editor = page.getByRole('region', {name: 'Edit office-net'});
  await expect(editor).toBeVisible();
  await expect(editor).toHaveCSS('left', '0px');
});

test('derives the system API from a workspace mount', async ({page}) => {
  const requests: string[] = [];
  page.on('request', request => {
    if (request.url().endsWith('/api/v1/status')) requests.push(new URL(request.url()).pathname);
  });
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.locator('smithproxy-gui').evaluate(element => element.remove());
  await page.evaluate(() => {
    history.replaceState({}, '', '/ws001/smithproxy-gui/');
    const application = document.createElement('smithproxy-gui');
    application.setAttribute('mode', 'standalone');
    document.body.append(application);
  });

  await expect(page.getByText('Core: Online')).toBeVisible();
  await expect.poll(() => requests).toContain('/ws001/smithproxy-gui/api/v1/status');
});
