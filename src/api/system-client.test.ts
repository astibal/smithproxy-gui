import {describe, expect, it, vi} from 'vitest';
import {SystemClient} from './system-client';

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}

describe('SystemClient', () => {
  it('loads health below the configured base path with safe fetch options', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      status: 'ok',
      smithproxy: {state: 'ready', detail: 'Connected', checked_at_unix_ms: 42},
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1/', '/ws001/smithproxy-gui/', fetcher);

    await expect(client.health()).resolves.toEqual({
      status: 'ok',
      smithproxy: {state: 'ready', detail: 'Connected', checkedAtUnixMs: 42},
    });
    expect(fetcher).toHaveBeenCalledWith('/ws001/smithproxy-gui/healthz', expect.objectContaining({
      cache: 'no-store', credentials: 'same-origin', redirect: 'error',
    }));
  });

  it('loads and maps capabilities', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      service: 'smithproxy-gui', api_version: 'v1', base_path: '/', smithproxy_state: 'unconfigured',
      features: {config_read: false, config_write: false, jobs: false, events: false},
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);

    await expect(client.capabilities()).resolves.toMatchObject({
      apiVersion: 'v1', smithproxyState: 'unconfigured', features: {configWrite: false},
    });
  });

  it('loads and validates the monitoring snapshot', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      service: 'smithproxy-gui', uptime_ms: 1234,
      smithproxy: {
        configured: true, state: 'ready', detail: 'Connected', checked_at_unix_ms: 100,
        last_success_at_unix_ms: 100, latency_ms: 7, total_probes: 2, consecutive_failures: 0,
        availability_window: {samples: 2, successful: 1},
        history: [
          {state: 'unreachable', checked_at_unix_ms: 90, latency_ms: 2500},
          {state: 'ready', checked_at_unix_ms: 100, latency_ms: 7},
        ],
      },
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.status()).resolves.toMatchObject({
      uptimeMs: 1234,
      smithproxy: {latencyMs: 7, totalProbes: 2, availabilityWindow: {samples: 2, successful: 1}},
    });
    expect(fetcher).toHaveBeenCalledWith('/ws001/smithproxy-gui/api/v1/status', expect.anything());
  });

  it('rejects inconsistent monitoring counters', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      service: 'smithproxy-gui', uptime_ms: 1,
      smithproxy: {
        configured: true, state: 'ready', detail: 'Connected', checked_at_unix_ms: 1,
        last_success_at_unix_ms: 1, latency_ms: 1, total_probes: 1, consecutive_failures: 0,
        availability_window: {samples: 2, successful: 2}, history: [],
      },
    }));
    await expect(client.status()).rejects.toThrow('Inconsistent Smithproxy status counters');
  });

  it('rejects malformed responses and unsafe endpoint configuration', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({status: 'ok'}));
    await expect(client.health()).rejects.toThrow('Invalid health response');
    expect(() => new SystemClient('https://other.example/api', '/')).toThrow('same-origin');
    expect(() => new SystemClient('/api/../secret', '/')).toThrow('relative path');
  });

  it('does not coerce non-string Smithproxy states', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      status: 'ok', smithproxy: {state: {toString: 'ready'}, detail: 'Invalid', checked_at_unix_ms: null},
    }));
    await expect(client.health()).rejects.toThrow('Invalid Smithproxy health response');
  });

  it('rejects non-success HTTP responses', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({}, 503));
    await expect(client.health()).rejects.toThrow('HTTP 503');
  });
});
