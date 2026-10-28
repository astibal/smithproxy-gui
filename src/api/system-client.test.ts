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
      features: {
        config_read: false, config_write: false, jobs: false, events: true,
        smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
      },
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);

    await expect(client.capabilities()).resolves.toMatchObject({
      apiVersion: 'v1', smithproxyState: 'unconfigured',
      features: {configWrite: false, events: true, smithproxyEvents: false, metrics: true},
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

  it('loads and validates aggregated runtime metrics', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100, last_success_at_unix_ms: 100,
      totals: {workers: 3, sessions_total: 19, sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
      listeners: [
        {name: 'tcp', workers: 2, sessions_total: 12, sessions_active: 3, bytes_up: 1024, bytes_down: 2048},
        {name: 'tls', workers: 1, sessions_total: 7, sessions_active: 1, bytes_up: 512, bytes_down: 256},
      ],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.metricsSummary()).resolves.toMatchObject({
      state: 'ready', totals: {sessionsActive: 4, bytesDown: 2304},
      listeners: [{name: 'tcp', sessionsTotal: 12}, {name: 'tls', sessionsTotal: 7}],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/metrics/summary', expect.anything(),
    );
  });

  it('rejects duplicate listeners and unsafe runtime counters', async () => {
    const response = {
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100, last_success_at_unix_ms: 100,
      totals: {workers: 2, sessions_total: 2, sessions_active: 1, bytes_up: 0, bytes_down: 0},
      listeners: [
        {name: 'tcp', workers: 1, sessions_total: 1, sessions_active: 1, bytes_up: 0, bytes_down: 0},
        {name: 'tcp', workers: 1, sessions_total: 1, sessions_active: 0, bytes_up: 0, bytes_down: 0},
      ],
    };
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse(response));
    await expect(client.metricsSummary()).rejects.toThrow('Invalid Smithproxy listener metrics');
    response.listeners[1]!.name = 'tls';
    response.listeners[1]!.bytes_up = Number.MAX_SAFE_INTEGER + 1;
    await expect(client.metricsSummary()).rejects.toThrow('Invalid Smithproxy runtime counters');
  });

  it('loads and validates privacy-preserving session activity', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100, last_success_at_unix_ms: 100,
      total: 3, speed_up: 12, speed_down: 34,
      protocols: [
        {protocol: 'tcp', sessions: 2, speed_up: 10, speed_down: 30, bytes_up: 100, bytes_down: 300},
        {protocol: 'tls', sessions: 1, speed_up: 2, speed_down: 4, bytes_up: 20, bytes_down: 40},
      ],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.sessionActivity()).resolves.toMatchObject({
      total: 3,
      speedDown: 34,
      protocols: [
        {protocol: 'tcp', sessions: 2, speedUp: 10, speedDown: 30, bytesUp: 100, bytesDown: 300},
        {protocol: 'tls', sessions: 1, speedUp: 2, speedDown: 4, bytesUp: 20, bytesDown: 40},
      ],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/sessions/activity', expect.anything(),
    );
  });

  it('loads and validates aggregate TLS cache metrics', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100,
      last_success_at_unix_ms: 100, size: 42, capacity: 1000,
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.tlsCacheSummary()).resolves.toMatchObject({size: 42, capacity: 1000});
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/tls/cache/summary', expect.anything(),
    );
  });

  it('rejects inconsistent TLS cache counters', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Invalid', checked_at_unix_ms: 1,
      last_success_at_unix_ms: 1, size: 2, capacity: 1,
    }));
    await expect(client.tlsCacheSummary()).rejects.toThrow('Invalid TLS cache response');
  });

  it('loads and validates privacy-safe neighborhood aggregates', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100,
      last_success_at_unix_ms: 100, hosts_total: 8, active_today: 3,
      active_week: 6, tagged_hosts: 4, observations: 20, bytes_up: 1000, bytes_down: 2000,
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.neighborSummary()).resolves.toMatchObject({
      hostsTotal: 8, activeToday: 3, activeWeek: 6, observations: 20,
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/network/neighbors/summary', expect.anything(),
    );
  });

  it('loads bounded operational events', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: '4-100', occurred_at_unix_ms: 100, severity: 'error', source: 'gui-core',
        message: 'Smithproxy control plane changed to unreachable',
      }],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.recentEvents()).resolves.toMatchObject({
      smithproxyEventsAvailable: false,
      events: [{id: '4-100', severity: 'error', occurredAtUnixMs: 100}],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/events/recent', expect.anything(),
    );
  });

  it('rejects unsafe operational event text', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: 'event', occurred_at_unix_ms: 1, severity: 'info', source: 'gui-core',
        message: 'unsafe\nmessage',
      }],
    }));
    await expect(client.recentEvents()).rejects.toThrow('Invalid operational event entry');
  });

  it('rejects inconsistent neighborhood aggregates', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Invalid', checked_at_unix_ms: 1,
      last_success_at_unix_ms: 1, hosts_total: 1, active_today: 2,
      active_week: 1, tagged_hosts: 0, observations: 0, bytes_up: 0, bytes_down: 0,
    }));
    await expect(client.neighborSummary()).rejects.toThrow('Invalid neighborhood response');
  });

  it('rejects inconsistent session activity totals', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 1, last_success_at_unix_ms: 1,
      total: 2, speed_up: 1, speed_down: 1,
      protocols: [
        {protocol: 'tcp', sessions: 1, speed_up: 1, speed_down: 1, bytes_up: 0, bytes_down: 0},
      ],
    }));
    await expect(client.sessionActivity()).rejects.toThrow('Inconsistent session activity totals');
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
