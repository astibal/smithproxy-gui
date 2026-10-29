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
        config_read: false, config_write: false, drafts: false, draft_preflight: false,
        jobs: false, events: true, alerts: true, audit: true,
        smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
      },
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);

    await expect(client.capabilities()).resolves.toMatchObject({
      apiVersion: 'v1', smithproxyState: 'unconfigured',
      features: {configWrite: false, drafts: false, draftPreflight: false, events: true,
        alerts: true, audit: true, smithproxyEvents: false, metrics: true},
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

  it('loads bounded structured operational alerts', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 100,
      alerts: [{
        id: 'tls-cache-capacity', severity: 'warning', title: 'TLS cache capacity is high',
        detail: 'The reported cache size is at least 90% of its configured capacity.',
      }],
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);
    await expect(client.activeAlerts()).resolves.toMatchObject({
      generatedAtUnixMs: 100, alerts: [{id: 'tls-cache-capacity', severity: 'warning'}],
    });
  });

  it('rejects alert text with control characters', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 100,
      alerts: [{id: 'bad', severity: 'critical', title: 'Bad\nalert', detail: 'Rejected'}],
    }));
    await expect(client.activeAlerts()).rejects.toThrow('Invalid operational alert entry');
  });

  it('rejects duplicate operational alert identifiers', async () => {
    const alert = {id: 'duplicate', severity: 'warning', title: 'Repeated', detail: 'Repeated alert'};
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 100, alerts: [alert, alert],
    }));
    await expect(client.activeAlerts()).rejects.toThrow('Duplicate operational alert identifier');
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
      history: [
        {state: 'ready', checked_at_unix_ms: 90, sessions_active: 2, bytes_up: 1000, bytes_down: 1500},
        {state: 'ready', checked_at_unix_ms: 100, sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
      ],
      listeners: [
        {name: 'tcp', workers: 2, sessions_total: 12, sessions_active: 3, bytes_up: 1024, bytes_down: 2048},
        {name: 'tls', workers: 1, sessions_total: 7, sessions_active: 1, bytes_up: 512, bytes_down: 256},
      ],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.metricsSummary()).resolves.toMatchObject({
      state: 'ready', totals: {sessionsActive: 4, bytesDown: 2304},
      listeners: [{name: 'tcp', sessionsTotal: 12}, {name: 'tls', sessionsTotal: 7}],
      history: [{sessionsActive: 2}, {sessionsActive: 4}],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/metrics/summary', expect.anything(),
    );
  });

  it('rejects duplicate listeners and unsafe runtime counters', async () => {
    const response = {
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100, last_success_at_unix_ms: 100,
      totals: {workers: 2, sessions_total: 2, sessions_active: 1, bytes_up: 0, bytes_down: 0},
      history: [],
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

  it('rejects unordered runtime history', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100, last_success_at_unix_ms: 100,
      totals: {workers: 1, sessions_total: 1, sessions_active: 1, bytes_up: 1, bytes_down: 1},
      listeners: [],
      history: [
        {state: 'ready', checked_at_unix_ms: 100, sessions_active: 1, bytes_up: 1, bytes_down: 1},
        {state: 'ready', checked_at_unix_ms: 99, sessions_active: 1, bytes_up: 1, bytes_down: 1},
      ],
    }));
    await expect(client.metricsSummary()).rejects.toThrow('Invalid runtime metrics history');
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
        id: '4-100', source_revision: 4, occurred_at_unix_ms: 100, severity: 'error', source: 'gui-core',
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
        id: 'event', source_revision: 1, occurred_at_unix_ms: 1, severity: 'info', source: 'gui-core',
        message: 'unsafe\nmessage',
      }],
    }));
    await expect(client.recentEvents()).rejects.toThrow('Invalid operational event entry');
  });

  it('loads bounded and redacted management audit records', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', actor_available: false,
      entries: [{
        id: 'audit-3', occurred_at_unix_ms: 100, request_id: 'abc123-9',
        operation: 'config.draft.upsert', outcome: 'succeeded', authentication: 'gateway', actor: null,
        target_count: 2, targets: ['policy.[0].action', 'settings.enabled'], targets_truncated: false,
      }],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.recentAudit()).resolves.toMatchObject({
      actorAvailable: false,
      entries: [{id: 'audit-3', requestId: 'abc123-9', targetCount: 2}],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/audit/recent', expect.anything(),
    );
  });

  it('rejects management audit records that claim incomplete targets without a marker', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', actor_available: false,
      entries: [{
        id: 'audit-1', occurred_at_unix_ms: 1, request_id: 'abc-1',
        operation: 'config.draft.clear', outcome: 'rejected', authentication: 'none', actor: null,
        target_count: 1, targets: [], targets_truncated: false,
      }],
    }));
    await expect(client.recentAudit()).rejects.toThrow('Invalid management audit entry');
  });

  it('subscribes to workspace-scoped operational event streams', () => {
    const listeners = new Map<string, (event: MessageEvent<string>) => void>();
    const close = vi.fn();
    const eventSourceFactory = vi.fn(() => ({
      addEventListener: (type: string, listener: (event: MessageEvent<string>) => void) => {
        listeners.set(type, listener);
      },
      close,
    }));
    const snapshot = vi.fn();
    const event = vi.fn();
    const invalid = vi.fn();
    const client = new SystemClient(
      '/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui',
      async () => jsonResponse({}), 3000, eventSourceFactory,
    );

    const unsubscribe = client.subscribeEvents({snapshot, event, invalid});
    listeners.get('snapshot')?.({data: JSON.stringify({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: '100-ready', source_revision: 1, occurred_at_unix_ms: 100, severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      }],
    })} as MessageEvent<string>);
    listeners.get('operational')?.({data: JSON.stringify({
      id: '200-error', source_revision: 2, occurred_at_unix_ms: 200, severity: 'error',
      source: 'gui-core', message: 'Smithproxy control plane changed to unreachable',
    })} as MessageEvent<string>);

    expect(eventSourceFactory).toHaveBeenCalledWith('/ws001/smithproxy-gui/api/v1/events');
    expect(snapshot).toHaveBeenCalledWith(expect.objectContaining({
      events: [expect.objectContaining({id: '100-ready'})],
    }));
    expect(event).toHaveBeenCalledWith(expect.objectContaining({id: '200-error'}));
    expect(invalid).not.toHaveBeenCalled();
    unsubscribe();
    expect(close).toHaveBeenCalledOnce();
  });

  it('closes an operational event stream after an invalid payload', () => {
    const listeners = new Map<string, (event: MessageEvent<string>) => void>();
    const close = vi.fn();
    const invalid = vi.fn();
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({}), 3000, () => ({
      addEventListener: (type, listener) => listeners.set(type, listener),
      close,
    }));
    client.subscribeEvents({snapshot: vi.fn(), event: vi.fn(), invalid});

    listeners.get('operational')?.({data: '{not-json'} as MessageEvent<string>);

    expect(close).toHaveBeenCalledOnce();
    expect(invalid).toHaveBeenCalledWith(expect.any(Error));
  });

  it('uses a credentialed native EventSource by default', () => {
    const instances: Array<{url: string; options: EventSourceInit; closed: boolean}> = [];
    class FakeEventSource {
      readonly record: {url: string; options: EventSourceInit; closed: boolean};

      constructor(url: string | URL, options: EventSourceInit = {}) {
        this.record = {url: String(url), options, closed: false};
        instances.push(this.record);
      }

      addEventListener(): void {}
      close(): void { this.record.closed = true; }
    }
    vi.stubGlobal('EventSource', FakeEventSource);
    try {
      const client = new SystemClient('/api/v1', '/');
      const unsubscribe = client.subscribeEvents({snapshot: vi.fn(), event: vi.fn(), invalid: vi.fn()});
      expect(instances).toEqual([{
        url: '/api/v1/events', options: {withCredentials: true}, closed: false,
      }]);
      unsubscribe();
      expect(instances[0]?.closed).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
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
