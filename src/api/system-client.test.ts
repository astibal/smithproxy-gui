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
      config_transaction_state: 'not-advertised',
      features: {
        config_read: false, config_write: false, drafts: false, draft_preflight: false,
        jobs: false, events: true, alerts: true, audit: true,
        smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
        interface_monitoring: true,
      },
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);

    await expect(client.capabilities()).resolves.toMatchObject({
      apiVersion: 'v1', smithproxyState: 'unconfigured', transactionState: 'not-advertised',
      features: {configWrite: false, drafts: false, draftPreflight: false, events: true,
        alerts: true, audit: true, smithproxyEvents: false, metrics: true},
    });
  });

  it('rejects inconsistent privileged capability combinations', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      service: 'smithproxy-gui', api_version: 'v1', base_path: '/', smithproxy_state: 'ready',
      features: {
        config_read: false, config_write: false, drafts: true, draft_preflight: true,
        jobs: false, events: true, alerts: true, audit: true, smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
        interface_monitoring: true,
      },
    }));
    await expect(client.capabilities()).rejects.toThrow('Inconsistent privileged capabilities');
  });

  it('rejects incoherent transaction, event, version, and mount capabilities', async () => {
    const capabilities = (overrides: Record<string, unknown> = {}) => ({
      service: 'smithproxy-gui', api_version: 'v1', base_path: '/', smithproxy_state: 'ready',
      config_transaction_state: 'ready',
      features: {
        config_read: true, config_write: true, drafts: true, draft_preflight: true,
        jobs: true, events: true, alerts: true, audit: true, smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
        interface_monitoring: true,
      },
      ...overrides,
    });
    const client = (payload: unknown, basePath = '/') =>
      new SystemClient('/api/v1', basePath, async () => jsonResponse(payload));

    await expect(client(capabilities({features: {
      ...capabilities().features, draft_preflight: false,
    }})).capabilities()).rejects.toThrow('Inconsistent privileged capabilities');
    await expect(client(capabilities({config_transaction_state: 'review-required'}))
      .capabilities()).rejects.toThrow('Inconsistent privileged capabilities');
    await expect(client(capabilities({features: {
      ...capabilities().features, events: false, smithproxy_events: true,
    }})).capabilities()).rejects.toThrow('Inconsistent event capabilities');
    await expect(client(capabilities({api_version: 'v2'})).capabilities())
      .rejects.toThrow('Invalid capabilities response');
    await expect(client(capabilities({base_path: '/workspace/'})).capabilities())
      .rejects.toThrow('canonical');
    await expect(client(capabilities({base_path: '/other'}), '/expected').capabilities())
      .rejects.toThrow('does not match');
  });

  it('rejects an unknown transaction capability state', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      service: 'smithproxy-gui', api_version: 'v1', base_path: '/', smithproxy_state: 'ready',
      config_transaction_state: 'optimistic',
      features: {
        config_read: false, config_write: false, drafts: false, draft_preflight: false,
        jobs: false, events: true, alerts: true, audit: true, smithproxy_events: false,
        metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
        interface_monitoring: true,
      },
    }));
    await expect(client.capabilities()).rejects.toThrow('Invalid transaction capability state');
  });

  it('loads and validates the trusted gateway session', async () => {
    const fetcher = vi.fn(async () => jsonResponse({mode: 'gateway', authenticated: true}));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.authSession()).resolves.toEqual({mode: 'gateway', authenticated: true});
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/auth/session', expect.objectContaining({redirect: 'error'}),
    );
  });

  it('rejects contradictory or malformed gateway sessions', async () => {
    const client = new SystemClient('/api/v1', '/', async () =>
      jsonResponse({mode: 'disabled', authenticated: true}));
    await expect(client.authSession()).rejects.toThrow('Invalid gateway session response');

    const malformed = new SystemClient('/api/v1', '/', async () =>
      jsonResponse({mode: 'proxy', authenticated: false}));
    await expect(malformed.authSession()).rejects.toThrow('Invalid gateway session response');
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

  it('rejects future-dated monitoring and operational snapshots', async () => {
    const future = Date.now() + 6 * 60 * 1000;
    const client = (payload: unknown) => new SystemClient(
      '/api/v1', '/', async () => jsonResponse(payload),
    );
    const checks: Array<() => Promise<unknown>> = [
      () => client({status: 'ok', smithproxy: {
        state: 'ready', detail: 'Connected', checked_at_unix_ms: future,
      }}).health(),
      () => client({service: 'smithproxy-gui', uptime_ms: 1, smithproxy: {
        configured: true, state: 'ready', detail: 'Connected', checked_at_unix_ms: future,
        last_success_at_unix_ms: future, latency_ms: 1, total_probes: 1,
        consecutive_failures: 0, availability_window: {samples: 1, successful: 1},
        history: [{state: 'ready', checked_at_unix_ms: future, latency_ms: 1}],
      }}).status(),
      () => client({state: 'ready', detail: 'Current', checked_at_unix_ms: future,
        last_success_at_unix_ms: future,
        totals: {workers: 0, sessions_total: 0, sessions_active: 0, bytes_up: 0, bytes_down: 0},
        listeners: [], history: [{state: 'ready', checked_at_unix_ms: future,
          sessions_active: 0, bytes_up: 0, bytes_down: 0}],
      }).metricsSummary(),
      () => client({state: 'ready', detail: 'Current', checked_at_unix_ms: future,
        last_success_at_unix_ms: future, total: 0, speed_up: 0, speed_down: 0, protocols: [],
      }).sessionActivity(),
      () => client({state: 'ready', detail: 'Current', checked_at_unix_ms: future,
        last_success_at_unix_ms: future, size: 0, capacity: 0,
      }).tlsCacheSummary(),
      () => client({state: 'ready', detail: 'Current', checked_at_unix_ms: future,
        last_success_at_unix_ms: future, hosts_total: 0, active_today: 0, active_week: 0,
        tagged_hosts: 0, observations: 0, bytes_up: 0, bytes_down: 0,
      }).neighborSummary(),
      () => client({state: 'ready', detail: 'Current', checked_at_unix_ms: future,
        last_success_at_unix_ms: future, generation: 1, synchronization_running: true,
        synchronization_attempts: 1, synchronization_successes: 1, synchronization_errors: 0,
        event_datagrams: 1, changed_event_datagrams: 1, interfaces: 1, addresses: 1,
        ipv4_addresses: 1, ipv6_addresses: 0, last_error_code: null,
      }).interfaceSummary(),
      () => client({source: 'gui-core', smithproxy_events_available: false, events: [{
        id: 'event-1', source_revision: 1, occurred_at_unix_ms: future,
        category: 'control-plane', code: 'control-plane.ready', severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      }]}).recentEvents(),
      () => client({source: 'gui-core', generated_at_unix_ms: future, alerts: []}).activeAlerts(),
      () => client({source: 'gui-core', actor_available: false, entries: [{
        id: 'audit-1', occurred_at_unix_ms: future, request_id: 'abc-1',
        operation: 'api.mutation', outcome: 'rejected', authentication: 'none', actor: null,
        target_count: 0, targets: [], targets_truncated: false,
      }]}).recentAudit(),
      () => client({source: 'gui-core', generated_at_unix_ms: future, owner_available: false,
        jobs: []}).jobs(),
    ];

    for (const check of checks) await expect(check()).rejects.toThrow();
  });

  it('rejects incoherent collector and event timelines', async () => {
    const tlsClient = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'unavailable', detail: 'Stale', checked_at_unix_ms: 100,
      last_success_at_unix_ms: 101, size: 1, capacity: 2,
    }));
    await expect(tlsClient.tlsCacheSummary()).rejects.toThrow('Invalid TLS cache response');

    const statusClient = new SystemClient('/api/v1', '/', async () => jsonResponse({
      service: 'smithproxy-gui', uptime_ms: 1, smithproxy: {
        configured: true, state: 'ready', detail: 'Connected', checked_at_unix_ms: 101,
        last_success_at_unix_ms: 101, latency_ms: 1, total_probes: 1,
        consecutive_failures: 0, availability_window: {samples: 1, successful: 1},
        history: [{state: 'ready', checked_at_unix_ms: 100, latency_ms: 1}],
      },
    }));
    await expect(statusClient.status()).rejects.toThrow('Inconsistent Smithproxy status timeline');

    const metricsClient = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 101,
      last_success_at_unix_ms: 101,
      totals: {workers: 0, sessions_total: 0, sessions_active: 0, bytes_up: 0, bytes_down: 0},
      listeners: [], history: [{state: 'ready', checked_at_unix_ms: 100,
        sessions_active: 0, bytes_up: 0, bytes_down: 0}],
    }));
    await expect(metricsClient.metricsSummary()).rejects.toThrow(
      'Inconsistent runtime metrics timeline',
    );

    const eventClient = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', smithproxy_events_available: false, events: [{
        id: 'event-2', source_revision: 2, occurred_at_unix_ms: 100,
        category: 'control-plane', code: 'control-plane.ready', severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      }, {
        id: 'event-1', source_revision: 1, occurred_at_unix_ms: 101,
        category: 'control-plane', code: 'control-plane.unreachable', severity: 'error',
        source: 'gui-core', message: 'Smithproxy control plane changed to unreachable',
      }],
    }));
    await expect(eventClient.recentEvents()).rejects.toThrow('Invalid operational event entry');
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

  it('rejects unordered probe history and inconsistent availability', async () => {
    const snapshot = {
      service: 'smithproxy-gui', uptime_ms: 1,
      smithproxy: {
        configured: true, state: 'ready', detail: 'Connected', checked_at_unix_ms: 100,
        last_success_at_unix_ms: 100, latency_ms: 1, total_probes: 2, consecutive_failures: 0,
        availability_window: {samples: 2, successful: 1},
        history: [
          {state: 'ready', checked_at_unix_ms: 100, latency_ms: 1},
          {state: 'unreachable', checked_at_unix_ms: 90, latency_ms: null},
        ],
      },
    };
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse(snapshot));
    await expect(client.status()).rejects.toThrow('Invalid Smithproxy probe history');

    snapshot.smithproxy.history[0]!.checked_at_unix_ms = 90;
    snapshot.smithproxy.history[1]!.checked_at_unix_ms = 100;
    snapshot.smithproxy.availability_window.successful = 2;
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

  it('loads and validates privacy-safe interface synchronization aggregates', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      state: 'ready', detail: 'Current', checked_at_unix_ms: 100,
      last_success_at_unix_ms: 100, generation: 42, synchronization_running: true,
      synchronization_attempts: 3, synchronization_successes: 3, synchronization_errors: 0,
      event_datagrams: 15, changed_event_datagrams: 4, interfaces: 3, addresses: 5,
      ipv4_addresses: 3, ipv6_addresses: 2, last_error_code: null,
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.interfaceSummary()).resolves.toMatchObject({
      state: 'ready', generation: 42, interfaces: 3, addresses: 5,
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/network/interfaces/summary', expect.anything(),
    );
  });

  it('accepts an explicitly unavailable interface capability without fabricating a sample', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'not-advertised', detail: 'Capability not advertised',
      checked_at_unix_ms: 100, last_success_at_unix_ms: null,
      generation: 0, synchronization_running: false,
      synchronization_attempts: 0, synchronization_successes: 0, synchronization_errors: 0,
      event_datagrams: 0, changed_event_datagrams: 0, interfaces: 0, addresses: 0,
      ipv4_addresses: 0, ipv6_addresses: 0, last_error_code: null,
    }));

    await expect(client.interfaceSummary()).resolves.toMatchObject({
      state: 'not-advertised', lastSuccessAtUnixMs: null, interfaces: 0,
    });
  });

  it('loads bounded operational events', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: '4-100', source_revision: 4, occurred_at_unix_ms: 100,
        category: 'control-plane', code: 'control-plane.unreachable',
        severity: 'error', source: 'gui-core',
        message: 'Smithproxy control plane changed to unreachable',
      }, {
        id: 'event-5', source_revision: 5, occurred_at_unix_ms: 101,
        category: 'backend-job', code: 'config-refresh.failed',
        severity: 'warning', source: 'gui-core',
        message: 'Configuration refresh did not converge',
      }],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.recentEvents()).resolves.toMatchObject({
      smithproxyEventsAvailable: false,
      events: [
        {id: '4-100', category: 'control-plane', code: 'control-plane.unreachable',
          severity: 'error', occurredAtUnixMs: 100},
        {id: 'event-5', category: 'backend-job', code: 'config-refresh.failed',
          severity: 'warning', occurredAtUnixMs: 101},
      ],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/events/recent', expect.anything(),
    );
  });

  it('rejects unsafe operational event text', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: 'event', source_revision: 1, occurred_at_unix_ms: 1,
        category: 'control-plane', code: 'control-plane.ready', severity: 'info', source: 'gui-core',
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
      }, {
        id: 'audit-4', occurred_at_unix_ms: 101, request_id: 'abc123-10',
        operation: 'config.draft.commit', outcome: 'succeeded', authentication: 'gateway', actor: null,
        target_count: 3, targets: [], targets_truncated: true,
      }],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.recentAudit()).resolves.toMatchObject({
      actorAvailable: false,
      entries: [
        {id: 'audit-3', requestId: 'abc123-9', targetCount: 2},
        {id: 'audit-4', operation: 'config.draft.commit', targetCount: 3, targetsTruncated: true},
      ],
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

  it('loads bounded backend jobs below the workspace API prefix', async () => {
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 200, owner_available: false,
      jobs: [{
        id: 'job-01234567-89ab-4def-8123-456789abcdef', type: 'config-refresh',
        state: 'running', phase: 'waiting-for-revision', progress_percent: 75,
        cancelable: false, created_at_unix_ms: 100, updated_at_unix_ms: 150,
        deadline_at_unix_ms: 300, owner: null, result: null,
      }],
    }));
    const client = new SystemClient('/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui', fetcher);

    await expect(client.jobs()).resolves.toMatchObject({
      ownerAvailable: false,
      jobs: [{state: 'running', phase: 'waiting-for-revision', progressPercent: 75}],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/jobs', expect.anything(),
    );
  });

  it('loads one terminal backend job and rejects unsafe identifiers', async () => {
    const id = 'job-01234567-89ab-4def-8123-456789abcdef';
    const fetcher = vi.fn(async () => jsonResponse({
      source: 'gui-core', owner_available: false,
      job: {
        id, type: 'config-refresh', state: 'succeeded', phase: 'synchronized',
        progress_percent: 100, cancelable: false, created_at_unix_ms: 100,
        updated_at_unix_ms: 150, deadline_at_unix_ms: 300, owner: null,
        result: 'Configuration snapshot synchronized',
      },
    }));
    const client = new SystemClient('/api/v1', '/', fetcher);

    await expect(client.job(id)).resolves.toMatchObject({state: 'succeeded', progressPercent: 100});
    await expect(client.job('../audit/recent')).rejects.toThrow('Invalid backend job identifier');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('rejects contradictory backend job records', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 200, owner_available: false,
      jobs: [{
        id: 'job-01234567-89ab-4def-8123-456789abcdef', type: 'config-refresh',
        state: 'succeeded', phase: 'synchronized', progress_percent: 75,
        cancelable: false, created_at_unix_ms: 100, updated_at_unix_ms: 150,
        deadline_at_unix_ms: 300, owner: null, result: null,
      }],
    }));
    await expect(client.jobs()).rejects.toThrow('Inconsistent backend job state');
  });

  it('rejects unreviewed backend job phases and result text', async () => {
    const job = {
      id: 'job-01234567-89ab-4def-8123-456789abcdef', type: 'config-refresh',
      state: 'failed', phase: 'timed-out', progress_percent: 100,
      cancelable: false, created_at_unix_ms: 100, updated_at_unix_ms: 150,
      deadline_at_unix_ms: 140, owner: null,
      result: 'Configuration refresh deadline exceeded',
    };
    const response = (override: Record<string, unknown>) => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 200, owner_available: false,
      jobs: [{...job, ...override}],
    });
    const phaseClient = new SystemClient('/api/v1', '/', async () => response({phase: 'retrying'}));
    const resultClient = new SystemClient('/api/v1', '/', async () => response({result: 'private failure'}));
    const futureClient = new SystemClient('/api/v1', '/', async () => response({
      state: 'cancelled', phase: 'cancelled', result: 'Cancelled',
    }));

    await expect(phaseClient.jobs()).rejects.toThrow('Inconsistent backend job state');
    await expect(resultClient.jobs()).rejects.toThrow('Inconsistent backend job state');
    await expect(futureClient.jobs()).rejects.toThrow('Invalid backend job entry');
  });

  it('rejects backend job updates from the future of their snapshot', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      source: 'gui-core', generated_at_unix_ms: 149, owner_available: false,
      jobs: [{
        id: 'job-01234567-89ab-4def-8123-456789abcdef', type: 'config-refresh',
        state: 'running', phase: 'waiting-for-revision', progress_percent: 75,
        cancelable: false, created_at_unix_ms: 100, updated_at_unix_ms: 150,
        deadline_at_unix_ms: 300, owner: null, result: null,
      }],
    }));
    await expect(client.jobs()).rejects.toThrow('Inconsistent backend job history');
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
    const connection = vi.fn();
    const client = new SystemClient(
      '/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui',
      async () => jsonResponse({}), 3000, eventSourceFactory,
    );

    const unsubscribe = client.subscribeEvents({snapshot, event, invalid, connection});
    listeners.get('open')?.({} as MessageEvent<string>);
    listeners.get('snapshot')?.({data: JSON.stringify({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: '100-ready', source_revision: 1, occurred_at_unix_ms: 100,
        category: 'control-plane', code: 'control-plane.ready', severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      }],
    })} as MessageEvent<string>);
    listeners.get('operational')?.({data: JSON.stringify({
      id: '200-error', source_revision: 2, occurred_at_unix_ms: 200,
      category: 'control-plane', code: 'control-plane.unreachable', severity: 'error',
      source: 'gui-core', message: 'Smithproxy control plane changed to unreachable',
    })} as MessageEvent<string>);

    expect(eventSourceFactory).toHaveBeenCalledWith('/ws001/smithproxy-gui/api/v1/events');
    expect(snapshot).toHaveBeenCalledWith(expect.objectContaining({
      events: [expect.objectContaining({id: '100-ready'})],
    }));
    expect(event).toHaveBeenCalledWith(expect.objectContaining({id: '200-error'}));
    expect(connection).toHaveBeenCalledWith('open');
    listeners.get('error')?.({} as MessageEvent<string>);
    expect(connection).toHaveBeenLastCalledWith('reconnecting');
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

  it('rejects inconsistent interface synchronization aggregates', async () => {
    const client = new SystemClient('/api/v1', '/', async () => jsonResponse({
      state: 'ready', detail: 'Invalid', checked_at_unix_ms: 1,
      last_success_at_unix_ms: 1, generation: 1, synchronization_running: true,
      synchronization_attempts: 1, synchronization_successes: 2, synchronization_errors: 0,
      event_datagrams: 1, changed_event_datagrams: 0, interfaces: 1, addresses: 1,
      ipv4_addresses: 1, ipv6_addresses: 0, last_error_code: null,
    }));
    await expect(client.interfaceSummary()).rejects.toThrow('Invalid interface monitoring response');
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

  it('cancels all in-flight management requests', async () => {
    const signals: AbortSignal[] = [];
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const signal = init?.signal;
      if (signal) signals.push(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new Error('request cancelled')), {once: true});
      });
    });
    const client = new SystemClient('/api/v1', '/', fetcher);
    const status = client.status();
    const metrics = client.metricsSummary();

    client.cancelPendingRequests();

    expect(signals).toHaveLength(2);
    expect(signals.every(signal => signal.aborted)).toBe(true);
    await expect(status).rejects.toThrow('request cancelled');
    await expect(metrics).rejects.toThrow('request cancelled');
  });
});
