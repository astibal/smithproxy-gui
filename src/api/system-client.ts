import {httpStatusError} from './http-error';

export type SmithproxyState =
  | 'starting'
  | 'ready'
  | 'unreachable'
  | 'unauthorized'
  | 'unconfigured'
  | 'error';

export interface SystemHealth {
  status: 'ok';
  smithproxy: {
    state: SmithproxyState;
    detail: string;
    checkedAtUnixMs: number | null;
  };
}

export interface SystemCapabilities {
  service: 'smithproxy-gui';
  apiVersion: string;
  basePath: string;
  smithproxyState: SmithproxyState;
  features: {
    configRead: boolean;
    configWrite: boolean;
    drafts: boolean;
    draftPreflight: boolean;
    jobs: boolean;
    events: boolean;
    alerts: boolean;
    audit: boolean;
    smithproxyEvents: boolean;
    metrics: boolean;
    sessionActivity: boolean;
    tlsMonitoring: boolean;
    neighborMonitoring: boolean;
  };
}

export interface ProbeSample {
  state: SmithproxyState;
  checkedAtUnixMs: number;
  latencyMs: number | null;
}

export interface SystemSnapshot {
  service: 'smithproxy-gui';
  uptimeMs: number;
  smithproxy: {
    configured: boolean;
    state: SmithproxyState;
    detail: string;
    checkedAtUnixMs: number | null;
    lastSuccessAtUnixMs: number | null;
    latencyMs: number | null;
    totalProbes: number;
    consecutiveFailures: number;
    availabilityWindow: {samples: number; successful: number};
    history: ReadonlyArray<ProbeSample>;
  };
}

export type RuntimeMetricsState = 'starting' | 'ready' | 'unavailable' | 'unconfigured';

export interface ListenerMetrics {
  name: string;
  workers: number;
  sessionsTotal: number;
  sessionsActive: number;
  bytesUp: number;
  bytesDown: number;
}

export interface RuntimeMetricsSnapshot {
  state: RuntimeMetricsState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  totals: Omit<ListenerMetrics, 'name'>;
  listeners: ReadonlyArray<ListenerMetrics>;
  history: ReadonlyArray<RuntimeMetricsSample>;
}

export interface RuntimeMetricsSample {
  state: RuntimeMetricsState;
  checkedAtUnixMs: number;
  sessionsActive: number;
  bytesUp: number;
  bytesDown: number;
}

export interface SessionActivityBucket {
  protocol: string;
  sessions: number;
  speedUp: number;
  speedDown: number;
  bytesUp: number;
  bytesDown: number;
}

export interface SessionActivitySnapshot {
  state: RuntimeMetricsState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  total: number;
  speedUp: number;
  speedDown: number;
  protocols: ReadonlyArray<SessionActivityBucket>;
}

export interface TlsCacheSnapshot {
  state: RuntimeMetricsState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  size: number;
  capacity: number;
}

export interface NeighborSnapshot {
  state: RuntimeMetricsState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  hostsTotal: number;
  activeToday: number;
  activeWeek: number;
  taggedHosts: number;
  observations: number;
  bytesUp: number;
  bytesDown: number;
}

export type EventSeverity = 'info' | 'notice' | 'warning' | 'error';

export interface OperationalEvent {
  id: string;
  sourceRevision: number;
  occurredAtUnixMs: number;
  severity: EventSeverity;
  source: 'gui-core';
  message: string;
}

export interface EventSnapshot {
  source: 'gui-core';
  smithproxyEventsAvailable: boolean;
  events: ReadonlyArray<OperationalEvent>;
}

export interface EventStreamHandlers {
  snapshot: (snapshot: EventSnapshot) => void;
  event: (event: OperationalEvent) => void;
  invalid: (error: Error) => void;
  connection?: (state: 'open' | 'reconnecting') => void;
}

interface EventSourceLike {
  addEventListener(type: string, listener: (event: MessageEvent<string>) => void): void;
  close(): void;
}

type EventSourceFactory = (url: string) => EventSourceLike;

export type OperationalAlertSeverity = 'notice' | 'warning' | 'critical';

export interface OperationalAlert {
  id: string;
  severity: OperationalAlertSeverity;
  title: string;
  detail: string;
}

export interface AlertSnapshot {
  source: 'gui-core';
  generatedAtUnixMs: number;
  alerts: ReadonlyArray<OperationalAlert>;
}

export type AuditOutcome = 'succeeded' | 'conflict' | 'rejected';
export type AuditAuthentication = 'gateway' | 'disabled' | 'none';

export interface AuditEntry {
  id: string;
  occurredAtUnixMs: number;
  requestId: string;
  operation: 'config.draft.upsert' | 'config.draft.clear' | 'api.mutation';
  outcome: AuditOutcome;
  authentication: AuditAuthentication;
  targetCount: number;
  targets: ReadonlyArray<string>;
  targetsTruncated: boolean;
}

export interface AuditSnapshot {
  source: 'gui-core';
  actorAvailable: false;
  entries: ReadonlyArray<AuditEntry>;
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSmithproxyState(value: unknown): value is SmithproxyState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'unreachable', 'unauthorized', 'unconfigured', 'error'].includes(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNullableNonNegativeInteger(value: unknown): value is number | null {
  return value === null || isNonNegativeInteger(value);
}

function isRuntimeMetricsState(value: unknown): value is RuntimeMetricsState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'unavailable', 'unconfigured'].includes(value);
}

function normalizedPath(value: string, label: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || /[?#]/u.test(value)) {
    throw new Error(`${label} must be a same-origin absolute path.`);
  }
  const segments = value.split('/').filter(Boolean);
  if (segments.some(segment => segment === '.' || segment === '..')) {
    throw new Error(`${label} cannot contain relative path segments.`);
  }
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

function joinedPath(base: string, suffix: string): string {
  return base === '/' ? suffix : `${base}${suffix}`;
}

function parseHealth(value: unknown): SystemHealth {
  if (!isObject(value) || value.status !== 'ok' || !isObject(value.smithproxy)) {
    throw new Error('Invalid health response.');
  }
  const {state, detail, checked_at_unix_ms: checkedAtUnixMs} = value.smithproxy;
  if (!isSmithproxyState(state) || typeof detail !== 'string' ||
      !(checkedAtUnixMs === null || (typeof checkedAtUnixMs === 'number' && Number.isSafeInteger(checkedAtUnixMs)))) {
    throw new Error('Invalid Smithproxy health response.');
  }
  return {status: 'ok', smithproxy: {state, detail, checkedAtUnixMs}};
}

function parseCapabilities(value: unknown): SystemCapabilities {
  if (!isObject(value) || value.service !== 'smithproxy-gui' || typeof value.api_version !== 'string' ||
      typeof value.base_path !== 'string' || !isSmithproxyState(value.smithproxy_state) ||
      !isObject(value.features)) {
    throw new Error('Invalid capabilities response.');
  }
  const features = value.features;
  if (typeof features.config_read !== 'boolean' || typeof features.config_write !== 'boolean' ||
      typeof features.drafts !== 'boolean' || typeof features.draft_preflight !== 'boolean' ||
      typeof features.jobs !== 'boolean' ||
      typeof features.events !== 'boolean' || typeof features.alerts !== 'boolean' ||
      typeof features.audit !== 'boolean' ||
      typeof features.smithproxy_events !== 'boolean' ||
      typeof features.metrics !== 'boolean' || typeof features.session_activity !== 'boolean' ||
      typeof features.tls_monitoring !== 'boolean' || typeof features.neighbor_monitoring !== 'boolean') {
    throw new Error('Invalid capabilities feature flags.');
  }
  return {
    service: 'smithproxy-gui',
    apiVersion: value.api_version,
    basePath: value.base_path,
    smithproxyState: value.smithproxy_state,
    features: {
      configRead: features.config_read,
      configWrite: features.config_write,
      drafts: features.drafts,
      draftPreflight: features.draft_preflight,
      jobs: features.jobs,
      events: features.events,
      alerts: features.alerts,
      audit: features.audit,
      smithproxyEvents: features.smithproxy_events,
      metrics: features.metrics,
      sessionActivity: features.session_activity,
      tlsMonitoring: features.tls_monitoring,
      neighborMonitoring: features.neighbor_monitoring,
    },
  };
}

function parseStatus(value: unknown): SystemSnapshot {
  if (!isObject(value) || value.service !== 'smithproxy-gui' || !isNonNegativeInteger(value.uptime_ms) ||
      !isObject(value.smithproxy)) {
    throw new Error('Invalid system status response.');
  }
  const source = value.smithproxy;
  if (typeof source.configured !== 'boolean' || !isSmithproxyState(source.state) ||
      typeof source.detail !== 'string' || !isNullableNonNegativeInteger(source.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(source.last_success_at_unix_ms) ||
      !isNullableNonNegativeInteger(source.latency_ms) || !isNonNegativeInteger(source.total_probes) ||
      !isNonNegativeInteger(source.consecutive_failures) || !isObject(source.availability_window) ||
      !isNonNegativeInteger(source.availability_window.samples) ||
      !isNonNegativeInteger(source.availability_window.successful) ||
      source.availability_window.successful > source.availability_window.samples ||
      !Array.isArray(source.history) || source.history.length > 60) {
    throw new Error('Invalid Smithproxy status response.');
  }
  const history = source.history.map((item): ProbeSample => {
    if (!isObject(item) || !isSmithproxyState(item.state) ||
        !isNonNegativeInteger(item.checked_at_unix_ms) || !isNullableNonNegativeInteger(item.latency_ms)) {
      throw new Error('Invalid Smithproxy probe history.');
    }
    return {state: item.state, checkedAtUnixMs: item.checked_at_unix_ms, latencyMs: item.latency_ms};
  });
  if (source.availability_window.samples !== history.length || source.total_probes < history.length) {
    throw new Error('Inconsistent Smithproxy status counters.');
  }
  return {
    service: 'smithproxy-gui',
    uptimeMs: value.uptime_ms,
    smithproxy: {
      configured: source.configured,
      state: source.state,
      detail: source.detail,
      checkedAtUnixMs: source.checked_at_unix_ms,
      lastSuccessAtUnixMs: source.last_success_at_unix_ms,
      latencyMs: source.latency_ms,
      totalProbes: source.total_probes,
      consecutiveFailures: source.consecutive_failures,
      availabilityWindow: {
        samples: source.availability_window.samples,
        successful: source.availability_window.successful,
      },
      history,
    },
  };
}

function parseMetricsCounters(value: unknown): Omit<ListenerMetrics, 'name'> {
  if (!isObject(value) || !isNonNegativeInteger(value.workers) ||
      !isNonNegativeInteger(value.sessions_total) || !isNonNegativeInteger(value.sessions_active) ||
      !isNonNegativeInteger(value.bytes_up) || !isNonNegativeInteger(value.bytes_down) ||
      value.sessions_active > value.sessions_total) {
    throw new Error('Invalid Smithproxy runtime counters.');
  }
  return {
    workers: value.workers,
    sessionsTotal: value.sessions_total,
    sessionsActive: value.sessions_active,
    bytesUp: value.bytes_up,
    bytesDown: value.bytes_down,
  };
}

function parseRuntimeMetrics(value: unknown): RuntimeMetricsSnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || typeof value.detail !== 'string' ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) || !Array.isArray(value.listeners) ||
      value.listeners.length > 32 || !Array.isArray(value.history) || value.history.length > 60) {
    throw new Error('Invalid runtime metrics response.');
  }
  const names = new Set<string>();
  const listeners = value.listeners.map((item): ListenerMetrics => {
    if (!isObject(item) || typeof item.name !== 'string' || item.name.length === 0 ||
        item.name.length > 64 || names.has(item.name)) {
      throw new Error('Invalid Smithproxy listener metrics.');
    }
    names.add(item.name);
    return {name: item.name, ...parseMetricsCounters(item)};
  });
  let previousTimestamp = -1;
  const history = value.history.map((item): RuntimeMetricsSample => {
    if (!isObject(item) || !isRuntimeMetricsState(item.state) ||
        !isNonNegativeInteger(item.checked_at_unix_ms) ||
        item.checked_at_unix_ms <= previousTimestamp || !isNonNegativeInteger(item.sessions_active) ||
        !isNonNegativeInteger(item.bytes_up) || !isNonNegativeInteger(item.bytes_down)) {
      throw new Error('Invalid runtime metrics history.');
    }
    previousTimestamp = item.checked_at_unix_ms;
    return {
      state: item.state,
      checkedAtUnixMs: item.checked_at_unix_ms,
      sessionsActive: item.sessions_active,
      bytesUp: item.bytes_up,
      bytesDown: item.bytes_down,
    };
  });
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    totals: parseMetricsCounters(value.totals),
    listeners,
    history,
  };
}

function parseSessionActivity(value: unknown): SessionActivitySnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || typeof value.detail !== 'string' ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !isNonNegativeInteger(value.total) || !isNonNegativeInteger(value.speed_up) ||
      !isNonNegativeInteger(value.speed_down) || !Array.isArray(value.protocols) ||
      value.protocols.length > 32) {
    throw new Error('Invalid session activity response.');
  }
  const names = new Set<string>();
  const protocols = value.protocols.map((item): SessionActivityBucket => {
    if (!isObject(item) || typeof item.protocol !== 'string' || item.protocol.length === 0 ||
        item.protocol.length > 32 || names.has(item.protocol) || !isNonNegativeInteger(item.sessions) ||
        !isNonNegativeInteger(item.speed_up) || !isNonNegativeInteger(item.speed_down) ||
        !isNonNegativeInteger(item.bytes_up) || !isNonNegativeInteger(item.bytes_down)) {
      throw new Error('Invalid session activity bucket.');
    }
    names.add(item.protocol);
    return {
      protocol: item.protocol,
      sessions: item.sessions,
      speedUp: item.speed_up,
      speedDown: item.speed_down,
      bytesUp: item.bytes_up,
      bytesDown: item.bytes_down,
    };
  });
  const total = protocols.reduce((sum, item) => sum + item.sessions, 0);
  const speedUp = protocols.reduce((sum, item) => sum + item.speedUp, 0);
  const speedDown = protocols.reduce((sum, item) => sum + item.speedDown, 0);
  if (!Number.isSafeInteger(total) || !Number.isSafeInteger(speedUp) ||
      !Number.isSafeInteger(speedDown) || total !== value.total || speedUp !== value.speed_up ||
      speedDown !== value.speed_down) {
    throw new Error('Inconsistent session activity totals.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    total: value.total,
    speedUp: value.speed_up,
    speedDown: value.speed_down,
    protocols,
  };
}

function parseTlsCache(value: unknown): TlsCacheSnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || typeof value.detail !== 'string' ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !isNonNegativeInteger(value.size) || !isNonNegativeInteger(value.capacity) ||
      value.size > value.capacity) {
    throw new Error('Invalid TLS cache response.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    size: value.size,
    capacity: value.capacity,
  };
}

function parseNeighbors(value: unknown): NeighborSnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || typeof value.detail !== 'string' ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !isNonNegativeInteger(value.hosts_total) || !isNonNegativeInteger(value.active_today) ||
      !isNonNegativeInteger(value.active_week) || !isNonNegativeInteger(value.tagged_hosts) ||
      !isNonNegativeInteger(value.observations) || !isNonNegativeInteger(value.bytes_up) ||
      !isNonNegativeInteger(value.bytes_down) || value.active_today > value.active_week ||
      value.active_week > value.hosts_total || value.tagged_hosts > value.hosts_total) {
    throw new Error('Invalid neighborhood response.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    hostsTotal: value.hosts_total,
    activeToday: value.active_today,
    activeWeek: value.active_week,
    taggedHosts: value.tagged_hosts,
    observations: value.observations,
    bytesUp: value.bytes_up,
    bytesDown: value.bytes_down,
  };
}

function parseEvents(value: unknown): EventSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' ||
      typeof value.smithproxy_events_available !== 'boolean' || !Array.isArray(value.events) ||
      value.events.length > 60) {
    throw new Error('Invalid operational event response.');
  }
  const ids = new Set<string>();
  const events = value.events.map((item): OperationalEvent => {
    if (!isObject(item) || typeof item.id !== 'string' || item.id.length === 0 || item.id.length > 96 ||
        ids.has(item.id) || !isNonNegativeInteger(item.source_revision) ||
        !isNonNegativeInteger(item.occurred_at_unix_ms) ||
        !['info', 'notice', 'warning', 'error'].includes(String(item.severity)) ||
        item.source !== 'gui-core' || typeof item.message !== 'string' ||
        item.message.length === 0 || item.message.length > 256 || /[\u0000-\u001f\u007f]/u.test(item.message)) {
      throw new Error('Invalid operational event entry.');
    }
    ids.add(item.id);
    return {
      id: item.id,
      sourceRevision: item.source_revision,
      occurredAtUnixMs: item.occurred_at_unix_ms,
      severity: item.severity as EventSeverity,
      source: 'gui-core',
      message: item.message,
    };
  });
  return {source: 'gui-core', smithproxyEventsAvailable: value.smithproxy_events_available, events};
}

function parseAlerts(value: unknown): AlertSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' ||
      !isNonNegativeInteger(value.generated_at_unix_ms) || !Array.isArray(value.alerts) ||
      value.alerts.length > 16) {
    throw new Error('Invalid operational alert response.');
  }
  const ids = new Set<string>();
  const alerts = value.alerts.map((item): OperationalAlert => {
    if (!isObject(item) || typeof item.id !== 'string' || !/^[a-z0-9-]{1,64}$/u.test(item.id) ||
        !['notice', 'warning', 'critical'].includes(String(item.severity)) ||
        typeof item.title !== 'string' || item.title.length < 1 || item.title.length > 96 ||
        typeof item.detail !== 'string' || item.detail.length < 1 || item.detail.length > 256 ||
        /[\u0000-\u001f\u007f]/u.test(item.title) || /[\u0000-\u001f\u007f]/u.test(item.detail)) {
      throw new Error('Invalid operational alert entry.');
    }
    if (ids.has(item.id)) throw new Error('Duplicate operational alert identifier.');
    ids.add(item.id);
    return {
      id: item.id,
      severity: item.severity as OperationalAlertSeverity,
      title: item.title,
      detail: item.detail,
    };
  });
  return {source: 'gui-core', generatedAtUnixMs: value.generated_at_unix_ms, alerts};
}

function parseAudit(value: unknown): AuditSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' || value.actor_available !== false ||
      !Array.isArray(value.entries) || value.entries.length > 256) {
    throw new Error('Invalid management audit response.');
  }
  const ids = new Set<string>();
  const entries = value.entries.map((item): AuditEntry => {
    if (!isObject(item) || typeof item.id !== 'string' || !/^audit-[1-9][0-9]{0,19}$/u.test(item.id) ||
        ids.has(item.id) || !isNonNegativeInteger(item.occurred_at_unix_ms) ||
        typeof item.request_id !== 'string' || !/^[0-9a-f]{1,32}-[1-9][0-9]{0,19}$/u.test(item.request_id) ||
        !['config.draft.upsert', 'config.draft.clear', 'api.mutation'].includes(String(item.operation)) ||
        !['succeeded', 'conflict', 'rejected'].includes(String(item.outcome)) ||
        !['gateway', 'disabled', 'none'].includes(String(item.authentication)) || item.actor !== null ||
        !isNonNegativeInteger(item.target_count) || item.target_count > 4096 ||
        !Array.isArray(item.targets) || item.targets.length > 32 ||
        !item.targets.every(target => typeof target === 'string' && target.length > 0 && target.length <= 512 &&
          /^[A-Za-z0-9_.\[\]-]+$/u.test(target)) || typeof item.targets_truncated !== 'boolean' ||
        item.targets.length > item.target_count || item.targets_truncated !== (item.targets.length < item.target_count)) {
      throw new Error('Invalid management audit entry.');
    }
    ids.add(item.id);
    return {
      id: item.id,
      occurredAtUnixMs: item.occurred_at_unix_ms,
      requestId: item.request_id,
      operation: item.operation as AuditEntry['operation'],
      outcome: item.outcome as AuditOutcome,
      authentication: item.authentication as AuditAuthentication,
      targetCount: item.target_count,
      targets: item.targets as string[],
      targetsTruncated: item.targets_truncated,
    };
  });
  return {source: 'gui-core', actorAvailable: false, entries};
}

export class SystemClient {
  readonly #apiBase: string;
  readonly #basePath: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #eventSourceFactory: EventSourceFactory;

  constructor(
    apiBase: string,
    basePath: string,
    fetchImplementation: typeof fetch = (input, init) => fetch(input, init),
    timeoutMs = 3000,
    eventSourceFactory: EventSourceFactory = url => new EventSource(url, {withCredentials: true}),
  ) {
    this.#apiBase = normalizedPath(apiBase, 'API base');
    this.#basePath = normalizedPath(basePath, 'Base path');
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
    this.#eventSourceFactory = eventSourceFactory;
  }

  async health(): Promise<SystemHealth> {
    return parseHealth(await this.#request(joinedPath(this.#basePath, '/healthz')));
  }

  async capabilities(): Promise<SystemCapabilities> {
    return parseCapabilities(await this.#request(joinedPath(this.#apiBase, '/capabilities')));
  }

  async status(): Promise<SystemSnapshot> {
    return parseStatus(await this.#request(joinedPath(this.#apiBase, '/status')));
  }

  async metricsSummary(): Promise<RuntimeMetricsSnapshot> {
    return parseRuntimeMetrics(await this.#request(joinedPath(this.#apiBase, '/metrics/summary')));
  }

  async sessionActivity(): Promise<SessionActivitySnapshot> {
    return parseSessionActivity(await this.#request(joinedPath(this.#apiBase, '/sessions/activity')));
  }

  async tlsCacheSummary(): Promise<TlsCacheSnapshot> {
    return parseTlsCache(await this.#request(joinedPath(this.#apiBase, '/tls/cache/summary')));
  }

  async neighborSummary(): Promise<NeighborSnapshot> {
    return parseNeighbors(await this.#request(joinedPath(this.#apiBase, '/network/neighbors/summary')));
  }

  async recentEvents(): Promise<EventSnapshot> {
    return parseEvents(await this.#request(joinedPath(this.#apiBase, '/events/recent')));
  }

  subscribeEvents(handlers: EventStreamHandlers): () => void {
    const source = this.#eventSourceFactory(joinedPath(this.#apiBase, '/events'));
    let closed = false;
    const fail = (reason: unknown): void => {
      if (closed) return;
      closed = true;
      source.close();
      handlers.invalid(reason instanceof Error ? reason : new Error('Invalid operational event stream.'));
    };
    const parseData = (event: MessageEvent<string>): unknown => {
      if (typeof event.data !== 'string' || event.data.length > 32 * 1024) {
        throw new Error('Invalid operational event stream payload.');
      }
      return JSON.parse(event.data) as unknown;
    };
    const acceptSnapshot = (event: MessageEvent<string>): void => {
      try {
        handlers.snapshot(parseEvents(parseData(event)));
      } catch (error) {
        fail(error);
      }
    };
    source.addEventListener('open', () => {
      if (!closed) handlers.connection?.('open');
    });
    source.addEventListener('error', () => {
      if (!closed) handlers.connection?.('reconnecting');
    });
    source.addEventListener('snapshot', acceptSnapshot);
    source.addEventListener('reset', acceptSnapshot);
    source.addEventListener('operational', (event): void => {
      try {
        const snapshot = parseEvents({
          source: 'gui-core',
          smithproxy_events_available: false,
          events: [parseData(event)],
        });
        const [accepted] = snapshot.events;
        if (!accepted) throw new Error('Operational event stream entry is missing.');
        handlers.event(accepted);
      } catch (error) {
        fail(error);
      }
    });
    return (): void => {
      if (closed) return;
      closed = true;
      source.close();
    };
  }

  async activeAlerts(): Promise<AlertSnapshot> {
    return parseAlerts(await this.#request(joinedPath(this.#apiBase, '/alerts')));
  }

  async recentAudit(): Promise<AuditSnapshot> {
    return parseAudit(await this.#request(joinedPath(this.#apiBase, '/audit/recent')));
  }

  async #request(path: string): Promise<unknown> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(path, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {Accept: 'application/json'},
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw httpStatusError(response, 'System API');
      return await response.json() as unknown;
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
