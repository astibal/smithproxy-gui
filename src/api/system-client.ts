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
    jobs: boolean;
    events: boolean;
    metrics: boolean;
    sessionActivity: boolean;
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
      typeof features.jobs !== 'boolean' || typeof features.events !== 'boolean' ||
      typeof features.metrics !== 'boolean' || typeof features.session_activity !== 'boolean') {
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
      jobs: features.jobs,
      events: features.events,
      metrics: features.metrics,
      sessionActivity: features.session_activity,
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
      value.listeners.length > 32) {
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
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    totals: parseMetricsCounters(value.totals),
    listeners,
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

export class SystemClient {
  readonly #apiBase: string;
  readonly #basePath: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(
    apiBase: string,
    basePath: string,
    fetchImplementation: typeof fetch = (input, init) => fetch(input, init),
    timeoutMs = 3000,
  ) {
    this.#apiBase = normalizedPath(apiBase, 'API base');
    this.#basePath = normalizedPath(basePath, 'Base path');
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
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
      if (!response.ok) throw new Error(`System API returned HTTP ${response.status}.`);
      return await response.json() as unknown;
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
