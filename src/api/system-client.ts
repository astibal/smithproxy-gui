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
  };
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSmithproxyState(value: unknown): value is SmithproxyState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'unreachable', 'unauthorized', 'unconfigured', 'error'].includes(value);
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
      typeof features.jobs !== 'boolean' || typeof features.events !== 'boolean') {
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
    },
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
