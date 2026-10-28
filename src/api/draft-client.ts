export type DraftScalar = boolean | number | string;

export interface DraftChange {
  path: string;
  value: DraftScalar;
}

export interface DraftSnapshot {
  id: string;
  baseRevision: string | null;
  version: number;
  changes: ReadonlyArray<DraftChange>;
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizedPath(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || /[?#]/u.test(value)) {
    throw new Error('API base must be a same-origin absolute path.');
  }
  const segments = value.split('/').filter(Boolean);
  if (segments.some(segment => segment === '.' || segment === '..')) {
    throw new Error('API base cannot contain relative path segments.');
  }
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

function scalar(value: unknown): DraftScalar {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.length <= 65536 && !value.includes('\0')) return value;
  throw new Error('Invalid draft scalar.');
}

function parseDraft(value: unknown): DraftSnapshot {
  if (!isObject(value) || value.id !== 'workspace-draft' ||
      !(value.base_revision === null || typeof value.base_revision === 'string') ||
      typeof value.version !== 'number' || !Number.isSafeInteger(value.version) || value.version < 0 ||
      !Array.isArray(value.changes) || value.changes.length > 4096) {
    throw new Error('Invalid draft response.');
  }
  const paths = new Set<string>();
  const changes = value.changes.map((item): DraftChange => {
    if (!isObject(item) || typeof item.path !== 'string' || item.path.length === 0 ||
        item.path.length > 512 || !/^[A-Za-z0-9_.\[\]-]+$/u.test(item.path) || paths.has(item.path)) {
      throw new Error('Invalid draft change.');
    }
    paths.add(item.path);
    return {path: item.path, value: scalar(item.value)};
  });
  return {id: value.id, baseRevision: value.base_revision, version: value.version, changes};
}

export class DraftClient {
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(apiBase: string, fetchImplementation: typeof fetch = (input, init) => fetch(input, init), timeoutMs = 5000) {
    const base = normalizedPath(apiBase);
    this.#endpoint = `${base === '/' ? '' : base}/config/draft`;
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
  }

  async load(): Promise<DraftSnapshot> {
    return parseDraft(await this.#request(this.#endpoint, {method: 'GET'}));
  }

  async upsert(expectedVersion: number, path: string, value: DraftScalar): Promise<DraftSnapshot> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid draft version.');
    return parseDraft(await this.#request(`${this.#endpoint}/changes`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion, path, value}),
    }));
  }

  async #request(path: string, init: RequestInit): Promise<unknown> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(path, {
        ...init,
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {Accept: 'application/json', ...init.headers},
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Draft API returned HTTP ${response.status}.`);
      return await response.json() as unknown;
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
