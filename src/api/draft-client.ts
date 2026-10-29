import {httpStatusError} from './http-error';

export type DraftScalar = boolean | number | string | ReadonlyArray<string> | ReadonlyArray<number>;

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

export type DraftSectionName =
  | 'settings' | 'debug' | 'address_objects' | 'port_objects' | 'proto_objects'
  | 'detection_profiles' | 'captures' | 'content_profiles' | 'tls_ca' | 'tls_profiles'
  | 'ssh_profiles' | 'alg_dns_profiles' | 'routing' | 'policy' | 'starttls_signatures'
  | 'detection_signatures' | 'script_profiles' | 'auth_profiles';

export interface DraftPreflightSection {
  name: DraftSectionName;
  changeCount: number;
  sensitiveChangeCount: number;
}

export interface DraftPreflightBlocker {
  code:
    | 'draft.empty'
    | 'upstream.transaction_unavailable'
    | 'upstream.transaction_incompatible'
    | 'upstream.schema_review_required'
    | 'draft.base_revision_unavailable'
    | 'gui.transaction_transport_unavailable';
  message: string;
}

export interface DraftPreflight {
  source: 'gui-core';
  draftId: 'workspace-draft';
  draftVersion: number;
  baseRevision: string | null;
  changeCount: number;
  sensitiveChangeCount: number;
  schemaValidation: 'valid';
  upstreamValidation: 'unavailable';
  commitAvailable: false;
  sections: ReadonlyArray<DraftPreflightSection>;
  blockers: ReadonlyArray<DraftPreflightBlocker>;
}

export interface DraftValidation {
  source: 'gui-core';
  draftId: 'workspace-draft';
  draftVersion: number;
  baseRevision: string;
  upstreamValidation: 'valid';
  validatedOperations: number;
  warningCount: number;
  restart: 'not-required' | 'required' | 'scheduled';
}

type JsonObject = Record<string, unknown>;
const MAX_DRAFT_RESPONSE_BYTES = 8 * 1024 * 1024;

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

function isCanonicalRevision(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value));
}

function scalar(value: unknown): DraftScalar {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.length <= 65536 && !value.includes('\0')) return value;
  if (Array.isArray(value) && value.length <= 256 && value.every(item =>
    typeof item === 'string' && item.length > 0 && item.length <= 65536 && !item.includes('\0'))) {
    return value;
  }
  if (Array.isArray(value) && value.length <= 256 && value.every(item =>
    typeof item === 'number' && Number.isSafeInteger(item))) {
    return value;
  }
  throw new Error('Invalid draft scalar.');
}

async function boundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('Content-Length');
  if (declaredLength !== null &&
      (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > MAX_DRAFT_RESPONSE_BYTES)) {
    throw new Error('Draft response exceeded the size limit.');
  }
  if (!response.body) return JSON.parse(await response.text()) as unknown;
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let size = 0;
  let payload = '';
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_DRAFT_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('Draft response exceeded the size limit.');
      }
      payload += decoder.decode(value, {stream: true});
    }
    payload += decoder.decode();
    return JSON.parse(payload) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes('size limit')) throw error;
    throw new Error('Draft API returned invalid JSON.');
  } finally {
    reader.releaseLock();
  }
}

function parseDraft(value: unknown): DraftSnapshot {
  if (!isObject(value) || value.id !== 'workspace-draft' ||
      !isCanonicalRevision(value.base_revision) ||
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

const draftSectionNames = new Set<DraftSectionName>([
  'settings', 'debug', 'address_objects', 'port_objects', 'proto_objects',
  'detection_profiles', 'captures', 'content_profiles', 'tls_ca', 'tls_profiles',
  'ssh_profiles', 'alg_dns_profiles', 'routing', 'policy', 'starttls_signatures',
  'detection_signatures', 'script_profiles', 'auth_profiles',
]);

const availabilityBlockerCodes = new Set<DraftPreflightBlocker['code']>([
  'upstream.transaction_unavailable',
  'upstream.transaction_incompatible',
  'upstream.schema_review_required',
  'draft.base_revision_unavailable',
  'gui.transaction_transport_unavailable',
]);

function parsePreflight(value: unknown): DraftPreflight {
  if (!isObject(value) || value.source !== 'gui-core' || value.draft_id !== 'workspace-draft' ||
      !Number.isSafeInteger(value.draft_version) || Number(value.draft_version) < 0 ||
      !isCanonicalRevision(value.base_revision) ||
      !Number.isSafeInteger(value.change_count) || Number(value.change_count) < 0 ||
      Number(value.change_count) > 4096 || !Number.isSafeInteger(value.sensitive_change_count) ||
      Number(value.sensitive_change_count) < 0 ||
      Number(value.sensitive_change_count) > Number(value.change_count) ||
      value.schema_validation !== 'valid' || value.upstream_validation !== 'unavailable' ||
      value.commit_available !== false || !Array.isArray(value.sections) || value.sections.length > 18 ||
      !Array.isArray(value.blockers) || value.blockers.length === 0 || value.blockers.length > 2) {
    throw new Error('Invalid draft preflight response.');
  }
  const sectionNames = new Set<string>();
  let sectionChanges = 0;
  let sectionSensitive = 0;
  const sections = value.sections.map((item): DraftPreflightSection => {
    if (!isObject(item) || typeof item.name !== 'string' ||
        !draftSectionNames.has(item.name as DraftSectionName) || sectionNames.has(item.name) ||
        !Number.isSafeInteger(item.change_count) || Number(item.change_count) <= 0 ||
        !Number.isSafeInteger(item.sensitive_change_count) || Number(item.sensitive_change_count) < 0 ||
        Number(item.sensitive_change_count) > Number(item.change_count)) {
      throw new Error('Invalid draft preflight section.');
    }
    sectionNames.add(item.name);
    sectionChanges += Number(item.change_count);
    sectionSensitive += Number(item.sensitive_change_count);
    return {
      name: item.name as DraftSectionName,
      changeCount: Number(item.change_count),
      sensitiveChangeCount: Number(item.sensitive_change_count),
    };
  });
  const blockerCodes = new Set<string>();
  const blockers = value.blockers.map((item): DraftPreflightBlocker => {
    if (!isObject(item) || typeof item.code !== 'string' || (item.code !== 'draft.empty' &&
        !availabilityBlockerCodes.has(item.code as DraftPreflightBlocker['code'])) ||
        blockerCodes.has(item.code) || typeof item.message !== 'string' || item.message.length === 0 ||
        item.message.length > 256 || /[\u0000-\u001f\u007f]/u.test(item.message)) {
      throw new Error('Invalid draft preflight blocker.');
    }
    blockerCodes.add(item.code);
    return {code: item.code as DraftPreflightBlocker['code'], message: item.message};
  });
  const availabilityBlockers = [...blockerCodes].filter(code =>
    availabilityBlockerCodes.has(code as DraftPreflightBlocker['code']));
  if (sectionChanges !== Number(value.change_count) || sectionSensitive !== Number(value.sensitive_change_count) ||
      (Number(value.change_count) === 0) !== blockerCodes.has('draft.empty') ||
      availabilityBlockers.length !== 1 ||
      (blockerCodes.has('draft.base_revision_unavailable') && value.base_revision !== null) ||
      (blockerCodes.has('gui.transaction_transport_unavailable') && value.base_revision === null)) {
    throw new Error('Inconsistent draft preflight response.');
  }
  return {
    source: 'gui-core', draftId: 'workspace-draft', draftVersion: Number(value.draft_version),
    baseRevision: value.base_revision, changeCount: Number(value.change_count),
    sensitiveChangeCount: Number(value.sensitive_change_count), schemaValidation: 'valid',
    upstreamValidation: 'unavailable', commitAvailable: false, sections, blockers,
  };
}

function parseValidation(value: unknown): DraftValidation {
  if (!isObject(value) || value.source !== 'gui-core' || value.draft_id !== 'workspace-draft' ||
      !Number.isSafeInteger(value.draft_version) || Number(value.draft_version) < 0 ||
      !isCanonicalRevision(value.base_revision) || value.base_revision === null ||
      value.upstream_validation !== 'valid' || !Number.isSafeInteger(value.validated_operations) ||
      Number(value.validated_operations) <= 0 || Number(value.validated_operations) > 4096 ||
      !Number.isSafeInteger(value.warning_count) || Number(value.warning_count) < 0 ||
      Number(value.warning_count) > 64 ||
      (value.restart !== 'not-required' && value.restart !== 'required' && value.restart !== 'scheduled')) {
    throw new Error('Invalid draft validation response.');
  }
  return {
    source: 'gui-core',
    draftId: 'workspace-draft',
    draftVersion: Number(value.draft_version),
    baseRevision: value.base_revision,
    upstreamValidation: 'valid',
    validatedOperations: Number(value.validated_operations),
    warningCount: Number(value.warning_count),
    restart: value.restart,
  };
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

  async preflight(): Promise<DraftPreflight> {
    return parsePreflight(await this.#request(`${this.#endpoint}/preflight`, {method: 'GET'}));
  }

  async validate(expectedVersion: number): Promise<DraftValidation> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new Error('Invalid draft version.');
    }
    return parseValidation(await this.#request(`${this.#endpoint}/validate`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion}),
    }));
  }

  async upsert(expectedVersion: number, path: string, value: DraftScalar): Promise<DraftSnapshot> {
    return this.upsertMany(expectedVersion, [{path, value}]);
  }

  async upsertMany(expectedVersion: number, changes: ReadonlyArray<DraftChange>): Promise<DraftSnapshot> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid draft version.');
    if (changes.length === 0 || changes.length > 4096) throw new Error('Invalid draft changes.');
    const paths = new Set<string>();
    const validated = changes.map(change => {
      if (change.path.length === 0 || change.path.length > 512 ||
          !/^[A-Za-z0-9_.\[\]-]+$/u.test(change.path) || paths.has(change.path)) {
        throw new Error('Invalid draft path.');
      }
      paths.add(change.path);
      return {path: change.path, value: scalar(change.value)};
    });
    return parseDraft(await this.#request(`${this.#endpoint}/changes`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion, changes: validated}),
    }));
  }

  async clear(expectedVersion: number): Promise<DraftSnapshot> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid draft version.');
    return parseDraft(await this.#request(`${this.#endpoint}/clear`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion}),
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
      if (!response.ok) throw httpStatusError(response, 'Draft API');
      return await boundedJson(response);
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
