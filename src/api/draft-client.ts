import {httpStatusError} from './http-error';
import {isCanonicalRevisionOrNull} from './revision';
import {boundedJson} from './bounded-json';

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
    | 'gui.commit_transport_unavailable';
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
  validationAvailable: boolean;
  commitAvailable: boolean;
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

export interface DraftCommit {
  source: 'gui-core';
  draftId: 'workspace-draft';
  committedDraftVersion: number;
  draftVersion: number;
  previousRevision: string;
  revision: string;
  committedOperations: number;
  warningCount: number;
  restart: 'not-required' | 'required' | 'scheduled';
  refreshJobId: string | null;
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

function parseDraft(value: unknown): DraftSnapshot {
  if (!isObject(value) || value.id !== 'workspace-draft' ||
      !isCanonicalRevisionOrNull(value.base_revision) ||
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
  'gui.commit_transport_unavailable',
]);

function parsePreflight(value: unknown): DraftPreflight {
  if (!isObject(value) || value.source !== 'gui-core' || value.draft_id !== 'workspace-draft' ||
      !Number.isSafeInteger(value.draft_version) || Number(value.draft_version) < 0 ||
      !isCanonicalRevisionOrNull(value.base_revision) ||
      !Number.isSafeInteger(value.change_count) || Number(value.change_count) < 0 ||
      Number(value.change_count) > 4096 || !Number.isSafeInteger(value.sensitive_change_count) ||
      Number(value.sensitive_change_count) < 0 ||
      Number(value.sensitive_change_count) > Number(value.change_count) ||
      value.schema_validation !== 'valid' || value.upstream_validation !== 'unavailable' ||
      typeof value.validation_available !== 'boolean' ||
      typeof value.commit_available !== 'boolean' || !Array.isArray(value.sections) ||
      value.sections.length > 18 || !Array.isArray(value.blockers) || value.blockers.length > 2) {
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
    availabilityBlockerCodes.has(code as DraftPreflightBlocker['code']) &&
    code !== 'gui.commit_transport_unavailable');
  const commitTransportUnavailable = blockerCodes.has('gui.commit_transport_unavailable');
  const expectedValidationAvailable = availabilityBlockers.length === 0 && value.base_revision !== null;
  const expectedCommitAvailable = expectedValidationAvailable && Number(value.change_count) > 0 &&
    !commitTransportUnavailable;
  if (sectionChanges !== Number(value.change_count) || sectionSensitive !== Number(value.sensitive_change_count) ||
      (Number(value.change_count) === 0) !== blockerCodes.has('draft.empty') ||
      availabilityBlockers.length > 1 ||
      (blockerCodes.has('draft.base_revision_unavailable') && value.base_revision !== null) ||
      value.validation_available !== expectedValidationAvailable ||
      value.commit_available !== expectedCommitAvailable ||
      (commitTransportUnavailable && (!expectedValidationAvailable || Number(value.change_count) === 0)) ||
      (!expectedValidationAvailable && availabilityBlockers.length !== 1)) {
    throw new Error('Inconsistent draft preflight response.');
  }
  return {
    source: 'gui-core', draftId: 'workspace-draft', draftVersion: Number(value.draft_version),
    baseRevision: value.base_revision, changeCount: Number(value.change_count),
    sensitiveChangeCount: Number(value.sensitive_change_count), schemaValidation: 'valid',
    upstreamValidation: 'unavailable', validationAvailable: value.validation_available,
    commitAvailable: value.commit_available, sections, blockers,
  };
}

function parseValidation(value: unknown): DraftValidation {
  if (!isObject(value) || value.source !== 'gui-core' || value.draft_id !== 'workspace-draft' ||
      !Number.isSafeInteger(value.draft_version) || Number(value.draft_version) < 0 ||
      !isCanonicalRevisionOrNull(value.base_revision) || value.base_revision === null ||
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

function parseCommit(value: unknown): DraftCommit {
  if (!isObject(value) || value.source !== 'gui-core' || value.draft_id !== 'workspace-draft' ||
      !Number.isSafeInteger(value.committed_draft_version) || Number(value.committed_draft_version) < 0 ||
      !Number.isSafeInteger(value.draft_version) ||
      Number(value.draft_version) !== Number(value.committed_draft_version) + 1 ||
      !isCanonicalRevisionOrNull(value.previous_revision) || value.previous_revision === null ||
      !isCanonicalRevisionOrNull(value.revision) || value.revision === null ||
      value.revision === value.previous_revision ||
      !Number.isSafeInteger(value.committed_operations) || Number(value.committed_operations) <= 0 ||
      Number(value.committed_operations) > 4096 ||
      !Number.isSafeInteger(value.warning_count) || Number(value.warning_count) < 0 ||
      Number(value.warning_count) > 64 ||
      !(value.refresh_job_id === null || (typeof value.refresh_job_id === 'string' &&
        /^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.refresh_job_id))) ||
      (value.restart !== 'not-required' && value.restart !== 'required' && value.restart !== 'scheduled')) {
    throw new Error('Invalid draft commit response.');
  }
  return {
    source: 'gui-core',
    draftId: 'workspace-draft',
    committedDraftVersion: Number(value.committed_draft_version),
    draftVersion: Number(value.draft_version),
    previousRevision: value.previous_revision,
    revision: value.revision,
    committedOperations: Number(value.committed_operations),
    warningCount: Number(value.warning_count),
    restart: value.restart,
    refreshJobId: value.refresh_job_id,
  };
}

export class DraftClient {
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #pendingRequests = new Set<AbortController>();

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

  async commit(expectedVersion: number): Promise<DraftCommit> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new Error('Invalid draft version.');
    }
    return parseCommit(await this.#request(`${this.#endpoint}/commit`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion}),
    }, Math.max(this.#timeoutMs, 15_000)));
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

  async remove(expectedVersion: number, path: string): Promise<DraftSnapshot> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid draft version.');
    if (path.length === 0 || path.length > 512 || !/^[A-Za-z0-9_.\[\]-]+$/u.test(path)) {
      throw new Error('Invalid draft path.');
    }
    return parseDraft(await this.#request(`${this.#endpoint}/changes/remove`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Smithproxy-GUI-CSRF': '1'},
      body: JSON.stringify({expected_version: expectedVersion, path}),
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

  cancelPendingRequests(): void {
    for (const controller of this.#pendingRequests) controller.abort();
    this.#pendingRequests.clear();
  }

  async #request(path: string, init: RequestInit, timeoutMs = this.#timeoutMs): Promise<unknown> {
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
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
      return await boundedJson(response, MAX_DRAFT_RESPONSE_BYTES, 'Draft');
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }
}
