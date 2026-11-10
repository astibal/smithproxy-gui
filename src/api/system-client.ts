import {httpStatusError} from './http-error';
import {boundedJson} from './bounded-json';
import {normalizeSameOriginPath} from '../security/deployment-path';

const MAX_SYSTEM_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_RESPONSE_BYTES = 2 * 1024 * 1024;
const ARCHIVE_REQUEST_TIMEOUT_MS = 30_000;

export type SmithproxyState =
  | 'starting'
  | 'ready'
  | 'unreachable'
  | 'unauthorized'
  | 'unconfigured'
  | 'error';

export type TransactionCapabilityState =
  | 'starting'
  | 'not-advertised'
  | 'review-required'
  | 'incompatible'
  | 'unavailable'
  | 'ready'
  | 'unknown';

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
  transactionState: TransactionCapabilityState;
  features: {
    configRead: boolean;
    configWrite: boolean;
    configSave: boolean;
    structuralDrafts: boolean;
    primitiveStructuralDrafts: boolean;
    namedStructuralDrafts: boolean;
    namedRenames: boolean;
    policyStructuralDrafts: boolean;
    contentRuleStructuralDrafts: boolean;
    signatureStructuralDrafts: boolean;
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
    interfaceMonitoring: boolean;
    console: boolean;
  };
}

export interface GatewaySession {
  mode: 'gateway' | 'disabled';
  authenticated: boolean;
}

export interface ArchiveEntry {
  path: string;
  size: number;
  executable: boolean;
}

export interface ArchiveInventory {
  state: 'ready';
  contentHash: string;
  resources: ReadonlyArray<ArchiveEntry>;
}

export interface ArchiveValidation {
  state: 'valid';
  contentHash: string;
  archiveSize: number;
  payloadSize: number;
  formatVersion: number;
  entries: ReadonlyArray<ArchiveEntry>;
}

export interface ArchiveRestore {
  state: 'restored';
  revision: string;
  contentHash: string;
  restartRequired: true;
}

export interface ArchiveResourceWrite {
  state: 'written';
  contentHash: string;
  restartRequired: true;
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

export interface LiveSessionEntry {
  id: string;
  sourceAddress: string;
  sourcePort: string;
  destinationAddress: string;
  destinationPort: string;
  protocol: string;
  policy: string;
  siftClassifications: ReadonlyArray<string>;
  loredClassifications: ReadonlyArray<string>;
  loredStatus: string;
  speedUp: number;
  speedDown: number;
  bytesUp: number;
  bytesDown: number;
  active: boolean;
  firstSeenAtUnixMs: number;
  lastSeenAtUnixMs: number;
  closedAtUnixMs: number | null;
}

export interface LiveSessionSnapshot {
  state: RuntimeMetricsState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  entries: ReadonlyArray<LiveSessionEntry>;
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

export type InterfaceMonitorState =
  | 'starting'
  | 'ready'
  | 'degraded'
  | 'unavailable'
  | 'unconfigured'
  | 'not-advertised';

export interface InterfaceSnapshot {
  state: InterfaceMonitorState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  generation: number;
  synchronizationRunning: boolean;
  synchronizationAttempts: number;
  synchronizationSuccesses: number;
  synchronizationErrors: number;
  eventDatagrams: number;
  changedEventDatagrams: number;
  interfaces: number;
  addresses: number;
  ipv4Addresses: number;
  ipv6Addresses: number;
  lastErrorCode: string | null;
}

export interface DnsLookup {
  source: 'gui-core';
  name: string;
  state: 'resolved' | 'not-found';
  addresses: ReadonlyArray<string>;
}

export type EventSeverity = 'info' | 'notice' | 'warning' | 'error';
const operationalEventVocabulary = {
  'control-plane.ready': ['control-plane', 'info', 'Smithproxy control plane is reachable'],
  'control-plane.starting': ['control-plane', 'notice', 'Smithproxy probe is starting'],
  'control-plane.unreachable': ['control-plane', 'error', 'Smithproxy control plane changed to unreachable'],
  'control-plane.unauthorized': ['control-plane', 'error', 'Smithproxy control plane changed to unauthorized'],
  'control-plane.unconfigured': ['control-plane', 'error', 'Smithproxy control plane changed to unconfigured'],
  'control-plane.error': ['control-plane', 'error', 'Smithproxy control plane changed to error'],
  'config-refresh.succeeded': ['backend-job', 'info', 'Configuration refresh synchronized'],
  'config-refresh.failed': ['backend-job', 'warning', 'Configuration refresh did not converge'],
  'config-refresh.cancelled': ['backend-job', 'notice', 'Configuration refresh was cancelled'],
} as const;
export type OperationalEventCode = keyof typeof operationalEventVocabulary;

export interface OperationalEvent {
  id: string;
  sourceRevision: number;
  occurredAtUnixMs: number;
  severity: EventSeverity;
  category: 'control-plane' | 'backend-job';
  code: OperationalEventCode;
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
  operation: 'config.draft.upsert' | 'config.draft.clear' | 'config.draft.validate' |
    'config.draft.commit' | 'api.mutation';
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

export type JobState = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelling' | 'cancelled';

export interface JobRecord {
  id: string;
  type: 'config-refresh';
  state: JobState;
  phase: string;
  progressPercent: number;
  cancelable: boolean;
  createdAtUnixMs: number;
  updatedAtUnixMs: number;
  deadlineAtUnixMs: number;
  owner: null;
  result: string | null;
}

export interface JobSnapshot {
  source: 'gui-core';
  generatedAtUnixMs: number;
  ownerAvailable: false;
  jobs: ReadonlyArray<JobRecord>;
}

type JsonObject = Record<string, unknown>;
const MAXIMUM_CLOCK_SKEW_MS = 5 * 60 * 1000;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDiagnosticText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function isBoundedDisplayText(value: unknown, maximumLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximumLength &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function isSmithproxyState(value: unknown): value is SmithproxyState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'unreachable', 'unauthorized', 'unconfigured', 'error'].includes(value);
}

function isTransactionCapabilityState(value: unknown): value is TransactionCapabilityState {
  return typeof value === 'string' && [
    'starting', 'not-advertised', 'review-required', 'incompatible', 'unavailable', 'ready',
  ].includes(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNullableNonNegativeInteger(value: unknown): value is number | null {
  return value === null || isNonNegativeInteger(value);
}

function isPlausibleTimestamp(value: unknown): value is number {
  return isNonNegativeInteger(value) && value <= Date.now() + MAXIMUM_CLOCK_SKEW_MS;
}

function coherentSampleTimes(
  state: SmithproxyState | RuntimeMetricsState | InterfaceMonitorState,
  checkedAtUnixMs: number | null,
  lastSuccessAtUnixMs: number | null,
): boolean {
  if (!(checkedAtUnixMs === null || isPlausibleTimestamp(checkedAtUnixMs)) ||
      !(lastSuccessAtUnixMs === null || isPlausibleTimestamp(lastSuccessAtUnixMs))) {
    return false;
  }
  if (lastSuccessAtUnixMs !== null &&
      (checkedAtUnixMs === null || lastSuccessAtUnixMs > checkedAtUnixMs)) {
    return false;
  }
  return (state !== 'ready' && state !== 'degraded') ||
    (checkedAtUnixMs !== null && lastSuccessAtUnixMs !== null);
}

function isRuntimeMetricsState(value: unknown): value is RuntimeMetricsState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'unavailable', 'unconfigured'].includes(value);
}

function isInterfaceMonitorState(value: unknown): value is InterfaceMonitorState {
  return typeof value === 'string' &&
    ['starting', 'ready', 'degraded', 'unavailable', 'unconfigured', 'not-advertised'].includes(value);
}

function joinedPath(base: string, suffix: string): string {
  return base === '/' ? suffix : `${base}${suffix}`;
}

function parseHealth(value: unknown): SystemHealth {
  if (!isObject(value) || value.status !== 'ok' || !isObject(value.smithproxy)) {
    throw new Error('Invalid health response.');
  }
  const {state, detail, checked_at_unix_ms: checkedAtUnixMs} = value.smithproxy;
  if (!isSmithproxyState(state) || !isDiagnosticText(detail) ||
      !(checkedAtUnixMs === null || isPlausibleTimestamp(checkedAtUnixMs))) {
    throw new Error('Invalid Smithproxy health response.');
  }
  return {status: 'ok', smithproxy: {state, detail, checkedAtUnixMs}};
}

function parseCapabilities(value: unknown): SystemCapabilities {
  if (!isObject(value) || value.service !== 'smithproxy-gui' || value.api_version !== 'v1' ||
      typeof value.base_path !== 'string' || !isSmithproxyState(value.smithproxy_state) ||
      !isObject(value.features)) {
    throw new Error('Invalid capabilities response.');
  }
  const basePath = normalizeSameOriginPath(value.base_path, 'Capability base path');
  if (basePath !== value.base_path) throw new Error('Capability base path must be canonical.');
  const features = value.features;
  const configSave = features.config_save ?? false;
  const primitiveStructuralDrafts = features.primitive_structural_drafts ?? false;
  const namedStructuralDrafts = features.named_structural_drafts ?? false;
  const namedRenames = features.named_renames ?? false;
  const policyStructuralDrafts = features.policy_structural_drafts ?? false;
  const contentRuleStructuralDrafts = features.content_rule_structural_drafts ?? false;
  const signatureStructuralDrafts = features.signature_structural_drafts ?? false;
  const consoleAvailable = features.console ?? false;
  if (typeof features.config_read !== 'boolean' || typeof features.config_write !== 'boolean' ||
      typeof configSave !== 'boolean' ||
      typeof features.structural_drafts !== 'boolean' ||
      typeof primitiveStructuralDrafts !== 'boolean' ||
      typeof namedStructuralDrafts !== 'boolean' ||
      typeof namedRenames !== 'boolean' ||
      typeof policyStructuralDrafts !== 'boolean' ||
      typeof contentRuleStructuralDrafts !== 'boolean' ||
      typeof signatureStructuralDrafts !== 'boolean' ||
      typeof features.drafts !== 'boolean' || typeof features.draft_preflight !== 'boolean' ||
      typeof features.jobs !== 'boolean' ||
      typeof features.events !== 'boolean' || typeof features.alerts !== 'boolean' ||
      typeof features.audit !== 'boolean' ||
      typeof features.smithproxy_events !== 'boolean' ||
      typeof features.metrics !== 'boolean' || typeof features.session_activity !== 'boolean' ||
      typeof features.tls_monitoring !== 'boolean' || typeof features.neighbor_monitoring !== 'boolean' ||
      typeof features.interface_monitoring !== 'boolean' || typeof consoleAvailable !== 'boolean') {
    throw new Error('Invalid capabilities feature flags.');
  }
  const transactionState = value.config_transaction_state ?? 'unknown';
  if (transactionState !== 'unknown' && !isTransactionCapabilityState(transactionState)) {
    throw new Error('Invalid transaction capability state.');
  }
  if ((!features.config_read &&
       (features.config_write || configSave || features.drafts || features.draft_preflight)) ||
      (features.config_write && (!features.drafts || !features.draft_preflight ||
        transactionState !== 'ready')) ||
      (features.structural_drafts && (!features.config_write || !features.drafts)) ||
      (primitiveStructuralDrafts && (!features.config_write || !features.drafts)) ||
      (namedStructuralDrafts && (!primitiveStructuralDrafts || !features.config_write || !features.drafts)) ||
      (namedRenames && (!features.config_write || !features.drafts)) ||
      (policyStructuralDrafts && (!namedStructuralDrafts || !features.config_write || !features.drafts)) ||
      (contentRuleStructuralDrafts && (!policyStructuralDrafts || !features.config_write || !features.drafts)) ||
      (signatureStructuralDrafts && (!contentRuleStructuralDrafts || !features.config_write || !features.drafts)) ||
      (features.draft_preflight && !features.drafts)) {
    throw new Error('Inconsistent privileged capabilities.');
  }
  if (features.smithproxy_events && !features.events) {
    throw new Error('Inconsistent event capabilities.');
  }
  return {
    service: 'smithproxy-gui',
    apiVersion: value.api_version,
    basePath,
    smithproxyState: value.smithproxy_state,
    transactionState,
    features: {
      configRead: features.config_read,
      configWrite: features.config_write,
      configSave,
      structuralDrafts: features.structural_drafts,
      primitiveStructuralDrafts,
      namedStructuralDrafts,
      namedRenames,
      policyStructuralDrafts,
      contentRuleStructuralDrafts,
      signatureStructuralDrafts,
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
      interfaceMonitoring: features.interface_monitoring,
      console: consoleAvailable,
    },
  };
}

function parseGatewaySession(value: unknown): GatewaySession {
  if (!isObject(value) || (value.mode !== 'gateway' && value.mode !== 'disabled') ||
      typeof value.authenticated !== 'boolean' ||
      (value.mode === 'disabled' && value.authenticated)) {
    throw new Error('Invalid gateway session response.');
  }
  return {mode: value.mode, authenticated: value.authenticated};
}

function parseStatus(value: unknown): SystemSnapshot {
  if (!isObject(value) || value.service !== 'smithproxy-gui' || !isNonNegativeInteger(value.uptime_ms) ||
      !isObject(value.smithproxy)) {
    throw new Error('Invalid system status response.');
  }
  const source = value.smithproxy;
  if (typeof source.configured !== 'boolean' || !isSmithproxyState(source.state) ||
      !isDiagnosticText(source.detail) || !isNullableNonNegativeInteger(source.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(source.last_success_at_unix_ms) ||
      !coherentSampleTimes(source.state, source.checked_at_unix_ms, source.last_success_at_unix_ms) ||
      !isNullableNonNegativeInteger(source.latency_ms) || !isNonNegativeInteger(source.total_probes) ||
      !isNonNegativeInteger(source.consecutive_failures) || !isObject(source.availability_window) ||
      !isNonNegativeInteger(source.availability_window.samples) ||
      !isNonNegativeInteger(source.availability_window.successful) ||
      source.availability_window.successful > source.availability_window.samples ||
      !Array.isArray(source.history) || source.history.length > 60) {
    throw new Error('Invalid Smithproxy status response.');
  }
  const snapshotCheckedAt = source.checked_at_unix_ms;
  let previousTimestamp = -1;
  const history = source.history.map((item): ProbeSample => {
    if (!isObject(item) || !isSmithproxyState(item.state) ||
        !isPlausibleTimestamp(item.checked_at_unix_ms) ||
        item.checked_at_unix_ms <= previousTimestamp ||
        (snapshotCheckedAt !== null && item.checked_at_unix_ms > snapshotCheckedAt) ||
        !isNullableNonNegativeInteger(item.latency_ms)) {
      throw new Error('Invalid Smithproxy probe history.');
    }
    previousTimestamp = item.checked_at_unix_ms;
    return {state: item.state, checkedAtUnixMs: item.checked_at_unix_ms, latencyMs: item.latency_ms};
  });
  const successful = history.filter(item => item.state === 'ready').length;
  if (source.availability_window.samples !== history.length ||
      source.availability_window.successful !== successful || source.total_probes < history.length) {
    throw new Error('Inconsistent Smithproxy status counters.');
  }
  if (history.length > 0 &&
      (history.at(-1)?.checkedAtUnixMs !== snapshotCheckedAt ||
       history.at(-1)?.state !== source.state)) {
    throw new Error('Inconsistent Smithproxy status timeline.');
  }
  return {
    service: 'smithproxy-gui',
    uptimeMs: value.uptime_ms,
    smithproxy: {
      configured: source.configured,
      state: source.state,
      detail: source.detail,
      checkedAtUnixMs: snapshotCheckedAt,
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
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
      !Array.isArray(value.listeners) ||
      value.listeners.length > 32 || !Array.isArray(value.history) || value.history.length > 60) {
    throw new Error('Invalid runtime metrics response.');
  }
  const snapshotCheckedAt = value.checked_at_unix_ms;
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
        !isPlausibleTimestamp(item.checked_at_unix_ms) ||
        item.checked_at_unix_ms <= previousTimestamp || !isNonNegativeInteger(item.sessions_active) ||
        (snapshotCheckedAt !== null && item.checked_at_unix_ms > snapshotCheckedAt) ||
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
  if (history.length > 0 &&
      (history.at(-1)?.checkedAtUnixMs !== snapshotCheckedAt ||
       history.at(-1)?.state !== value.state)) {
    throw new Error('Inconsistent runtime metrics timeline.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: snapshotCheckedAt,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    totals: parseMetricsCounters(value.totals),
    listeners,
    history,
  };
}

function parseSessionActivity(value: unknown): SessionActivitySnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
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

function parseLiveSessions(value: unknown): LiveSessionSnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
      !Array.isArray(value.entries) || value.entries.length > 512) {
    throw new Error('Invalid live session response.');
  }
  const identifiers = new Set<string>();
  const entries = value.entries.map((item): LiveSessionEntry => {
    const classifications = (field: unknown): ReadonlyArray<string> | undefined => {
      if (field === undefined) return [];
      if (!Array.isArray(field) || field.length > 16 ||
          field.some(entry => !isBoundedDisplayText(entry, 128)) ||
          new Set(field).size !== field.length) return undefined;
      return field as ReadonlyArray<string>;
    };
    const siftClassifications = isObject(item) ? classifications(item.sift_classifications) : undefined;
    const loredClassifications = isObject(item) ? classifications(item.lored_classifications) : undefined;
    if (!isObject(item) || !isBoundedDisplayText(item.id, 128) || identifiers.has(item.id) ||
        !isBoundedDisplayText(item.source_address, 255) ||
        !isBoundedDisplayText(item.source_port, 16) ||
        !isBoundedDisplayText(item.destination_address, 255) ||
        !isBoundedDisplayText(item.destination_port, 16) ||
        !isBoundedDisplayText(item.protocol, 32) || !isBoundedDisplayText(item.policy, 128) ||
        !siftClassifications || !loredClassifications ||
        (item.lored_status !== undefined && item.lored_status !== '' &&
          !isBoundedDisplayText(item.lored_status, 128)) ||
        !isNonNegativeInteger(item.speed_up) || !isNonNegativeInteger(item.speed_down) ||
        !isNonNegativeInteger(item.bytes_up) || !isNonNegativeInteger(item.bytes_down) ||
        typeof item.active !== 'boolean' || !isPlausibleTimestamp(item.first_seen_at_unix_ms) ||
        !isPlausibleTimestamp(item.last_seen_at_unix_ms) ||
        !isNullableNonNegativeInteger(item.closed_at_unix_ms) ||
        (item.closed_at_unix_ms !== null && !isPlausibleTimestamp(item.closed_at_unix_ms)) ||
        item.first_seen_at_unix_ms > item.last_seen_at_unix_ms ||
        (item.active && item.closed_at_unix_ms !== null) ||
        (!item.active && item.closed_at_unix_ms === null) ||
        (item.closed_at_unix_ms !== null && item.closed_at_unix_ms < item.last_seen_at_unix_ms)) {
      throw new Error('Invalid live session entry.');
    }
    identifiers.add(item.id);
    return {
      id: item.id,
      sourceAddress: item.source_address,
      sourcePort: item.source_port,
      destinationAddress: item.destination_address,
      destinationPort: item.destination_port,
      protocol: item.protocol,
      policy: item.policy,
      siftClassifications,
      loredClassifications,
      loredStatus: typeof item.lored_status === 'string' ? item.lored_status : '',
      speedUp: item.speed_up,
      speedDown: item.speed_down,
      bytesUp: item.bytes_up,
      bytesDown: item.bytes_down,
      active: item.active,
      firstSeenAtUnixMs: item.first_seen_at_unix_ms,
      lastSeenAtUnixMs: item.last_seen_at_unix_ms,
      closedAtUnixMs: item.closed_at_unix_ms,
    };
  });
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    entries,
  };
}

function parseTlsCache(value: unknown): TlsCacheSnapshot {
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
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
  if (!isObject(value) || !isRuntimeMetricsState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
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

function parseInterfaces(value: unknown): InterfaceSnapshot {
  if (!isObject(value) || !isInterfaceMonitorState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
      !isNonNegativeInteger(value.generation) || typeof value.synchronization_running !== 'boolean' ||
      !isNonNegativeInteger(value.synchronization_attempts) ||
      !isNonNegativeInteger(value.synchronization_successes) ||
      !isNonNegativeInteger(value.synchronization_errors) ||
      !isNonNegativeInteger(value.event_datagrams) ||
      !isNonNegativeInteger(value.changed_event_datagrams) ||
      !isNonNegativeInteger(value.interfaces) || !isNonNegativeInteger(value.addresses) ||
      !isNonNegativeInteger(value.ipv4_addresses) || !isNonNegativeInteger(value.ipv6_addresses) ||
      !(value.last_error_code === null ||
        (typeof value.last_error_code === 'string' && /^[a-z][a-z0-9._-]{0,63}$/u.test(value.last_error_code))) ||
      value.synchronization_successes > value.synchronization_attempts ||
      value.synchronization_errors > value.synchronization_attempts ||
      value.synchronization_successes + value.synchronization_errors > value.synchronization_attempts ||
      value.changed_event_datagrams > value.event_datagrams ||
      value.ipv4_addresses + value.ipv6_addresses !== value.addresses ||
      (value.state === 'ready' && value.last_error_code !== null)) {
    throw new Error('Invalid interface monitoring response.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    generation: value.generation,
    synchronizationRunning: value.synchronization_running,
    synchronizationAttempts: value.synchronization_attempts,
    synchronizationSuccesses: value.synchronization_successes,
    synchronizationErrors: value.synchronization_errors,
    eventDatagrams: value.event_datagrams,
    changedEventDatagrams: value.changed_event_datagrams,
    interfaces: value.interfaces,
    addresses: value.addresses,
    ipv4Addresses: value.ipv4_addresses,
    ipv6Addresses: value.ipv6_addresses,
    lastErrorCode: value.last_error_code,
  };
}

function parseEvents(value: unknown): EventSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' ||
      typeof value.smithproxy_events_available !== 'boolean' || !Array.isArray(value.events) ||
      value.events.length > 60) {
    throw new Error('Invalid operational event response.');
  }
  const ids = new Set<string>();
  let previousRevision = -1;
  let previousOccurredAt = -1;
  const events = value.events.map((item): OperationalEvent => {
    if (!isObject(item)) throw new Error('Invalid operational event entry.');
    const {id, source_revision: sourceRevision, occurred_at_unix_ms: occurredAtUnixMs,
      category, code, severity, source, message} = item;
    if (typeof code !== 'string') throw new Error('Invalid operational event entry.');
    const expected = operationalEventVocabulary[code as keyof typeof operationalEventVocabulary];
    if (typeof id !== 'string' || id.length === 0 || id.length > 96 || ids.has(id) ||
        !isNonNegativeInteger(sourceRevision) || sourceRevision <= previousRevision ||
        !isPlausibleTimestamp(occurredAtUnixMs) || occurredAtUnixMs < previousOccurredAt ||
        typeof category !== 'string' || typeof severity !== 'string' || typeof message !== 'string' ||
        !expected || category !== expected[0] || severity !== expected[1] || source !== 'gui-core' ||
        message !== expected[2] || message.length === 0 || message.length > 256 ||
        /[\u0000-\u001f\u007f]/u.test(message)) {
      throw new Error('Invalid operational event entry.');
    }
    ids.add(id);
    previousRevision = sourceRevision;
    previousOccurredAt = occurredAtUnixMs;
    return {
      id,
      sourceRevision,
      occurredAtUnixMs,
      severity: severity as EventSeverity,
      category: category as OperationalEvent['category'],
      code: code as OperationalEventCode,
      source: 'gui-core',
      message,
    };
  });
  return {source: 'gui-core', smithproxyEventsAvailable: value.smithproxy_events_available, events};
}

function parseAlerts(value: unknown): AlertSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' ||
      !isPlausibleTimestamp(value.generated_at_unix_ms) || !Array.isArray(value.alerts) ||
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
  let previousOccurredAt = -1;
  const entries = value.entries.map((item): AuditEntry => {
    if (!isObject(item) || typeof item.id !== 'string' || !/^audit-[1-9][0-9]{0,19}$/u.test(item.id) ||
        ids.has(item.id) || !isPlausibleTimestamp(item.occurred_at_unix_ms) ||
        item.occurred_at_unix_ms < previousOccurredAt ||
        typeof item.request_id !== 'string' || !/^[0-9a-f]{1,32}-[1-9][0-9]{0,19}$/u.test(item.request_id) ||
        !['config.draft.upsert', 'config.draft.clear', 'config.draft.validate',
          'config.draft.commit', 'api.mutation']
          .includes(String(item.operation)) ||
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
    previousOccurredAt = item.occurred_at_unix_ms;
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

function parseJobRecord(value: unknown): JobRecord {
  if (!isObject(value) || typeof value.id !== 'string' ||
      !/^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.id) ||
      value.type !== 'config-refresh' ||
      !['running', 'succeeded', 'failed'].includes(String(value.state)) ||
      typeof value.phase !== 'string' || value.phase.length < 1 || value.phase.length > 64 ||
      !/^[a-z][a-z0-9-]*$/u.test(value.phase) || !isNonNegativeInteger(value.progress_percent) ||
      value.progress_percent > 100 || typeof value.cancelable !== 'boolean' ||
      !isPlausibleTimestamp(value.created_at_unix_ms) || !isPlausibleTimestamp(value.updated_at_unix_ms) ||
      !isNonNegativeInteger(value.deadline_at_unix_ms) || value.updated_at_unix_ms < value.created_at_unix_ms ||
      value.deadline_at_unix_ms < value.created_at_unix_ms || value.owner !== null ||
      !(value.result === null || typeof value.result === 'string')) {
    throw new Error('Invalid backend job entry.');
  }
  const validLifecycle =
    (value.state === 'running' && value.phase === 'refreshing' &&
      (value.progress_percent === 10 || value.progress_percent === 50) && value.result === null) ||
    (value.state === 'running' && value.phase === 'waiting-for-control-plane' &&
      value.progress_percent === 25 && value.result === null) ||
    (value.state === 'running' && value.phase === 'waiting-for-revision' &&
      value.progress_percent === 75 && value.result === null) ||
    (value.state === 'succeeded' && value.phase === 'synchronized' &&
      value.progress_percent === 100 && value.result === 'Configuration snapshot synchronized') ||
    (value.state === 'failed' && value.phase === 'timed-out' &&
      value.progress_percent === 100 && value.result === 'Configuration refresh deadline exceeded');
  if (!validLifecycle || value.cancelable) {
    throw new Error('Inconsistent backend job state.');
  }
  return {
    id: value.id,
    type: 'config-refresh',
    state: value.state as JobState,
    phase: value.phase,
    progressPercent: value.progress_percent,
    cancelable: value.cancelable,
    createdAtUnixMs: value.created_at_unix_ms,
    updatedAtUnixMs: value.updated_at_unix_ms,
    deadlineAtUnixMs: value.deadline_at_unix_ms,
    owner: null,
    result: value.result,
  };
}

function parseJobs(value: unknown): JobSnapshot {
  if (!isObject(value) || value.source !== 'gui-core' || value.owner_available !== false ||
      !isPlausibleTimestamp(value.generated_at_unix_ms) || !Array.isArray(value.jobs) ||
      value.jobs.length > 128) {
    throw new Error('Invalid backend job response.');
  }
  const generatedAtUnixMs = value.generated_at_unix_ms;
  const ids = new Set<string>();
  let previousCreatedAt = -1;
  const jobs = value.jobs.map(item => {
    const job = parseJobRecord(item);
    if (ids.has(job.id) || job.createdAtUnixMs < previousCreatedAt ||
        job.createdAtUnixMs > generatedAtUnixMs || job.updatedAtUnixMs > generatedAtUnixMs) {
      throw new Error('Inconsistent backend job history.');
    }
    ids.add(job.id);
    previousCreatedAt = job.createdAtUnixMs;
    return job;
  });
  return {
    source: 'gui-core',
    generatedAtUnixMs,
    ownerAvailable: false,
    jobs,
  };
}

function parseJob(value: unknown): JobRecord {
  if (!isObject(value) || value.source !== 'gui-core' || value.owner_available !== false ||
      !Object.hasOwn(value, 'job')) {
    throw new Error('Invalid backend job response.');
  }
  return parseJobRecord(value.job);
}

function parseDnsLookup(value: unknown): DnsLookup {
  if (!isObject(value) || value.source !== 'gui-core' || typeof value.name !== 'string' ||
      value.name.length === 0 || value.name.length > 253 ||
      !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(value.name) ||
      (value.state !== 'resolved' && value.state !== 'not-found') ||
      !Array.isArray(value.addresses) || value.addresses.length > 16 ||
      value.addresses.some(address => typeof address !== 'string' ||
        !/^[0-9a-f:.]{2,45}$/iu.test(address))) {
    throw new Error('Invalid DNS lookup response.');
  }
  if ((value.state === 'resolved') !== (value.addresses.length > 0)) {
    throw new Error('Inconsistent DNS lookup response.');
  }
  return {
    source: 'gui-core',
    name: value.name,
    state: value.state,
    addresses: value.addresses,
  };
}

function parseArchiveHash(value: unknown): string {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new Error('Invalid configuration archive content hash.');
  }
  return value;
}

function parseArchiveEntries(value: unknown, label: string): ReadonlyArray<ArchiveEntry> {
  if (!Array.isArray(value) || value.length > 4096) {
    throw new Error(`Invalid configuration archive ${label}.`);
  }
  return value.map(entry => {
    if (!isObject(entry) || typeof entry.path !== 'string' || entry.path.length === 0 ||
        entry.path.length > 512 || entry.path.startsWith('/') || entry.path.includes('\\') ||
        entry.path.split('/').some(part => part.length === 0 || part === '.' || part === '..') ||
        !Number.isSafeInteger(entry.size) || (entry.size as number) < 0 ||
        typeof entry.executable !== 'boolean') {
      throw new Error(`Invalid configuration archive ${label} entry.`);
    }
    return {path: entry.path, size: entry.size as number, executable: entry.executable};
  });
}

function parseArchiveInventory(value: unknown): ArchiveInventory {
  if (!isObject(value) || value.state !== 'ready') {
    throw new Error('Invalid configuration archive inventory.');
  }
  return {
    state: 'ready',
    contentHash: parseArchiveHash(value.content_hash),
    resources: parseArchiveEntries(value.resources, 'resource'),
  };
}

function parseArchiveValidation(value: unknown): ArchiveValidation {
  if (!isObject(value) || value.state !== 'valid' ||
      !Number.isSafeInteger(value.archive_size) || (value.archive_size as number) <= 0 ||
      !Number.isSafeInteger(value.payload_size) || (value.payload_size as number) <= 0 ||
      !Number.isSafeInteger(value.format_version) || (value.format_version as number) <= 0) {
    throw new Error('Invalid configuration archive validation response.');
  }
  return {
    state: 'valid',
    contentHash: parseArchiveHash(value.content_hash),
    archiveSize: value.archive_size as number,
    payloadSize: value.payload_size as number,
    formatVersion: value.format_version as number,
    entries: parseArchiveEntries(value.entries, 'validation'),
  };
}

function parseArchiveRestore(value: unknown): ArchiveRestore {
  if (!isObject(value) || value.state !== 'restored' || value.restart_required !== true ||
      typeof value.revision !== 'string' || value.revision.length === 0 || value.revision.length > 256) {
    throw new Error('Invalid configuration archive restore response.');
  }
  return {
    state: 'restored',
    revision: value.revision,
    contentHash: parseArchiveHash(value.content_hash),
    restartRequired: true,
  };
}

function parseArchiveResourceWrite(value: unknown): ArchiveResourceWrite {
  if (!isObject(value) || value.state !== 'written' || value.restart_required !== true) {
    throw new Error('Invalid configuration resource write response.');
  }
  return {
    state: 'written',
    contentHash: parseArchiveHash(value.content_hash),
    restartRequired: true,
  };
}

export class SystemClient {
  readonly #apiBase: string;
  readonly #basePath: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #eventSourceFactory: EventSourceFactory;
  readonly #pendingRequests = new Set<AbortController>();

  constructor(
    apiBase: string,
    basePath: string,
    fetchImplementation: typeof fetch = (input, init) => fetch(input, init),
    timeoutMs = 3000,
    eventSourceFactory: EventSourceFactory = url => new EventSource(url, {withCredentials: true}),
  ) {
    this.#apiBase = normalizeSameOriginPath(apiBase, 'API base');
    this.#basePath = normalizeSameOriginPath(basePath, 'Base path');
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
    this.#eventSourceFactory = eventSourceFactory;
  }

  async health(): Promise<SystemHealth> {
    return parseHealth(await this.#request(joinedPath(this.#basePath, '/healthz')));
  }

  async capabilities(): Promise<SystemCapabilities> {
    const capabilities = parseCapabilities(
      await this.#request(joinedPath(this.#apiBase, '/capabilities')),
    );
    if (capabilities.basePath !== this.#basePath) {
      throw new Error('Capability base path does not match the application mount.');
    }
    return capabilities;
  }

  async authSession(): Promise<GatewaySession> {
    return parseGatewaySession(await this.#request(joinedPath(this.#apiBase, '/auth/session')));
  }

  async archiveInventory(): Promise<ArchiveInventory> {
    return parseArchiveInventory(
      await this.#request(joinedPath(this.#apiBase, '/config/archive')),
    );
  }

  archiveDownloadUrl(version: 'current' | 'previous'): string {
    return `${joinedPath(this.#apiBase, '/config/archive/download')}?version=${version}`;
  }

  archiveResourceUrl(path: string): string {
    this.#validateArchiveResourcePath(path);
    return `${joinedPath(this.#apiBase, '/config/archive/resource')}?${new URLSearchParams({path})}`;
  }

  async validateArchive(payload: ArrayBuffer): Promise<ArchiveValidation> {
    return parseArchiveValidation(await this.#archiveMutation('/validate', payload));
  }

  async restoreArchive(
    payload: ArrayBuffer,
    expectedRevision: string,
    contentHash: string,
  ): Promise<ArchiveRestore> {
    if (expectedRevision.length === 0 || expectedRevision.length > 256 || /[\r\n]/u.test(expectedRevision)) {
      throw new Error('Invalid expected configuration revision.');
    }
    parseArchiveHash(contentHash);
    return parseArchiveRestore(await this.#archiveMutation('/restore', payload, {
      'X-Smithproxy-Expected-Revision': expectedRevision,
      'X-Smithproxy-Archive-SHA256': contentHash,
    }));
  }

  async writeArchiveResource(
    path: string,
    payload: ArrayBuffer,
    expectedRevision: string,
    archiveHash: string,
    executable = false,
  ): Promise<ArchiveResourceWrite> {
    this.#validateArchiveResourcePath(path);
    return parseArchiveResourceWrite(await this.#resourceMutation(
      'write', path, payload, expectedRevision, archiveHash, executable,
    ));
  }

  async deleteArchiveResource(
    path: string,
    expectedRevision: string,
    archiveHash: string,
  ): Promise<ArchiveResourceWrite> {
    this.#validateArchiveResourcePath(path);
    return parseArchiveResourceWrite(await this.#resourceMutation(
      'delete', path, new ArrayBuffer(0), expectedRevision, archiveHash, false,
    ));
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

  async sessions(): Promise<LiveSessionSnapshot> {
    return parseLiveSessions(await this.#request(joinedPath(this.#apiBase, '/sessions')));
  }

  async tlsCacheSummary(): Promise<TlsCacheSnapshot> {
    return parseTlsCache(await this.#request(joinedPath(this.#apiBase, '/tls/cache/summary')));
  }

  async neighborSummary(): Promise<NeighborSnapshot> {
    return parseNeighbors(await this.#request(joinedPath(this.#apiBase, '/network/neighbors/summary')));
  }

  async interfaceSummary(): Promise<InterfaceSnapshot> {
    return parseInterfaces(await this.#request(joinedPath(this.#apiBase, '/network/interfaces/summary')));
  }

  async resolveDnsName(name: string): Promise<DnsLookup> {
    const query = new URLSearchParams({name});
    const result = parseDnsLookup(await this.#request(
      `${joinedPath(this.#apiBase, '/tools/dns/resolve')}?${query.toString()}`,
    ));
    const expectedName = name.trim().toLowerCase().replace(/\.$/u, '');
    if (result.name !== expectedName) throw new Error('DNS lookup response name does not match the request.');
    return result;
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

  async jobs(): Promise<JobSnapshot> {
    return parseJobs(await this.#request(joinedPath(this.#apiBase, '/jobs')));
  }

  async job(id: string): Promise<JobRecord> {
    if (!/^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(id)) {
      throw new Error('Invalid backend job identifier.');
    }
    return parseJob(await this.#request(joinedPath(this.#apiBase, `/jobs/${id}`)));
  }

  cancelPendingRequests(): void {
    for (const controller of this.#pendingRequests) controller.abort();
    this.#pendingRequests.clear();
  }

  async #request(path: string): Promise<unknown> {
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
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
      return await boundedJson(response, MAX_SYSTEM_RESPONSE_BYTES, 'System');
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }

  async #archiveMutation(
    suffix: '/validate' | '/restore',
    payload: ArrayBuffer,
    extraHeaders: Readonly<Record<string, string>> = {},
  ): Promise<unknown> {
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), ARCHIVE_REQUEST_TIMEOUT_MS);
    try {
      const response = await this.#fetch(joinedPath(this.#apiBase, `/config/archive${suffix}`), {
        method: 'POST',
        body: payload,
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/octet-stream',
          'X-Smithproxy-GUI-CSRF': '1',
          ...extraHeaders,
        },
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw httpStatusError(response, 'Configuration archive API');
      return await boundedJson(response, MAX_ARCHIVE_RESPONSE_BYTES, 'Configuration archive');
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }

  #validateArchiveResourcePath(path: string): void {
    const managedNamespace = ['pki/', 'templates/', 'commands/']
      .some(prefix => path.startsWith(prefix));
    // Match the native CFtar path contract before a request crosses the API
    // boundary. This produces one predictable client error for every caller.
    if (path.length === 0 || path.length > 1024 || path.startsWith('/') || path.includes('\\') ||
        /[\u0000-\u001f\u007f]/u.test(path) ||
        !managedNamespace ||
        path.split('/').some(part => part.length === 0 || part === '.' || part === '..')) {
      throw new Error('Invalid configuration archive resource path.');
    }
  }

  async #resourceMutation(
    operation: 'write' | 'delete',
    path: string,
    payload: ArrayBuffer,
    expectedRevision: string,
    archiveHash: string,
    executable: boolean,
  ): Promise<unknown> {
    if (expectedRevision.length === 0 || expectedRevision.length > 256 || /[\r\n]/u.test(expectedRevision)) {
      throw new Error('Invalid expected configuration revision.');
    }
    parseArchiveHash(archiveHash);
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), ARCHIVE_REQUEST_TIMEOUT_MS);
    try {
      const query = new URLSearchParams({path});
      const response = await this.#fetch(
        `${joinedPath(this.#apiBase, `/config/archive/resource/${operation}`)}?${query}`,
        {
          method: 'POST',
          body: payload,
          cache: 'no-store',
          credentials: 'same-origin',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/octet-stream',
            'X-Smithproxy-GUI-CSRF': '1',
            'X-Smithproxy-Expected-Revision': expectedRevision,
            'X-Smithproxy-Archive-SHA256': archiveHash,
            'X-Smithproxy-Executable': executable ? 'true' : 'false',
          },
          redirect: 'error',
          signal: controller.signal,
        },
      );
      if (!response.ok) throw httpStatusError(response, 'Configuration resource API');
      return await boundedJson(response, MAX_ARCHIVE_RESPONSE_BYTES, 'Configuration resource');
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }
}
