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
    optionalGroupMaterialization: boolean;
    structuralDrafts: boolean;
    primitiveStructuralDrafts: boolean;
    namedStructuralDrafts: boolean;
    namedRenames: boolean;
    policyStructuralDrafts: boolean;
    contentRuleStructuralDrafts: boolean;
    signatureStructuralDrafts: boolean;
    structuralCollections: ReadonlyArray<string>;
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
  mode: 'gateway' | 'standalone';
  authenticated: boolean;
  administrator: string | null;
  administratorsConfigured: boolean;
  enrollmentReady: boolean;
  initialEnrollmentReady: boolean;
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

export interface GuiConfiguration {
  state: 'ready' | 'absent';
  restartRequired: boolean;
  activeBackend?: {
    bindAddress: string;
    port: number;
    basePath: string;
  };
  activeRuntime?: {
    smithproxyApiCredentialLoaded: boolean;
    previousSmithproxyApiCredentialLoaded: boolean;
    browserGatewayCredentialLoaded: boolean;
    previousBrowserGatewayCredentialLoaded: boolean;
    cliBrokerConfigured: boolean;
  };
  schemaVersion?: 1 | 2 | 3 | 4 | 5;
  backend?: {
    bindAddress: string;
    port: number;
    basePath: string;
  };
  frontend?: {
    assetRoot: string;
  };
  smithproxy?: {
    apiUrl: string;
    caCert: string;
    apiTokenFile: string;
    previousApiTokenFile: string;
    credentialEnabled: boolean;
    bootstrapFreshnessSeconds: number;
    rotationSeconds: number;
    overlapSeconds: number;
    administratorAuthSocketEnabled: boolean;
    administratorAuthSocket: string;
    cliEndpoint: string;
  };
  gateway?: {
    secretFile: string;
    previousSecretFile: string;
    credentialEnabled: boolean;
    bootstrapFreshnessSeconds: number;
    rotationSeconds: number;
    overlapSeconds: number;
  };
}

export interface AdministratorRecord {
  name: string;
  enabled: boolean;
}

export interface AdministratorInventory {
  revision: string;
  contentHash: string;
  restartRequired: boolean;
  administrators: ReadonlyArray<AdministratorRecord>;
}

export interface AdministratorMutation {
  state: 'created' | 'password_changed' | 'enabled_changed' | 'removed';
  administrator: string;
  revision: string;
  contentHash: string;
  changed: boolean;
  restartRequired: boolean;
}

export type GuiBootstrapConfiguration = {
  backend: NonNullable<GuiConfiguration['backend']>;
  frontend: GuiConfiguration['frontend'];
  smithproxy: GuiConfiguration['smithproxy'];
  gateway: GuiConfiguration['gateway'];
};

export type GuiBootstrapConfigurationField =
  'backend.bindAddress' | 'backend.port' | 'backend.basePath' |
  'frontend.assetRoot' | 'smithproxy.apiUrl' | 'smithproxy.caCert' |
  'smithproxy.apiTokenFile' | 'smithproxy.previousApiTokenFile' |
  'smithproxy.credentialEnabled' | 'smithproxy.bootstrapFreshnessSeconds' |
  'smithproxy.rotationSeconds' | 'smithproxy.overlapSeconds' | 'smithproxy.cliEndpoint' |
  'smithproxy.administratorAuthSocket' |
  'gateway.enabled' | 'gateway.secretFile' | 'gateway.previousSecretFile' |
  'gateway.credentialEnabled' | 'gateway.bootstrapFreshnessSeconds' |
  'gateway.rotationSeconds' | 'gateway.overlapSeconds';

export interface GuiBootstrapConfigurationIssue {
  field: GuiBootstrapConfigurationField;
  message: string;
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
  closedRetentionSeconds: number;
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
  entries: NeighborEntrySnapshot[];
}

export interface NeighborSampleSnapshot {
  relativeDays: number;
  observations: number;
  bytesUp: number;
  bytesDown: number;
  labels: string[];
}

export interface NeighborEntrySnapshot {
  hostname: string;
  tags: string;
  lastSeenUnixSeconds: number;
  samples: NeighborSampleSnapshot[];
}

export type InterfaceMonitorState =
  | 'starting'
  | 'ready'
  | 'degraded'
  | 'unavailable'
  | 'unconfigured'
  | 'not-advertised';

export interface InterfaceAddressSnapshot {
  family: 'IPv4' | 'IPv6' | 'other';
  address: string;
  prefixLength: number;
  scope: number;
  flags: number;
}

export interface InterfaceInventoryEntry {
  index: number;
  name: string;
  role: string;
  flags: number;
  uplink: boolean;
  addresses: ReadonlyArray<InterfaceAddressSnapshot>;
}

export interface InterfaceSnapshot {
  state: InterfaceMonitorState;
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  generation: number;
  snapshotValid: boolean;
  rolesValid: boolean;
  routeGeneration: number;
  roleGeneration: number;
  routeChangedAt: string | null;
  roleChangedAt: string | null;
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
  inventory: ReadonlyArray<InterfaceInventoryEntry>;
  lastErrorCode: string | null;
  lastErrorDetail: string | null;
}

export interface DnsLookup {
  source: 'gui-core';
  name: string;
  state: 'resolved' | 'not-found';
  addresses: ReadonlyArray<string>;
}

export type EventSeverity = 'info' | 'notice' | 'warning' | 'error';
const operationalEventVocabulary = {
  'control-plane.ready': ['control-plane', 'info', 'Smithproxy management connection is available'],
  'control-plane.starting': ['control-plane', 'notice', 'Smithproxy management check is starting'],
  'control-plane.unreachable': ['control-plane', 'error', 'Smithproxy management connection became unreachable'],
  'control-plane.unauthorized': ['control-plane', 'error', 'Smithproxy management connection was rejected'],
  'control-plane.unconfigured': ['control-plane', 'error', 'Smithproxy management connection is not configured'],
  'control-plane.error': ['control-plane', 'error', 'Smithproxy management connection reported an error'],
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
export type AuditAuthentication = 'gateway' | 'session' | 'none';

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
  const optionalGroupMaterialization = features.optional_group_materialization ?? false;
  const namedStructuralDrafts = features.named_structural_drafts ?? false;
  const namedRenames = features.named_renames ?? false;
  const policyStructuralDrafts = features.policy_structural_drafts ?? false;
  const contentRuleStructuralDrafts = features.content_rule_structural_drafts ?? false;
  const signatureStructuralDrafts = features.signature_structural_drafts ?? false;
  const legacyCollections = [
    ...(primitiveStructuralDrafts ? ['address_objects', 'port_objects', 'proto_objects'] : []),
    ...(namedStructuralDrafts ? [
      'routing', 'tls_profiles', 'content_profiles', 'ssh_profiles', 'script_profiles',
      'detection_profiles', 'alg_dns_profiles', 'auth_profiles', 'tls_ca',
    ] : []),
    ...(policyStructuralDrafts ? ['policy'] : []),
    ...(contentRuleStructuralDrafts ? ['content_profiles.content_rules'] : []),
    ...(signatureStructuralDrafts ? [
      'starttls_signatures', 'detection_signatures',
      'starttls_signatures.flow', 'detection_signatures.flow',
    ] : []),
  ];
  const structuralCollectionsValue = features.structural_collections ?? legacyCollections;
  if (!Array.isArray(structuralCollectionsValue) ||
      !structuralCollectionsValue.every(item => typeof item === 'string' &&
        /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)?$/u.test(item)) ||
      new Set(structuralCollectionsValue).size !== structuralCollectionsValue.length) {
    throw new Error('Invalid structural collection capabilities.');
  }
  const structuralCollections = structuralCollectionsValue as string[];
  const consoleAvailable = features.console ?? false;
  if (typeof features.config_read !== 'boolean' || typeof features.config_write !== 'boolean' ||
      typeof configSave !== 'boolean' ||
      typeof features.structural_drafts !== 'boolean' ||
      typeof optionalGroupMaterialization !== 'boolean' ||
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
      (optionalGroupMaterialization && (!features.config_write || !features.drafts)) ||
      (features.structural_drafts && (!features.config_write || !features.drafts)) ||
      (primitiveStructuralDrafts && (!features.config_write || !features.drafts)) ||
      (namedStructuralDrafts && (!primitiveStructuralDrafts || !features.config_write || !features.drafts)) ||
      (namedRenames && (!features.config_write || !features.drafts)) ||
      (policyStructuralDrafts && (!namedStructuralDrafts || !features.config_write || !features.drafts)) ||
      (contentRuleStructuralDrafts && (!policyStructuralDrafts || !features.config_write || !features.drafts)) ||
      (signatureStructuralDrafts && (!contentRuleStructuralDrafts || !features.config_write || !features.drafts)) ||
      (structuralCollections.length > 0 && (!features.config_write || !features.drafts)) ||
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
      optionalGroupMaterialization,
      structuralDrafts: features.structural_drafts,
      primitiveStructuralDrafts,
      namedStructuralDrafts,
      namedRenames,
      policyStructuralDrafts,
      contentRuleStructuralDrafts,
      signatureStructuralDrafts,
      structuralCollections,
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
  if (!isObject(value) || (value.mode !== 'gateway' && value.mode !== 'standalone') ||
      typeof value.authenticated !== 'boolean' ||
      typeof value.administrators_configured !== 'boolean' ||
      typeof value.enrollment_ready !== 'boolean' ||
      typeof value.initial_enrollment_ready !== 'boolean' ||
      (value.administrator !== null &&
       (typeof value.administrator !== 'string' || value.administrator.length === 0 ||
        value.administrator.length > 64)) ||
      (value.mode === 'gateway' && value.administrator !== null) ||
      (value.mode === 'standalone' && value.authenticated !== (value.administrator !== null))) {
    throw new Error('Invalid gateway session response.');
  }
  return {
    mode: value.mode, authenticated: value.authenticated,
    administrator: value.administrator,
    administratorsConfigured: value.administrators_configured,
    enrollmentReady: value.enrollment_ready,
    initialEnrollmentReady: value.initial_enrollment_ready,
  };
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
    throw new Error('Invalid Smithproxy management-check history.');
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
      !isNonNegativeInteger(value.closed_retention_seconds) || value.closed_retention_seconds === 0 ||
      value.closed_retention_seconds > 86_400 ||
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
    closedRetentionSeconds: value.closed_retention_seconds,
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
      !isNonNegativeInteger(value.bytes_down) || !Array.isArray(value.entries) ||
      value.entries.length > 4096 || value.active_today > value.active_week ||
      value.active_week > value.hosts_total || value.tagged_hosts > value.hosts_total) {
    throw new Error('Invalid neighborhood response.');
  }
  const hostnames = new Set<string>();
  const entries: NeighborEntrySnapshot[] = value.entries.map(entry => {
    if (!isObject(entry) || !isBoundedDisplayText(entry.hostname, 253) ||
        hostnames.has(entry.hostname) || typeof entry.tags !== 'string' ||
        entry.tags.length > 2048 || /[\u0000-\u001f\u007f]/u.test(entry.tags) ||
        !isNonNegativeInteger(entry.last_seen_unix_seconds) || !Array.isArray(entry.samples) ||
        entry.samples.length > 30) {
      throw new Error('Invalid neighborhood response.');
    }
    hostnames.add(entry.hostname);
    const relativeDays = new Set<number>();
    const samples: NeighborSampleSnapshot[] = entry.samples.map(sample => {
      if (!isObject(sample) || !isNonNegativeInteger(sample.relative_days) ||
          sample.relative_days > 29 || relativeDays.has(sample.relative_days) ||
          !isNonNegativeInteger(sample.observations) || !isNonNegativeInteger(sample.bytes_up) ||
          !isNonNegativeInteger(sample.bytes_down) || !Array.isArray(sample.labels) ||
          sample.labels.length > 64 ||
          sample.labels.some(label => !isBoundedDisplayText(label, 128)) ||
          new Set(sample.labels).size !== sample.labels.length) {
        throw new Error('Invalid neighborhood response.');
      }
      relativeDays.add(sample.relative_days);
      return {
        relativeDays: sample.relative_days,
        observations: sample.observations,
        bytesUp: sample.bytes_up,
        bytesDown: sample.bytes_down,
        labels: sample.labels,
      };
    });
    return {
      hostname: entry.hostname,
      tags: entry.tags,
      lastSeenUnixSeconds: entry.last_seen_unix_seconds,
      samples,
    };
  });
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
    entries,
  };
}

function parseInterfaces(value: unknown): InterfaceSnapshot {
  if (!isObject(value) || !isInterfaceMonitorState(value.state) || !isDiagnosticText(value.detail) ||
      !isNullableNonNegativeInteger(value.checked_at_unix_ms) ||
      !isNullableNonNegativeInteger(value.last_success_at_unix_ms) ||
      !coherentSampleTimes(value.state, value.checked_at_unix_ms, value.last_success_at_unix_ms) ||
      !isNonNegativeInteger(value.generation) || typeof value.snapshot_valid !== 'boolean' ||
      typeof value.roles_valid !== 'boolean' || !isNonNegativeInteger(value.route_generation) ||
      !isNonNegativeInteger(value.role_generation) ||
      !(value.route_changed_at === null || isBoundedDisplayText(value.route_changed_at, 32)) ||
      !(value.role_changed_at === null || isBoundedDisplayText(value.role_changed_at, 32)) ||
      typeof value.synchronization_running !== 'boolean' ||
      !isNonNegativeInteger(value.synchronization_attempts) ||
      !isNonNegativeInteger(value.synchronization_successes) ||
      !isNonNegativeInteger(value.synchronization_errors) ||
      !isNonNegativeInteger(value.event_datagrams) ||
      !isNonNegativeInteger(value.changed_event_datagrams) ||
      !isNonNegativeInteger(value.interfaces) || !isNonNegativeInteger(value.addresses) ||
      !isNonNegativeInteger(value.ipv4_addresses) || !isNonNegativeInteger(value.ipv6_addresses) ||
      !Array.isArray(value.inventory) || value.inventory.length > 4096 ||
      !(value.last_error_code === null ||
        (typeof value.last_error_code === 'string' && /^[a-z][a-z0-9._-]{0,63}$/u.test(value.last_error_code))) ||
      !(value.last_error_detail === null || isBoundedDisplayText(value.last_error_detail, 1024)) ||
      value.synchronization_successes > value.synchronization_attempts ||
      value.changed_event_datagrams > value.event_datagrams ||
      value.ipv4_addresses + value.ipv6_addresses !== value.addresses ||
      (value.state === 'ready' && value.last_error_code !== null)) {
    throw new Error('Invalid interface monitoring response.');
  }
  const indexes = new Set<number>();
  let addressCount = 0;
  const inventory = value.inventory.map((item): InterfaceInventoryEntry => {
    if (!isObject(item) || !isNonNegativeInteger(item.index) || item.index === 0 ||
        indexes.has(item.index) || !isBoundedDisplayText(item.name, 64) ||
        typeof item.role !== 'string' || item.role.length > 64 ||
        /[\u0000-\u001f\u007f]/u.test(item.role) || !isNonNegativeInteger(item.flags) ||
        item.flags > 0xffffffff || typeof item.uplink !== 'boolean' ||
        !Array.isArray(item.addresses) || item.addresses.length > 1024) {
      throw new Error('Invalid interface inventory entry.');
    }
    indexes.add(item.index);
    const addresses = item.addresses.map((address): InterfaceAddressSnapshot => {
      if (!isObject(address) ||
          (address.family !== 'IPv4' && address.family !== 'IPv6' && address.family !== 'other') ||
          !isBoundedDisplayText(address.address, 128) ||
          !isNonNegativeInteger(address.prefix_length) ||
          address.prefix_length > (address.family === 'IPv4' ? 32 : address.family === 'IPv6' ? 128 : 255) ||
          !isNonNegativeInteger(address.scope) || address.scope > 255 ||
          !isNonNegativeInteger(address.flags) || address.flags > 0xffffffff) {
        throw new Error('Invalid interface address entry.');
      }
      ++addressCount;
      return {
        family: address.family,
        address: address.address,
        prefixLength: address.prefix_length,
        scope: address.scope,
        flags: address.flags,
      };
    });
    return {
      index: item.index,
      name: item.name,
      role: item.role,
      flags: item.flags,
      uplink: item.uplink,
      addresses,
    };
  });
  if (inventory.length !== value.interfaces || addressCount !== value.addresses) {
    throw new Error('Incoherent interface inventory response.');
  }
  return {
    state: value.state,
    detail: value.detail,
    checkedAtUnixMs: value.checked_at_unix_ms,
    lastSuccessAtUnixMs: value.last_success_at_unix_ms,
    generation: value.generation,
    snapshotValid: value.snapshot_valid,
    rolesValid: value.roles_valid,
    routeGeneration: value.route_generation,
    roleGeneration: value.role_generation,
    routeChangedAt: value.route_changed_at,
    roleChangedAt: value.role_changed_at,
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
    inventory,
    lastErrorCode: value.last_error_code,
    lastErrorDetail: value.last_error_detail,
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
        !['gateway', 'session', 'none'].includes(String(item.authentication)) || item.actor !== null ||
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

function validAdministratorName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._@-]{1,64}$/u.test(value);
}

function parseAdministratorRevision(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 ||
      /[\r\n]/u.test(value)) {
    throw new Error('Invalid administrator configuration revision.');
  }
  return value;
}

function parseAdministratorInventory(value: unknown): AdministratorInventory {
  if (!isObject(value) || value.state !== 'ready' ||
      typeof value.restart_required !== 'boolean' ||
      !Array.isArray(value.administrators) || value.administrators.length > 64) {
    throw new Error('Invalid administrator inventory.');
  }
  const administrators = value.administrators.map(item => {
    if (!isObject(item) || !validAdministratorName(item.name) ||
        typeof item.enabled !== 'boolean') {
      throw new Error('Invalid administrator inventory entry.');
    }
    return {name: item.name, enabled: item.enabled};
  });
  if (new Set(administrators.map(item => item.name)).size !== administrators.length) {
    throw new Error('Duplicate administrator inventory entry.');
  }
  return {
    revision: parseAdministratorRevision(value.revision),
    contentHash: parseArchiveHash(value.content_hash),
    restartRequired: value.restart_required,
    administrators,
  };
}

function parseAdministratorMutation(
  value: unknown,
  expectedAdministrator: string,
): AdministratorMutation {
  const validStates = new Set(['created', 'password_changed', 'enabled_changed', 'removed']);
  if (!isObject(value) || typeof value.state !== 'string' || !validStates.has(value.state) ||
      value.administrator !== expectedAdministrator || typeof value.changed !== 'boolean' ||
      typeof value.restart_required !== 'boolean') {
    throw new Error('Invalid administrator mutation response.');
  }
  return {
    state: value.state as AdministratorMutation['state'],
    administrator: expectedAdministrator,
    revision: parseAdministratorRevision(value.revision),
    contentHash: parseArchiveHash(value.content_hash),
    changed: value.changed,
    restartRequired: value.restart_required,
  };
}

function validArchiveEntryPath(path: string): boolean {
  return path.length > 0 && path.length <= 1024 && !path.startsWith('/') && !path.includes('\\') &&
    !/[\u0000-\u001f\u007f]/u.test(path) &&
    !path.split('/').some(part => part.length === 0 || part === '.' || part === '..');
}

function managedArchiveResourcePath(path: string): boolean {
  return validArchiveEntryPath(path) && (path === 'gui.cfg' || ['pki/', 'templates/', 'commands/']
    .some(prefix => path.startsWith(prefix) && path.length > prefix.length));
}

function parseArchiveEntries(
  value: unknown,
  label: string,
  validPath: (path: string) => boolean = validArchiveEntryPath,
): ReadonlyArray<ArchiveEntry> {
  if (!Array.isArray(value) || value.length > 4096) {
    throw new Error(`Invalid configuration archive ${label}.`);
  }
  return value.map(entry => {
    if (!isObject(entry) || typeof entry.path !== 'string' || !validPath(entry.path) ||
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
    resources: parseArchiveEntries(value.resources, 'resource', managedArchiveResourcePath),
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

function parseGuiConfiguration(value: unknown): GuiConfiguration {
  if (!isObject(value) || typeof value.restart_required !== 'boolean' ||
      (value.state !== 'ready' && value.state !== 'absent')) {
    throw new Error('Invalid GUI configuration response.');
  }
  const parseBackend = (backend: unknown, label: string) => {
    if (!isObject(backend) || typeof backend.bind_address !== 'string' ||
        !Number.isSafeInteger(backend.port) || (backend.port as number) < 1 ||
        (backend.port as number) > 65535 || typeof backend.base_path !== 'string' ||
        !validIpv4Address(backend.bind_address) || !validBasePath(backend.base_path)) {
      throw new Error(`Invalid GUI ${label} configuration.`);
    }
    return {
      bindAddress: backend.bind_address,
      port: backend.port as number,
      basePath: backend.base_path,
    };
  };
  const activeBackend = value.active_backend === undefined
    ? undefined : parseBackend(value.active_backend, 'active backend');
  const activeRuntime = value.active_runtime === undefined ? undefined : (() => {
    const runtime = value.active_runtime;
    if (!isObject(runtime) ||
        typeof runtime.smithproxy_api_credential_loaded !== 'boolean' ||
        typeof runtime.previous_smithproxy_api_credential_loaded !== 'boolean' ||
        typeof runtime.browser_gateway_credential_loaded !== 'boolean' ||
        typeof runtime.previous_browser_gateway_credential_loaded !== 'boolean' ||
        typeof runtime.cli_broker_configured !== 'boolean') {
      throw new Error('Invalid GUI active runtime configuration.');
    }
    return {
      smithproxyApiCredentialLoaded: runtime.smithproxy_api_credential_loaded,
      previousSmithproxyApiCredentialLoaded:
        runtime.previous_smithproxy_api_credential_loaded,
      browserGatewayCredentialLoaded: runtime.browser_gateway_credential_loaded,
      previousBrowserGatewayCredentialLoaded: runtime.previous_browser_gateway_credential_loaded,
      cliBrokerConfigured: runtime.cli_broker_configured,
    };
  })();
  if (value.state === 'absent') return {
    state: 'absent', restartRequired: value.restart_required,
    ...(activeBackend ? {activeBackend} : {}),
    ...(activeRuntime ? {activeRuntime} : {}),
  };
  if (value.schema_version !== 1 && value.schema_version !== 2 &&
      value.schema_version !== 3 && value.schema_version !== 4 &&
      value.schema_version !== 5) {
    throw new Error('Unsupported GUI configuration schema.');
  }
  const backend = parseBackend(value.backend, 'backend');
  const optionalGroup = (group: unknown, keys: ReadonlyArray<string>): Record<string, string> | undefined => {
    if (group === null || group === undefined) return undefined;
    if (!isObject(group) || keys.some(key => typeof group[key] !== 'string' ||
        (group[key] as string).length > 4096 || /[\u0000-\u001f\u007f]/u.test(group[key] as string))) {
      throw new Error('Invalid GUI bootstrap configuration.');
    }
    return group as Record<string, string>;
  };
  const smithproxy = value.smithproxy;
  const gateway = value.gateway;
  const frontend = optionalGroup(value.frontend, ['asset_root']);
  const stringMember = (
    group: Record<string, unknown>, key: string, fallback?: string,
  ): string => {
    const member = group[key];
    if (member === undefined && fallback !== undefined) return fallback;
    if (typeof member !== 'string' || member.length > 4096 ||
        /[\u0000-\u001f\u007f]/u.test(member)) {
      throw new Error('Invalid GUI bootstrap configuration.');
    }
    return member;
  };
  const booleanMember = (
    group: Record<string, unknown>, key: string, fallback: boolean,
  ): boolean => {
    const member = group[key];
    if (member === undefined) return fallback;
    if (typeof member !== 'boolean') throw new Error('Invalid GUI bootstrap configuration.');
    return member;
  };
  const integerMember = (
    group: Record<string, unknown>, key: string, fallback: number,
  ): number => {
    const member = group[key];
    if (member === undefined) return fallback;
    if (!Number.isSafeInteger(member)) throw new Error('Invalid GUI bootstrap configuration.');
    return member as number;
  };
  const previousCredentialFile = (
    group: Record<string, unknown>, currentKey: string, previousKey: string,
  ): string => {
    const current = stringMember(group, currentKey);
    return stringMember(group, previousKey, `${current}.previous`);
  };
  const parsed: GuiConfiguration = {
    state: 'ready',
    restartRequired: value.restart_required,
    ...(activeBackend ? {activeBackend} : {}),
    ...(activeRuntime ? {activeRuntime} : {}),
    schemaVersion: value.schema_version,
    backend,
    ...(frontend ? {frontend: {assetRoot: frontend.asset_root!}} : {}),
    ...(isObject(smithproxy) ? {smithproxy: {
      apiUrl: stringMember(smithproxy, 'api_url'),
      caCert: stringMember(smithproxy, 'ca_cert'),
      apiTokenFile: stringMember(smithproxy, 'api_token_file'),
      previousApiTokenFile: previousCredentialFile(
        smithproxy, 'api_token_file', 'previous_api_token_file'),
      credentialEnabled: booleanMember(smithproxy, 'credential_enabled', true),
      bootstrapFreshnessSeconds: integerMember(
        smithproxy, 'credential_bootstrap_freshness_seconds', 300),
      rotationSeconds: integerMember(smithproxy, 'credential_rotation_seconds', 86400),
      overlapSeconds: integerMember(smithproxy, 'credential_overlap_seconds', 3600),
      administratorAuthSocketEnabled: booleanMember(
        smithproxy, 'administrator_auth_socket_enabled', true),
      administratorAuthSocket: stringMember(
        smithproxy, 'administrator_auth_socket', '/run/smithproxy/admin-auth.sock'),
      cliEndpoint: stringMember(smithproxy, 'cli_endpoint'),
    }} : {}),
    ...(isObject(gateway) ? {gateway: {
      secretFile: stringMember(gateway, 'secret_file'),
      previousSecretFile: previousCredentialFile(
        gateway, 'secret_file', 'previous_secret_file'),
      credentialEnabled: booleanMember(gateway, 'credential_enabled', true),
      bootstrapFreshnessSeconds: integerMember(
        gateway, 'credential_bootstrap_freshness_seconds', 300),
      rotationSeconds: integerMember(gateway, 'credential_rotation_seconds', 86400),
      overlapSeconds: integerMember(gateway, 'credential_overlap_seconds', 3600),
    }} : {}),
  };
  const validationError = validateGuiBootstrapConfiguration({
    backend: parsed.backend!, frontend: parsed.frontend,
    smithproxy: parsed.smithproxy, gateway: parsed.gateway,
  });
  if (validationError) throw new Error(validationError);
  return parsed;
}

function libconfigString(value: string): string {
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function validIpv4Address(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part =>
    /^\d{1,3}$/u.test(part) && Number(part) <= 255 && String(Number(part)) === part);
}

function validBasePath(value: string): boolean {
  if (!value.startsWith('/') || /[?#\\]/u.test(value)) return false;
  const normalized = value.length > 1 ? value.replace(/\/+$/u, '') : value;
  return normalized === '/' || normalized.slice(1).split('/').every(part =>
    part.length !== 0 && part !== '.' && part !== '..');
}

function validApiUrl(value: string): boolean {
  const loopbackHttp = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):/u.test(value);
  if ((!value.startsWith('https://') && !loopbackHttp) || /[\s?#@]/u.test(value)) return false;
  try {
    const url = new URL(value);
    return (url.pathname === '/' || url.pathname === '') && !url.username && !url.password;
  } catch {
    return false;
  }
}

function validAbsolutePath(value: string): boolean {
  return value.startsWith('/') && value.length <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validUnixSocketPath(value: string): boolean {
  return validAbsolutePath(value) && new TextEncoder().encode(value).length < 108;
}

function credentialDirectory(value: string): string {
  const separator = value.lastIndexOf('/');
  return separator === 0 ? '/' : value.slice(0, separator);
}

function sharedCredentialDirectory(current: string, previous: string): boolean {
  return credentialDirectory(current) === credentialDirectory(previous);
}

function validCliEndpoint(value: string): boolean {
  if (value === '') return true;
  const match = value.match(/^([^:\s/\\?#@\[\]]+):(\d{1,5})$/u) ??
    value.match(/^\[([^\s/\\?#@\[\]]+)\]:(\d{1,5})$/u);
  return match !== null && Number(match[2]) >= 1 && Number(match[2]) <= 65535;
}

export function guiBootstrapConfigurationIssue(
  value: GuiBootstrapConfiguration,
): GuiBootstrapConfigurationIssue | undefined {
  const issue = (field: GuiBootstrapConfigurationField, message: string) => ({field, message});
  if (!validIpv4Address(value.backend.bindAddress)) {
    return issue('backend.bindAddress', 'Bind address must be a valid IPv4 literal.');
  }
  if (!Number.isSafeInteger(value.backend.port) || value.backend.port < 1 || value.backend.port > 65535) {
    return issue('backend.port', 'Backend port must use 1 through 65535.');
  }
  if (!validBasePath(value.backend.basePath)) {
    return issue('backend.basePath', 'Public base path is invalid.');
  }
  if (value.frontend && !validAbsolutePath(value.frontend.assetRoot)) {
    return issue('frontend.assetRoot', 'Frontend asset root must use an absolute safe path.');
  }
  if (value.smithproxy) {
    if (!validApiUrl(value.smithproxy.apiUrl)) {
      return issue('smithproxy.apiUrl', 'Smithproxy API must use HTTPS, or HTTP on a loopback address.');
    }
    if (!validAbsolutePath(value.smithproxy.caCert)) {
      return issue('smithproxy.caCert', 'Smithproxy API CA certificate must use an absolute safe path.');
    }
    if (!validAbsolutePath(value.smithproxy.apiTokenFile)) {
      return issue('smithproxy.apiTokenFile', 'Smithproxy API token file must use an absolute safe path.');
    }
    if (!validAbsolutePath(value.smithproxy.previousApiTokenFile)) {
      return issue(
        'smithproxy.previousApiTokenFile',
        'Previous Smithproxy API token file must use an absolute safe path.',
      );
    }
    if (value.smithproxy.previousApiTokenFile === value.smithproxy.apiTokenFile) {
      return issue(
        'smithproxy.previousApiTokenFile',
        'Current and previous Smithproxy API token files must differ.',
      );
    }
    if (!sharedCredentialDirectory(
      value.smithproxy.apiTokenFile, value.smithproxy.previousApiTokenFile,
    )) {
      return issue(
        'smithproxy.previousApiTokenFile',
        'Current and previous Smithproxy API token files must share one directory.',
      );
    }
    for (const [field, timing] of [
      ['smithproxy.bootstrapFreshnessSeconds', value.smithproxy.bootstrapFreshnessSeconds],
      ['smithproxy.rotationSeconds', value.smithproxy.rotationSeconds],
      ['smithproxy.overlapSeconds', value.smithproxy.overlapSeconds],
    ] as const) {
      if (!Number.isSafeInteger(timing) || timing < 1 || timing > 31536000) {
        return issue(field, 'Credential timing must use 1 through 31536000 seconds.');
      }
    }
    if (!validCliEndpoint(value.smithproxy.cliEndpoint)) {
      return issue('smithproxy.cliEndpoint', 'CLI broker endpoint is invalid.');
    }
    if (!validUnixSocketPath(value.smithproxy.administratorAuthSocket)) {
      return issue(
        'smithproxy.administratorAuthSocket',
        'Administrator authentication socket must use a bounded absolute Unix socket path.',
      );
    }
  }
  if (value.gateway) {
    for (const timing of [value.gateway.bootstrapFreshnessSeconds,
      value.gateway.rotationSeconds, value.gateway.overlapSeconds]) {
      if (!Number.isSafeInteger(timing) || timing < 1 || timing > 31536000) {
        return issue('gateway.secretFile', 'Credential timing must use 1 through 31536000 seconds.');
      }
    }
    if (!validAbsolutePath(value.gateway.secretFile)) {
      return issue('gateway.secretFile', 'Gateway credential file must use an absolute safe path.');
    }
    if (value.gateway.previousSecretFile &&
        !validAbsolutePath(value.gateway.previousSecretFile)) {
      return issue(
        'gateway.previousSecretFile', 'Previous gateway credential file must use an absolute safe path.',
      );
    }
    if (value.gateway.previousSecretFile === value.gateway.secretFile) {
      return issue(
        'gateway.previousSecretFile', 'Current and previous gateway credential files must differ.',
      );
    }
    if (value.gateway.previousSecretFile &&
        !sharedCredentialDirectory(value.gateway.secretFile, value.gateway.previousSecretFile)) {
      return issue(
        'gateway.previousSecretFile',
        'Current and previous gateway credential files must share one directory.',
      );
    }
    if (value.smithproxy && value.smithproxy.apiTokenFile === value.gateway.secretFile) {
      return issue('gateway.secretFile', 'Smithproxy API and gateway credentials must use separate files.');
    }
    if (value.smithproxy && value.smithproxy.apiTokenFile === value.gateway.previousSecretFile) {
      return issue(
        'gateway.previousSecretFile', 'Smithproxy API and gateway credentials must use separate files.',
      );
    }
    if (value.smithproxy &&
        (value.smithproxy.previousApiTokenFile === value.gateway.secretFile ||
         value.smithproxy.previousApiTokenFile === value.gateway.previousSecretFile)) {
      return issue('gateway.secretFile', 'Smithproxy API and gateway credentials must use separate files.');
    }
  }
  if (!value.backend.bindAddress.startsWith('127.') &&
      (!value.gateway || !value.gateway.credentialEnabled)) {
    return issue('gateway.enabled', 'A non-loopback bind requires a gateway credential.');
  }
  return undefined;
}

export function validateGuiBootstrapConfiguration(value: GuiBootstrapConfiguration): string | undefined {
  return guiBootstrapConfigurationIssue(value)?.message;
}

export function serializeGuiConfiguration(value: GuiBootstrapConfiguration): ArrayBuffer {
  const validationError = validateGuiBootstrapConfiguration(value);
  if (validationError) throw new Error(validationError);
  const lines = [
    'gui = {',
    '  schema_version = 5;',
    '',
    '  backend = {',
    `    bind_address = ${libconfigString(value.backend.bindAddress)};`,
    `    port = ${value.backend.port};`,
    `    base_path = ${libconfigString(value.backend.basePath)};`,
    '  };',
  ];
  if (value.frontend) {
    lines.push('', '  frontend = {',
      `    asset_root = ${libconfigString(value.frontend.assetRoot)};`,
      '  };');
  }
  if (value.smithproxy) {
    lines.push('', '  smithproxy = {',
      `    api_url = ${libconfigString(value.smithproxy.apiUrl)};`,
      `    ca_cert = ${libconfigString(value.smithproxy.caCert)};`,
      `    credential_enabled = ${value.smithproxy.credentialEnabled ? 'true' : 'false'};`,
      `    api_token_file = ${libconfigString(value.smithproxy.apiTokenFile)};`,
      `    previous_api_token_file = ${libconfigString(value.smithproxy.previousApiTokenFile)};`,
      `    credential_bootstrap_freshness_seconds = ${value.smithproxy.bootstrapFreshnessSeconds}L;`,
      `    credential_rotation_seconds = ${value.smithproxy.rotationSeconds}L;`,
      `    credential_overlap_seconds = ${value.smithproxy.overlapSeconds}L;`);
    lines.push(
      `    administrator_auth_socket_enabled = ${
        value.smithproxy.administratorAuthSocketEnabled ? 'true' : 'false'};`,
      `    administrator_auth_socket = ${
        libconfigString(value.smithproxy.administratorAuthSocket)};`,
    );
    if (value.smithproxy.cliEndpoint) {
      lines.push(`    cli_endpoint = ${libconfigString(value.smithproxy.cliEndpoint)};`);
    }
    lines.push('  };');
  }
  if (value.gateway) {
    lines.push('', '  gateway = {',
      `    credential_enabled = ${value.gateway.credentialEnabled ? 'true' : 'false'};`,
      `    secret_file = ${libconfigString(value.gateway.secretFile)};`);
    if (value.gateway.previousSecretFile) {
      lines.push(`    previous_secret_file = ${libconfigString(value.gateway.previousSecretFile)};`);
    }
    lines.push(
      `    credential_bootstrap_freshness_seconds = ${value.gateway.bootstrapFreshnessSeconds}L;`,
      `    credential_rotation_seconds = ${value.gateway.rotationSeconds}L;`,
      `    credential_overlap_seconds = ${value.gateway.overlapSeconds}L;`,
      '  };');
  }
  lines.push('};', '');
  return new TextEncoder().encode(lines.join('\n')).buffer as ArrayBuffer;
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

  async enrollAdministrator(
    token: string, password: string,
  ): Promise<{administrator: string; operation: 'created' | 'rotated'}> {
    if (!/^[0-9a-f]{64}$/u.test(token)) throw new Error('Invalid enrollment token.');
    if (password.length < 14 || password.length > 1024) {
      throw new Error('Administrator password must contain 14 through 1024 characters.');
    }
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(joinedPath(this.#apiBase, '/auth/enroll'), {
        method: 'POST',
        body: JSON.stringify({token, password}),
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-Smithproxy-GUI-CSRF': '1',
        },
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw httpStatusError(response, 'Administrator enrollment');
      const value = await boundedJson(response, MAX_SYSTEM_RESPONSE_BYTES, 'Administrator enrollment');
      if (!isObject(value) || typeof value.administrator !== 'string' ||
          value.administrator.length === 0 || value.administrator.length > 64 ||
          (value.operation !== 'created' && value.operation !== 'rotated')) {
        throw new Error('Invalid administrator enrollment response.');
      }
      return {administrator: value.administrator, operation: value.operation};
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }

  async loginAdministrator(administrator: string, password: string): Promise<{administrator: string}> {
    if (!/^[A-Za-z0-9._@-]{1,64}$/u.test(administrator) ||
        password.length === 0 || password.length > 1024) {
      throw new Error('Invalid administrator credentials.');
    }
    const value = await this.#jsonMutation('/auth/login', {administrator, password}, 'Administrator login');
    if (!isObject(value) || value.administrator !== administrator) {
      throw new Error('Invalid administrator login response.');
    }
    return {administrator};
  }

  async logoutAdministrator(): Promise<void> {
    const value = await this.#jsonMutation('/auth/logout', {}, 'Administrator logout');
    if (!isObject(value) || value.state !== 'logged-out') {
      throw new Error('Invalid administrator logout response.');
    }
  }

  async archiveInventory(): Promise<ArchiveInventory> {
    return parseArchiveInventory(
      await this.#request(joinedPath(this.#apiBase, '/config/archive')),
    );
  }

  async guiConfiguration(): Promise<GuiConfiguration> {
    return parseGuiConfiguration(
      await this.#request(joinedPath(this.#apiBase, '/config/gui')),
    );
  }

  async administratorInventory(): Promise<AdministratorInventory> {
    return parseAdministratorInventory(
      await this.#request(joinedPath(this.#apiBase, '/admin/administrators')),
    );
  }

  async createAdministrator(
    name: string, password: string, expectedRevision: string, contentHash: string,
  ): Promise<AdministratorMutation> {
    this.#validateAdministratorPassword(name, password);
    return await this.#administratorMutation(
      'create', {name, password}, name, expectedRevision, contentHash);
  }

  async changeAdministratorPassword(
    name: string, password: string, expectedRevision: string, contentHash: string,
  ): Promise<AdministratorMutation> {
    this.#validateAdministratorPassword(name, password);
    return await this.#administratorMutation(
      'password', {name, password}, name, expectedRevision, contentHash);
  }

  async setAdministratorEnabled(
    name: string, enabled: boolean, expectedRevision: string, contentHash: string,
  ): Promise<AdministratorMutation> {
    if (!validAdministratorName(name)) throw new Error('Invalid administrator name.');
    return await this.#administratorMutation(
      'enabled', {name, enabled}, name, expectedRevision, contentHash);
  }

  async removeAdministrator(
    name: string, expectedRevision: string, contentHash: string,
  ): Promise<AdministratorMutation> {
    if (!validAdministratorName(name)) throw new Error('Invalid administrator name.');
    return await this.#administratorMutation(
      'remove', {name}, name, expectedRevision, contentHash);
  }

  async publishGuiConfiguration(
    value: GuiBootstrapConfiguration, expectedRevision: string, archiveHash: string,
  ): Promise<ArchiveResourceWrite> {
    const validationError = validateGuiBootstrapConfiguration(value);
    if (validationError) throw new Error(validationError);
    if (expectedRevision.length === 0 || expectedRevision.length > 256 || /[\r\n]/u.test(expectedRevision)) {
      throw new Error('Invalid expected configuration revision.');
    }
    parseArchiveHash(archiveHash);
    const payload = {
      backend: {
        bind_address: value.backend.bindAddress,
        port: value.backend.port,
        base_path: value.backend.basePath,
      },
      frontend: value.frontend ? {asset_root: value.frontend.assetRoot} : null,
      smithproxy: value.smithproxy ? {
        api_url: value.smithproxy.apiUrl,
        ca_cert: value.smithproxy.caCert,
        api_token_file: value.smithproxy.apiTokenFile,
        previous_api_token_file: value.smithproxy.previousApiTokenFile,
        credential_enabled: value.smithproxy.credentialEnabled,
        credential_bootstrap_freshness_seconds: value.smithproxy.bootstrapFreshnessSeconds,
        credential_rotation_seconds: value.smithproxy.rotationSeconds,
        credential_overlap_seconds: value.smithproxy.overlapSeconds,
        administrator_auth_socket_enabled: value.smithproxy.administratorAuthSocketEnabled,
        administrator_auth_socket: value.smithproxy.administratorAuthSocket,
        cli_endpoint: value.smithproxy.cliEndpoint,
      } : null,
      gateway: value.gateway ? {
        secret_file: value.gateway.secretFile,
        previous_secret_file: value.gateway.previousSecretFile,
        credential_enabled: value.gateway.credentialEnabled,
        credential_bootstrap_freshness_seconds: value.gateway.bootstrapFreshnessSeconds,
        credential_rotation_seconds: value.gateway.rotationSeconds,
        credential_overlap_seconds: value.gateway.overlapSeconds,
      } : null,
    };
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), ARCHIVE_REQUEST_TIMEOUT_MS);
    try {
      const response = await this.#fetch(joinedPath(this.#apiBase, '/config/gui/publish'), {
        method: 'POST', body: JSON.stringify(payload), cache: 'no-store',
        credentials: 'same-origin', redirect: 'error', signal: controller.signal,
        headers: {
          Accept: 'application/json', 'Content-Type': 'application/json',
          'X-Smithproxy-GUI-CSRF': '1',
          'X-Smithproxy-Expected-Revision': expectedRevision,
          'X-Smithproxy-Archive-SHA256': archiveHash,
        },
      });
      if (!response.ok) throw httpStatusError(response, 'GUI configuration publication');
      return parseArchiveResourceWrite(await boundedJson(
        response, MAX_SYSTEM_RESPONSE_BYTES, 'GUI configuration publication'));
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
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

  #validateAdministratorPassword(name: string, password: string): void {
    if (!validAdministratorName(name)) throw new Error('Invalid administrator name.');
    if (password.length < 14 || password.length > 1024) {
      throw new Error('Administrator password must contain 14 through 1024 characters.');
    }
  }

  async #administratorMutation(
    operation: 'create' | 'password' | 'enabled' | 'remove',
    body: Readonly<Record<string, unknown>>,
    expectedAdministrator: string,
    expectedRevision: string,
    contentHash: string,
  ): Promise<AdministratorMutation> {
    parseAdministratorRevision(expectedRevision);
    parseArchiveHash(contentHash);
    const value = await this.#jsonMutation(
      `/admin/administrators/${operation}`, body, 'Administrator configuration', {
        'X-Smithproxy-Expected-Revision': expectedRevision,
        'X-Smithproxy-Archive-SHA256': contentHash,
      });
    return parseAdministratorMutation(value, expectedAdministrator);
  }

  async #jsonMutation(
    suffix: string,
    body: Readonly<Record<string, unknown>>,
    label: string,
    extraHeaders: Readonly<Record<string, string>> = {},
  ): Promise<unknown> {
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(joinedPath(this.#apiBase, suffix), {
        method: 'POST', body: JSON.stringify(body), cache: 'no-store',
        credentials: 'same-origin', redirect: 'error', signal: controller.signal,
        headers: {
          Accept: 'application/json', 'Content-Type': 'application/json',
          'X-Smithproxy-GUI-CSRF': '1',
          ...extraHeaders,
        },
      });
      if (!response.ok) throw httpStatusError(response, label);
      return await boundedJson(response, MAX_SYSTEM_RESPONSE_BYTES, label);
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
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
    // Match the native CFtar path contract before a request crosses the API
    // boundary. This produces one predictable client error for every caller.
    if (!managedArchiveResourcePath(path)) {
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
